package app

import (
	"encoding/json"
	"github.com/mattermost/mattermost-server/v5/mlog"
	"io/ioutil"
	"net/http"

	"github.com/mattermost/mattermost-server/v5/model"
)

func (a *App) AuthenticateTokenForLogin(code string, service string) (user *model.User, err *model.AppError) {
	if len(code) == 0 {
		return nil, model.NewAppError("createSessionForUserAccessToken 1", "app.user_access_token.invalid_or_missing", nil, "", http.StatusBadRequest)
	}

	mlog.Debug("code", mlog.Any("code", code))

	// appId & appSecret & accessTokenBaseURL
	appId := *a.Config().OAuthSettings.AppId
	mlog.Debug("appId", mlog.Any("appId", appId))
	appSecret := *a.Config().OAuthSettings.AppSecret
	mlog.Debug("appSecret", mlog.Any("appSecret", appSecret))
	accessTokenBaseURL := *a.Config().OAuthSettings.AccessTokenBaseURL
	mlog.Debug("accessTokenBaseURL", mlog.Any("accessTokenBaseURL", accessTokenBaseURL))

	client := &http.Client{}

	// accessToken
	accessTokenUrl := accessTokenBaseURL + "?appId=" + appId + "&appSecret=" + appSecret + "&code=" + code
	mlog.Debug("accessTokenUrl", mlog.Any("accessTokenUrl", accessTokenUrl))

	accessTokenRequest, _ := http.NewRequest("GET", accessTokenUrl, nil)
	accessTokenResponse, accessTokenHttpErr := client.Do(accessTokenRequest)

	if accessTokenHttpErr != nil || accessTokenResponse.StatusCode < 200 || accessTokenResponse.StatusCode > 299 {
		return nil, model.NewAppError("createSessionForUserAccessToken 2", "app.user_access_token.invalid_or_missing", nil, "", http.StatusForbidden)
	}

	accessTokenResponseBody, _ := ioutil.ReadAll(accessTokenResponse.Body)
	defer accessTokenResponse.Body.Close()
	mlog.Debug("accessTokenResponseBody", mlog.Any("accessTokenResponseBody", accessTokenResponseBody))

	accessTokenJson := map[string]interface{}{}
	json.Unmarshal(accessTokenResponseBody, &accessTokenJson)
	mlog.Debug("accessTokenJson", mlog.Any("accessTokenJson", accessTokenResponseBody))

	ok := accessTokenJson["ok"].(bool)
	mlog.Debug("ok", mlog.Any("ok", ok))
	if !ok {
		return nil, model.NewAppError("createSessionForUserAccessToken 3", "app.user_access_token.invalid_or_missing", nil, "", http.StatusForbidden)
	}

	accessToken := accessTokenJson["accessToken"]
	mlog.Debug("accessToken", mlog.Any("accessToken", accessToken))

	// userInfo
	userInfoUrl := "https://oauth.foxconnedu.com/api/user/getUserInfoByAccessToken?accessToken=" + accessToken.(string)
	mlog.Debug("userInfoUrl", mlog.Any("userInfoUrl", userInfoUrl))

	userInfoRequest, _ := http.NewRequest("GET", userInfoUrl, nil)
	userInfoResponse, userInfoHttpErr := client.Do(userInfoRequest)

	if userInfoHttpErr != nil || userInfoResponse.StatusCode < 200 || userInfoResponse.StatusCode > 299 {
		return nil, model.NewAppError("createSessionForUserAccessToken 4", "app.user_access_token.invalid_or_missing", nil, "", http.StatusForbidden)
	}

	userInfoResponseBody, _ := ioutil.ReadAll(userInfoResponse.Body)
	defer userInfoResponse.Body.Close()
	mlog.Debug("userInfoResponseBody", mlog.Any("userInfoResponseBody", userInfoResponseBody))

	userInfoJson := map[string]interface{}{}
	json.Unmarshal(userInfoResponseBody, &userInfoJson)

	ok = userInfoJson["ok"].(bool)
	mlog.Debug("ok", mlog.Any("ok", ok))
	if !ok {
		return nil, model.NewAppError("createSessionForUserAccessToken 5", "app.user_access_token.invalid_or_missing", nil, "", http.StatusForbidden)
	}

	userId := userInfoJson["userId"].(string)
	nickname := userInfoJson["nickname"].(string)
	email := userInfoJson["email"].(string)
	avatar := userInfoJson["avatar"].(string)
	mlog.Debug("userId & nickname & email & avatar", mlog.Any("userId", userId), mlog.Any("nickname", nickname), mlog.Any("email", email), mlog.Any("avatar", avatar))

	user, err = a.GetUserForLogin("", email)
	if user != nil {
		mlog.Debug("user", mlog.Any("user", user))
	}

	// if err != nil, create new user
	if err != nil {
		mlog.Debug("err", mlog.Any("err", err))

		user := model.User{Email: email, Nickname: nickname, Username: nickname, Roles: model.SYSTEM_USER_ROLE_ID}
		mlog.Debug("user", mlog.Any("user", user))

		var registerUser *model.User
		registerUser, err = a.CreateUser(&user)

		if err != nil {
			mlog.Debug("err", mlog.Any("err", err))
			return nil, err
		}

		mlog.Debug("registerUser", mlog.Any("registerUser", registerUser))
		return registerUser, nil
	}

	return user, nil
}

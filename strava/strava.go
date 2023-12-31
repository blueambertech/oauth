package strava

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blueambertech/oauth"
	"github.com/blueambertech/secretmanager"
	"golang.org/x/oauth2"
)

const (
	Read            = "read"
	ReadAll         = "read_all"
	ProfileReadAll  = "profile:read_all"
	ProfileWrite    = "profile:write"
	ActivityRead    = "activity:read"
	ActivityReadAll = "activity:read_all"
	ActivityWrite   = "activity:write"
)

var (
	endpoint = oauth2.Endpoint{
		AuthURL:       "https://www.strava.com/oauth/authorize",
		DeviceAuthURL: "https://www.strava.com/oauth/mobile/authorize",
		TokenURL:      "https://www.strava.com/oauth/token",
	}
)

type TokenInfo struct {
	TokenType    string `json:"token_type"`
	ExpiresAt    int64  `json:"expires_at"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

// AuthRedirect generates an oauth URL based on the scopes, client ID and callback URL provided and then sets it in the X-Redirect header for the client to use
func AuthRedirect(w http.ResponseWriter, r *http.Request, sm secretmanager.SecretManager, scopes []string, clientID, callbackURL string) error {
	secret, err := sm.Get(r.Context(), "strava-oauth-client-secret")
	if err != nil {
		return errors.New("failed to get strava client secret: " + err.Error())
	}
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: secret.(string),
		RedirectURL:  callbackURL,
		Endpoint:     endpoint,
	}
	authUrl := config.AuthCodeURL(oauth.GetStateString()) + "&scope=" + url.QueryEscape(strings.Join(scopes, ","))
	w.Header().Add("X-Redirect", authUrl)
	w.WriteHeader(http.StatusOK)
	return nil
}

// AuthCallback should be triggered as a result of calling the callbackURL supplied to the AuthRedirect func, it will
// post a request to the strava API to exchange the code supplied on the callback with an oauth token and then return it
// as a json string
func AuthCallback(w http.ResponseWriter, r *http.Request, sm secretmanager.SecretManager, clientID string) (string, error) {
	qs := r.URL.Query()

	queryErrors := qs["error"]
	if len(queryErrors) >= 1 && queryErrors[0] == "access_denied" {
		return "", errors.New("user cancelled or permission not granted")
	}
	secret, err := sm.Get(r.Context(), "strava-oauth-client-secret")
	if err != nil {
		return "", errors.New("failed to get strava client secret: " + err.Error())
	}

	formData := fmt.Sprintf("client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code", clientID, secret.(string), qs["code"][0])
	resp, err := http.Post(endpoint.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(formData))
	if err != nil {
		return "", errors.New("failed to get strava auth token: " + err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("failed to read strava response: " + err.Error())
	}

	// Verify the token returned is valid
	var t TokenInfo
	err = json.Unmarshal(body, &t)
	if err != nil {
		return "", errors.New("failed to decode strava token: " + err.Error())
	}

	if t.TokenType == "Bearer" {
		return string(body), nil
	}
	return "", errors.New("token type from Strava was invalid: " + t.TokenType)
}

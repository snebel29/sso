package providers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/datadog/datadog-go/statsd"
)

// Provider is an interface exposing functions necessary to authenticate with a given provider.
type Provider interface {
	Data() *ProviderData
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(string, []string) ([]string, bool, error)
	UserGroups(string, []string) ([]string, error)
	ValidateSessionState(*SessionState, []string) bool
	RefreshSession(*SessionState, []string) (bool, error)
}

// New returns a new sso Provider
func New(provider string, p *ProviderData, sc *statsd.Client) Provider {
	return NewSSOProvider(p, sc)
}

// GetSignInURL with typical oauth parameters
func GetSignInURL(data *ProviderData, redirectURL *url.URL, state string) *url.URL {
	var a url.URL
	a = *data.SignInURL
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", rawRedirect)
	params.Add("scope", data.Scope)
	params.Set("client_id", data.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", signRedirectURL(data.ClientSecret, rawRedirect, now))
	a.RawQuery = params.Encode()
	return &a
}

// GetSignOutURL creates and returns the sign out URL, given a redirectURL
func GetSignOutURL(data *ProviderData, redirectURL *url.URL) *url.URL {
	var a url.URL
	a = *data.SignOutURL
	now := time.Now()
	rawRedirect := redirectURL.String()
	params, _ := url.ParseQuery(a.RawQuery)
	params.Add("redirect_uri", rawRedirect)
	params.Set("ts", fmt.Sprint(now.Unix()))
	params.Set("sig", signRedirectURL(data.ClientSecret, rawRedirect, now))
	a.RawQuery = params.Encode()
	return &a
}

// signRedirectURL signs the redirect url string, given a timestamp, and returns it
func signRedirectURL(clientSecret, rawRedirect string, timestamp time.Time) string {
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

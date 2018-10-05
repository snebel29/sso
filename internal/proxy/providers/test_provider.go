package providers

import (
	"net/url"
)

// TestProvider is a mock provider
type TestProvider struct {
	*ProviderData
	EmailAddress string
	ValidToken   bool
	ValidGroup   bool
	Refreshed    bool
	Session      *SessionState
	Groups       []string
}

// NewTestProvider returns a new TestProvider
func NewTestProvider(providerURL *url.URL, emailAddress string) *TestProvider {
	return &TestProvider{
		ProviderData: &ProviderData{
			ProviderName: "Test Provider",
			SignInURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/authorize",
			},
			RedeemURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/token",
			},
			ProfileURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/api/v1/profile",
			},
			SignOutURL: &url.URL{
				Scheme: "http",
				Host:   providerURL.Host,
				Path:   "/oauth/sign_out",
			},
			Scope: "profile.email",
		},
		EmailAddress: emailAddress,
	}
}

// ValidateSessionState mocks the ValidateSessionState function
func (tp *TestProvider) ValidateSessionState(*SessionState, []string) bool {
	return tp.ValidToken
}

// Redeem mocks the provider Redeem function
func (tp *TestProvider) Redeem(string, string) (*SessionState, error) {
	return tp.Session, nil
}

// RefreshSession mocks the RefreshSession function
func (tp *TestProvider) RefreshSession(*SessionState, []string) (bool, error) {
	return tp.Refreshed, nil
}

// UserGroups mocks the UserGroups function
func (tp *TestProvider) UserGroups(string, []string) ([]string, error) {
	return tp.Groups, nil
}

// ValidateGroup mocks the ValidateGroup function
func (tp *TestProvider) ValidateGroup(string, []string) ([]string, bool, error) {
	return tp.Groups, tp.ValidGroup, nil
}

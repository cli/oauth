package oauth_test

import (
	"errors"
	"fmt"
	"os"

	"github.com/cli/oauth"
	"github.com/cli/oauth/api"
)

// DetectFlow attempts to initiate OAuth Device flow with the server and falls back to OAuth Web
// application flow if Device flow seems unsupported. This approach isn't strictly needed for
// github.com, as its Device flow support is globally available, but it enables logging in to
// self-hosted GitHub instances as well.
func ExampleFlow_DetectFlow() {
	host, err := oauth.NewGitHubHost("https://github.com")
	if err != nil {
		panic(err)
	}
	flow := &oauth.Flow{
		Host:         host,
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"), // only applicable to web app flow
		CallbackURI:  "http://127.0.0.1/callback",      // only applicable to web app flow
		Scopes:       []string{"repo", "read:org", "gist"},
	}

	accessToken, err := flow.DetectFlow()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Access token: %s\n", accessToken.Token)
}

// Opt in to expiring access tokens and use the resulting token with an HTTP client that refreshes it
// automatically. Refresh tokens are single-use, so the OnRefresh callback must persist the new token.
func ExampleFlow_requestRefreshToken() {
	host, err := oauth.NewGitHubHost("https://github.com")
	if err != nil {
		panic(err)
	}
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")

	flow := &oauth.Flow{
		Host:         host,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CallbackURI:  "http://127.0.0.1/callback",
		Scopes:       []string{"repo", "read:org"},

		// Request an expiring access token along with a refresh token.
		RequestRefreshToken: true,
	}

	accessToken, err := flow.DetectFlow()
	if err != nil {
		panic(err)
	}

	// Servers without support for expiring tokens ignore the request and return a non-expiring token
	// with no refresh token, so never assume that one was issued.
	if accessToken.RefreshToken == "" {
		fmt.Println("received a non-expiring token")
	}

	src := oauth.NewTokenSource(accessToken, clientID, clientSecret, host.TokenURL)

	// Refreshing invalidates both the previous access token and the previous refresh token, so the
	// new credentials must be stored before they are used.
	src.OnRefresh = func(token *api.AccessToken) error {
		return saveCredentials(token)
	}

	// This client attaches the token, refreshes it when it expires, and retries a rejected request
	// once with a freshly refreshed token.
	httpClient := oauth.NewHTTPClient(src)

	resp, err := httpClient.Get("https://api.github.com/user")
	if err != nil {
		if errors.Is(err, api.ErrRefreshTokenInvalid) || errors.Is(err, oauth.ErrNotRefreshable) {
			// The token can no longer be renewed; the user has to authorize the app again.
			panic("re-authorization required")
		}
		panic(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	fmt.Printf("Status: %d\n", resp.StatusCode)
}

// saveCredentials stands in for writing the token to the application's credential store. Along with
// the token value itself, the refresh token and both expiration times must be persisted.
func saveCredentials(token *api.AccessToken) error {
	_ = token.Token
	_ = token.RefreshToken
	_ = token.ExpiresAt
	_ = token.RefreshTokenExpiresAt
	return nil
}

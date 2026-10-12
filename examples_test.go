package oauth_test

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cli/oauth"
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

func ExampleRefresh() {
	host, err := oauth.NewGitHubHost("https://github.com")
	if err != nil {
		panic(err)
	}
	flow := &oauth.Flow{
		Host:                host,
		ClientID:            os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret:        os.Getenv("OAUTH_CLIENT_SECRET"), // only applicable to web app flow
		Scopes:              []string{"repo", "read:org", "gist"},
		RequestRefreshToken: true,
	}

	accessToken, err := flow.DeviceFlow()
	if err != nil {
		panic(err)
	}

	refreshedToken, err := oauth.Refresh(oauth.RefreshOptions{
		Host:         host,
		ClientID:     flow.ClientID,
		ClientSecret: flow.ClientSecret, // only applicable to web app flow
		RefreshToken: accessToken.RefreshToken,
		HTTPClient:   http.DefaultClient,
	})
	if err != nil {
		panic(err)
	}

	// Persist the complete refreshed token because the previous token pair is no longer usable.
	fmt.Printf("Refreshed refresh token: %s\n", refreshedToken.RefreshToken)
	fmt.Printf("Refreshed access token: %s\n", refreshedToken.Token)
}

package webapp

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cli/browser"
)

// This demonstrates how to perform OAuth App Authorization Flow for GitHub.com.
// Ensure that the OAuth app on GitHub lists the callback URL: "http://127.0.0.1/callback"
func Example() {
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")

	flow, err := InitFlow()
	if err != nil {
		panic(err)
	}

	params := BrowserParams{
		ClientID:    clientID,
		RedirectURI: "http://127.0.0.1/callback",
		Scopes:      []string{"repo", "read:org"},
		AllowSignup: true,
	}
	browserURL, err := flow.BrowserURL("https://github.com/login/oauth/authorize", params)
	if err != nil {
		panic(err)
	}

	// A localhost server on a random available port will receive the web redirect.
	go func() {
		_ = flow.StartServer(nil)
	}()

	// Note: the user's web browser must run on the same device as the running app.
	err = browser.OpenURL(browserURL)
	if err != nil {
		panic(err)
	}

	httpClient := http.DefaultClient
	accessToken, err := flow.AccessToken(httpClient, "https://github.com/login/oauth/access_token", clientSecret)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Access token: %s\n", accessToken.Token)
}

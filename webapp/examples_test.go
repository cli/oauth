package webapp_test

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/cli/browser"
	"github.com/cli/oauth/webapp"
)

// Initiate the OAuth App Authorization Flow for GitHub.com.
func ExampleInitFlow() {
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	callbackURL := "http://127.0.0.1/callback"

	flow, err := webapp.InitFlow()
	if err != nil {
		panic(err)
	}

	params := webapp.BrowserParams{
		ClientID:    clientID,
		RedirectURI: callbackURL,
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
	accessToken, err := flow.Wait(context.TODO(), httpClient, "https://github.com/login/oauth/access_token", webapp.WaitOptions{
		ClientSecret: clientSecret,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Access token: %s\n", accessToken.Token)
}

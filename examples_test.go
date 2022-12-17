package oauth_test

import (
	"fmt"
	"os"

	"github.com/cli/oauth"
)

// DetectFlow attempts to initiate OAuth Device flow with the server and falls back to OAuth Web
// application flow if Device flow seems unsupported. This approach isn't strictly needed for
// github.com, as its Device flow support is globally available, but it enables logging in to
// self-hosted GitHub instances as well.
func ExampleFlow_DetectFlow() {
	flow := &oauth.Flow{
		Host:         oauth.GitHubHost("https://github.com"),
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

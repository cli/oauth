package oauth

import (
	"fmt"
	"os"
)

// Try initiating OAuth Device flow on the server and fall back to OAuth Web application flow if
// Device flow seems unsupported. This approach isn't strictly needed for github.com, as its Device
// flow support is globally available, but enables logging in to hosted GitHub instances as well.
func Example() {
	flow := &Flow{
		Hostname:     "github.com",
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

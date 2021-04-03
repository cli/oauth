package oauth

import (
	"fmt"
	"net/http"

	"github.com/cli/browser"
	"github.com/cli/oauth/api"
	"github.com/cli/oauth/webapp"
)

// WebAppFlow starts a local HTTP server, opens the web browser to initiate the OAuth Web application
// flow, blocks until the user completes authorization and is redirected back, and returns the access token.
func (oa *Flow) WebAppFlow() (*api.AccessToken, error) {
	host := oa.Host
	if host == nil {
		host = GitHubHost("https://" + oa.Hostname)
	}

	flow, err := webapp.InitFlow()
	if err != nil {
		return nil, err
	}

	params := webapp.BrowserParams{
		ClientID:    oa.ClientID,
		RedirectURI: oa.CallbackURI,
		Scopes:      oa.Scopes,
		AllowSignup: true,
	}
	browserURL, err := flow.BrowserURL(host.AuthorizeURL, params)
	if err != nil {
		return nil, err
	}

	go func() {
		_ = flow.StartServer(oa.WriteSuccessHTML)
	}()

	browseURL := oa.BrowseURL
	if browseURL == nil {
		browseURL = browser.OpenURL
	}

	err = browseURL(browserURL)
	if err != nil {
		return nil, fmt.Errorf("error opening the web browser: %w", err)
	}

	httpClient := oa.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return flow.AccessToken(httpClient, host.TokenURL, oa.ClientSecret)
}

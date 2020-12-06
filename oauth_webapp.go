package oauth

import (
	"fmt"
	"net/http"

	"github.com/cli/browser"
	"github.com/cli/oauth/api"
	"github.com/cli/oauth/webapp"
)

func (oa *OAuthFlow) WebAppFlow() (*api.AccessToken, error) {
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
	browserURL, err := flow.BrowserURL(webappInitURL(oa.Hostname), params)
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

	return flow.AccessToken(httpClient, tokenURL(oa.Hostname), oa.ClientSecret)
}

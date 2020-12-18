// Package webapp implements the OAuth Web Application authorization flow for client applications by
// starting a server at localhost to receive the web redirect after the user has authorized the application.
package webapp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cli/oauth/api"
)

type httpClient interface {
	PostForm(string, url.Values) (*http.Response, error)
}

// Flow holds the state for the steps of OAuth Web Application flow.
type Flow struct {
	server   *localServer
	clientID string
	state    string
}

// InitFlow creates a new Flow instance by detecting a locally available port number.
func InitFlow() (*Flow, error) {
	server, err := bindLocalServer()
	if err != nil {
		return nil, err
	}

	state, _ := randomString(20)

	return &Flow{
		server: server,
		state:  state,
	}, nil
}

// BrowserParams are GET query parameters for initiating the web flow.
type BrowserParams struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
	LoginHandle string
	AllowSignup bool
}

// BrowserURL appends GET query parameters to baseURL and returns the url that the user should
// navigate to in their web browser.
func (flow *Flow) BrowserURL(baseURL string, params BrowserParams) (string, error) {
	ru, err := url.Parse(params.RedirectURI)
	if err != nil {
		return "", err
	}

	ru.Host = fmt.Sprintf("%s:%d", ru.Hostname(), flow.server.Port())
	flow.server.CallbackPath = ru.Path
	flow.clientID = params.ClientID

	q := url.Values{}
	q.Set("client_id", params.ClientID)
	q.Set("redirect_uri", ru.String())
	q.Set("scope", strings.Join(params.Scopes, " "))
	q.Set("state", flow.state)
	if params.LoginHandle != "" {
		q.Set("login", params.LoginHandle)
	}
	if !params.AllowSignup {
		q.Set("allow_signup", "false")
	}

	return fmt.Sprintf("%s?%s", baseURL, q.Encode()), nil
}

// StartServer starts the localhost server and blocks until it has received the web redirect. The
// writeSuccess function can be used to render a HTML page to the user upon completion.
func (flow *Flow) StartServer(writeSuccess func(io.Writer)) error {
	flow.server.WriteSuccessHTML = writeSuccess
	return flow.server.Serve()
}

// AccessToken blocks until the browser flow has completed and returns the access token.
func (flow *Flow) AccessToken(c httpClient, tokenURL, clientSecret string) (*api.AccessToken, error) {
	code, err := flow.server.WaitForCode()
	if err != nil {
		return nil, err
	}
	if code.State != flow.state {
		return nil, errors.New("state mismatch")
	}

	resp, err := api.PostForm(c, tokenURL,
		url.Values{
			"client_id":     {flow.clientID},
			"client_secret": {clientSecret},
			"code":          {code.Code},
			"state":         {flow.state},
		})
	if err != nil {
		return nil, err
	}

	return resp.AccessToken()
}

func randomString(length int) (string, error) {
	b := make([]byte, length/2)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

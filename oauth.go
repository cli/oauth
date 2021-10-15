// Package oauth is a library for Go client applications that need to perform OAuth authorization
// against a server, typically GitHub.com.
package oauth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/cli/oauth/api"
	"github.com/cli/oauth/device"
)

type httpClient interface {
	PostForm(string, url.Values) (*http.Response, error)
}

// Host defines the endpoints used to authorize against an OAuth server.
type Host struct {
	DeviceCodeURL string
	AuthorizeURL  string
	TokenURL      string
}

// GitHubHost constructs a Host from the given URL to a GitHub instance.
func GitHubHost(hostURL string) *Host {
	u, _ := url.Parse(hostURL)

	return &Host{
		DeviceCodeURL: fmt.Sprintf("%s://%s/login/device/code", u.Scheme, u.Host),
		AuthorizeURL:  fmt.Sprintf("%s://%s/login/oauth/authorize", u.Scheme, u.Host),
		TokenURL:      fmt.Sprintf("%s://%s/login/oauth/access_token", u.Scheme, u.Host),
	}
}

// Flow facilitates a single OAuth authorization flow.
type Flow struct {
	// The hostname to authorize the app with.
	//
	// Deprecated: Use Host instead.
	Hostname string
	// Host configuration to authorize the app with.
	Host *Host
	// OAuth scopes to request from the user.
	Scopes []string
	// OAuth application ID.
	ClientID string
	// OAuth application secret. Only applicable in web application flow.
	ClientSecret string
	// The localhost URI for web application flow callback, e.g. "http://127.0.0.1/callback".
	CallbackURI string

	// Display a one-time code to the user. Receives the code and the browser URL as arguments. Defaults to printing the
	// code to the user on Stdout with instructions to copy the code and to press Enter to continue in their browser.
	DisplayCode func(string, string) error
	// Open a web browser at a URL. Defaults to opening the default system browser.
	BrowseURL func(string) error
	// Render an HTML page to the user upon completion of web application flow. The default is to
	// render a simple message that informs the user they can close the browser tab and return to the app.
	WriteSuccessHTML func(io.Writer)

	// The HTTP client to use for API POST requests. Defaults to http.DefaultClient.
	HTTPClient httpClient
	// The stream to listen to keyboard input on. Defaults to os.Stdin.
	Stdin io.Reader
	// The stream to print UI messages to. Defaults to os.Stdout.
	Stdout io.Writer
}

// DetectFlow tries to perform Device flow first and falls back to Web application flow.
func (oa *Flow) DetectFlow() (*api.AccessToken, error) {
	accessToken, err := oa.DeviceFlow()
	if errors.Is(err, device.ErrUnsupported) {
		return oa.WebAppFlow()
	}
	return accessToken, err
}

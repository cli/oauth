package oauth

import "fmt"

// Server represents the endpoints used to authorize against an OAuth server.
type Server struct {
	DeviceCodeURL string
	AuthorizeURL  string
	TokenURL      string
}

// ServerGitHub gets a Server for the given GitHub (Enterprise) host. If host is empty,
// it will default to "github.com".
func ServerGitHub(host string) *Server {
	if host == "" {
		host = "github.com"
	}

	return &Server{
		DeviceCodeURL: fmt.Sprintf("https://%s/login/device/code", host),
		AuthorizeURL:  fmt.Sprintf("https://%s/login/oauth/authorize", host),
		TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", host),
	}
}

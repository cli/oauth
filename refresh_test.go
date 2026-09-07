package oauth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cli/oauth/api"
)

type refreshClient struct {
	status      int
	body        string
	contentType string
	err         error

	postCount int
	lastURL   string
	lastForm  url.Values
}

func (c *refreshClient) PostForm(u string, params url.Values) (*http.Response, error) {
	c.postCount++
	c.lastURL = u
	c.lastForm = params
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		Body:       io.NopCloser(bytes.NewBufferString(c.body)),
		Header:     http.Header{"Content-Type": {c.contentType}},
		StatusCode: c.status,
	}, nil
}

func TestRefresh(t *testing.T) {
	transportErr := errors.New("network is unreachable")
	host := &Host{TokenURL: "https://example.com/token"}

	tests := []struct {
		name            string
		client          *refreshClient
		options         RefreshOptions
		wantToken       string
		wantForm        url.Values
		wantPosts       int
		wantInvalid     bool
		wantAPIError    string
		wantError       error
		wantErrorString string
	}{
		{
			name: "success with client secret",
			client: &refreshClient{
				status:      http.StatusOK,
				contentType: "application/x-www-form-urlencoded",
				body:        "access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800",
			},
			options: RefreshOptions{
				Host:         host,
				ClientID:     "CLIENTID",
				ClientSecret: "CLIENTSECRET",
				RefreshToken: "OLDREFRESH",
			},
			wantToken: "NEWTOKEN",
			wantForm: url.Values{
				"client_id":     {"CLIENTID"},
				"client_secret": {"CLIENTSECRET"},
				"refresh_token": {"OLDREFRESH"},
				"grant_type":    {"refresh_token"},
			},
			wantPosts: 1,
		},
		{
			name: "success without client secret",
			client: &refreshClient{
				status:      http.StatusOK,
				contentType: "application/x-www-form-urlencoded",
				body:        "access_token=NEWTOKEN&refresh_token=NEWREFRESH",
			},
			options: RefreshOptions{
				Host:         host,
				ClientID:     "CLIENTID",
				RefreshToken: "OLDREFRESH",
			},
			wantToken: "NEWTOKEN",
			wantForm: url.Values{
				"client_id":     {"CLIENTID"},
				"refresh_token": {"OLDREFRESH"},
				"grant_type":    {"refresh_token"},
			},
			wantPosts: 1,
		},
		{
			name:   "missing host",
			client: &refreshClient{},
			options: RefreshOptions{
				ClientID:     "CLIENTID",
				RefreshToken: "OLDREFRESH",
			},
			wantPosts:       0,
			wantErrorString: "host is required",
		},
		{
			name:   "empty refresh token",
			client: &refreshClient{},
			options: RefreshOptions{
				Host:     host,
				ClientID: "CLIENTID",
			},
			wantInvalid:     true,
			wantPosts:       0,
			wantErrorString: "refresh token is empty",
		},
		{
			name: "invalid refresh token",
			client: &refreshClient{
				status:      http.StatusBadRequest,
				contentType: "application/x-www-form-urlencoded",
				body:        "error=bad_refresh_token&error_description=The+refresh+token+is+invalid.",
			},
			options: RefreshOptions{
				Host:         host,
				ClientID:     "CLIENTID",
				RefreshToken: "OLDREFRESH",
			},
			wantInvalid:  true,
			wantAPIError: "bad_refresh_token",
			wantPosts:    1,
		},
		{
			name: "other API error",
			client: &refreshClient{
				status:      http.StatusBadRequest,
				contentType: "application/x-www-form-urlencoded",
				body:        "error=incorrect_client_credentials",
			},
			options: RefreshOptions{
				Host:         host,
				ClientID:     "CLIENTID",
				RefreshToken: "OLDREFRESH",
			},
			wantAPIError: "incorrect_client_credentials",
			wantPosts:    1,
		},
		{
			name: "transport error",
			client: &refreshClient{
				err: transportErr,
			},
			options: RefreshOptions{
				Host:         host,
				ClientID:     "CLIENTID",
				RefreshToken: "OLDREFRESH",
			},
			wantError: transportErr,
			wantPosts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.options.HTTPClient = tt.client
			token, err := Refresh(tt.options)

			if tt.wantToken != "" {
				if err != nil {
					t.Fatalf("Refresh() error = %v", err)
				}
				if token.Token != tt.wantToken {
					t.Errorf("Token = %q, want %q", token.Token, tt.wantToken)
				}
			} else if err == nil {
				t.Fatal("Refresh() error = nil")
			}

			if errors.Is(err, ErrRefreshTokenInvalid) != tt.wantInvalid {
				t.Errorf("errors.Is(ErrRefreshTokenInvalid) = %v, want %v", errors.Is(err, ErrRefreshTokenInvalid), tt.wantInvalid)
			}
			if tt.wantError != nil && !errors.Is(err, tt.wantError) {
				t.Errorf("error = %v, want %v", err, tt.wantError)
			}
			if tt.wantErrorString != "" && !strings.Contains(err.Error(), tt.wantErrorString) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErrorString)
			}
			if tt.wantAPIError != "" {
				var apiError *api.Error
				if !errors.As(err, &apiError) {
					t.Fatalf("error = %v, want *api.Error", err)
				}
				if apiError.Code != tt.wantAPIError {
					t.Errorf("error code = %q, want %q", apiError.Code, tt.wantAPIError)
				}
			}
			if tt.client.postCount != tt.wantPosts {
				t.Errorf("post count = %d, want %d", tt.client.postCount, tt.wantPosts)
			}
			if tt.wantForm != nil && tt.client.lastForm.Encode() != tt.wantForm.Encode() {
				t.Errorf("form = %v, want %v", tt.client.lastForm, tt.wantForm)
			}
			if tt.wantPosts > 0 && tt.client.lastURL != host.TokenURL {
				t.Errorf("URL = %q, want %q", tt.client.lastURL, host.TokenURL)
			}
		})
	}
}

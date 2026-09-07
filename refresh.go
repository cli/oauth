package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cli/oauth/api"
)

// ErrRefreshTokenInvalid is returned when the server rejects a refresh token because it is invalid,
// expired, or already used.
var ErrRefreshTokenInvalid = errors.New("refresh token is invalid or expired")

// RefreshOptions specifies parameters for exchanging a refresh token for a new token pair.
type RefreshOptions struct {
	// Host contains the token endpoint used for the refresh request.
	Host *Host
	// ClientID is the OAuth application ID.
	ClientID string
	// ClientSecret is the OAuth application secret. It is not required for device flow tokens.
	ClientSecret string
	// RefreshToken is the refresh token issued with the current access token.
	RefreshToken string
	// HTTPClient is the client used for the refresh request. It defaults to http.DefaultClient.
	HTTPClient httpClient
}

// Refresh exchanges a refresh token for a new access token and refresh token.
func Refresh(opts RefreshOptions) (*api.AccessToken, error) {
	if opts.Host == nil {
		return nil, errors.New("host is required")
	}
	if opts.RefreshToken == "" {
		return nil, fmt.Errorf("%w: refresh token is empty", ErrRefreshTokenInvalid)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	values := url.Values{
		"client_id":     {opts.ClientID},
		"refresh_token": {opts.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	if opts.ClientSecret != "" {
		values.Set("client_secret", opts.ClientSecret)
	}

	resp, err := api.PostForm(httpClient, opts.Host.TokenURL, values)
	if err != nil {
		return nil, err
	}

	token, err := resp.AccessToken()
	if err != nil {
		var apiError *api.Error
		if errors.As(err, &apiError) && apiError.Code == "bad_refresh_token" {
			return nil, fmt.Errorf("%w: %w", ErrRefreshTokenInvalid, err)
		}
		return nil, err
	}

	return token, nil
}

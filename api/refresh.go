package api

import (
	"errors"
	"net/url"
)

// ErrRefreshTokenInvalid is returned when the server rejects the refresh token, either because it
// has expired or because it has already been used. Recovering requires sending the user through an
// authorization flow again.
var ErrRefreshTokenInvalid = errors.New("refresh token is invalid or expired")

const refreshGrantType = "refresh_token"

// RefreshOptions specifies parameters to exchange a refresh token for a new access token.
type RefreshOptions struct {
	// ClientID is the app client ID value.
	ClientID string
	// ClientSecret is the app client secret value. Required for tokens obtained via web application
	// flow; not needed for tokens obtained via device flow.
	ClientSecret string
	// RefreshToken is the refresh token issued alongside the expiring access token.
	RefreshToken string
}

// Refresh exchanges a refresh token for a new access token at tokenURL.
//
// Refresh tokens are single-use: on success, both the refresh token passed in and its associated
// access token are immediately invalidated by the server, and the returned AccessToken carries their
// replacements. Callers must persist the result before making further requests.
func Refresh(c httpClient, tokenURL string, opts RefreshOptions) (*AccessToken, error) {
	if opts.RefreshToken == "" {
		return nil, ErrRefreshTokenInvalid
	}

	values := url.Values{
		"client_id":     {opts.ClientID},
		"refresh_token": {opts.RefreshToken},
		"grant_type":    {refreshGrantType},
	}
	if opts.ClientSecret != "" {
		values.Set("client_secret", opts.ClientSecret)
	}

	resp, err := PostForm(c, tokenURL, values)
	if err != nil {
		return nil, err
	}

	token, err := resp.AccessToken()
	if err != nil {
		var apiError *Error
		if errors.As(err, &apiError) && apiError.Code == "bad_refresh_token" {
			return nil, ErrRefreshTokenInvalid
		}
		return nil, err
	}

	return token, nil
}

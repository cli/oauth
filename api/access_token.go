package api

import (
	"strconv"
)

// AccessToken is an OAuth access token.
type AccessToken struct {
	// The token value, typically a 40-character random string.
	Token string
	// Number of seconds until the access token expires.
	ExpiresIn int
	// The refresh token value, associated with the access token.
	RefreshToken string
	// Number of seconds until the refresh token expires.
	RefreshTokenExpiresIn int
	// The token type, e.g. "bearer".
	Type string
	// Space-separated list of OAuth scopes that this token grants.
	Scope string
}

// AccessToken extracts the access token information from a server response.
func (f FormResponse) AccessToken() (*AccessToken, error) {
	if accessToken := f.Get("access_token"); accessToken != "" {
		// Default to 0 if the expiry fields aren't present.
		expiresIn, _ := strconv.Atoi(f.Get("expires_in"))
		refreshTokenExpiresIn, _ := strconv.Atoi(f.Get("refresh_token_expires_in"))

		return &AccessToken{
			Token:                 accessToken,
			ExpiresIn:             expiresIn,
			RefreshToken:          f.Get("refresh_token"),
			RefreshTokenExpiresIn: refreshTokenExpiresIn,
			Type:                  f.Get("token_type"),
			Scope:                 f.Get("scope"),
		}, nil
	}

	return nil, f.Err()
}

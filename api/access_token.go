package api

import (
	"strconv"
)

// AccessToken is an OAuth access token.
type AccessToken struct {
	// The token value, typically a 40-character random string.
	Token string
	// The refresh token value, associated with the access token.
	RefreshToken string
	// The token type, e.g. "bearer".
	Type string
	// Space-separated list of OAuth scopes that this token grants.
	Scope string
	// The number of seconds from issuance until Token expires. Zero means the server did not return
	// expiration metadata.
	ExpiresIn int
	// The number of seconds from issuance until RefreshToken expires. Zero means the server did not
	// return expiration metadata.
	RefreshTokenExpiresIn int
}

// AccessToken extracts the access token information from a server response.
func (f FormResponse) AccessToken() (*AccessToken, error) {
	accessToken := f.Get("access_token")
	if accessToken == "" {
		return nil, f.Err()
	}

	token := &AccessToken{
		Token:        accessToken,
		RefreshToken: f.Get("refresh_token"),
		Type:         f.Get("token_type"),
		Scope:        f.Get("scope"),
	}

	if expiresIn, err := strconv.Atoi(f.Get("expires_in")); err == nil && expiresIn > 0 {
		token.ExpiresIn = expiresIn
	}
	if token.RefreshToken != "" {
		if expiresIn, err := strconv.Atoi(f.Get("refresh_token_expires_in")); err == nil && expiresIn > 0 {
			token.RefreshTokenExpiresIn = expiresIn
		}
	}

	return token, nil
}

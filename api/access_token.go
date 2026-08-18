package api

import (
	"strconv"
	"time"
)

// timeNow is swappable in tests.
var timeNow = time.Now

// expiryLeeway is subtracted from a token's expiration time when determining whether it is expired,
// so that a token is not considered valid moments before the server would reject it.
const expiryLeeway = 60 * time.Second

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

	// The number of seconds from the time of issue until Token expires. Zero if the server issued a
	// non-expiring token.
	ExpiresIn int
	// The number of seconds from the time of issue until RefreshToken expires. Zero if the server did
	// not issue a refresh token.
	RefreshTokenExpiresIn int
	// The absolute time at which Token expires. Zero if the server issued a non-expiring token.
	ExpiresAt time.Time
	// The absolute time at which RefreshToken expires. Zero if the server did not issue a refresh token.
	RefreshTokenExpiresAt time.Time
}

// IsExpired reports whether the access token has expired. Tokens that never expire are never
// reported as expired. A small leeway is applied to guard against clock skew.
func (t *AccessToken) IsExpired() bool {
	if t == nil || t.ExpiresAt.IsZero() {
		return false
	}
	return !timeNow().Before(t.ExpiresAt.Add(-expiryLeeway))
}

// CanRefresh reports whether the token carries a refresh token that has not itself expired. If it
// returns false, obtaining a new token requires sending the user through an authorization flow again.
func (t *AccessToken) CanRefresh() bool {
	if t == nil || t.RefreshToken == "" {
		return false
	}
	if t.RefreshTokenExpiresAt.IsZero() {
		return true
	}
	return timeNow().Before(t.RefreshTokenExpiresAt.Add(-expiryLeeway))
}

// AccessToken extracts the access token information from a server response.
func (f FormResponse) AccessToken() (*AccessToken, error) {
	accessToken := f.Get("access_token")
	if accessToken == "" {
		return nil, f.Err()
	}

	now := timeNow()
	token := &AccessToken{
		Token:        accessToken,
		RefreshToken: f.Get("refresh_token"),
		Type:         f.Get("token_type"),
		Scope:        f.Get("scope"),
	}

	// Servers that do not support expiring tokens omit these values entirely. Unparseable values are
	// treated the same as missing ones so that a usable token is never discarded over metadata.
	if expiresIn, err := strconv.Atoi(f.Get("expires_in")); err == nil && expiresIn > 0 {
		token.ExpiresIn = expiresIn
		token.ExpiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	}
	if token.RefreshToken != "" {
		if expiresIn, err := strconv.Atoi(f.Get("refresh_token_expires_in")); err == nil && expiresIn > 0 {
			token.RefreshTokenExpiresIn = expiresIn
			token.RefreshTokenExpiresAt = now.Add(time.Duration(expiresIn) * time.Second)
		}
	}

	return token, nil
}

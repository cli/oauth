package api

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
}

// AccessToken extracts the access token information from a server response.
func (f FormResponse) AccessToken() (*AccessToken, error) {
	if accessToken := f.Get("access_token"); accessToken != "" {
		return &AccessToken{
			Token:        accessToken,
			RefreshToken: f.Get("refresh_token"),
			Type:         f.Get("token_type"),
			Scope:        f.Get("scope"),
		}, nil
	}

	return nil, f.Err()
}

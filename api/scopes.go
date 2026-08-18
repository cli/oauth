package api

// ScopeOfflineAccess is the scope that opts an individual authorization into receiving an expiring
// access token and a refresh token, even when the OAuth app is not globally configured to use
// expiring tokens.
//
// Servers that do not support expiring tokens, such as older GitHub Enterprise Server instances,
// ignore this scope and issue a non-expiring token with no refresh token. It is not tracked as a
// normal scope and does not affect the scopes granted to the resulting token.
const ScopeOfflineAccess = "offline_access"

// AppendOfflineAccess returns scopes with ScopeOfflineAccess appended, unless it is already present.
// The input slice is never modified.
func AppendOfflineAccess(scopes []string) []string {
	for _, s := range scopes {
		if s == ScopeOfflineAccess {
			return scopes
		}
	}
	result := make([]string, len(scopes), len(scopes)+1)
	copy(result, scopes)
	return append(result, ScopeOfflineAccess)
}

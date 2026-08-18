# Changelog

## Unreleased

### Added: opt-in support for expiring access tokens and refresh tokens

GitHub OAuth apps can issue access tokens that expire after 8 hours along with a refresh token valid
for 6 months. This release adds support for that flow. It is **opt-in and fully backwards
compatible** — existing applications continue to receive non-expiring tokens with no code changes.

- `Flow.RequestRefreshToken` opts an authorization into expiring tokens by requesting the
  `offline_access` scope, in both Device flow and Web application flow. Also available as
  `device.WithRefreshToken()` and `webapp.WithRefreshToken()` for callers using those packages
  directly.
- `api.AccessToken` now records `ExpiresIn`, `ExpiresAt`, `RefreshTokenExpiresIn`, and
  `RefreshTokenExpiresAt`, with `IsExpired()` and `CanRefresh()` helpers.
- `api.Refresh` exchanges a refresh token for a new token. A rejected refresh token is reported as
  `api.ErrRefreshTokenInvalid`.
- `oauth.TokenSource` holds a token and refreshes it on demand, with an `OnRefresh` callback for
  persisting rotated credentials.
- `oauth.NewHTTPClient` returns an `http.Client` that attaches the token and, on a rejected request,
  refreshes once and retries once.

Servers that do not support expiring tokens ignore the request and return a non-expiring token with
no refresh token, so applications must not assume a refresh token was issued.

See the "Expiring access tokens" section of the README for an adoption guide.

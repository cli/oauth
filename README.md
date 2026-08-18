# oauth

A library for Go client applications that need to perform OAuth authorization against a server, typically GitHub.com.

<p align="center">
  <img width="598" alt="" src="https://user-images.githubusercontent.com/887/102650961-f2751e80-416b-11eb-8b37-d82b076eb2d1.png"><br>
  <img width="976" alt="" src="https://user-images.githubusercontent.com/887/102650543-5e0abc00-416b-11eb-8e54-7b6e334ab092.png">
</p>

Traditionally, OAuth for web applications involves redirecting to a URI after the user authorizes an app. While web apps (and some native client apps) can receive a browser redirect, client apps such as CLI applications do not have such an option.

To accommodate client apps, this library implements the [OAuth Device Authorization Grant][oauth-device] which [GitHub.com now supports][gh-device]. With Device flow, the user is presented with a one-time code that they will have to enter in a web browser while authorizing the app on the server. Device flow is suitable for cases where the web browser may be running on a separate device than the client app itself; for example a CLI application could run within a headless, containerized instance, but the user may complete authorization using a browser on their phone.

To transparently enable OAuth authorization on _any GitHub host_ (e.g. GHES instances without OAuth “Device flow” support), this library also bundles an implementation of OAuth web application flow in which the client app starts a local server at `http://127.0.0.1:<port>/` that acts as a receiver for the browser redirect. First, Device flow is attempted, and the localhost server is used as fallback. With the localhost server, the user's web browser must be running on the same machine as the client application itself.

## Usage

- [OAuth Device flow with fallback](./examples_test.go)
- [OAuth flow with refresh token support](./examples_test.go)
- [manual OAuth Device flow](./device/examples_test.go)
- [manual OAuth web application flow](./webapp/examples_test.go)

Applications that need more control over the user experience around authentication should directly interface with `github.com/cli/oauth/device` and `github.com/cli/oauth/webapp` packages.

In theory, these packages would enable authorization on any OAuth-enabled host. In practice, however, this was only tested for authorizing with GitHub.

## Expiring access tokens

GitHub OAuth apps can issue access tokens that expire after 8 hours, accompanied by a refresh token that is valid for 6 months. Rotating tokens limits the damage a leaked token can do. See [Expiring access tokens][gh-expiring].

Support in this library is **opt-in and off by default**: existing code continues to receive non-expiring tokens and needs no changes.

### 1. Opt in

Set `RequestRefreshToken`, which requests the `offline_access` scope so that GitHub issues an expiring token even if your app isn't globally configured for them:

```go
flow := &oauth.Flow{
    Host:     host,
    ClientID: clientID,
    Scopes:   []string{"repo", "read:org"},

    RequestRefreshToken: true, // <- the only change needed to opt in
}

accessToken, err := flow.DetectFlow()
```

`offline_access` is not a normal scope: it doesn't widen the token's access and doesn't add anything to the authorization prompt.

### 2. Persist the new fields

Apps typically store only `accessToken.Token`. That is no longer enough — you must persist the refresh token and both expiration times, or the user will have to re-authorize every 8 hours:

```go
type storedCredentials struct {
    Token                 string    `json:"token"`
    RefreshToken          string    `json:"refresh_token,omitempty"`
    ExpiresAt             time.Time `json:"expires_at,omitempty"`
    RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at,omitempty"`
}
```

If `RefreshToken` is empty, the server does not support expiring tokens. This is expected on GitHub Enterprise Server. Store the token as you always have and skip the rest of this section — **never assume a refresh token was returned**.

### 3. Use a `TokenSource` instead of setting the header yourself

Wrap the token in a `TokenSource` and build an HTTP client from it. The client attaches the `Authorization` header, refreshes the token when it expires, and — if the server rejects a request anyway — refreshes once and retries the request exactly once:

```go
src := oauth.NewTokenSource(accessToken, clientID, clientSecret, host.TokenURL)
httpClient := oauth.NewHTTPClient(src)

resp, err := httpClient.Get("https://api.github.com/user")
```

Replace any code that sets `Authorization` manually. Share one `TokenSource` across your app so a refresh performed for one request is seen by all the others.

### 4. Save rotated tokens with `OnRefresh`

**Refresh tokens are single-use.** A successful refresh immediately invalidates both the old access token and the old refresh token, so a rotated token that you fail to save is a token you have lost:

```go
src.OnRefresh = func(token *api.AccessToken) error {
    return saveCredentials(token)
}
```

If `OnRefresh` returns an error, that error is returned to the caller so the failure is visible, but the `TokenSource` keeps the refreshed token — discarding it would not bring back the old one. The callback runs without the `TokenSource` lock held, so it is safe for it to use a client built from the same source.

### 5. Handle the failure cases

| Situation | How to detect it | What to do |
| --- | --- | --- |
| Refresh token expired or already used | `errors.Is(err, api.ErrRefreshTokenInvalid)` | Send the user through the flow again |
| Token expired, no refresh token available | `errors.Is(err, oauth.ErrNotRefreshable)` | Send the user through the flow again |
| Server doesn't support expiring tokens | `accessToken.RefreshToken == ""` | Nothing — behaves exactly as before |

### Adoption checklist

1. Set `RequestRefreshToken: true` on your `Flow`.
2. Extend your credential storage with `RefreshToken`, `ExpiresAt`, and `RefreshTokenExpiresAt`.
3. Build a `TokenSource` from the stored token and replace manual `Authorization` headers with `oauth.NewHTTPClient`.
4. Set `OnRefresh` to persist rotated tokens.
5. Handle `api.ErrRefreshTokenInvalid` and `oauth.ErrNotRefreshable` by restarting the authorization flow.
6. Confirm your app still works against a server that returns no refresh token.

See [the complete example](./examples_test.go).


[oauth-device]: https://oauth.net/2/device-flow/
[gh-device]: https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps#device-flow
[gh-expiring]: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#expiring-access-tokens

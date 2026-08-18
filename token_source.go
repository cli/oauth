package oauth

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/cli/oauth/api"
)

// ErrNotRefreshable is returned when a refresh is attempted for a token that has no usable refresh
// token, either because the server never issued one or because the refresh token itself expired.
// Recovering requires sending the user through an authorization flow again.
var ErrNotRefreshable = errors.New("token cannot be refreshed")

// TokenSource holds an access token and knows how to refresh it.
//
// It is safe for concurrent use. A single TokenSource should be shared by everything in the
// application that needs the token, so that a refresh performed on behalf of one caller is observed
// by all the others.
type TokenSource struct {
	// ClientID is the app client ID value.
	ClientID string
	// ClientSecret is the app client secret value. Required to refresh tokens obtained via web
	// application flow; not needed for tokens obtained via device flow.
	ClientSecret string
	// TokenURL is the URL to exchange the refresh token at, e.g. Host.TokenURL.
	TokenURL string

	// OnRefresh is invoked with the new token whenever a refresh succeeds. Use it to persist the new
	// credentials.
	//
	// Refresh tokens are single-use: once a refresh succeeds, the previous access token and refresh
	// token are both dead, and the token passed here is the only usable credential. If OnRefresh
	// returns an error, that error is returned to the caller alongside the new token, which is
	// retained by the TokenSource regardless so that a failure to persist does not also destroy the
	// only working token.
	//
	// The callback is invoked without the TokenSource's lock held, so it may safely call back into
	// this TokenSource, including through an http.Client built from it.
	OnRefresh func(*api.AccessToken) error

	// HTTPClient is the client used for the refresh request. Defaults to http.DefaultClient.
	HTTPClient httpClient

	mu    sync.Mutex
	token *api.AccessToken
}

// NewTokenSource creates a TokenSource for an existing token, which may have been loaded from
// storage or just obtained from a Flow.
func NewTokenSource(token *api.AccessToken, clientID, clientSecret, tokenURL string) *TokenSource {
	return &TokenSource{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		token:        token,
	}
}

// SetToken replaces the current token, e.g. after the user has re-authorized the app.
func (ts *TokenSource) SetToken(token *api.AccessToken) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.token = token
}

// Token returns a usable access token, refreshing it first if it has expired and can be refreshed.
//
// A non-expiring token is returned as-is. An expired token that cannot be refreshed is also returned
// as-is, along with ErrNotRefreshable, so that callers which prefer to try the token anyway may do so.
func (ts *TokenSource) Token(ctx context.Context) (*api.AccessToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.token == nil {
		return nil, ErrNotRefreshable
	}
	if !ts.token.IsExpired() {
		return ts.token, nil
	}
	if !ts.token.CanRefresh() {
		return ts.token, ErrNotRefreshable
	}
	return ts.refreshLocked(ctx)
}

// Refresh unconditionally exchanges the current refresh token for a new token, invokes OnRefresh,
// and returns the new token.
//
// If another goroutine refreshed the token in the meantime, that newer token is returned instead and
// no request is made, so that a single expired token does not cause a stampede of refreshes.
func (ts *TokenSource) Refresh(ctx context.Context) (*api.AccessToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.refreshLocked(ctx)
}

// refreshStale exchanges the token only if it is still the one the caller saw. It is used by the
// transport so that a burst of concurrent 401s results in exactly one refresh.
func (ts *TokenSource) refreshStale(ctx context.Context, seen *api.AccessToken) (*api.AccessToken, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if seen != nil && ts.token != nil && ts.token != seen {
		return ts.token, nil
	}
	return ts.refreshLocked(ctx)
}

func (ts *TokenSource) refreshLocked(ctx context.Context) (*api.AccessToken, error) {
	if ts.token == nil || !ts.token.CanRefresh() {
		return nil, ErrNotRefreshable
	}

	// The api package does not yet accept a context; respect cancellation at the boundary.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	client := ts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	newToken, err := api.Refresh(client, ts.TokenURL, api.RefreshOptions{
		ClientID:     ts.ClientID,
		ClientSecret: ts.ClientSecret,
		RefreshToken: ts.token.RefreshToken,
	})
	if err != nil {
		return nil, err
	}

	// The exchange succeeded, so the server has already invalidated the previous token pair and
	// newToken is now the only usable credential. Adopt it before doing anything that can fail, so
	// that it cannot be lost.
	ts.token = newToken

	if ts.OnRefresh != nil {
		// Release the lock around the callback: it is caller-supplied code that may legitimately
		// re-enter this TokenSource, and sync.Mutex is not reentrant.
		ts.mu.Unlock()
		err := ts.OnRefresh(newToken)
		ts.mu.Lock()
		if err != nil {
			// Report the failure to persist, but still hand back the live token: discarding it would
			// not bring back the old one, it would only strand the user.
			return newToken, err
		}
	}

	return newToken, nil
}

package oauth

import (
	"io"
	"net/http"
	"strings"

	"github.com/cli/oauth/api"
)

// Transport is an http.RoundTripper that authenticates requests with a token from a TokenSource and
// transparently recovers from an expired access token.
//
// Before each request it attaches the current token, refreshing it first if it is known to have
// expired. If the server rejects the request anyway, the token is refreshed and the request is
// retried exactly once; a second rejection is returned to the caller unmodified. Requests are
// therefore never attempted more than twice, so a persistently rejected token cannot produce a
// refresh loop.
type Transport struct {
	// Source supplies the access token. Required.
	Source *TokenSource
	// Base is the underlying transport. Defaults to http.DefaultTransport.
	Base http.RoundTripper
}

// NewHTTPClient returns an http.Client that authenticates requests with tokens from src and refreshes
// them as needed.
func NewHTTPClient(src *TokenSource) *http.Client {
	return &http.Client{Transport: &Transport{Source: src}}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	ctx := req.Context()

	// An ErrNotRefreshable here means the token is expired but cannot be renewed. Send it anyway:
	// the server is the authority on whether it is still accepted, and failing here would turn a
	// working request into an error whenever expiry metadata is wrong.
	token, err := t.Source.Token(ctx)
	if err != nil && token == nil {
		return nil, err
	}

	resp, err := base.RoundTrip(setAuth(cloneRequest(req), token))
	if err != nil {
		return resp, err
	}

	if !isTokenRejected(resp) || !token.CanRefresh() {
		return resp, nil
	}

	// The request must be replayable to retry it. If the body cannot be rewound, return the original
	// response rather than sending a request with a consumed body.
	retryReq, ok := rewind(req)
	if !ok {
		return resp, nil
	}

	newToken, err := t.Source.refreshStale(ctx, token)
	if err != nil {
		// Refreshing failed; the caller gets the original rejection, which is the more actionable
		// error, and can inspect the token source themselves.
		return resp, nil
	}

	// This is the one and only retry: its response is returned regardless of status.
	drain(resp)
	return base.RoundTrip(setAuth(retryReq, newToken))
}

func isTokenRejected(resp *http.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized {
		return true
	}
	// GitHub answers an expired token with 401, but some endpoints answer 403. Only treat a 403 as a
	// token problem when the server says so, to avoid refreshing on ordinary permission errors.
	if resp.StatusCode == http.StatusForbidden {
		return strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "expired")
	}
	return false
}

func setAuth(req *http.Request, token *api.AccessToken) *http.Request {
	if token == nil {
		return req
	}
	tokenType := token.Type
	if tokenType == "" {
		tokenType = "Bearer"
	}
	req.Header.Set("Authorization", tokenType+" "+token.Token)
	return req
}

func cloneRequest(req *http.Request) *http.Request {
	r := req.Clone(req.Context())
	r.Header = req.Header.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	return r
}

// rewind returns a copy of req with a fresh body, reporting whether it can be safely replayed.
func rewind(req *http.Request) (*http.Request, bool) {
	r := cloneRequest(req)
	if req.Body == nil || req.Body == http.NoBody {
		return r, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	r.Body = body
	return r, true
}

// drain discards and closes a response body that is being replaced by a retry, so the underlying
// connection can be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
}

package oauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cli/oauth/api"
)

type stubTokenClient struct {
	mu        sync.Mutex
	responses []string
	postCount int
	lastForm  url.Values
	err       error
}

func (c *stubTokenClient) PostForm(_ string, params url.Values) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastForm = params
	if c.err != nil {
		c.postCount++
		return nil, c.err
	}

	body := "error=bad_refresh_token"
	if c.postCount < len(c.responses) {
		body = c.responses[c.postCount]
	}
	c.postCount++

	return &http.Response{
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		StatusCode: 200,
	}, nil
}

func (c *stubTokenClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.postCount
}

func expiredToken() *api.AccessToken {
	return &api.AccessToken{
		Token:        "OLDTOKEN",
		RefreshToken: "OLDREFRESH",
		Type:         "bearer",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
}

func TestTokenSource_TokenRefreshesExpiredToken(t *testing.T) {
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	src := &TokenSource{
		ClientID:     "CLIENTID",
		ClientSecret: "SECRET",
		TokenURL:     "https://example.com/token",
		HTTPClient:   client,
		token:        expiredToken(),
	}

	token, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Token != "NEWTOKEN" {
		t.Errorf("Token = %q, want NEWTOKEN", token.Token)
	}

	// A second call must reuse the fresh token rather than refresh again.
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.count() != 1 {
		t.Errorf("made %d refresh requests, want 1", client.count())
	}
}

func TestTokenSource_TokenLeavesValidTokenAlone(t *testing.T) {
	client := &stubTokenClient{}
	src := &TokenSource{
		HTTPClient: client,
		token:      &api.AccessToken{Token: "ATOKEN", RefreshToken: "R", ExpiresAt: time.Now().Add(time.Hour)},
	}

	token, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Token != "ATOKEN" {
		t.Errorf("Token = %q, want ATOKEN", token.Token)
	}
	if client.count() != 0 {
		t.Errorf("made %d refresh requests, want 0", client.count())
	}
}

func TestTokenSource_TokenNonExpiringToken(t *testing.T) {
	// A server without expiring-token support returns no expiry and no refresh token; that token
	// must keep working exactly as before.
	client := &stubTokenClient{}
	src := &TokenSource{HTTPClient: client, token: &api.AccessToken{Token: "ATOKEN"}}

	token, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Token != "ATOKEN" {
		t.Errorf("Token = %q, want ATOKEN", token.Token)
	}
	if client.count() != 0 {
		t.Errorf("made %d refresh requests, want 0", client.count())
	}
}

func TestTokenSource_TokenExpiredWithoutRefreshToken(t *testing.T) {
	src := &TokenSource{
		HTTPClient: &stubTokenClient{},
		token:      &api.AccessToken{Token: "ATOKEN", ExpiresAt: time.Now().Add(-time.Hour)},
	}

	token, err := src.Token(context.Background())
	if !errors.Is(err, ErrNotRefreshable) {
		t.Fatalf("error = %v, want ErrNotRefreshable", err)
	}
	if token == nil || token.Token != "ATOKEN" {
		t.Error("expired token should still be returned for the caller to try")
	}
}

func TestTokenSource_RefreshInvokesOnRefresh(t *testing.T) {
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}

	var persisted *api.AccessToken
	src := &TokenSource{
		ClientID:   "CLIENTID",
		HTTPClient: client,
		token:      expiredToken(),
		OnRefresh: func(tok *api.AccessToken) error {
			persisted = tok
			return nil
		},
	}

	token, err := src.Refresh(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if persisted == nil || persisted.Token != "NEWTOKEN" {
		t.Fatal("OnRefresh was not called with the new token")
	}
	if persisted != token {
		t.Error("OnRefresh received a different token than the caller")
	}
	if persisted.RefreshToken != "NEWREFRESH" {
		t.Errorf("RefreshToken = %q, want NEWREFRESH", persisted.RefreshToken)
	}
}

func TestTokenSource_RefreshPropagatesOnRefreshError(t *testing.T) {
	// Persisting may fail transiently. The error must reach the caller, but the refreshed token must
	// survive, since the server already invalidated the previous one.
	wantErr := errors.New("disk full")
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	src := &TokenSource{
		HTTPClient: client,
		token:      expiredToken(),
		OnRefresh:  func(*api.AccessToken) error { return wantErr },
	}

	token, err := src.Refresh(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if token == nil || token.Token != "NEWTOKEN" {
		t.Fatal("the refreshed token was not returned to the caller")
	}

	// The source must now hold the new token, not the dead one.
	src.OnRefresh = nil
	current, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current.Token != "NEWTOKEN" {
		t.Errorf("Token = %q, want NEWTOKEN; the refreshed token was lost", current.Token)
	}
	if client.count() != 1 {
		t.Errorf("made %d refresh requests, want 1", client.count())
	}
}

func TestTokenSource_OnRefreshMayReenter(t *testing.T) {
	// A callback that persists via a client built on the same TokenSource must not deadlock.
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	src := &TokenSource{HTTPClient: client, token: expiredToken()}

	var seen string
	src.OnRefresh = func(*api.AccessToken) error {
		token, err := src.Token(context.Background())
		if err != nil {
			return err
		}
		seen = token.Token
		return nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := src.Refresh(context.Background()); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OnRefresh deadlocked against the TokenSource lock")
	}

	if seen != "NEWTOKEN" {
		t.Errorf("re-entrant Token() saw %q, want NEWTOKEN", seen)
	}
}

func TestTokenSource_RefreshWithoutNewRefreshToken(t *testing.T) {
	// The consumed refresh token must not be carried forward: it is dead by definition, and keeping
	// it would make the token claim to be refreshable when it is not.
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&expires_in=28800"}}
	src := &TokenSource{HTTPClient: client, token: expiredToken()}

	token, err := src.Refresh(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty", token.RefreshToken)
	}
	if token.CanRefresh() {
		t.Error("token reports itself refreshable with a spent refresh token")
	}
}

func TestTokenSource_RefreshNotRefreshable(t *testing.T) {
	client := &stubTokenClient{}
	src := &TokenSource{HTTPClient: client, token: &api.AccessToken{Token: "ATOKEN"}}

	if _, err := src.Refresh(context.Background()); !errors.Is(err, ErrNotRefreshable) {
		t.Fatalf("error = %v, want ErrNotRefreshable", err)
	}
	if client.count() != 0 {
		t.Errorf("made %d requests, want 0", client.count())
	}
}

func TestTokenSource_RefreshBadRefreshToken(t *testing.T) {
	client := &stubTokenClient{responses: []string{"error=bad_refresh_token"}}
	src := &TokenSource{HTTPClient: client, token: expiredToken()}

	if _, err := src.Refresh(context.Background()); !errors.Is(err, api.ErrRefreshTokenInvalid) {
		t.Fatalf("error = %v, want ErrRefreshTokenInvalid", err)
	}
}

func TestTokenSource_ConcurrentTokenCalls(t *testing.T) {
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	src := &TokenSource{HTTPClient: client, token: expiredToken()}

	var wg sync.WaitGroup
	results := make([]string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token, err := src.Token(context.Background())
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			results[i] = token.Token
		}(i)
	}
	wg.Wait()

	if client.count() != 1 {
		t.Errorf("made %d refresh requests, want 1", client.count())
	}
	for i, got := range results {
		if got != "NEWTOKEN" {
			t.Errorf("result %d = %q, want NEWTOKEN", i, got)
		}
	}
}

func TestTokenSource_SetToken(t *testing.T) {
	src := NewTokenSource(&api.AccessToken{Token: "OLD"}, "CLIENTID", "SECRET", "https://example.com/token")
	src.SetToken(&api.AccessToken{Token: "NEW"})

	token, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Token != "NEW" {
		t.Errorf("Token = %q, want NEW", token.Token)
	}
}

func TestTokenSource_RefreshOmitsEmptyClientSecret(t *testing.T) {
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH"}}
	src := &TokenSource{ClientID: "CLIENTID", HTTPClient: client, token: expiredToken()}

	if _, err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := client.lastForm["client_secret"]; ok {
		t.Error("client_secret was sent for a device flow token")
	}
}

func TestTokenSource_RefreshRespectsCanceledContext(t *testing.T) {
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN"}}
	src := &TokenSource{HTTPClient: client, token: expiredToken()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := src.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if client.count() != 0 {
		t.Errorf("made %d requests, want 0", client.count())
	}
}

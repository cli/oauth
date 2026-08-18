package oauth

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cli/oauth/api"
)

type stubTransport struct {
	mu sync.Mutex
	// statuses are returned in order; the last one repeats.
	statuses []int
	headers  []http.Header

	authHeaders []string
	bodies      []string
}

func (t *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	i := len(t.authHeaders)
	t.authHeaders = append(t.authHeaders, req.Header.Get("Authorization"))

	body := ""
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(b)
	}
	t.bodies = append(t.bodies, body)

	status := t.statuses[len(t.statuses)-1]
	if i < len(t.statuses) {
		status = t.statuses[i]
	}

	header := http.Header{}
	if i < len(t.headers) && t.headers[i] != nil {
		header = t.headers[i]
	}

	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("response body")),
	}, nil
}

func (t *stubTransport) calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.authHeaders...)
}

func newTestTransport(base http.RoundTripper, client *stubTokenClient, token *api.AccessToken) *Transport {
	return &Transport{
		Source: &TokenSource{
			ClientID:   "CLIENTID",
			TokenURL:   "https://example.com/token",
			HTTPClient: client,
			token:      token,
		},
		Base: base,
	}
}

func validToken() *api.AccessToken {
	return &api.AccessToken{
		Token:        "OLDTOKEN",
		RefreshToken: "OLDREFRESH",
		Type:         "bearer",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
}

func TestTransport_AttachesToken(t *testing.T) {
	base := &stubTransport{statuses: []int{200}}
	tr := newTestTransport(base, &stubTokenClient{}, validToken())

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	calls := base.calls()
	if len(calls) != 1 {
		t.Fatalf("made %d requests, want 1", len(calls))
	}
	if calls[0] != "bearer OLDTOKEN" {
		t.Errorf("Authorization = %q, want %q", calls[0], "bearer OLDTOKEN")
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("caller's request was mutated: Authorization = %q", got)
	}
}

func TestTransport_RefreshesOnceAndRetries(t *testing.T) {
	base := &stubTransport{statuses: []int{401, 200}}
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	tr := newTestTransport(base, client, validToken())

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	calls := base.calls()
	if len(calls) != 2 {
		t.Fatalf("made %d requests, want 2", len(calls))
	}
	if calls[0] != "bearer OLDTOKEN" {
		t.Errorf("first Authorization = %q, want bearer OLDTOKEN", calls[0])
	}
	if calls[1] != "Bearer NEWTOKEN" {
		t.Errorf("retry Authorization = %q, want Bearer NEWTOKEN", calls[1])
	}
	if client.count() != 1 {
		t.Errorf("made %d refresh requests, want 1", client.count())
	}
}

func TestTransport_DoesNotLoopWhenRetryAlsoFails(t *testing.T) {
	// The whole point of refresh-once: a persistently rejected token must not spin.
	base := &stubTransport{statuses: []int{401}}
	client := &stubTokenClient{responses: []string{
		"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800",
		"access_token=NEWERTOKEN&refresh_token=NEWERREFRESH&expires_in=28800",
	}}
	tr := newTestTransport(base, client, validToken())

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := len(base.calls()); got != 2 {
		t.Errorf("made %d requests, want exactly 2", got)
	}
	if client.count() != 1 {
		t.Errorf("made %d refresh requests, want 1", client.count())
	}
}

func TestTransport_NoRefreshWithoutRefreshToken(t *testing.T) {
	// A non-expiring token from a server without refresh support: a 401 is just a 401.
	base := &stubTransport{statuses: []int{401}}
	client := &stubTokenClient{}
	tr := newTestTransport(base, client, &api.AccessToken{Token: "ATOKEN"})

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := len(base.calls()); got != 1 {
		t.Errorf("made %d requests, want 1", got)
	}
	if client.count() != 0 {
		t.Errorf("made %d refresh requests, want 0", client.count())
	}
}

func TestTransport_ReturnsOriginalResponseWhenRefreshFails(t *testing.T) {
	base := &stubTransport{statuses: []int{401}}
	client := &stubTokenClient{responses: []string{"error=bad_refresh_token"}}
	tr := newTestTransport(base, client, validToken())

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := len(base.calls()); got != 1 {
		t.Errorf("made %d requests, want 1", got)
	}
}

func TestTransport_RetriesWithReplayedBody(t *testing.T) {
	base := &stubTransport{statuses: []int{401, 200}}
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	tr := newTestTransport(base, client, validToken())

	req, _ := http.NewRequest("POST", "https://api.github.com/user/repos", bytes.NewBufferString(`{"name":"x"}`))
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.bodies) != 2 {
		t.Fatalf("made %d requests, want 2", len(base.bodies))
	}
	if base.bodies[0] != `{"name":"x"}` || base.bodies[1] != `{"name":"x"}` {
		t.Errorf("bodies = %q, want both to be the request body", base.bodies)
	}
}

func TestTransport_DoesNotRetryUnreplayableBody(t *testing.T) {
	base := &stubTransport{statuses: []int{401, 200}}
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH"}}
	tr := newTestTransport(base, client, validToken())

	// A request built with an opaque reader has no GetBody, so it cannot be safely replayed.
	req, _ := http.NewRequest("POST", "https://api.github.com/user/repos", io.NopCloser(strings.NewReader("data")))
	req.GetBody = nil

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := len(base.calls()); got != 1 {
		t.Errorf("made %d requests, want 1", got)
	}
}

func TestTransport_RefreshesProactivelyForExpiredToken(t *testing.T) {
	base := &stubTransport{statuses: []int{200}}
	client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
	tr := newTestTransport(base, client, expiredToken())

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := base.calls()
	if len(calls) != 1 {
		t.Fatalf("made %d requests, want 1", len(calls))
	}
	if calls[0] != "Bearer NEWTOKEN" {
		t.Errorf("Authorization = %q, want Bearer NEWTOKEN", calls[0])
	}
}

func TestTransport_Forbidden(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		wantCalls   int
		wantRefresh int
	}{
		{
			name:        "expired token indicated",
			header:      http.Header{"Www-Authenticate": {`Bearer error="invalid_token", error_description="token expired"`}},
			wantCalls:   2,
			wantRefresh: 1,
		},
		{
			name:        "ordinary permission error",
			header:      http.Header{},
			wantCalls:   1,
			wantRefresh: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &stubTransport{statuses: []int{403, 200}, headers: []http.Header{tt.header}}
			client := &stubTokenClient{responses: []string{"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800"}}
			tr := newTestTransport(base, client, validToken())

			req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
			if _, err := tr.RoundTrip(req); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := len(base.calls()); got != tt.wantCalls {
				t.Errorf("made %d requests, want %d", got, tt.wantCalls)
			}
			if client.count() != tt.wantRefresh {
				t.Errorf("made %d refresh requests, want %d", client.count(), tt.wantRefresh)
			}
		})
	}
}

func TestTransport_DefaultsTokenTypeToBearer(t *testing.T) {
	base := &stubTransport{statuses: []int{200}}
	tr := newTestTransport(base, &stubTokenClient{}, &api.AccessToken{Token: "ATOKEN"})

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := base.calls()[0]; got != "Bearer ATOKEN" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer ATOKEN")
	}
}

func TestTransport_ConcurrentRequestsRefreshOnce(t *testing.T) {
	// Several in-flight requests all rejected for the same stale token must collapse into a single
	// refresh, rather than each performing its own and invalidating the others'.
	base := &rejectStaleTransport{staleToken: "OLDTOKEN"}
	client := &stubTokenClient{responses: []string{
		"access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800",
		"access_token=NEWERTOKEN&refresh_token=NEWERREFRESH&expires_in=28800",
	}}
	tr := newTestTransport(base, client, validToken())

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if resp.StatusCode != 200 {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
		}()
	}
	wg.Wait()

	if client.count() != 1 {
		t.Errorf("made %d refresh requests, want 1", client.count())
	}
}

// rejectStaleTransport answers 401 for one specific token and 200 for anything else, modeling a
// server that has expired a token but accepts its replacement.
type rejectStaleTransport struct {
	staleToken string
}

func (t *rejectStaleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	status := 200
	if strings.HasSuffix(req.Header.Get("Authorization"), " "+t.staleToken) {
		status = 401
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("response body")),
	}, nil
}

func TestNewHTTPClient(t *testing.T) {
	src := NewTokenSource(&api.AccessToken{Token: "ATOKEN"}, "CLIENTID", "SECRET", "https://example.com/token")
	client := NewHTTPClient(src)

	tr, ok := client.Transport.(*Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *Transport", client.Transport)
	}
	if tr.Source != src {
		t.Error("Transport was not wired to the given TokenSource")
	}
}

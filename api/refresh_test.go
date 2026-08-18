package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
)

type recordingClient struct {
	status      int
	body        string
	contentType string
	err         error

	postCount int
	lastURL   string
	lastForm  url.Values
}

func (c *recordingClient) PostForm(u string, params url.Values) (*http.Response, error) {
	c.postCount++
	c.lastURL = u
	c.lastForm = params
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		Body:       io.NopCloser(bytes.NewBufferString(c.body)),
		Header:     http.Header{"Content-Type": {c.contentType}},
		StatusCode: c.status,
	}, nil
}

func TestRefresh(t *testing.T) {
	client := &recordingClient{
		status:      200,
		contentType: "application/x-www-form-urlencoded",
		body:        "access_token=NEWTOKEN&refresh_token=NEWREFRESH&expires_in=28800&refresh_token_expires_in=15897600&token_type=bearer&scope=repo",
	}

	token, err := Refresh(client, "https://github.com/login/oauth/access_token", RefreshOptions{
		ClientID:     "CLIENTID",
		ClientSecret: "CLIENTSECRET",
		RefreshToken: "OLDREFRESH",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Token != "NEWTOKEN" {
		t.Errorf("Token = %q, want NEWTOKEN", token.Token)
	}
	if token.RefreshToken != "NEWREFRESH" {
		t.Errorf("RefreshToken = %q, want NEWREFRESH", token.RefreshToken)
	}
	if token.ExpiresIn != 28800 {
		t.Errorf("ExpiresIn = %d, want 28800", token.ExpiresIn)
	}
	if token.ExpiresAt.IsZero() {
		t.Error("ExpiresAt was not set")
	}

	wantForm := url.Values{
		"client_id":     {"CLIENTID"},
		"client_secret": {"CLIENTSECRET"},
		"refresh_token": {"OLDREFRESH"},
		"grant_type":    {"refresh_token"},
	}
	if client.lastForm.Encode() != wantForm.Encode() {
		t.Errorf("form = %v, want %v", client.lastForm, wantForm)
	}
}

func TestRefresh_omitsEmptyClientSecret(t *testing.T) {
	// Tokens obtained via device flow are refreshed without a client secret.
	client := &recordingClient{
		status:      200,
		contentType: "application/x-www-form-urlencoded",
		body:        "access_token=NEWTOKEN",
	}

	if _, err := Refresh(client, "https://example.com/token", RefreshOptions{
		ClientID:     "CLIENTID",
		RefreshToken: "OLDREFRESH",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := client.lastForm["client_secret"]; ok {
		t.Error("client_secret was sent despite being empty")
	}
}

func TestRefresh_badRefreshToken(t *testing.T) {
	client := &recordingClient{
		status:      400,
		contentType: "application/x-www-form-urlencoded",
		body:        "error=bad_refresh_token&error_description=The+refresh+token+passed+is+incorrect+or+expired.",
	}

	_, err := Refresh(client, "https://example.com/token", RefreshOptions{
		ClientID:     "CLIENTID",
		RefreshToken: "EXPIRED",
	})
	if !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("error = %v, want ErrRefreshTokenInvalid", err)
	}
}

func TestRefresh_otherAPIError(t *testing.T) {
	client := &recordingClient{
		status:      400,
		contentType: "application/x-www-form-urlencoded",
		body:        "error=incorrect_client_credentials",
	}

	_, err := Refresh(client, "https://example.com/token", RefreshOptions{
		ClientID:     "CLIENTID",
		RefreshToken: "AREFRESH",
	})
	if errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatal("unrelated API error was reported as an invalid refresh token")
	}
	var apiError *Error
	if !errors.As(err, &apiError) || apiError.Code != "incorrect_client_credentials" {
		t.Fatalf("error = %v, want incorrect_client_credentials", err)
	}
}

func TestRefresh_withoutRefreshToken(t *testing.T) {
	client := &recordingClient{status: 200}

	_, err := Refresh(client, "https://example.com/token", RefreshOptions{ClientID: "CLIENTID"})
	if !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Fatalf("error = %v, want ErrRefreshTokenInvalid", err)
	}
	if client.postCount != 0 {
		t.Errorf("made %d requests, want 0", client.postCount)
	}
}

func TestRefresh_transportError(t *testing.T) {
	wantErr := errors.New("network is unreachable")
	client := &recordingClient{err: wantErr}

	_, err := Refresh(client, "https://example.com/token", RefreshOptions{
		ClientID:     "CLIENTID",
		RefreshToken: "AREFRESH",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

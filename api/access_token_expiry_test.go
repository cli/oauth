package api

import (
	"net/url"
	"testing"
	"time"
)

func TestFormResponse_AccessToken_expiry(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	tests := []struct {
		name                      string
		values                    url.Values
		wantExpiresIn             int
		wantExpiresAt             time.Time
		wantRefreshExpiresIn      int
		wantRefreshTokenExpiresAt time.Time
	}{
		{
			name: "expiring token with refresh token",
			values: url.Values{
				"access_token":             []string{"ATOKEN"},
				"refresh_token":            []string{"RTOKEN"},
				"expires_in":               []string{"28800"},
				"refresh_token_expires_in": []string{"15897600"},
			},
			wantExpiresIn:             28800,
			wantExpiresAt:             now.Add(28800 * time.Second),
			wantRefreshExpiresIn:      15897600,
			wantRefreshTokenExpiresAt: now.Add(15897600 * time.Second),
		},
		{
			name: "server without expiring token support",
			values: url.Values{
				"access_token": []string{"ATOKEN"},
				"token_type":   []string{"bearer"},
			},
		},
		{
			name: "unparseable expiry is ignored",
			values: url.Values{
				"access_token": []string{"ATOKEN"},
				"expires_in":   []string{"soon"},
			},
		},
		{
			name: "refresh expiry ignored without refresh token",
			values: url.Values{
				"access_token":             []string{"ATOKEN"},
				"refresh_token_expires_in": []string{"15897600"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormResponse{values: tt.values}.AccessToken()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ExpiresIn != tt.wantExpiresIn {
				t.Errorf("ExpiresIn = %d, want %d", got.ExpiresIn, tt.wantExpiresIn)
			}
			if !got.ExpiresAt.Equal(tt.wantExpiresAt) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, tt.wantExpiresAt)
			}
			if got.RefreshTokenExpiresIn != tt.wantRefreshExpiresIn {
				t.Errorf("RefreshTokenExpiresIn = %d, want %d", got.RefreshTokenExpiresIn, tt.wantRefreshExpiresIn)
			}
			if !got.RefreshTokenExpiresAt.Equal(tt.wantRefreshTokenExpiresAt) {
				t.Errorf("RefreshTokenExpiresAt = %v, want %v", got.RefreshTokenExpiresAt, tt.wantRefreshTokenExpiresAt)
			}
		})
	}
}

func TestAccessToken_IsExpired(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	tests := []struct {
		name  string
		token *AccessToken
		want  bool
	}{
		{name: "nil token", token: nil, want: false},
		{name: "non-expiring token", token: &AccessToken{Token: "A"}, want: false},
		{name: "valid token", token: &AccessToken{ExpiresAt: now.Add(time.Hour)}, want: false},
		{name: "expired token", token: &AccessToken{ExpiresAt: now.Add(-time.Second)}, want: true},
		{name: "within leeway counts as expired", token: &AccessToken{ExpiresAt: now.Add(30 * time.Second)}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessToken_CanRefresh(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	tests := []struct {
		name  string
		token *AccessToken
		want  bool
	}{
		{name: "nil token", token: nil, want: false},
		{name: "no refresh token", token: &AccessToken{Token: "A"}, want: false},
		{name: "refresh token without expiry", token: &AccessToken{RefreshToken: "R"}, want: true},
		{name: "unexpired refresh token", token: &AccessToken{RefreshToken: "R", RefreshTokenExpiresAt: now.Add(time.Hour)}, want: true},
		{name: "expired refresh token", token: &AccessToken{RefreshToken: "R", RefreshTokenExpiresAt: now.Add(-time.Hour)}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.CanRefresh(); got != tt.want {
				t.Errorf("CanRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAppendOfflineAccess(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "empty", input: nil, want: []string{"offline_access"}},
		{name: "appends", input: []string{"repo"}, want: []string{"repo", "offline_access"}},
		{name: "dedupes", input: []string{"repo", "offline_access"}, want: []string{"repo", "offline_access"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendOfflineAccess(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestAppendOfflineAccess_doesNotMutateInput(t *testing.T) {
	// A caller's Scopes slice with spare capacity must not be written through.
	input := make([]string, 1, 4)
	input[0] = "repo"

	_ = AppendOfflineAccess(input)

	if got := input[:cap(input)]; got[1] != "" {
		t.Errorf("input slice was mutated: %q", got[1])
	}
}

package webapp

import (
	"net/url"
	"testing"
)

func TestFlow_BrowserURL_offlineAccess(t *testing.T) {
	tests := []struct {
		name                string
		scopes              []string
		requestRefreshToken bool
		wantScope           string
	}{
		{
			name:      "not requested",
			scopes:    []string{"repo", "read:org"},
			wantScope: "repo read:org",
		},
		{
			name:                "requested",
			scopes:              []string{"repo", "read:org"},
			requestRefreshToken: true,
			wantScope:           "repo read:org offline_access",
		},
		{
			name:                "already present",
			scopes:              []string{"repo", "offline_access"},
			requestRefreshToken: true,
			wantScope:           "repo offline_access",
		},
		{
			name:                "no other scopes",
			requestRefreshToken: true,
			wantScope:           "offline_access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow, err := InitFlow()
			if err != nil {
				t.Fatalf("InitFlow: %v", err)
			}

			browserURL, err := flow.BrowserURL("https://github.com/login/oauth/authorize", BrowserParams{
				ClientID:            "CLIENTID",
				RedirectURI:         "http://127.0.0.1/callback",
				Scopes:              tt.scopes,
				RequestRefreshToken: tt.requestRefreshToken,
			})
			if err != nil {
				t.Fatalf("BrowserURL: %v", err)
			}

			u, err := url.Parse(browserURL)
			if err != nil {
				t.Fatalf("parsing %q: %v", browserURL, err)
			}
			if got := u.Query().Get("scope"); got != tt.wantScope {
				t.Errorf("scope = %q, want %q", got, tt.wantScope)
			}
		})
	}
}

func TestFlow_BrowserURL_doesNotMutateCallerScopes(t *testing.T) {
	flow, err := InitFlow()
	if err != nil {
		t.Fatalf("InitFlow: %v", err)
	}

	scopes := []string{"repo"}
	if _, err := flow.BrowserURL("https://github.com/login/oauth/authorize", BrowserParams{
		ClientID:            "CLIENTID",
		RedirectURI:         "http://127.0.0.1/callback",
		Scopes:              scopes,
		RequestRefreshToken: true,
	}); err != nil {
		t.Fatalf("BrowserURL: %v", err)
	}

	if len(scopes) != 1 || scopes[0] != "repo" {
		t.Errorf("caller's scopes were modified: %v", scopes)
	}
}

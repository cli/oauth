package device

import (
	"net/url"
	"testing"
)

func TestWithOfflineAccess(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{name: "adds to existing scopes", scope: "repo read:org", want: "repo read:org offline_access"},
		{name: "adds to empty scope", scope: "", want: "offline_access"},
		{name: "does not duplicate", scope: "repo offline_access", want: "repo offline_access"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := url.Values{"scope": {tt.scope}}
			WithOfflineAccess()(&values)
			if got := values.Get("scope"); got != tt.want {
				t.Errorf("scope = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequestCode_withOfflineAccess(t *testing.T) {
	client := &apiClient{
		stubs: []apiStub{
			{
				status:      200,
				contentType: "application/x-www-form-urlencoded",
				body:        "verification_uri=http://verify.me&interval=5&expires_in=99&device_code=DEVIC&user_code=123-abc",
			},
		},
	}

	if _, err := RequestCode(client, "https://example.com/device/code", "CLIENTID",
		[]string{"repo"}, WithOfflineAccess()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := client.calls[0].params.Get("scope"); got != "repo offline_access" {
		t.Errorf("scope = %q, want %q", got, "repo offline_access")
	}
}

package oauth

import (
	"slices"
	"testing"
)

func TestWithOfflineAccess(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{
			name:   "appends scope",
			scopes: []string{"repo", "read:org"},
			want:   []string{"repo", "read:org", "offline_access"},
		},
		{
			name:   "does not duplicate scope",
			scopes: []string{"repo", "offline_access"},
			want:   []string{"repo", "offline_access"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := slices.Clone(tt.scopes)
			got := withOfflineAccess(tt.scopes)
			if !slices.Equal(got, tt.want) {
				t.Errorf("withOfflineAccess() = %v, want %v", got, tt.want)
			}
			if !slices.Equal(tt.scopes, original) {
				t.Errorf("input scopes changed from %v to %v", original, tt.scopes)
			}
		})
	}
}

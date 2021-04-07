package api

import (
	"reflect"
	"testing"
)

func TestFormResponse_AccessToken(t *testing.T) {
	tests := []struct {
		name     string
		response FormResponse
		want     *AccessToken
		wantErr  *Error
	}{
		{
			name: "with token",
			response: FormResponse{
				values: map[string]string{
					"access_token": "ATOKEN",
					"token_type":   "bearer",
					"scope":        "repo gist",
				},
			},
			want: &AccessToken{
				Token: "ATOKEN",
				Type:  "bearer",
				Scope: "repo gist",
			},
			wantErr: nil,
		},
		{
			name: "no token",
			response: FormResponse{
				StatusCode: 200,
				values: map[string]string{
					"error": "access_denied",
				},
			},
			want: nil,
			wantErr: &Error{
				Code:         "access_denied",
				ResponseCode: 200,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.response.AccessToken()
			if err != nil {
				apiError := err.(*Error)
				if !reflect.DeepEqual(apiError, tt.wantErr) {
					t.Fatalf("error %v, want %v", apiError, tt.wantErr)
				}
			} else if tt.wantErr != nil {
				t.Fatalf("want error %v, got nil", tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FormResponse.AccessToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

package api

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestFormResponse_Get(t *testing.T) {
	tests := []struct {
		name     string
		response FormResponse
		key      string
		want     string
	}{
		{
			name:     "blank",
			response: FormResponse{},
			key:      "access_token",
			want:     "",
		},
		{
			name: "with value",
			response: FormResponse{
				values: url.Values{
					"access_token": []string{"ATOKEN"},
				},
			},
			key:  "access_token",
			want: "ATOKEN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.Get(tt.key); got != tt.want {
				t.Errorf("FormResponse.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormResponse_Err(t *testing.T) {
	tests := []struct {
		name     string
		response FormResponse
		wantErr  Error
		errorMsg string
	}{
		{
			name:     "blank",
			response: FormResponse{},
			wantErr:  Error{},
			errorMsg: "HTTP 0",
		},
		{
			name: "with values",
			response: FormResponse{
				StatusCode: 422,
				requestURI: "http://example.com/path",
				values: url.Values{
					"error":             []string{"try_again"},
					"error_description": []string{"maybe it works later"},
				},
			},
			wantErr: Error{
				Code:         "try_again",
				ResponseCode: 422,
				RequestURI:   "http://example.com/path",
			},
			errorMsg: "maybe it works later (try_again)",
		},
		{
			name: "no values",
			response: FormResponse{
				StatusCode: 422,
				requestURI: "http://example.com/path",
			},
			wantErr: Error{
				Code:         "",
				ResponseCode: 422,
				RequestURI:   "http://example.com/path",
			},
			errorMsg: "HTTP 422",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.response.Err()
			if err == nil {
				t.Fatalf("FormResponse.Err() = %v, want %v", nil, tt.wantErr)
			}
			apiError := err.(*Error)
			if apiError.Code != tt.wantErr.Code {
				t.Errorf("Error.Code = %v, want %v", apiError.Code, tt.wantErr.Code)
			}
			if apiError.ResponseCode != tt.wantErr.ResponseCode {
				t.Errorf("Error.ResponseCode = %v, want %v", apiError.ResponseCode, tt.wantErr.ResponseCode)
			}
			if apiError.RequestURI != tt.wantErr.RequestURI {
				t.Errorf("Error.RequestURI = %v, want %v", apiError.RequestURI, tt.wantErr.RequestURI)
			}
			if apiError.Error() != tt.errorMsg {
				t.Errorf("Error.Error() = %q, want %q", apiError.Error(), tt.errorMsg)
			}
		})
	}
}

type apiClient struct {
	status      int
	body        string
	contentType string

	postCount int
}

func (c *apiClient) PostForm(u string, params url.Values) (*http.Response, error) {
	c.postCount++
	return &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString(c.body)),
		Header: http.Header{
			"Content-Type": {c.contentType},
		},
		StatusCode: c.status,
	}, nil
}

func TestPostForm(t *testing.T) {
	type args struct {
		url    string
		params url.Values
	}
	tests := []struct {
		name    string
		args    args
		http    apiClient
		want    *FormResponse
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				url: "https://github.com/oauth",
			},
			http: apiClient{
				body:        "access_token=123abc&scopes=repo%20gist",
				status:      200,
				contentType: "application/x-www-form-urlencoded; charset=utf-8",
			},
			want: &FormResponse{
				StatusCode: 200,
				requestURI: "https://github.com/oauth",
				values: url.Values{
					"access_token": {"123abc"},
					"scopes":       {"repo gist"},
				},
			},
			wantErr: false,
		},
		{
			name: "HTML response",
			args: args{
				url: "https://github.com/oauth",
			},
			http: apiClient{
				body:        "<h1>Something went wrong</h1>",
				status:      502,
				contentType: "text/html",
			},
			want: &FormResponse{
				StatusCode: 502,
				requestURI: "https://github.com/oauth",
				values:     url.Values(nil),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PostForm(&tt.http, tt.args.url, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("PostForm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.http.postCount != 1 {
				t.Errorf("expected PostForm to happen 1 time; happened %d times", tt.http.postCount)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PostForm() = %v, want %v", got, tt.want)
			}
		})
	}
}

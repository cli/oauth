package device

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cli/oauth/api"
)

type apiStub struct {
	status      int
	body        string
	contentType string
}

type postArgs struct {
	url    string
	params url.Values
}

type apiClient struct {
	stubs []apiStub
	calls []postArgs

	postCount int
}

func (c *apiClient) PostForm(u string, params url.Values) (*http.Response, error) {
	stub := c.stubs[c.postCount]
	c.calls = append(c.calls, postArgs{url: u, params: params})
	c.postCount++
	return &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString(stub.body)),
		Header: http.Header{
			"Content-Type": {stub.contentType},
		},
		StatusCode: stub.status,
	}, nil
}

func TestRequestCode(t *testing.T) {
	type args struct {
		http     apiClient
		url      string
		clientID string
		scopes   []string
	}
	tests := []struct {
		name    string
		args    args
		want    *CodeResponse
		wantErr string
		posts   []postArgs
	}{
		{
			name: "success",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "verification_uri=http://verify.me&interval=5&expires_in=99&device_code=DEVIC&user_code=123-abc",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				scopes:   []string{"repo", "gist"},
			},
			want: &CodeResponse{
				DeviceCode:      "DEVIC",
				UserCode:        "123-abc",
				VerificationURI: "http://verify.me",
				ExpiresIn:       99,
				Interval:        5,
			},
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id": {"CLIENT-ID"},
						"scope":     {"repo gist"},
					},
				},
			},
		},
		{
			name: "unsupported",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "",
							status:      404,
							contentType: "text/html",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				scopes:   []string{"repo", "gist"},
			},
			wantErr: "device flow not supported",
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id": {"CLIENT-ID"},
						"scope":     {"repo gist"},
					},
				},
			},
		},
		{
			name: "unauthorized client",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=unauthorized_client",
							status:      400,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				scopes:   []string{"repo", "gist"},
			},
			wantErr: "device flow not supported",
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id": {"CLIENT-ID"},
						"scope":     {"repo gist"},
					},
				},
			},
		},
		{
			name: "server error",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "<h1>Something went wrong</h1>",
							status:      502,
							contentType: "text/html",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				scopes:   []string{"repo", "gist"},
			},
			wantErr: "HTTP 502",
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id": {"CLIENT-ID"},
						"scope":     {"repo gist"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RequestCode(&tt.args.http, tt.args.url, tt.args.clientID, tt.args.scopes)
			if (err != nil) != (tt.wantErr != "") {
				t.Errorf("RequestCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
			if tt.args.http.postCount != 1 {
				t.Errorf("expected PostForm to happen 1 time; happened %d times", tt.args.http.postCount)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RequestCode() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.args.http.calls, tt.posts) {
				t.Errorf("PostForm() = %v, want %v", tt.args.http.calls, tt.posts)
			}
		})
	}
}

func TestPollToken(t *testing.T) {
	var totalSlept time.Duration
	mockSleep := func(d time.Duration) {
		totalSlept += d
	}
	duration := func(d string) time.Duration {
		res, _ := time.ParseDuration(d)
		return res
	}
	clock := func(durations ...string) func() time.Time {
		count := 0
		now := time.Now()
		return func() time.Time {
			t := now.Add(duration(durations[count]))
			count++
			return t
		}
	}

	type args struct {
		http     apiClient
		url      string
		clientID string
		code     *CodeResponse
	}
	tests := []struct {
		name    string
		args    args
		want    *api.AccessToken
		wantErr string
		posts   []postArgs
		slept   time.Duration
	}{
		{
			name: "success",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "access_token=123abc",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				code: &CodeResponse{
					DeviceCode:      "DEVIC",
					UserCode:        "123-abc",
					VerificationURI: "http://verify.me",
					ExpiresIn:       99,
					Interval:        5,
					timeSleep:       mockSleep,
					timeNow:         clock("0", "5s", "10s"),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
			slept: duration("10s"),
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
		},
		{
			name: "timed out",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				code: &CodeResponse{
					DeviceCode:      "DEVIC",
					UserCode:        "123-abc",
					VerificationURI: "http://verify.me",
					ExpiresIn:       99,
					Interval:        5,
					timeSleep:       mockSleep,
					timeNow:         clock("0", "5s", "15m"),
				},
			},
			wantErr: "authentication timed out",
			slept:   duration("10s"),
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
		},
		{
			name: "access denied",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=access_denied",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				code: &CodeResponse{
					DeviceCode:      "DEVIC",
					UserCode:        "123-abc",
					VerificationURI: "http://verify.me",
					ExpiresIn:       99,
					Interval:        5,
					timeSleep:       mockSleep,
					timeNow:         clock("0", "5s"),
				},
			},
			wantErr: "access_denied",
			slept:   duration("5s"),
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totalSlept = 0
			got, err := PollToken(&tt.args.http, tt.args.url, tt.args.clientID, tt.args.code)
			if (err != nil) != (tt.wantErr != "") {
				t.Errorf("PollToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Errorf("PollToken error = %q, want %q", err.Error(), tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PollToken() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.args.http.calls, tt.posts) {
				t.Errorf("PostForm() = %v, want %v", tt.args.http.calls, tt.posts)
			}
			if totalSlept != tt.slept {
				t.Errorf("slept %v, wanted %v", totalSlept, tt.slept)
			}
		})
	}
}

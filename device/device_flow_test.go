package device

import (
	"bytes"
	"context"
	"errors"
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
		audience string
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
			name: "with verification_uri_complete",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "verification_uri=http://verify.me&interval=5&expires_in=99&device_code=DEVIC&user_code=123-abc&verification_uri_complete=http://verify.me/?code=123-abc",
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
				DeviceCode:              "DEVIC",
				UserCode:                "123-abc",
				VerificationURI:         "http://verify.me",
				VerificationURIComplete: "http://verify.me/?code=123-abc",
				ExpiresIn:               99,
				Interval:                5,
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
			name: "with audience",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "verification_uri=http://verify.me&interval=5&expires_in=99&device_code=DEVIC&user_code=123-abc&verification_uri_complete=http://verify.me/?code=123-abc",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url:      "https://github.com/oauth",
				clientID: "CLIENT-ID",
				scopes:   []string{"repo", "gist"},
				audience: "https://api.github.com",
			},
			want: &CodeResponse{
				DeviceCode:              "DEVIC",
				UserCode:                "123-abc",
				VerificationURI:         "http://verify.me",
				VerificationURIComplete: "http://verify.me/?code=123-abc",
				ExpiresIn:               99,
				Interval:                5,
			},
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id": {"CLIENT-ID"},
						"scope":     {"repo gist"},
						"audience":  {"https://api.github.com"},
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
			name: "device flow disabled",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=device_flow_disabled",
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
			got, err := RequestCode(&tt.args.http, tt.args.url,
				tt.args.clientID, tt.args.scopes, WithAudience(tt.args.audience))
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
	singletonFakePoller := func(maxWaits int) pollerFactory {
		var instance *fakePoller
		return func(ctx context.Context, interval, expiresIn time.Duration) (context.Context, poller) {
			if instance != nil {
				// This is to make the factory return the same instance in tests.
				return ctx, instance
			}
			instance = &fakePoller{
				maxWaits: maxWaits,
				interval: interval,
			}
			return ctx, instance
		}
	}

	type args struct {
		http apiClient
		url  string
		opts WaitOptions
	}
	tests := []struct {
		name       string
		args       args
		want       *api.AccessToken
		wantErr    string
		assertFunc func(*testing.T, args)
		posts      []postArgs
		slept      time.Duration
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(2),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
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
			assertFunc: func(t *testing.T, a args) {
				// Get the created poller
				_, poller := a.opts.newPoller(context.Background(), 0, 0)
				if poller.(*fakePoller).updatedIntervals != nil {
					t.Errorf("no interval change expected = %v", poller.(*fakePoller).updatedIntervals)
				}
			},
		},
		{
			name: "success with slow down, new interval in returned response",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=slow_down&error_description=Too+many+requests+have+been+made+in+the+same+timeframe.&error_uri=https%3A%2F%2Fdocs.github.com&interval=22",
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(3),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
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
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
			assertFunc: func(t *testing.T, a args) {
				// Get the created poller
				_, poller := a.opts.newPoller(context.Background(), 0, 0)
				got := poller.(*fakePoller).updatedIntervals
				want := []time.Duration{22 * time.Second}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("unexpected updated intervals = %v, want %v", got, want)
				}
			},
		},
		{
			name: "success with multiple slow down, new interval in returned response",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=slow_down&error_description=Too+many+requests+have+been+made+in+the+same+timeframe.&error_uri=https%3A%2F%2Fdocs.github.com&interval=22",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=slow_down&error_description=Too+many+requests+have+been+made+in+the+same+timeframe.&error_uri=https%3A%2F%2Fdocs.github.com&interval=33",
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(4),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
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
			assertFunc: func(t *testing.T, a args) {
				// Get the created poller
				_, poller := a.opts.newPoller(context.Background(), 0, 0)
				got := poller.(*fakePoller).updatedIntervals
				want := []time.Duration{22 * time.Second, 33 * time.Second}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("unexpected updated intervals = %v, want %v", got, want)
				}
			},
		},
		{
			name: "success with slow down, no interval in returned response",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=slow_down",
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(3),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
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
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":   {"CLIENT-ID"},
						"device_code": {"DEVIC"},
						"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
			assertFunc: func(t *testing.T, a args) {
				// Get the created poller
				_, poller := a.opts.newPoller(context.Background(), 0, 0)
				got := poller.(*fakePoller).updatedIntervals
				want := []time.Duration{10 * time.Second}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("unexpected updated intervals = %v, want %v", got, want)
				}
			},
		},
		{
			name: "success with multiple slow down, no interval in returned response",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "error=authorization_pending",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=slow_down",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
						{
							body:        "error=slow_down",
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(4),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
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
			assertFunc: func(t *testing.T, a args) {
				// Get the created poller
				_, poller := a.opts.newPoller(context.Background(), 0, 0)
				got := poller.(*fakePoller).updatedIntervals
				want := []time.Duration{10 * time.Second, 15 * time.Second}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("unexpected updated intervals = %v, want %v", got, want)
				}
			},
		},
		{
			name: "with client secret and grant type",
			args: args{
				http: apiClient{
					stubs: []apiStub{
						{
							body:        "access_token=123abc",
							status:      200,
							contentType: "application/x-www-form-urlencoded; charset=utf-8",
						},
					},
				},
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID:     "CLIENT-ID",
					ClientSecret: "SEKRIT",
					GrantType:    "device_code",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(1),
				},
			},
			want: &api.AccessToken{
				Token: "123abc",
			},
			posts: []postArgs{
				{
					url: "https://github.com/oauth",
					params: url.Values{
						"client_id":     {"CLIENT-ID"},
						"client_secret": {"SEKRIT"},
						"device_code":   {"DEVIC"},
						"grant_type":    {"device_code"},
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       14,
						Interval:        5,
					},
					newPoller: singletonFakePoller(2),
				},
			},
			wantErr: "context deadline exceeded",
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
				url: "https://github.com/oauth",
				opts: WaitOptions{
					ClientID: "CLIENT-ID",
					DeviceCode: &CodeResponse{
						DeviceCode:      "DEVIC",
						UserCode:        "123-abc",
						VerificationURI: "http://verify.me",
						ExpiresIn:       99,
						Interval:        5,
					},
					newPoller: singletonFakePoller(1),
				},
			},
			wantErr: "access_denied",
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
			got, err := Wait(context.Background(), &tt.args.http, tt.args.url, tt.args.opts)
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

			if tt.assertFunc != nil {
				tt.assertFunc(t, tt.args)
			}
		})
	}
}

type fakePoller struct {
	interval         time.Duration
	maxWaits         int
	count            int
	updatedIntervals []time.Duration
}

func (p *fakePoller) GetInterval() time.Duration {
	return p.interval
}

func (p *fakePoller) SetInterval(d time.Duration) {
	p.interval = d
	p.updatedIntervals = append(p.updatedIntervals, d)
}

func (p *fakePoller) Wait() error {
	if p.count == p.maxWaits {
		return errors.New("context deadline exceeded")
	}
	p.count++
	return nil
}

func (p *fakePoller) Cancel() {
}

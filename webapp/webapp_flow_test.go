package webapp

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestFlow_BrowserURL(t *testing.T) {
	server := &localServer{
		listener: &fakeListener{
			addr: &net.TCPAddr{Port: 12345},
		},
	}

	type fields struct {
		server   *localServer
		clientID string
		state    string
	}
	type args struct {
		baseURL string
		params  BrowserParams
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "happy path",
			fields: fields{
				server: server,
				state:  "xy/z",
			},
			args: args{
				baseURL: "https://github.com/authorize",
				params: BrowserParams{
					ClientID:    "CLIENT-ID",
					RedirectURI: "http://127.0.0.1/hello",
					Scopes:      []string{"repo", "read:org"},
					AllowSignup: true,
				},
			},
			want:    "https://github.com/authorize?client_id=CLIENT-ID&redirect_uri=http%3A%2F%2F127.0.0.1%3A12345%2Fhello&scope=repo+read%3Aorg&state=xy%2Fz",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &Flow{
				server:   tt.fields.server,
				clientID: tt.fields.clientID,
				state:    tt.fields.state,
			}
			got, err := flow.BrowserURL(tt.args.baseURL, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Flow.BrowserURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Flow.BrowserURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestFlow_AccessToken(t *testing.T) {
	server := &localServer{
		listener: &fakeListener{
			addr: &net.TCPAddr{Port: 12345},
		},
		resultChan: make(chan CodeResponse),
	}

	flow := Flow{
		server:   server,
		clientID: "CLIENT-ID",
		state:    "xy/z",
	}

	client := &apiClient{
		stubs: []apiStub{
			{
				body:        "access_token=ATOKEN&token_type=bearer&scope=repo+gist",
				status:      200,
				contentType: "application/x-www-form-urlencoded; charset=utf-8",
			},
		},
	}

	go func() {
		server.resultChan <- CodeResponse{
			Code:  "ABC-123",
			State: "xy/z",
		}
	}()

	token, err := flow.AccessToken(client, "https://github.com/access_token", "OAUTH-SEKRIT")
	if err != nil {
		t.Fatalf("AccessToken() error: %v", err)
	}

	if len(client.calls) != 1 {
		t.Fatalf("expected 1 HTTP POST, got %d", len(client.calls))
	}
	apiPost := client.calls[0]
	if apiPost.url != "https://github.com/access_token" {
		t.Errorf("HTTP POST to %q", apiPost.url)
	}
	if params := apiPost.params.Encode(); params != "client_id=CLIENT-ID&client_secret=OAUTH-SEKRIT&code=ABC-123&state=xy%2Fz" {
		t.Errorf("HTTP POST params: %v", params)
	}

	if token.Token != "ATOKEN" {
		t.Errorf("Token = %q", token.Token)
	}
}

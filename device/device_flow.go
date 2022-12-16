// Package device facilitates performing OAuth Device Authorization Flow for client applications
// such as CLIs that can not receive redirects from a web site.
//
// First, RequestCode should be used to obtain a CodeResponse.
//
// Next, the user will need to navigate to VerificationURI in their web browser on any device and fill
// in the UserCode.
//
// While the user is completing the web flow, the application should invoke PollToken, which blocks
// the goroutine until the user has authorized the app on the server.
//
// https://docs.github.com/en/free-pro-team@latest/developers/apps/authorizing-oauth-apps#device-flow
package device

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cli/oauth/api"
)

var (
	// ErrUnsupported is thrown when the server does not implement Device flow.
	ErrUnsupported = errors.New("device flow not supported")
	// ErrTimeout is thrown when polling the server for the granted token has timed out.
	ErrTimeout = errors.New("authentication timed out")
)

type httpClient interface {
	PostForm(string, url.Values) (*http.Response, error)
}

// CodeResponse holds information about the authorization-in-progress.
type CodeResponse struct {
	// The user verification code is displayed on the device so the user can enter the code in a browser.
	UserCode string
	// The verification URL where users need to enter the UserCode.
	VerificationURI string
	// The optional verification URL that includes the UserCode.
	VerificationURIComplete string

	// The device verification code is 40 characters and used to verify the device.
	DeviceCode string
	// The number of seconds before the DeviceCode and UserCode expire.
	ExpiresIn int
	// The minimum number of seconds that must pass before you can make a new access token request to
	// complete the device authorization.
	Interval int
}

// RequestCode initiates the authorization flow by requesting a code from uri.
func RequestCode(c httpClient, uri string, clientID string, scopes []string) (*CodeResponse, error) {
	resp, err := api.PostForm(c, uri, url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(scopes, " ")},
	})
	if err != nil {
		return nil, err
	}

	verificationURI := resp.Get("verification_uri")
	if verificationURI == "" {
		// Google's "OAuth 2.0 for TV and Limited-Input Device Applications" uses `verification_url`.
		verificationURI = resp.Get("verification_url")
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 422 ||
		(resp.StatusCode == 200 && verificationURI == "") ||
		(resp.StatusCode == 400 && resp.Get("error") == "unauthorized_client") {
		return nil, ErrUnsupported
	}

	if resp.StatusCode != 200 {
		return nil, resp.Err()
	}

	intervalSeconds, err := strconv.Atoi(resp.Get("interval"))
	if err != nil {
		return nil, fmt.Errorf("could not parse interval=%q as integer: %w", resp.Get("interval"), err)
	}

	expiresIn, err := strconv.Atoi(resp.Get("expires_in"))
	if err != nil {
		return nil, fmt.Errorf("could not parse expires_in=%q as integer: %w", resp.Get("expires_in"), err)
	}

	return &CodeResponse{
		DeviceCode:              resp.Get("device_code"),
		UserCode:                resp.Get("user_code"),
		VerificationURI:         verificationURI,
		VerificationURIComplete: resp.Get("verification_uri_complete"),
		Interval:                intervalSeconds,
		ExpiresIn:               expiresIn,
	}, nil
}

const defaultGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// PollToken polls the server at pollURL until an access token is granted or denied.
//
// Deprecated: use PollTokenWithOptions.
func PollToken(c httpClient, pollURL string, clientID string, code *CodeResponse) (*api.AccessToken, error) {
	return PollTokenWithOptions(c, pollURL, PollOptions{
		ClientID:   clientID,
		DeviceCode: code,
	})
}

// PollOptions specifies parameters to poll the server with until authentication completes.
type PollOptions struct {
	// ClientID is the app client ID value.
	ClientID string
	// ClientSecret is the app client secret value. Optional: only pass if the server requires it.
	ClientSecret string
	// DeviceCode is the value obtained from RequestCode.
	DeviceCode *CodeResponse
	// GrantType overrides the default value specified by OAuth 2.0 Device Code. Optional.
	GrantType string

	timeNow   func() time.Time
	timeSleep func(time.Duration)
}

// PollTokenWithOptions polls the server at uri until authorization completes.
func PollTokenWithOptions(c httpClient, uri string, opts PollOptions) (*api.AccessToken, error) {
	timeNow := opts.timeNow
	if timeNow == nil {
		timeNow = time.Now
	}
	timeSleep := opts.timeSleep
	if timeSleep == nil {
		timeSleep = time.Sleep
	}

	checkInterval := time.Duration(opts.DeviceCode.Interval) * time.Second
	expiresAt := timeNow().Add(time.Duration(opts.DeviceCode.ExpiresIn) * time.Second)
	grantType := opts.GrantType
	if opts.GrantType == "" {
		grantType = defaultGrantType
	}

	for {
		timeSleep(checkInterval)

		values := url.Values{
			"client_id":   {opts.ClientID},
			"device_code": {opts.DeviceCode.DeviceCode},
			"grant_type":  {grantType},
		}

		// Google's "OAuth 2.0 for TV and Limited-Input Device Applications" requires `client_secret`.
		if opts.ClientSecret != "" {
			values.Add("client_secret", opts.ClientSecret)
		}

		resp, err := api.PostForm(c, uri, values)
		if err != nil {
			return nil, err
		}

		var apiError *api.Error
		token, err := resp.AccessToken()
		if err == nil {
			return token, nil
		} else if !(errors.As(err, &apiError) && apiError.Code == "authorization_pending") {
			return nil, err
		}

		if timeNow().After(expiresAt) {
			return nil, ErrTimeout
		}
	}
}

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
	"context"
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

// AuthRequestEditorFn defines the function signature for setting additional form values.
type AuthRequestEditorFn func(*url.Values)

// WithAudience sets the audience parameter in the request.
func WithAudience(audience string) AuthRequestEditorFn {
	return func(values *url.Values) {
		if audience != "" {
			values.Add("audience", audience)
		}
	}
}

// RequestCode initiates the authorization flow by requesting a code from uri.
func RequestCode(c httpClient, uri string, clientID string, scopes []string,
	optionalRequestParams ...AuthRequestEditorFn) (*CodeResponse, error) {
	values := url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(scopes, " ")},
	}

	for _, fn := range optionalRequestParams {
		fn(&values)
	}

	resp, err := api.PostForm(c, uri, values)
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
		(resp.StatusCode == 400 && resp.Get("error") == "device_flow_disabled") ||
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
// Deprecated: use Wait.
func PollToken(c httpClient, pollURL string, clientID string, code *CodeResponse) (*api.AccessToken, error) {
	return Wait(context.Background(), c, pollURL, WaitOptions{
		ClientID:   clientID,
		DeviceCode: code,
	})
}

// WaitOptions specifies parameters to poll the server with until authentication completes.
type WaitOptions struct {
	// ClientID is the app client ID value.
	ClientID string
	// ClientSecret is the app client secret value. Optional: only pass if the server requires it.
	ClientSecret string
	// DeviceCode is the value obtained from RequestCode.
	DeviceCode *CodeResponse
	// GrantType overrides the default value specified by OAuth 2.0 Device Code. Optional.
	GrantType string

	newPoller                pollerFactory
	calculateTimeDriftRatioF func(tstart, tstop time.Time) float64
}

const (
	primaryIntervalMultiplier   = 1.2
	secondaryIntervalMultiplier = 1.4
)

// Wait polls the server at uri until authorization completes.
func Wait(ctx context.Context, c httpClient, uri string, opts WaitOptions) (*api.AccessToken, error) {
	// We know that in virtualised environments (e.g. WSL or VMs), the monotonic
	// clock, which is the source of time measurements in Go, can run faster than
	// real time. So, polling intervals should be adjusted to avoid falling into
	// an endless loop of "slow_down" errors. See the following issue in cli/cli
	// for more context (especially what's after this particular comment):
	//   - https://github.com/cli/cli/issues/9370#issuecomment-3759706125
	//
	// We've observed ~10% faster ticking, thanks to community, but a chat with
	// AI suggests it's typically between 5-15% on WSL, and can get up to 30% in
	// worst cases. There are issues reported on the WSL repo, but I couldn't
	// find any documented/conclusive data about this.
	//
	// See more:
	//   - https://github.com/microsoft/WSL/issues/12583
	//
	// What we're doing here is to play on the safe side by applying a default
	// 20% increase to the polling interval from the start. That is, instead of
	// 5s, we begin with 6s waits. This should resolve most cases without any
	// "slow_down" errors. However, upon receiving a "slow_down" from the OAuth
	// server, we will bump the safety margin to 40%. This will eliminate further
	// "slow_down"s in most cases.
	//
	// We also bail out if we receive two "slow_down" errors, as that's probably
	// an indication of severe clock drift. In such cases, we'll report the
	// measured clock drift to hint the user at the root cause.

	baseCheckInterval := time.Duration(opts.DeviceCode.Interval) * time.Second
	expiresIn := time.Duration(opts.DeviceCode.ExpiresIn) * time.Second
	grantType := opts.GrantType
	if opts.GrantType == "" {
		grantType = defaultGrantType
	}

	makePoller := opts.newPoller
	if makePoller == nil {
		makePoller = newPoller
	}
	_, poll := makePoller(ctx, baseCheckInterval, expiresIn)

	calculateTimeDriftRatioF := opts.calculateTimeDriftRatioF
	if calculateTimeDriftRatioF == nil {
		calculateTimeDriftRatioF = calculateTimeDriftRatio
	}

	multiplier := primaryIntervalMultiplier

	var slowDowns int
	for {
		tstart := time.Now()

		if err := poll.Wait(multiplier); err != nil {
			return nil, err
		}

		tstop := time.Now()

		values := url.Values{
			"client_id":   {opts.ClientID},
			"device_code": {opts.DeviceCode.DeviceCode},
			"grant_type":  {grantType},
		}

		// Google's "OAuth 2.0 for TV and Limited-Input Device Applications" requires `client_secret`.
		if opts.ClientSecret != "" {
			values.Add("client_secret", opts.ClientSecret)
		}

		// TODO: pass tctx down to the HTTP layer
		resp, err := api.PostForm(c, uri, values)
		if err != nil {
			return nil, err
		}

		var apiError *api.Error
		token, err := resp.AccessToken()
		if err == nil {
			return token, nil
		}

		if !errors.As(err, &apiError) {
			return nil, err
		}

		if apiError.Code == "authorization_pending" {
			// Keep polling
			continue
		}

		if apiError.Code == "slow_down" {
			slowDowns++

			// Since we have already added the secondary safety multiplier upon
			// receiving the first slow_down, getting a second one is a strong
			// indication of a huge clock drift (+40% faster mono). More polling
			// is just futile unless we apply some unreasonably large multiplier.
			// So, we bail out and inform the user about the potential cause.
			if slowDowns > 1 {
				driftRatio := calculateTimeDriftRatioF(tstart, tstop)
				return nil, fmt.Errorf("too many slow_down responses; detected clock drift of roughly %.0f%% between monotonic and wall clocks; please ensure your system clock is accurate", driftRatio*100)
			}

			// Based on the RFC spec, we must add 5 seconds to our current polling interval.
			// (See https://www.rfc-editor.org/rfc/rfc8628#section-3.5)
			newInterval := poll.GetInterval() + 5*time.Second

			// GitHub OAuth API returns the new interval in seconds in the response.
			// We should try to use that if provided. It's okay if we couldn't find
			// it as we have already increased our interval as of the RFC spec.
			if s := resp.Get("interval"); s != "" {
				if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 {
					newInterval = time.Duration(v) * time.Second
				}
			}

			poll.SetInterval(newInterval)
			multiplier = secondaryIntervalMultiplier
			continue
		}

		return nil, err
	}
}

func calculateTimeDriftRatio(tstart, tstop time.Time) float64 {
	elapsedWall := tstop.UnixNano() - tstart.UnixNano()
	elapsedMono := tstop.Sub(tstart).Nanoseconds()
	drift := elapsedMono - elapsedWall
	return float64(drift) / float64(elapsedWall)
}

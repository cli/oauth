package device_test

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/cli/oauth/api"
	"github.com/cli/oauth/device"
)

// This demonstrates how to perform OAuth Device Authorization Flow for GitHub.com.
// After RequestCode successfully completes, the client app should prompt the user to copy
// the UserCode and to open VerificationURI in their web browser to enter the code.
func ExampleRequestCode() {
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	scopes := []string{"repo", "read:org"}
	httpClient := http.DefaultClient

	code, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, scopes)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Copy code: %s\n", code.UserCode)
	fmt.Printf("then open: %s\n", code.VerificationURI)

	accessToken, err := device.Wait(context.TODO(), httpClient, "https://github.com/login/oauth/access_token", device.WaitOptions{
		ClientID:   clientID,
		DeviceCode: code,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Access token: %s\n", accessToken.Token)
}

// Request an expiring access token and a refresh token.
// Servers that do not support expiring tokens ignore the request and return a non-expiring token instead.
func ExampleWithRefreshToken() {
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	scopes := []string{"repo", "read:org"}
	httpClient := http.DefaultClient

	code, err := device.RequestCode(httpClient, "https://github.com/login/device/code",
		clientID, scopes, device.WithRefreshToken())
	if err != nil {
		panic(err)
	}

	fmt.Printf("Copy code: %s\n", code.UserCode)
	fmt.Printf("then open: %s\n", code.VerificationURI)

	accessToken, err := device.Wait(context.TODO(), httpClient, "https://github.com/login/oauth/access_token", device.WaitOptions{
		ClientID:   clientID,
		DeviceCode: code,
	})
	if err != nil {
		panic(err)
	}

	if accessToken.RefreshToken == "" {
		// The server does not support expiring tokens; the access token does not expire.
		fmt.Println("no refresh token issued")
		return
	}

	// Store the refresh token and both expiration times alongside the access token. Refreshing a
	// token invalidates the previous access token and refresh token, so the replacements returned by
	// api.Refresh must be persisted. The client secret is not needed for device flow tokens.
	newToken, err := api.Refresh(httpClient, "https://github.com/login/oauth/access_token", api.RefreshOptions{
		ClientID:     clientID,
		RefreshToken: accessToken.RefreshToken,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Access token expires in %d seconds\n", newToken.ExpiresIn)
}

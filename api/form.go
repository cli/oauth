package api

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type httpClient interface {
	PostForm(string, url.Values) (*http.Response, error)
}

// FormResponse is the parsed "www-form-urlencoded" response from the server.
type FormResponse struct {
	StatusCode int

	requestURI string
	values     url.Values
}

// Get the response value named k.
func (f FormResponse) Get(k string) string {
	return f.values.Get(k)
}

// Err returns an Error object extracted from the response.
func (f FormResponse) Err() error {
	return &Error{
		RequestURI:   f.requestURI,
		ResponseCode: f.StatusCode,
		Code:         f.Get("error"),
		message:      f.Get("error_description"),
	}
}

// Error is the result of an unexpected HTTP response from the server.
type Error struct {
	Code         string
	ResponseCode int
	RequestURI   string

	message string
}

func (e Error) Error() string {
	if e.message != "" {
		return fmt.Sprintf("%s (%s)", e.message, e.Code)
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("HTTP %d", e.ResponseCode)
}

// PostForm makes an POST request by serializing input parameters as a form and parsing the response
// of the same type.
func PostForm(c httpClient, u string, params url.Values) (*FormResponse, error) {
	resp, err := c.PostForm(u, params)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	r := &FormResponse{
		StatusCode: resp.StatusCode,
		requestURI: u,
	}

	if contentType(resp.Header.Get("Content-Type")) == formType {
		var bb []byte
		bb, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return r, err
		}

		r.values, err = url.ParseQuery(string(bb))
		if err != nil {
			return r, err
		}
	} else {
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return r, err
		}
	}

	return r, nil
}

const formType = "application/x-www-form-urlencoded"

func contentType(t string) string {
	if i := strings.IndexRune(t, ';'); i >= 0 {
		return t[0:i]
	}
	return t
}

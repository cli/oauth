package api

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
)

type httpClient interface {
	PostForm(string, url.Values) (*http.Response, error)
}

// FormResponse is the parsed "www-form-urlencoded" response from the server.
type FormResponse struct {
	StatusCode int

	requestURI string
	values     map[string]string
}

// Get the response value named k.
func (f FormResponse) Get(k string) string {
	v, ok := f.values[k]
	if !ok {
		return ""
	}
	return v
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
		values:     make(map[string]string),
	}

	// since mine.ParseMediaType always returns the media type regardless of error, and
	// that we don't use the params - we can just ignore any errors.
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))

	if mediaType == formType {
		var bb []byte
		bb, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return r, err
		}

		values, err := url.ParseQuery(string(bb))
		if err != nil {
			return r, err
		}

		readFormValues(r, values)
	} else if mediaType == jsonType {
		var bb []byte
		bb, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return r, err
		}

		var values map[string]interface{}
		err = json.Unmarshal(bb, &values)
		if err != nil {
			return r, err
		}

		readJSONValues(r, values)
	} else {
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return r, err
		}
	}

	return r, nil
}

const formType = "application/x-www-form-urlencoded"
const jsonType = "application/json"

// readFormValues feeds information from a url.Values into a FormResponse's values
// map.
func readFormValues(r *FormResponse, values url.Values) {
	for key, value := range values {
		if len(value) < 1 {
			continue
		}

		r.values[key] = value[0]
	}
}

// readJsonValues feeds information from an un-marshaled JSON response into a
// FormResponse's values map.
func readJSONValues(r *FormResponse, values map[string]interface{}) {
	for key, value := range values {
		// Go's JSON library uses float64 and int64 for numbers.
		if v, ok := value.(string); ok {
			r.values[key] = v
		} else if v, ok := value.(int64); ok {
			r.values[key] = strconv.FormatInt(v, 10)
		} else if v, ok := value.(float64); ok {
			r.values[key] = strconv.FormatFloat(v, 'f', -1, 64)
		}
	}
}

package webapp

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

// CodeResponse represents the code received by the local server's callback handler.
type CodeResponse struct {
	Code  string
	State string
}

// bindLocalServer initializes a LocalServer that will listen on a randomly available TCP port.
func bindLocalServer() (*localServer, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	return &localServer{
		listener:   listener,
		resultChan: make(chan CodeResponse, 1),
	}, nil
}

type localServer struct {
	CallbackPath     string
	WriteSuccessHTML func(w io.Writer)

	resultChan chan (CodeResponse)
	listener   net.Listener
}

func (s *localServer) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *localServer) Close() error {
	return s.listener.Close()
}

func (s *localServer) Serve() error {
	return http.Serve(s.listener, s)
}

func (s *localServer) WaitForCode() (CodeResponse, error) {
	return <-s.resultChan, nil
}

// ServeHTTP implements http.Handler.
func (s *localServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.CallbackPath != "" && r.URL.Path != s.CallbackPath {
		w.WriteHeader(404)
		return
	}
	defer func() {
		_ = s.Close()
	}()

	params := r.URL.Query()
	s.resultChan <- CodeResponse{
		Code:  params.Get("code"),
		State: params.Get("state"),
	}

	w.Header().Add("content-type", "text/html")
	if s.WriteSuccessHTML != nil {
		s.WriteSuccessHTML(w)
	} else {
		defaultSuccessHTML(w)
	}
}

func defaultSuccessHTML(w io.Writer) {
	fmt.Fprintf(w, "<p>You may now close this page and return to the client app.</p>")
}

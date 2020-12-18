package webapp

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"testing"
)

type fakeListener struct {
	closed bool
	addr   *net.TCPAddr
}

func (l *fakeListener) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (l *fakeListener) Close() error {
	l.closed = true
	return nil
}
func (l *fakeListener) Addr() net.Addr {
	return l.addr
}

type responseWriter struct {
	header  http.Header
	written bytes.Buffer
	status  int
}

func (w *responseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.written.Write(b)
}
func (w *responseWriter) WriteHeader(s int) {
	w.status = s
}

func Test_localServer_ServeHTTP(t *testing.T) {
	listener := &fakeListener{}
	s := &localServer{
		CallbackPath: "/hello",
		resultChan:   make(chan CodeResponse, 1),
		listener:     listener,
	}

	w1 := &responseWriter{}
	w2 := &responseWriter{}

	serveChan := make(chan struct{})
	go func() {
		req1, _ := http.NewRequest("GET", "http://127.0.0.1:12345/favicon.ico", nil)
		s.ServeHTTP(w1, req1)
		req2, _ := http.NewRequest("GET", "http://127.0.0.1:12345/hello?code=ABC-123&state=xy%2Fz", nil)
		s.ServeHTTP(w2, req2)
		serveChan <- struct{}{}
	}()

	res := <-s.resultChan
	if res.Code != "ABC-123" {
		t.Errorf("got code %q", res.Code)
	}
	if res.State != "xy/z" {
		t.Errorf("got state %q", res.State)
	}

	<-serveChan
	if w1.status != 404 {
		t.Errorf("status = %d", w2.status)
	}

	if w2.status != 200 {
		t.Errorf("status = %d", w2.status)
	}
	if w2.written.String() != "<p>You may now close this page and return to the client app.</p>" {
		t.Errorf("written: %q", w2.written.String())
	}
	if w2.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Content-Type: %v", w2.Header().Get("Content-Type"))
	}
	if !listener.closed {
		t.Error("expected listener to be closed")
	}
}

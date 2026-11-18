package webserver

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSplitListenerRedirectsHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sl := newSplitListener(l)
	defer sl.close()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("secure"))
		}))
	ts.Listener = sl.tls
	ts.StartTLS()
	defer ts.Close()
	go newRedirectServer().Serve(sl.plain)

	addr := l.Addr().String()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + addr + "/group/main/?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", resp.StatusCode)
	}
	want := "https://" + addr + "/group/main/?x=1"
	if got := resp.Header.Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	tc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err = tc.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("https status = %d, want 200", resp.StatusCode)
	}
}

func TestRedirectPreservesMethodForPost(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://example.com:8443/api", nil)
	w := httptest.NewRecorder()
	httpsRedirectHandler(w, r)
	if w.Code != http.StatusPermanentRedirect {
		t.Errorf("status = %d, want 308", w.Code)
	}
	if got := w.Header().Get("Location"); got != "https://example.com:8443/api" {
		t.Errorf("Location = %q", got)
	}
}

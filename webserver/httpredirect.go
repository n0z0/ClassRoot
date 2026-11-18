package webserver

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// tlsRecordHandshake is the first byte of every TLS ClientHello.
const tlsRecordHandshake = 0x16

// sniffTimeout bounds how long we wait for a client's first byte.
const sniffTimeout = 10 * time.Second

// splitListener accepts connections on a single port and dispatches
// them to a TLS listener or a plain-HTTP listener depending on the
// first byte sent by the client.
type splitListener struct {
	parent net.Listener
	tls    *chanListener
	plain  *chanListener
	done   chan struct{}
	once   sync.Once
}

func newSplitListener(l net.Listener) *splitListener {
	sl := &splitListener{
		parent: l,
		done:   make(chan struct{}),
	}
	sl.tls = &chanListener{sl: sl, ch: make(chan net.Conn)}
	sl.plain = &chanListener{sl: sl, ch: make(chan net.Conn)}
	go sl.acceptLoop()
	return sl
}

func (sl *splitListener) close() error {
	var err error
	sl.once.Do(func() {
		close(sl.done)
		err = sl.parent.Close()
	})
	return err
}

func (sl *splitListener) acceptLoop() {
	for {
		c, err := sl.parent.Accept()
		if err != nil {
			select {
			case <-sl.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				sl.close()
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go sl.dispatch(c)
	}
}

func (sl *splitListener) dispatch(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(sniffTimeout))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}

	target := sl.plain
	if b[0] == tlsRecordHandshake {
		target = sl.tls
	}
	select {
	case target.ch <- &peekedConn{Conn: c, r: br}:
	case <-sl.done:
		c.Close()
	}
}

// chanListener is a virtual net.Listener fed by a splitListener.
type chanListener struct {
	sl *splitListener
	ch chan net.Conn
}

func (cl *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-cl.ch:
		return c, nil
	case <-cl.sl.done:
		return nil, net.ErrClosed
	}
}

func (cl *chanListener) Close() error   { return cl.sl.close() }
func (cl *chanListener) Addr() net.Addr { return cl.sl.parent.Addr() }

// peekedConn replays bytes already buffered while sniffing.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (pc *peekedConn) Read(p []byte) (int, error) { return pc.r.Read(p) }

// httpsRedirectHandler redirects every plain-HTTP request to the same
// host, port and path over HTTPS.
func httpsRedirectHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			host = la.String()
		}
	}
	code := http.StatusMovedPermanently
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		code = http.StatusPermanentRedirect
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), code)
}

func newRedirectServer() *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(httpsRedirectHandler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

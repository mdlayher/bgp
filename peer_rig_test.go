package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

// A peerRig runs one Peer under test: its handlers record establishment and
// close events, and Run's lifecycle is managed for the test.
type peerRig struct {
	tb testing.TB
	p  *Peer

	// Exactly one transport is set: l accepts the Peer's real TCP dials,
	// and dials carries the scripted side of each in-memory one.
	l     net.Listener
	dials chan *script

	cancel context.CancelFunc

	// cancelCause ends Run with a cancellation cause: the teardown-reason
	// seam under test in the shutdown cause tests.
	cancelCause context.CancelCauseFunc

	estC   chan Session
	closeC chan Close
	events chan string
}

// testLogger returns the logger for a Peer under test: it writes to the test
// log when the -test.v flag is set, and discards everything otherwise. Tests
// which assert on log output configure their own Logger instead.
func testLogger(tb testing.TB) *slog.Logger {
	if !testing.Verbose() {
		return slog.New(slog.DiscardHandler)
	}

	return slog.New(slog.NewTextHandler(tb.Output(), &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// The test log carries its own ordering; slog's timestamps are noise.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}

			return a
		},
	}))
}

// testPeer builds a Peer for the remote speaker at addr from cfg with
// recording handlers and runs it in the background. Run must exit via
// cancellation by the end of the test.
func testPeer(tb testing.TB, addr netip.Addr, cfg PeerConfig) *peerRig {
	tb.Helper()
	return buildPeer(tb, addr, cfg).start()
}

// buildPeer is testPeer without the start: a rig whose Peer a test may
// adjust before any goroutine runs it.
func buildPeer(tb testing.TB, addr netip.Addr, cfg PeerConfig) *peerRig {
	tb.Helper()

	r := &peerRig{
		tb:     tb,
		estC:   make(chan Session, 4),
		closeC: make(chan Close, 4),
		events: make(chan string, 16),
	}

	// The rig's recorders run first, then any handler the test configured.
	userEst, userClose := cfg.OnEstablished, cfg.OnClose
	cfg.OnEstablished = func(ctx context.Context, p *Peer, s Session) error {
		r.events <- "established"
		r.estC <- s
		if userEst != nil {
			return userEst(ctx, p, s)
		}

		return nil
	}

	cfg.OnClose = func(p *Peer, c Close) {
		r.events <- "close"
		r.closeC <- c
		if userClose != nil {
			userClose(p, c)
		}
	}

	if cfg.Logger == nil {
		cfg.Logger = testLogger(tb)
	}

	r.p = must(NewPeer(addr, cfg))
	return r
}

// start runs the rig's Peer in the background. Run must exit via
// cancellation by the end of the test.
func (r *peerRig) start() *peerRig {
	tb, p := r.tb, r.p
	tb.Helper()

	ctx, cancel := context.WithCancelCause(context.Background())
	r.cancelCause = cancel
	r.cancel = func() { cancel(nil) }
	runC := make(chan error, 1)
	go func() { runC <- p.Run(ctx) }()

	tb.Cleanup(func() {
		cancel(nil)
		if err := recv(tb, runC, "Run to return"); !errors.Is(err, context.Canceled) {
			tb.Errorf("unexpected Run error: %v", err)
		}
	})

	// Run starts concurrently, and a DeliverConn which outraces it is
	// refused; wait until the Peer is accepting so tests need not tolerate
	// the startup window.
	waitRunning(tb, p)
	return r
}

// newPipeRig starts a Peer under test over in-memory connections, for use
// inside a synctest bubble: the Peer dials memPipes, acceptScript returns
// the scripted side of each, and deliver hands in an accepted one. Fake time
// is the bubble's, so a test sleeps onto the FSM's timers; retry jitter is
// fixed at one, so a connect retry tick lands exactly connectRetryTime after
// its arm. The default identity is ASN 64496, identifier 192.0.2.1.
//
// A DialFunc in cfg runs first on each dial, and a (nil, nil) result falls
// through to the rig's pipe dial: a test refuses or stalls some dials and
// lets the rest connect.
func newPipeRig(tb testing.TB, cfg PeerConfig) *peerRig {
	tb.Helper()

	dials := make(chan *script, 4)
	user := cfg.DialFunc
	cfg.DialFunc = func(ctx context.Context) (*Conn, error) {
		if user != nil {
			if c, err := user(ctx); c != nil || err != nil {
				return c, err
			}
		}

		local, remote := memPipe()
		dials <- newScript(tb, remote)
		return NewConn(local), nil
	}

	if cfg.LocalASN == 0 {
		cfg.LocalASN = 64496
	}

	if cfg.LocalID == 0 {
		cfg.LocalID = MustParseIdentifier("192.0.2.1")
	}

	// A DialFunc transport addresses its peer itself: raddr stays zero, so
	// a delivered memConn — which carries no address — passes unchecked.
	r := buildPeer(tb, netip.Addr{}, cfg)
	r.p.fsm.jitter = func() float64 { return 1 }
	r.dials = dials
	return r.start()
}

// waitRunning blocks until p's Run has taken ownership.
func waitRunning(tb testing.TB, p *Peer) {
	tb.Helper()

	// The lock covers the field load only, because Run replaces the field
	// when it stops. The copied channel value still refers to the same
	// underlying channel, so Run's close is visible through it.
	p.mu.Lock()
	runningC := p.runningC
	p.mu.Unlock()

	select {
	case <-runningC:
	case <-time.After(peerTimeout):
		tb.Fatal("timed out waiting for Run to start")
	}
}

// newTCPRig starts an active Peer under test which dials a scripted loopback
// listener, in real time: the rig for behavior only a kernel socket has,
// such as buffers filling and resets. The default identity is ASN 64496,
// identifier 192.0.2.1; acceptScript hands out the scripted side of each
// dialed connection.
func newTCPRig(tb testing.TB, cfg PeerConfig) *peerRig {
	tb.Helper()

	l, err := nettest.NewLocalListener("tcp")
	if err != nil {
		tb.Fatalf("failed to create listener: %v", err)
	}

	tb.Cleanup(func() { _ = l.Close() })

	if cfg.LocalASN == 0 {
		cfg.LocalASN = 64496
	}

	if cfg.LocalID == 0 {
		cfg.LocalID = MustParseIdentifier("192.0.2.1")
	}

	ap := l.Addr().(*net.TCPAddr).AddrPort()
	cfg.Dialer.Port = ap.Port()
	r := testPeer(tb, ap.Addr(), cfg)
	r.l = l
	return r
}

// acceptScript waits for the Peer's next dial and returns its scripted side.
func (r *peerRig) acceptScript() *script {
	r.tb.Helper()

	if r.l == nil {
		return recv(r.tb, r.dials, "the peer to dial")
	}

	type accepted struct {
		c   net.Conn
		err error
	}

	acceptC := make(chan accepted, 1)
	go func() {
		c, err := r.l.Accept()
		acceptC <- accepted{c: c, err: err}
	}()

	a := recv(r.tb, acceptC, "the peer to dial")
	if a.err != nil {
		r.tb.Fatalf("failed to accept: %v", a.err)
	}

	return newScript(r.tb, a.c)
}

// deliver creates a loopback connection pair, hands one side to the Peer as
// an inbound connection, and returns the scripted other side.
func (r *peerRig) deliver() *script {
	r.tb.Helper()

	if r.l == nil {
		local, remote := memPipe()
		if err := r.p.DeliverConn(NewConn(local)); err != nil {
			r.tb.Fatalf("failed to deliver connection: %v", err)
		}

		return newScript(r.tb, remote)
	}

	client, server := testConns(r.tb, "tcp4")
	if err := r.p.DeliverConn(client); err != nil {
		r.tb.Fatalf("failed to deliver connection: %v", err)
	}

	return &script{tb: r.tb, nc: server.rawConn(), c: server}
}

// A script is the scripted peer of the FSM plan: the raw side of a
// connection to a Peer under test, speaking both well-formed and hand-built
// messages to reach paths a correct implementation never produces.
type script struct {
	tb testing.TB
	nc net.Conn
	c  *Conn
}

func newScript(tb testing.TB, nc net.Conn) *script {
	tb.Helper()
	tb.Cleanup(func() { _ = nc.Close() })
	return &script{tb: tb, nc: nc, c: NewConn(nc)}
}

// read returns the next message from the Peer.
func (s *script) read() Message {
	s.tb.Helper()

	_ = s.c.SetReadDeadline(time.Now().Add(peerTimeout))
	m, err := s.c.ReadMessage()
	if err != nil {
		s.tb.Fatalf("failed to read message: %v", err)
	}

	return m
}

// write sends a well-formed message to the Peer.
func (s *script) write(m Message) {
	s.tb.Helper()

	_ = s.c.SetWriteDeadline(time.Now().Add(peerTimeout))
	if err := s.c.WriteMessage(m); err != nil {
		s.tb.Fatalf("failed to write message: %v", err)
	}
}

// writeRaw sends hand-built wire bytes to the Peer.
func (s *script) writeRaw(b []byte) {
	s.tb.Helper()

	_ = s.nc.SetWriteDeadline(time.Now().Add(peerTimeout))
	if _, err := s.nc.Write(b); err != nil {
		s.tb.Fatalf("failed to write raw message: %v", err)
	}
}

// expectOpen returns the Peer's OPEN, failing on any other message.
func (s *script) expectOpen() *Open {
	s.tb.Helper()

	m := s.read()
	o, ok := m.(*Open)
	if !ok {
		s.tb.Fatalf("expected an OPEN, but got: %T", m)
	}

	return o
}

// expectKeepalive consumes a KEEPALIVE, failing on any other message.
func (s *script) expectKeepalive() {
	s.tb.Helper()

	if m := s.read(); !isKeepalive(m) {
		s.tb.Fatalf("expected a KEEPALIVE, but got: %T", m)
	}
}

func isKeepalive(m Message) bool {
	_, ok := m.(*Keepalive)
	return ok
}

// nextKeepalive reads until a KEEPALIVE arrives.
func (s *script) nextKeepalive() {
	s.tb.Helper()

	for {
		if _, ok := s.read().(*Keepalive); ok {
			return
		}
	}
}

// expectNotification consumes a NOTIFICATION and compares it against want.
func (s *script) expectNotification(want *Notification) {
	s.tb.Helper()

	m := s.read()
	n, ok := m.(*Notification)
	if !ok {
		s.tb.Fatalf("expected a NOTIFICATION, but got: %T", m)
	}

	if d := diff(s.tb, want, n); d != "" {
		s.tb.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
	}
}

// nextNotification reads until a NOTIFICATION arrives, skipping keepalives
// the FSM may emit first, and returns an owned copy.
func (s *script) nextNotification() *Notification {
	s.tb.Helper()

	for {
		if n, ok := s.read().(*Notification); ok {
			return detachMessage(s.tb, n).(*Notification)
		}
	}
}

// expectClosed asserts that the Peer closed the connection.
func (s *script) expectClosed() {
	s.tb.Helper()

	_ = s.c.SetReadDeadline(time.Now().Add(peerTimeout))
	m, err := s.c.ReadMessage()
	if err == nil {
		s.tb.Fatalf("expected the connection to close, but read: %T", m)
	}

	if nerr, ok := errors.AsType[net.Error](err); ok && nerr.Timeout() {
		s.tb.Fatalf("timed out waiting for the connection to close: %v", err)
	}
}

// establish drives a complete OPEN exchange from the scripted side, with
// open as the scripted peer's own OPEN.
func (s *script) establish(open *Open) {
	s.tb.Helper()

	s.expectOpen()
	s.write(open)
	s.expectKeepalive()
	s.write(&Keepalive{})
}

// scriptOpen is the scripted peer's default well-formed OPEN: ASN 64497,
// identifier 192.0.2.2, and a 30s hold time so tests sleep one short hold
// interval.
func scriptOpen() *Open {
	return &Open{
		ASN:      64497,
		HoldTime: 30 * time.Second,
		ID:       MustParseIdentifier("192.0.2.2"),
	}
}

// rawMessage hand-builds a wire message this package refuses to marshal: the
// scripted peer's tool for reaching parse error paths.
func rawMessage(typ MessageType, body []byte) []byte {
	b := make([]byte, 0, headerLen+len(body))
	for range markerLen {
		b = append(b, 0xff)
	}

	b = binary.BigEndian.AppendUint16(b, uint16(headerLen+len(body)))
	b = append(b, byte(typ))
	return append(b, body...)
}

// rawOpenBody hand-builds an OPEN body with no optional parameters.
func rawOpenBody(version byte, asn uint16, hold uint16, id uint32) []byte {
	b := []byte{version}
	b = binary.BigEndian.AppendUint16(b, asn)
	b = binary.BigEndian.AppendUint16(b, hold)
	b = binary.BigEndian.AppendUint32(b, id)
	return append(b, 0)
}

// mustMessage marshals m, failing the test on error.
func mustMessage(tb testing.TB, m Message) []byte {
	tb.Helper()

	b, err := m.AppendBinary(nil)
	if err != nil {
		tb.Fatalf("failed to marshal message: %v", err)
	}

	return b
}

// recv receives one value, failing the test if what does not happen within
// the timeout.
func recv[T any](tb testing.TB, ch <-chan T, what string) T {
	tb.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(peerTimeout):
		tb.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

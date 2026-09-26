package bgp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

// dialAddrPort dials ap with d: the Dialer's Port is ap's, so a test reaches
// an ephemeral listener port while Dial itself takes only an address.
func dialAddrPort(ctx context.Context, d *Dialer, ap netip.AddrPort) (*Conn, error) {
	dd := *d
	dd.Port = ap.Port()
	return dd.Dial(ctx, ap.Addr())
}

// replayConn is a net.Conn which serves an in-memory byte stream on repeat,
// so a benchmark measures Conn framing rather than kernel behavior.
type replayConn struct {
	b   []byte
	off int
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.off == len(c.b) {
		c.off = 0
	}

	n := copy(p, c.b[c.off:])
	c.off += n
	return n, nil
}

func (c *replayConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *replayConn) Close() error { return nil }

func (c *replayConn) LocalAddr() net.Addr { return nil }

func (c *replayConn) RemoteAddr() net.Addr { return nil }

func (c *replayConn) SetDeadline(time.Time) error { return nil }

func (c *replayConn) SetReadDeadline(time.Time) error { return nil }

func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

// listenerAddrPort returns the address a Listener is bound to.
func listenerAddrPort(tb testing.TB, l *Listener) netip.AddrPort {
	tb.Helper()

	a, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		tb.Fatalf("unexpected listener address type: %T", l.Addr())
	}

	return a.AddrPort()
}

// testConns creates a pair of Conns joined by a real loopback TCP connection
// on the given network, and registers cleanup for both. Real TCP is used
// rather than net.Pipe so that kernel buffering, partial reads, and deadlines
// behave as they do in production.
func testConns(tb testing.TB, network string) (client, server *Conn) {
	tb.Helper()

	l, err := nettest.NewLocalListener(network)
	if err != nil {
		tb.Fatalf("failed to create listener: %v", err)
	}

	defer func() { _ = l.Close() }()

	cc, err := net.Dial(network, l.Addr().String())
	if err != nil {
		tb.Fatalf("failed to dial: %v", err)
	}

	// The kernel completes the handshake into the listen backlog, so the
	// dial returns before Accept is called.
	sc, err := l.Accept()
	if err != nil {
		_ = cc.Close()
		tb.Fatalf("failed to accept: %v", err)
	}

	client, server = NewConn(cc), NewConn(sc)
	tb.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	return client, server
}

// rawConn exposes a Conn's underlying connection, so that tests may place
// arbitrary bytes on the wire.
func (c *Conn) rawConn() net.Conn { return c.c }

// detachMessage copies every byte slice reachable from m, producing a Message
// which outlives the next Conn.ReadMessage call.
func detachMessage(tb testing.TB, m Message) Message {
	tb.Helper()

	b, err := m.AppendBinary(nil)
	if err != nil {
		tb.Fatalf("failed to marshal message: %v", err)
	}

	r, err := ParseMessage(b)
	if err != nil {
		tb.Fatalf("failed to parse message: %v", err)
	}

	return r.Message
}

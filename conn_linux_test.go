//go:build linux

package bgp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

// blockedTimeout bounds a connection attempt which the kernel is expected to
// drop silently: a bad TCP-MD5 digest or a TTL below the GTSM minimum
// produces no reset, only retransmissions.
const blockedTimeout = 2 * time.Second

func TestListenerSetMD5(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery"

	for _, loopback := range localAddrs(t) {
		t.Run(loopback.String(), func(t *testing.T) {
			t.Parallel()

			t.Run("matching keys", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{}, loopback)
				if err := l.SetMD5(loopback, password); err != nil {
					skipUnsupported(t, err)
					t.Fatalf("failed to set MD5 key: %v", err)
				}

				testSession(t, l, &Dialer{}, password, blockedTimeout)
			})

			t.Run("mismatched keys", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{}, loopback)
				if err := l.SetMD5(loopback, password); err != nil {
					skipUnsupported(t, err)
					t.Fatalf("failed to set MD5 key: %v", err)
				}

				// The kernel drops a SYN whose digest does not verify, so the
				// only observable outcome is a connection attempt which never
				// completes.
				var d Dialer
				testBlocked(t, func(ctx context.Context) error {
					_, err := dialListener(t, ctx, &d, l, "wrong")
					return err
				})
			})

			t.Run("no key on dialer", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{}, loopback)
				if err := l.SetMD5(loopback, password); err != nil {
					skipUnsupported(t, err)
					t.Fatalf("failed to set MD5 key: %v", err)
				}

				testBlocked(t, func(ctx context.Context) error {
					_, err := dialListener(t, ctx, &Dialer{}, l, "")
					return err
				})
			})

			t.Run("removed key", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{}, loopback)
				if err := l.SetMD5(loopback, password); err != nil {
					skipUnsupported(t, err)
					t.Fatalf("failed to set MD5 key: %v", err)
				}

				// Removing the key restores a plain TCP listener.
				if err := l.RemoveMD5(loopback); err != nil {
					t.Fatalf("failed to remove MD5 key: %v", err)
				}

				testSession(t, l, &Dialer{}, "", blockedTimeout)
			})
		})
	}
}

func TestListenerSetMD5LinkLocal(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery"

	// A link-local peer without a zone is ambiguous, and a key installed
	// anyway would silently fail to match: it must be rejected loudly. So
	// must a zone which names no interface.
	tests := []struct {
		name string
		peer netip.Addr
	}{
		{
			name: "missing zone",
			peer: netip.MustParseAddr("fe80::1"),
		},
		{
			name: "bad zone",
			peer: netip.MustParseAddr("fe80::1").WithZone("nonexistent0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l := testListener(t, ListenConfig{}, netip.MustParseAddr("127.0.0.1"))
			if err := l.SetMD5(tt.peer, password); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestListenerSetMD5LinkLocalSession(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery"

	// Self-peering over a real interface's link-local address exercises
	// the zoned peer path (the zone resolved into the sockaddr's scope):
	// the BGP unnumbered pattern.
	lla := linkLocalAddr(t)

	l := testListener(t, ListenConfig{}, lla)
	if err := l.SetMD5(lla, password); err != nil {
		skipUnsupported(t, err)
		t.Fatalf("failed to set MD5 key: %v", err)
	}

	testSession(t, l, &Dialer{}, password, blockedTimeout)
}

func TestListenConfigGTSM(t *testing.T) {
	t.Parallel()

	for _, loopback := range localAddrs(t) {
		t.Run(loopback.String(), func(t *testing.T) {
			t.Parallel()

			t.Run("both ends", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{GTSM: true}, loopback)
				testSession(t, l, &Dialer{GTSM: true}, "", blockedTimeout)
			})

			t.Run("dialer without GTSM", func(t *testing.T) {
				t.Parallel()

				// The listener requires a received TTL of 255, and a dialer
				// which does not set one sends the kernel default instead.
				l := testListener(t, ListenConfig{GTSM: true}, loopback)
				testBlocked(t, func(ctx context.Context) error {
					c, err := (&net.Dialer{}).DialContext(
						ctx, tcpNetwork(loopback), l.Addr().String(),
					)
					if err != nil {
						return err
					}

					return c.Close()
				})
			})
		})
	}
}

func TestListenConfigDSCP(t *testing.T) {
	t.Parallel()

	for _, loopback := range localAddrs(t) {
		t.Run(loopback.String(), func(t *testing.T) {
			t.Parallel()

			t.Run("both ends", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{DSCP: DSCPCS6}, loopback)
				client, server := testConnPair(t, l, &Dialer{DSCP: DSCPCS6})
				wantDSCP(t, client, DSCPCS6)
				wantDSCP(t, server, DSCPCS6)
			})

			t.Run("dialer unmarked", func(t *testing.T) {
				t.Parallel()

				// The marking is a per-socket property, not a negotiated
				// one: the accepted connection inherits the listener's
				// and the dialed one stays at the kernel default.
				l := testListener(t, ListenConfig{DSCP: DSCPCS6}, loopback)
				client, server := testConnPair(t, l, &Dialer{})
				wantDSCP(t, client, 0)
				wantDSCP(t, server, DSCPCS6)
			})
		})
	}
}

func TestListenConfigUserTimeout(t *testing.T) {
	t.Parallel()

	const timeout = 90 * time.Second

	for _, loopback := range localAddrs(t) {
		t.Run(loopback.String(), func(t *testing.T) {
			t.Parallel()

			t.Run("both ends", func(t *testing.T) {
				t.Parallel()

				l := testListener(t, ListenConfig{UserTimeout: timeout}, loopback)
				client, server := testConnPair(t, l, &Dialer{UserTimeout: timeout})
				wantUserTimeout(t, client, timeout)
				wantUserTimeout(t, server, timeout)
			})

			t.Run("dialer unset", func(t *testing.T) {
				t.Parallel()

				// The accepted connection inherits the listener's bound and
				// the dialed one stays at the kernel default of none.
				l := testListener(t, ListenConfig{UserTimeout: timeout}, loopback)
				client, server := testConnPair(t, l, &Dialer{})
				wantUserTimeout(t, client, 0)
				wantUserTimeout(t, server, timeout)
			})

			t.Run("rounded up", func(t *testing.T) {
				t.Parallel()

				// A bound below the kernel's millisecond unit must not
				// round to zero, which would mean no bound at all.
				l := testListener(t, ListenConfig{}, loopback)
				client, _ := testConnPair(t, l, &Dialer{UserTimeout: time.Microsecond})
				wantUserTimeout(t, client, time.Millisecond)
			})
		})
	}
}

func TestListenConfigBuffers(t *testing.T) {
	t.Parallel()

	const send, recv = 64 * 1024, 96 * 1024

	for _, loopback := range localAddrs(t) {
		t.Run(loopback.String(), func(t *testing.T) {
			t.Parallel()

			t.Run("both ends", func(t *testing.T) {
				t.Parallel()

				o := TCPOptions{SendBuffer: send, RecvBuffer: recv}
				l := testListener(t, ListenConfig{TCPOptions: o}, loopback)
				client, server := testConnPair(t, l, &Dialer{TCPOptions: o})
				for _, c := range []*Conn{client, server} {
					wantBuffer(t, c, unix.SO_SNDBUF, send)
					wantBuffer(t, c, unix.SO_RCVBUF, recv)
				}
			})

			t.Run("dialer unset", func(t *testing.T) {
				t.Parallel()

				// The accepted connection inherits the listener's sizes.
				// The dialed one keeps whatever the kernel chose, which
				// this test cannot know, so only the server is checked.
				o := TCPOptions{SendBuffer: send, RecvBuffer: recv}
				l := testListener(t, ListenConfig{TCPOptions: o}, loopback)
				_, server := testConnPair(t, l, &Dialer{})
				wantBuffer(t, server, unix.SO_SNDBUF, send)
				wantBuffer(t, server, unix.SO_RCVBUF, recv)
			})
		})
	}
}

func TestListenConfigKeepAlive(t *testing.T) {
	t.Parallel()

	custom := &net.KeepAliveConfig{
		Enable:   true,
		Idle:     42 * time.Second,
		Interval: 7 * time.Second,
		Count:    3,
	}

	for _, loopback := range localAddrs(t) {
		t.Run(loopback.String(), func(t *testing.T) {
			t.Parallel()

			t.Run("default", func(t *testing.T) {
				t.Parallel()

				// The net package enables probes on its own; the exact
				// timings are its business.
				l := testListener(t, ListenConfig{}, loopback)
				client, server := testConnPair(t, l, &Dialer{})
				for _, c := range []*Conn{client, server} {
					wantKeepAlive(t, c, nil)
				}
			})

			t.Run("custom", func(t *testing.T) {
				t.Parallel()

				// Unlike every other option, this one does not inherit
				// from the listening socket: the net package overwrites
				// it on accept, so it must reach the accepted connection
				// through the net package's own configuration.
				o := TCPOptions{KeepAlive: custom}
				l := testListener(t, ListenConfig{TCPOptions: o}, loopback)
				client, server := testConnPair(t, l, &Dialer{TCPOptions: o})
				for _, c := range []*Conn{client, server} {
					wantKeepAlive(t, c, custom)
				}
			})

			t.Run("disabled", func(t *testing.T) {
				t.Parallel()

				o := TCPOptions{KeepAlive: &net.KeepAliveConfig{}}
				l := testListener(t, ListenConfig{TCPOptions: o}, loopback)
				client, server := testConnPair(t, l, &Dialer{TCPOptions: o})
				for _, c := range []*Conn{client, server} {
					wantKeepAlive(t, c, o.KeepAlive)
				}
			})
		})
	}
}

// wantKeepAlive reads the keepalive options back from the socket underlying
// c and asserts that they reflect want: enabled with the net package's
// defaults when nil, enabled with want's timings when Enable is set, and
// disabled otherwise.
func wantKeepAlive(tb testing.TB, c *Conn, want *net.KeepAliveConfig) {
	tb.Helper()

	enabled := sockoptInt(tb, c, unix.SOL_SOCKET, unix.SO_KEEPALIVE) != 0
	if wantEnabled := want == nil || want.Enable; enabled != wantEnabled {
		tb.Fatalf("unexpected SO_KEEPALIVE on %s: got %tb, want %tb", c.LocalAddr(), enabled, wantEnabled)
	}

	if want == nil || !want.Enable {
		return
	}

	got := net.KeepAliveConfig{
		Enable:   enabled,
		Idle:     time.Duration(sockoptInt(tb, c, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)) * time.Second,
		Interval: time.Duration(sockoptInt(tb, c, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)) * time.Second,
		Count:    sockoptInt(tb, c, unix.IPPROTO_TCP, unix.TCP_KEEPCNT),
	}

	if got != *want {
		tb.Fatalf("unexpected keepalive on %s:\n got: %+v\nwant: %+v", c.LocalAddr(), got, *want)
	}
}

// wantBuffer reads the SO_SNDBUF or SO_RCVBUF option opt back from the
// socket underlying c and asserts that it reflects a size of want.
func wantBuffer(tb testing.TB, c *Conn, opt, want int) {
	tb.Helper()

	// Linux reserves as much again for bookkeeping, so the socket reports
	// double the size it was given. The sizes tested are far below the
	// default net.core.{r,w}mem_max, so no clamping is expected.
	if got := sockoptInt(tb, c, unix.SOL_SOCKET, opt); got != 2*want {
		tb.Fatalf("unexpected socket buffer option %d on %s: got %d, want %d", opt, c.LocalAddr(), got, 2*want)
	}
}

// wantDSCP reads the code point back from the socket underlying c and
// asserts that it is dscp.
func wantDSCP(tb testing.TB, c *Conn, dscp uint8) {
	tb.Helper()

	level, opt := unix.IPPROTO_IPV6, unix.IPV6_TCLASS
	if connAddr(tb, c).Is4() {
		level, opt = unix.IPPROTO_IP, unix.IP_TOS
	}

	// The code point is the upper six bits of the octet; the ECN bits
	// below it are the kernel's.
	if got := uint8(sockoptInt(tb, c, level, opt) >> 2); got != dscp {
		tb.Fatalf("unexpected DSCP on %s: got %d, want %d", c.LocalAddr(), got, dscp)
	}
}

// wantUserTimeout reads TCP_USER_TIMEOUT back from the socket underlying c
// and asserts that it is d.
func wantUserTimeout(tb testing.TB, c *Conn, d time.Duration) {
	tb.Helper()

	got := time.Duration(sockoptInt(tb, c, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)) * time.Millisecond
	if got != d {
		tb.Fatalf("unexpected TCP_USER_TIMEOUT on %s: got %s, want %s", c.LocalAddr(), got, d)
	}
}

// connAddr returns the local address of the TCP connection underlying c.
func connAddr(tb testing.TB, c *Conn) netip.Addr {
	tb.Helper()

	a, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		tb.Fatalf("unexpected local address type %T", c.LocalAddr())
	}

	return a.AddrPort().Addr().Unmap()
}

// sockoptInt reads an integer socket option from the TCP connection
// underlying c.
func sockoptInt(tb testing.TB, c *Conn, level, opt int) int {
	tb.Helper()

	tc, ok := c.c.(*net.TCPConn)
	if !ok {
		tb.Fatalf("unexpected connection type %T", c.c)
	}

	rc, err := tc.SyscallConn()
	if err != nil {
		tb.Fatalf("failed to get raw connection: %v", err)
	}

	var got int
	if err := control(rc, func(fd int) error {
		var err error
		got, err = unix.GetsockoptInt(fd, level, opt)
		return err
	}); err != nil {
		tb.Fatalf("failed to get socket option %d/%d: %v", level, opt, err)
	}

	return got
}

// localAddrs returns the loopback addresses to test: IPv4 always, plus IPv6
// when available, so both address families' socket option paths are
// exercised.
func localAddrs(tb testing.TB) []netip.Addr {
	tb.Helper()

	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if nettest.SupportsIPv6() {
		addrs = append(addrs, netip.MustParseAddr("::1"))
	} else {
		tb.Log("IPv6 is unavailable, skipping ::1")
	}

	return addrs
}

// testListener creates a Listener on the given loopback address using lc,
// skipping the test if the environment does not permit its socket options.
func testListener(tb testing.TB, lc ListenConfig, loopback netip.Addr) *Listener {
	tb.Helper()

	l, err := lc.Listen(context.Background(), netip.AddrPortFrom(loopback, 0))
	if err != nil {
		skipUnsupported(tb, err)
		tb.Fatalf("failed to listen: %v", err)
	}

	tb.Cleanup(func() { _ = l.Close() })
	return l
}

// testSession dials l using d and exchanges a message in both directions,
// verifying that the sockets agree on their options.
func testSession(tb testing.TB, l *Listener, d *Dialer, md5 string, timeout time.Duration) {
	tb.Helper()

	type accepted struct {
		c   *Conn
		err error
	}

	acceptC := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptC <- accepted{c: c, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := dialListener(tb, ctx, d, l, md5)
	if err != nil {
		skipUnsupported(tb, err)
		tb.Fatalf("failed to dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	a := <-acceptC
	if a.err != nil {
		tb.Fatalf("failed to accept: %v", a.err)
	}

	server := a.c
	defer func() { _ = server.Close() }()

	if err := server.SetDeadline(time.Now().Add(timeout)); err != nil {
		tb.Fatalf("failed to set deadline: %v", err)
	}

	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		tb.Fatalf("failed to set deadline: %v", err)
	}

	for _, p := range []struct{ w, r *Conn }{{client, server}, {server, client}} {
		if err := p.w.WriteMessage(&Keepalive{}); err != nil {
			tb.Fatalf("failed to write KEEPALIVE: %v", err)
		}

		m, err := p.r.ReadMessage()
		if err != nil {
			tb.Fatalf("failed to read KEEPALIVE: %v", err)
		}

		if _, ok := m.(*Keepalive); !ok {
			tb.Fatalf("expected *Keepalive, but got: %T", m)
		}
	}
}

// testBlocked asserts that dial never completes because the kernel silently
// drops the connection attempt.
func testBlocked(tb testing.TB, dial func(ctx context.Context) error) {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), blockedTimeout)
	defer cancel()

	err := dial(ctx)
	if err == nil {
		tb.Fatal("expected the connection to be dropped, but it succeeded")
	}

	skipUnsupported(tb, err)

	// The connection attempt is retransmitted until the context expires, which
	// the net package reports either as the context error or as a timeout on
	// the socket itself.
	nerr, ok := errors.AsType[net.Error](err)
	timeout := errors.Is(err, context.DeadlineExceeded) || (ok && nerr.Timeout())
	if !timeout {
		tb.Fatalf("expected a timeout, but got: %v", err)
	}
}

// skipUnsupported skips the test when err indicates that the kernel or the
// current privileges do not permit a socket option this package sets.
func skipUnsupported(tb testing.TB, err error) {
	tb.Helper()

	switch {
	case errors.Is(err, errors.ErrUnsupported),
		errors.Is(err, unix.ENOPROTOOPT),
		errors.Is(err, unix.EOPNOTSUPP),
		errors.Is(err, unix.EPERM),
		errors.Is(err, unix.EACCES):
		tb.Skipf("skipping, socket option not permitted in this environment: %v", err)
	}
}

// linkLocalAddr finds an IPv6 link-local address, with its zone, on an up
// non-loopback interface, skipping the test when the host has none.
func linkLocalAddr(tb testing.TB) netip.Addr {
	tb.Helper()

	ifis, err := net.Interfaces()
	if err != nil {
		tb.Fatalf("failed to list interfaces: %v", err)
	}

	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}

			if addr = addr.Unmap(); addr.Is6() && addr.IsLinkLocalUnicast() {
				return addr.WithZone(ifi.Name)
			}
		}
	}

	tb.Skip("skipping, no up interface with an IPv6 link-local address")
	return netip.Addr{}
}

// testConnPair dials l using d and returns the dialed and accepted
// connections, both closed when the test ends.
func testConnPair(tb testing.TB, l *Listener, d *Dialer) (client, server *Conn) {
	tb.Helper()

	type accepted struct {
		c   *Conn
		err error
	}

	acceptC := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptC <- accepted{c: c, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), blockedTimeout)
	defer cancel()

	client, err := dialListener(tb, ctx, d, l, "")
	if err != nil {
		skipUnsupported(tb, err)
		tb.Fatalf("failed to dial: %v", err)
	}

	tb.Cleanup(func() { _ = client.Close() })

	a := <-acceptC
	if a.err != nil {
		tb.Fatalf("failed to accept: %v", a.err)
	}

	tb.Cleanup(func() { _ = a.c.Close() })
	return client, a.c
}

// dialListener is dialAddrPort for a Listener's address, with the TCP-MD5
// key the internal dial applies.
func dialListener(tb testing.TB, ctx context.Context, d *Dialer, l *Listener, md5 string) (*Conn, error) {
	tb.Helper()

	ap := listenerAddrPort(tb, l)
	dd := *d
	dd.Port = ap.Port()
	return dd.dial(ctx, ap.Addr(), md5)
}

// TestAcceptTransient pins the accept-loop resilience classification: a
// kernel-aborted connection retries immediately, file descriptor exhaustion
// retries after a pause, and anything else is fatal to Run.
func TestAcceptTransient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		err              error
		abort, exhausted bool
	}{
		{
			name:  "connection aborted",
			err:   unix.ECONNABORTED,
			abort: true,
		},
		{
			// The shape a real accept failure arrives in.
			name:      "wrapped EMFILE",
			err:       &net.OpError{Op: "accept", Err: os.NewSyscallError("accept4", unix.EMFILE)},
			exhausted: true,
		},
		{
			name:      "ENFILE",
			err:       unix.ENFILE,
			exhausted: true,
		},
		{
			name: "other",
			err:  errors.New("listener died"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			abort, exhausted := acceptTransient(tt.err)
			if abort != tt.abort || exhausted != tt.exhausted {
				t.Fatalf("unexpected classification: got (%t, %t), want (%t, %t)",
					abort, exhausted, tt.abort, tt.exhausted)
			}
		})
	}
}

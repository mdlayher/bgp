package bgprib_test

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/bgp"
	"github.com/mdlayher/bgp/internal/bgprib"
)

var (
	v4u = bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	v6u = bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}
)

func TestNewErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		local map[bgp.Family][]*bgp.Update
	}{
		{
			name: "IPv4 unicast UPDATE with no prefixes",
			local: map[bgp.Family][]*bgp.Update{
				v4u: {{}},
			},
		},
		{
			name: "IPv6 unicast UPDATE with only IPv4 prefixes",
			local: map[bgp.Family][]*bgp.Update{
				v6u: {{NLRI: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := bgprib.New(bgprib.Config{Local: tt.local}); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestTableBest(t *testing.T) {
	t.Parallel()

	var (
		p4 = netip.MustParsePrefix("198.51.100.0/24")
		p6 = netip.MustParsePrefix("2001:db8::/32")

		u4 = &bgp.Update{
			NLRI:       []netip.Prefix{p4},
			Attributes: attrs(t, bgp.OriginIGP, bgp.NextHop(netip.MustParseAddr("192.0.2.1"))),
		}

		u6 = &bgp.Update{
			Attributes: attrs(t, bgp.OriginIGP, bgp.MPReachNLRI{
				Family:  v6u,
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI:    bgp.Prefixes{p6},
			}),
		}
	)

	tb, err := bgprib.New(bgprib.Config{Local: map[bgp.Family][]*bgp.Update{
		v4u: {u4},
		v6u: {u6},
	}})
	if err != nil {
		t.Fatalf("failed to create Table: %v", err)
	}

	if u, ok := tb.Best(v4u, p4); !ok || u != u4 {
		t.Fatalf("unexpected best path for %v: got %v, %v", p4, u, ok)
	}

	if u, ok := tb.Best(v6u, p6); !ok || u != u6 {
		t.Fatalf("unexpected best path for %v: got %v, %v", p6, u, ok)
	}

	if _, ok := tb.Best(v4u, netip.MustParsePrefix("203.0.113.0/24")); ok {
		t.Fatal("expected no best path for an unknown prefix")
	}
}

func TestTableOnUpdate(t *testing.T) {
	t.Parallel()

	var (
		ctx = context.Background()
		tb  = newTable(t, bgprib.Config{})
		p   = testPeer(t)

		pA = netip.MustParsePrefix("198.51.100.0/24")
		pB = netip.MustParsePrefix("203.0.113.0/24")
		p6 = netip.MustParsePrefix("2001:db8::/32")
	)

	if err := tb.OnEstablished(ctx, p, session(false, nil, v4u, v6u)); err != nil {
		t.Fatalf("failed to establish: %v", err)
	}

	// Announce two IPv4 prefixes sharing one attribute slice, and one IPv6
	// prefix via MP_REACH_NLRI.
	u := &bgp.Update{
		NLRI:       []netip.Prefix{pB, pA},
		Attributes: attrs(t, bgp.OriginIGP, bgp.NextHop(netip.MustParseAddr("192.0.2.1"))),
	}

	if err := tb.OnUpdate(ctx, p, u); err != nil {
		t.Fatalf("failed to apply IPv4 UPDATE: %v", err)
	}

	if err := tb.OnUpdate(ctx, p, &bgp.Update{
		Attributes: attrs(t, bgp.OriginIGP, bgp.MPReachNLRI{
			Family:  v6u,
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    bgp.Prefixes{p6},
		}),
	}); err != nil {
		t.Fatalf("failed to apply IPv6 UPDATE: %v", err)
	}

	// Snapshots are sorted by prefix, and the IPv6 route retains its full
	// attribute slice, MP_REACH_NLRI container included.
	if d := diff(t, []netip.Prefix{pA, pB}, prefixes(tb.Routes(p, v4u))); d != "" {
		t.Fatalf("unexpected IPv4 unicast routes (-want +got):\n%s", d)
	}

	r6 := tb.Routes(p, v6u)
	if d := diff(t, []netip.Prefix{p6}, prefixes(r6)); d != "" {
		t.Fatalf("unexpected IPv6 unicast routes (-want +got):\n%s", d)
	}

	if len(r6[0].Attributes) != 2 {
		t.Fatalf("expected the IPv6 route to retain 2 attributes, but got: %v", r6[0].Attributes)
	}

	// The Table copies on insert: mutating the caller's UPDATE after the
	// fact must not reach the stored route.
	want := r6[0].Attributes[0].Data[0]
	u.Attributes[0].Data[0] ^= 0xff
	if got := tb.Routes(p, v6u)[0].Attributes[0].Data[0]; got != want {
		t.Fatalf("stored route aliased the caller's UPDATE: got %#x, want %#x", got, want)
	}

	// And copies on the way out: mutating a snapshot must not reach the
	// stored route either.
	r6[0].Attributes[0].Data[0] ^= 0xff
	if got := tb.Routes(p, v6u)[0].Attributes[0].Data[0]; got != want {
		t.Fatalf("snapshot aliased the stored route: got %#x, want %#x", got, want)
	}

	// Withdraw one prefix per family, both ways.
	if err := tb.OnUpdate(ctx, p, &bgp.Update{
		Withdrawn:  []netip.Prefix{pB},
		Attributes: attrs(t, bgp.MPUnreachNLRI{Family: v6u, NLRI: bgp.Prefixes{p6}}),
	}); err != nil {
		t.Fatalf("failed to apply withdrawal: %v", err)
	}

	if d := diff(t, []netip.Prefix{pA}, prefixes(tb.Routes(p, v4u))); d != "" {
		t.Fatalf("unexpected IPv4 unicast routes after withdrawal (-want +got):\n%s", d)
	}

	if n := len(tb.Routes(p, v6u)); n != 0 {
		t.Fatalf("expected no IPv6 unicast routes after withdrawal, but got %d", n)
	}
}

func TestTableRetention(t *testing.T) {
	t.Parallel()

	var (
		gr = &bgp.GracefulRestart{
			NotificationSupport: true,
			RestartTime:         60 * time.Second,
			Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
		}

		grNoN = &bgp.GracefulRestart{
			RestartTime: 60 * time.Second,
			Families:    []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
		}

		grV6Only = &bgp.GracefulRestart{
			NotificationSupport: true,
			RestartTime:         60 * time.Second,
			Families:            []bgp.GracefulRestartFamily{{Family: v6u, ForwardingPreserved: true}},
		}

		shutdown = &bgp.Notification{
			Code:    bgp.NotificationCease,
			Subcode: bgp.SubcodeCeaseAdministrativeShutdown,
		}

		hardReset = &bgp.Notification{
			Code:    bgp.NotificationCease,
			Subcode: bgp.SubcodeCeaseHardReset,
		}
	)

	tests := []struct {
		name   string
		gr     *bgp.GracefulRestart
		notif  bool
		close  bgp.Close
		retain bool
	}{
		{
			name:   "transport death retains",
			gr:     gr,
			close:  bgp.Close{Err: net.ErrClosed, Established: true},
			retain: true,
		},
		{
			name:  "no capability flushes",
			close: bgp.Close{Err: net.ErrClosed, Established: true},
		},
		{
			name: "zero restart time flushes",
			gr: &bgp.GracefulRestart{
				NotificationSupport: true,
				Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
			},
			close: bgp.Close{Err: net.ErrClosed, Established: true},
		},
		{
			name:   "notification with both N bits retains",
			gr:     gr,
			notif:  true,
			close:  bgp.Close{Notification: shutdown, Local: false, Established: true},
			retain: true,
		},
		{
			name:  "notification without peer N bit flushes",
			gr:    grNoN,
			notif: true,
			close: bgp.Close{Notification: shutdown, Local: false, Established: true},
		},
		{
			name:  "notification without local N bit flushes",
			gr:    gr,
			close: bgp.Close{Notification: shutdown, Local: false, Established: true},
		},
		{
			name:  "hard reset flushes",
			gr:    gr,
			notif: true,
			close: bgp.Close{Notification: hardReset, Local: false, Established: true},
		},
		{
			name:   "family absent from capability flushes",
			gr:     grV6Only,
			close:  bgp.Close{Err: net.ErrClosed, Established: true},
			retain: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var (
				ctx = context.Background()
				tb  = newTable(t, bgprib.Config{AfterFunc: (&fakeSweep{}).afterFunc})
				p   = testPeer(t)
			)

			if err := tb.OnEstablished(ctx, p, session(tt.notif, tt.gr, v4u)); err != nil {
				t.Fatalf("failed to establish: %v", err)
			}

			announce(t, tb, p, "198.51.100.0/24")
			tb.OnClose(p, tt.close)

			rs := tb.Routes(p, v4u)
			if tt.retain {
				if len(rs) != 1 || !rs[0].Stale {
					t.Fatalf("expected one stale route, but got: %v", rs)
				}
			} else if len(rs) != 0 {
				t.Fatalf("expected no routes, but got: %v", rs)
			}
		})
	}
}

func TestTableEndOfRIBSweep(t *testing.T) {
	t.Parallel()

	var (
		ctx = context.Background()
		fs  = &fakeSweep{}
		tb  = newTable(t, bgprib.Config{AfterFunc: fs.afterFunc})
		p   = testPeer(t)

		pA = netip.MustParsePrefix("198.51.100.0/24")
		pB = netip.MustParsePrefix("203.0.113.0/24")
	)

	gr := &bgp.GracefulRestart{
		NotificationSupport: true,
		RestartTime:         60 * time.Second,
		Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
	}

	if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
		t.Fatalf("failed to establish: %v", err)
	}

	announce(t, tb, p, pA.String())
	announce(t, tb, p, pB.String())
	tb.OnClose(p, bgp.Close{Err: net.ErrClosed, Established: true})

	for _, r := range tb.Routes(p, v4u) {
		if !r.Stale {
			t.Fatalf("expected route %v to be stale after close", r.Prefix)
		}
	}

	// The restarted peer returns, still claiming preserved forwarding: the
	// sweep timer stops and stale routes survive until End-of-RIB.
	if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
		t.Fatalf("failed to re-establish: %v", err)
	}

	if !fs.stopped {
		t.Fatal("expected re-establishment to stop the sweep timer")
	}

	if n := len(tb.Routes(p, v4u)); n != 2 {
		t.Fatalf("expected 2 stale routes to survive re-establishment, but got %d", n)
	}

	// Only pA is re-announced before End-of-RIB: pB is swept, pA is fresh.
	announce(t, tb, p, pA.String())
	if err := tb.OnUpdate(ctx, p, bgp.NewEndOfRIB(v4u)); err != nil {
		t.Fatalf("failed to apply End-of-RIB: %v", err)
	}

	rs := tb.Routes(p, v4u)
	if d := diff(t, []netip.Prefix{pA}, prefixes(rs)); d != "" {
		t.Fatalf("unexpected routes after End-of-RIB (-want +got):\n%s", d)
	}

	if rs[0].Stale {
		t.Fatal("expected the re-announced route to be fresh after End-of-RIB")
	}
}

func TestTableForwardingNotPreserved(t *testing.T) {
	t.Parallel()

	gr := &bgp.GracefulRestart{
		NotificationSupport: true,
		RestartTime:         60 * time.Second,
		Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
	}

	tests := []struct {
		name string
		next *bgp.GracefulRestart
	}{
		{
			name: "forwarding not preserved",
			next: &bgp.GracefulRestart{
				NotificationSupport: true,
				RestartTime:         60 * time.Second,
				Families:            []bgp.GracefulRestartFamily{{Family: v4u}},
			},
		},
		{
			name: "family absent",
			next: &bgp.GracefulRestart{
				NotificationSupport: true,
				RestartTime:         60 * time.Second,
			},
		},
		{
			name: "no capability",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var (
				ctx = context.Background()
				tb  = newTable(t, bgprib.Config{AfterFunc: (&fakeSweep{}).afterFunc})
				p   = testPeer(t)
			)

			if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
				t.Fatalf("failed to establish: %v", err)
			}

			announce(t, tb, p, "198.51.100.0/24")
			tb.OnClose(p, bgp.Close{Err: net.ErrClosed, Established: true})

			// A new session which no longer preserves the family flushes
			// its stale routes immediately, not at End-of-RIB.
			if err := tb.OnEstablished(ctx, p, session(true, tt.next, v4u)); err != nil {
				t.Fatalf("failed to re-establish: %v", err)
			}

			if rs := tb.Routes(p, v4u); len(rs) != 0 {
				t.Fatalf("expected stale routes to be flushed at re-establishment, but got: %v", rs)
			}
		})
	}
}

func TestTableRestartTimerExpiry(t *testing.T) {
	t.Parallel()

	var (
		ctx = context.Background()
		fs  = &fakeSweep{}
		tb  = newTable(t, bgprib.Config{AfterFunc: fs.afterFunc})
		p   = testPeer(t)
	)

	gr := &bgp.GracefulRestart{
		NotificationSupport: true,
		RestartTime:         45 * time.Second,
		Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
	}

	if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
		t.Fatalf("failed to establish: %v", err)
	}

	announce(t, tb, p, "198.51.100.0/24")
	tb.OnClose(p, bgp.Close{Err: net.ErrClosed, Established: true})

	if fs.d != gr.RestartTime {
		t.Fatalf("unexpected sweep delay: got %v, want %v", fs.d, gr.RestartTime)
	}

	// The peer never returns: expiry flushes everything it left behind.
	fs.fire()
	if rs := tb.Routes(p, v4u); len(rs) != 0 {
		t.Fatalf("expected no routes after restart time expiry, but got: %v", rs)
	}
}

func TestTableRestartTimerLateFire(t *testing.T) {
	t.Parallel()

	var (
		ctx = context.Background()
		fs  = &fakeSweep{}
		tb  = newTable(t, bgprib.Config{AfterFunc: fs.afterFunc})
		p   = testPeer(t)
	)

	gr := &bgp.GracefulRestart{
		NotificationSupport: true,
		RestartTime:         45 * time.Second,
		Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
	}

	if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
		t.Fatalf("failed to establish: %v", err)
	}

	announce(t, tb, p, "198.51.100.0/24")
	tb.OnClose(p, bgp.Close{Err: net.ErrClosed, Established: true})

	// The peer returns, and the sweep callback fires anyway: time.AfterFunc's
	// Stop cannot un-run a callback already in flight, so the generation
	// check must discard it.
	if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
		t.Fatalf("failed to re-establish: %v", err)
	}

	fs.fire()

	if n := len(tb.Routes(p, v4u)); n != 1 {
		t.Fatalf("expected a late sweep to be discarded, but got %d routes", n)
	}
}

func TestTableAttemptCloseIgnored(t *testing.T) {
	t.Parallel()

	var (
		ctx = context.Background()
		fs  = &fakeSweep{}
		tb  = newTable(t, bgprib.Config{AfterFunc: fs.afterFunc})
		p   = testPeer(t)
	)

	// A close for a peer with no state at all must not panic.
	tb.OnClose(testPeer(t), bgp.Close{Err: net.ErrClosed, Established: true})

	gr := &bgp.GracefulRestart{
		NotificationSupport: true,
		RestartTime:         45 * time.Second,
		Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
	}

	if err := tb.OnEstablished(ctx, p, session(true, gr, v4u)); err != nil {
		t.Fatalf("failed to establish: %v", err)
	}

	announce(t, tb, p, "198.51.100.0/24")
	tb.OnClose(p, bgp.Close{Err: net.ErrClosed, Established: true})

	// A failed attempt between sessions reports OnClose with Established
	// false: retention and the armed sweep must survive it.
	tb.OnClose(p, bgp.Close{Err: net.ErrClosed})

	rs := tb.Routes(p, v4u)
	if len(rs) != 1 || !rs[0].Stale {
		t.Fatalf("expected one stale route to survive an attempt close, but got: %v", rs)
	}

	if fs.stopped {
		t.Fatal("expected the sweep timer to survive an attempt close")
	}
}

// TestTablePeersTCP proves the whole seam end to end using only exported API:
// two Peers over real TCP, each wired to a Table, through establishment, a
// graceful restart with retention, and the sweep at End-of-RIB.
func TestTablePeersTCP(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping, test uses real TCP connections and timers")
	}

	var (
		pA = netip.MustParsePrefix("198.51.100.0/24")
		pB = netip.MustParsePrefix("203.0.113.0/24")
	)

	gr := &bgp.GracefulRestartConfig{
		RestartTime:         30 * time.Second,
		NotificationSupport: true,
		Families:            []bgp.GracefulRestartFamily{{Family: v4u, ForwardingPreserved: true}},
	}

	tableA := newTable(t, bgprib.Config{
		Local: map[bgp.Family][]*bgp.Update{v4u: {{
			NLRI:       []netip.Prefix{pA},
			Attributes: attrs(t, bgp.OriginIGP, bgp.NextHop(netip.MustParseAddr("192.0.2.1"))),
		}}},
	})
	tableB := newTable(t, bgprib.Config{
		Local: map[bgp.Family][]*bgp.Update{v4u: {{
			NLRI:       []netip.Prefix{pB},
			Attributes: attrs(t, bgp.OriginIGP, bgp.NextHop(netip.MustParseAddr("192.0.2.2"))),
		}}},
	})

	// A accepts, B dials.
	ln, err := (&bgp.ListenConfig{}).Listen(t.Context(), netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	peerA, err := bgp.NewPeer(netip.MustParseAddr("127.0.0.1"), wire(tableA, bgp.PeerConfig{
		LocalASN:        65001,
		LocalID:         bgp.MustParseIdentifier("192.0.2.1"),
		Passive:         true,
		Families:        []bgp.Family{v4u},
		GracefulRestart: gr,
		Logger:          logger(t, "A"),
	}))
	if err != nil {
		t.Fatalf("failed to create peer A: %v", err)
	}

	raddrB := netip.MustParseAddrPort(ln.Addr().String())
	cfgB := wire(tableB, bgp.PeerConfig{
		LocalASN:        65002,
		LocalID:         bgp.MustParseIdentifier("192.0.2.2"),
		Families:        []bgp.Family{v4u},
		GracefulRestart: gr,
		Logger:          logger(t, "B1"),
	})
	cfgB.Dialer.Port = raddrB.Port()
	peerB1, err := bgp.NewPeer(raddrB.Addr(), cfgB)
	if err != nil {
		t.Fatalf("failed to create peer B1: %v", err)
	}

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			if err := peerA.DeliverConn(c); err != nil {
				// Refused, such as during an idle hold; the dialer retries.
				_ = c.Close()
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-acceptDone
	})

	// run starts a Peer and joins its Run goroutine in cleanup: Run's
	// teardown logs through t.Output, which panics if written after the
	// test completes.
	run := func(p *bgp.Peer) context.CancelFunc {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = p.Run(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		return cancel
	}

	run(peerA)
	cancelB1 := run(peerB1)

	// Phase 1: both tables learn the other speaker's static route.
	waitFor(t, "both tables to learn a fresh route", func() bool {
		ra, rb := tableA.Routes(peerA, v4u), tableB.Routes(peerB1, v4u)
		return len(ra) == 1 && ra[0].Prefix == pB && !ra[0].Stale &&
			len(rb) == 1 && rb[0].Prefix == pA && !rb[0].Stale
	})

	// Phase 2: B shuts down with Administrative Shutdown. Both speakers
	// advertised the N bit, so A retains B's route as stale.
	cancelB1()
	waitFor(t, "table A to retain B's route as stale", func() bool {
		ra := tableA.Routes(peerA, v4u)
		return len(ra) == 1 && ra[0].Prefix == pB && ra[0].Stale
	})

	// Phase 3: B restarts as a new Peer claiming the Restart State bit,
	// re-announces, and its End-of-RIB sweeps A back to a fresh route.
	cfgB.GracefulRestart.Restarting = func() bool { return true }
	cfgB.Logger = logger(t, "B2")
	peerB2, err := bgp.NewPeer(raddrB.Addr(), cfgB)
	if err != nil {
		t.Fatalf("failed to create peer B2: %v", err)
	}

	run(peerB2)

	waitFor(t, "table A to sweep back to a fresh route", func() bool {
		ra := tableA.Routes(peerA, v4u)
		return len(ra) == 1 && ra[0].Prefix == pB && !ra[0].Stale
	})
}

// wire is the pluggable-RIB wiring pattern: a Table attaches to a peer by assigning
// its handler-shaped methods into the PeerConfig, and nothing else.
func wire(tb *bgprib.Table, cfg bgp.PeerConfig) bgp.PeerConfig {
	cfg.OnEstablished = tb.OnEstablished
	cfg.OnUpdate = tb.OnUpdate
	cfg.OnRouteRefresh = tb.OnRouteRefresh
	cfg.OnKeepalive = tb.OnKeepalive
	cfg.OnClose = tb.OnClose
	return cfg
}

// newTable creates a Table whose configuration must be valid, and joins its
// pusher goroutines before the test completes. This cleanup is registered
// first, so it runs last: every session is already dead by then, and the
// pushers exit on their first failed send.
func newTable(t *testing.T, cfg bgprib.Config) *bgprib.Table {
	t.Helper()

	tb, err := bgprib.New(cfg)
	if err != nil {
		t.Fatalf("failed to create Table: %v", err)
	}

	t.Cleanup(tb.Wait)
	return tb
}

// testPeer creates a valid Peer which never runs: a stable map key whose
// SendUpdate reports ErrNotEstablished.
func testPeer(t *testing.T) *bgp.Peer {
	t.Helper()

	p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.2"), bgp.PeerConfig{
		LocalASN: 65001,
		LocalID:  bgp.MustParseIdentifier("192.0.2.1"),
	})
	if err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	return p
}

// session synthesizes the Session a Table sees at establishment: gr is the
// peer's graceful restart capability, and localN the N bit of this speaker's
// own capability, carried on Session.Local like the FSM reports it.
func session(localN bool, gr *bgp.GracefulRestart, families ...bgp.Family) bgp.Session {
	cap, err := bgp.GracefulRestartCapability(bgp.GracefulRestart{
		NotificationSupport: localN,
		RestartTime:         60 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	return bgp.Session{
		Local: &bgp.Open{
			ASN:          65001,
			HoldTime:     90 * time.Second,
			ID:           bgp.MustParseIdentifier("192.0.2.1"),
			Capabilities: []bgp.Capability{cap},
		},
		Families:        families,
		GracefulRestart: gr,
		HoldTime:        90 * time.Second,
	}
}

// announce applies an UPDATE announcing one IPv4 unicast prefix.
func announce(t *testing.T, tb *bgprib.Table, p *bgp.Peer, prefix string) {
	t.Helper()

	u := &bgp.Update{
		NLRI:       []netip.Prefix{netip.MustParsePrefix(prefix)},
		Attributes: attrs(t, bgp.OriginIGP, bgp.NextHop(netip.MustParseAddr("192.0.2.1"))),
	}

	if err := tb.OnUpdate(context.Background(), p, u); err != nil {
		t.Fatalf("failed to announce %s: %v", prefix, err)
	}
}

// attrs marshals typed attributes which must be valid.
func attrs(t *testing.T, as ...bgp.Attribute) []bgp.RawAttribute {
	t.Helper()

	ras, err := bgp.MarshalAttributes(as...)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	return ras
}

// diff compares two values of the same static type, returning a non-empty,
// human readable description of the difference when the values are not equal.
func diff[T any](tb testing.TB, want, got T) string {
	tb.Helper()
	return cmp.Diff(
		want, got,
		cmp.Comparer(func(x, y netip.Prefix) bool { return x == y }),
	)
}

// prefixes projects a snapshot to its prefixes.
func prefixes(rs []bgprib.Route) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Prefix)
	}

	return out
}

// A fakeSweep captures the Table's scheduled graceful restart sweep so tests
// control time.
type fakeSweep struct {
	d       time.Duration
	fire    func()
	stopped bool
}

// afterFunc is a Config.AfterFunc which captures the scheduled sweep instead
// of arming a timer.
func (fs *fakeSweep) afterFunc(d time.Duration, f func()) func() bool {
	fs.d, fs.fire = d, f
	return func() bool {
		fs.stopped = true
		return true
	}
}

// waitFor polls cond until it holds or a generous deadline expires.
func waitFor(t *testing.T, msg string, cond func() bool) {
	t.Helper()

	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if cond() {
			return
		}

		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", msg)
}

// logger emits a peer's logs under -test.v, silently discarding otherwise.
func logger(t *testing.T, name string) *slog.Logger {
	if !testing.Verbose() {
		return nil
	}

	return slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("name", name)
}

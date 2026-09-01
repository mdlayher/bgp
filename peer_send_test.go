package bgp

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// TestPeerSendNotEstablished verifies the send gate: sends fail with
// ErrNotEstablished both before a session is up and after it ends.
func TestPeerSendNotEstablished(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		// The connection is only in OpenSent.
		s.expectOpen()
		if err := r.p.SendUpdate(context.Background(), &Update{}); !errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected ErrNotEstablished before establishment, but got: %v", err)
		}

		v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
		if err := r.p.SendRouteRefresh(context.Background(), v4u); !errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected ErrNotEstablished before establishment, but got: %v", err)
		}

		s.write(scriptOpen())
		s.expectKeepalive()
		s.write(&Keepalive{})
		recv(t, r.estC, "session establishment")

		s.write(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeReset,
		})
		recv(t, r.closeC, "session close")

		if err := r.p.SendUpdate(context.Background(), &Update{}); !errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected ErrNotEstablished after close, but got: %v", err)
		}

		if err := r.p.SendRouteRefresh(context.Background(), v4u); !errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected ErrNotEstablished after close, but got: %v", err)
		}
	})
}

// TestPeerSendUpdate verifies that a sent UPDATE arrives byte-faithful, and
// that sequential sends from one goroutine arrive in order.
func TestPeerSendUpdate(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		want := &Update{
			Attributes: mustAttributes(
				t,
				OriginIGP,
				ASPath{{ASNs: []uint32{64496}}},
				NextHop(netip.MustParseAddr("192.0.2.1")),
			),
			NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}

		if err := r.p.SendUpdate(context.Background(), want); err != nil {
			t.Fatalf("failed to send UPDATE: %v", err)
		}

		m := s.read()
		got, ok := m.(*Update)
		if !ok {
			t.Fatalf("expected an UPDATE, but got: %T", m)
		}

		if d := diff(t, want, got); d != "" {
			t.Fatalf("unexpected UPDATE (-want +got):\n%s", d)
		}

		// One goroutine's sends are written in order.
		attrs := mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
			NextHop(netip.MustParseAddr("192.0.2.1")))
		for i := range 100 {
			u := &Update{
				Attributes: attrs,
				NLRI: []netip.Prefix{netip.PrefixFrom(
					netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 32,
				)},
			}

			if err := r.p.SendUpdate(context.Background(), u); err != nil {
				t.Fatalf("failed to send UPDATE %d: %v", i, err)
			}
		}

		for i := range 100 {
			u, ok := s.read().(*Update)
			if !ok || len(u.NLRI) != 1 {
				t.Fatalf("unexpected message %d: %+v", i, u)
			}

			if want := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 32); u.NLRI[0] != want {
				t.Fatalf("UPDATE %d out of order: want %s, got %s", i, want, u.NLRI[0])
			}
		}
	})
}

// TestPeerSendRouteRefresh verifies the RFC 2918 negotiation gate: a
// negotiated refresh reaches the wire, an unnegotiated one is refused
// locally.
func TestPeerSendRouteRefreshNegotiated(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		open := scriptOpen()
		open.Capabilities = []Capability{{Code: CapabilityRouteRefresh}}
		s.establish(open)
		recv(t, r.estC, "session establishment")

		if err := r.p.SendRouteRefresh(context.Background(), v4u); err != nil {
			t.Fatalf("failed to send ROUTE-REFRESH: %v", err)
		}

		m := s.read()
		rr, ok := m.(*RouteRefresh)
		if !ok {
			t.Fatalf("expected a ROUTE-REFRESH, but got: %T", m)
		}

		if d := diff(t, v4u, rr.Family); d != "" {
			t.Fatalf("unexpected family (-want +got):\n%s", d)
		}
	})
}

func TestPeerSendRouteRefreshUnnegotiated(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		err := r.p.SendRouteRefresh(context.Background(), v4u)
		if err == nil || errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected a negotiation error, but got: %v", err)
		}
	})
}

// TestPeerSendMarshalError verifies error classification by origin: a
// message which fails to marshal returns its error to the caller alone,
// and the session stays healthy for the next send.
func TestPeerSendMarshalError(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// Enough prefixes to exceed MaxMessageSize: the marshal fails before
		// any byte reaches the connection.
		prefixes := make([]netip.Prefix, 1024)
		for i := range prefixes {
			prefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 32)
		}

		err := r.p.SendUpdate(context.Background(), &Update{
			Attributes: mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
				NextHop(netip.MustParseAddr("192.0.2.1"))),
			NLRI: prefixes,
		})
		if err == nil || errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected a marshal error, but got: %v", err)
		}

		// The session survived: a valid UPDATE still flows.
		want := &Update{
			Attributes: mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
				NextHop(netip.MustParseAddr("192.0.2.1"))),
			NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}

		if err := r.p.SendUpdate(context.Background(), want); err != nil {
			t.Fatalf("failed to send UPDATE: %v", err)
		}

		if d := diff[Message](t, want, s.read()); d != "" {
			t.Fatalf("unexpected UPDATE (-want +got):\n%s", d)
		}

		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	})
}

// TestPeerSendCanceledContext verifies that an already-canceled ctx fails a
// send deterministically, before it reaches the writer.
func TestPeerSendCanceledContext(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.p.SendUpdate(ctx, &Update{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, but got: %v", err)
		}
	})
}

// TestPeerSendBackpressure verifies that a sender blocked by a peer which
// stopped reading is unblocked with an error when the connection dies,
// rather than hanging forever: backpressure bounds memory, and teardown
// bounds the wait.
func TestPeerSendBackpressure(t *testing.T) {
	t.Parallel()

	r := newTCPRig(t, PeerConfig{})
	s := r.acceptScript()
	s.establish(scriptOpen())
	recv(t, r.estC, "session establishment")

	// A filler UPDATE around 1 KiB, so a few hundred sends exhaust the
	// loopback socket buffers once the scripted peer stops reading.
	prefixes := make([]netip.Prefix, 200)
	for i := range prefixes {
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
	}

	filler := &Update{
		Attributes: mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
			NextHop(netip.MustParseAddr("192.0.2.1"))),
		NLRI: prefixes,
	}

	// The completion channel's elements are zero-size, so the huge capacity
	// costs nothing; it exists so the pusher can never block on reporting.
	errC := make(chan error, 1)
	sends := make(chan struct{}, 1<<20)
	go func() {
		for {
			if err := r.p.SendUpdate(context.Background(), filler); err != nil {
				errC <- err
				return
			}

			sends <- struct{}{}
		}
	}()

	// Drain completions until the pusher stalls: a quiet period with no
	// completed send means it is parked inside SendUpdate by backpressure.
	// Then kill the connection from the scripted side; the blocked send
	// must surface an error.
	quiet := time.NewTimer(250 * time.Millisecond)
	defer quiet.Stop()
drain:
	for {
		select {
		case <-sends:
			quiet.Reset(250 * time.Millisecond)
		case err := <-errC:
			t.Fatalf("send failed before the connection closed: %v", err)
		case <-quiet.C:
			break drain
		}
	}

	_ = s.nc.Close()

	if err := recv(t, errC, "the blocked send to fail"); err == nil {
		t.Fatal("expected the blocked send to fail")
	}

	recv(t, r.closeC, "session close")
}

// TestPeerSendWriteDeadline verifies the writer's per-write deadline: a peer
// which stops reading wedges the writer mid-write, and the deadline of the
// negotiated hold time must fail the write and end the session on its own —
// the scripted peer neither closes the connection nor runs a hold timer of
// its own. Without the deadline, session liveness would rest entirely on
// the remote speaker's good behavior.
func TestPeerSendWriteDeadline(t *testing.T) {
	t.Parallel()

	// The local proposal of 3s wins against scriptOpen's 30s, keeping the
	// deadline the test waits out short. The scripted peer keeps sending
	// KEEPALIVEs while it stops reading — the exact misbehavior the
	// deadline exists for — so the FSM's own hold timer stays fed and only
	// the write deadline can end this session.
	r := newTCPRig(t, PeerConfig{HoldTime: 3 * time.Second})
	s := r.acceptScript()
	s.establish(scriptOpen())
	recv(t, r.estC, "session establishment")

	stopFeeding := make(chan struct{})
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				_ = s.c.WriteMessage(&Keepalive{})
			case <-stopFeeding:
				return
			}
		}
	}()
	defer func() {
		close(stopFeeding)
		<-fed
	}()

	prefixes := make([]netip.Prefix, 200)
	for i := range prefixes {
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
	}

	filler := &Update{
		Attributes: mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
			NextHop(netip.MustParseAddr("192.0.2.1"))),
		NLRI: prefixes,
	}

	errC := make(chan error, 1)
	sends := make(chan struct{}, 1<<20)
	go func() {
		for {
			if err := r.p.SendUpdate(context.Background(), filler); err != nil {
				errC <- err
				return
			}

			sends <- struct{}{}
		}
	}()

	// Drain completions until the pusher stalls against the full socket
	// buffers, then simply wait: the deadline must do the rest.
	quiet := time.NewTimer(250 * time.Millisecond)
	defer quiet.Stop()
drain:
	for {
		select {
		case <-sends:
			quiet.Reset(250 * time.Millisecond)
		case err := <-errC:
			t.Fatalf("send failed before the deadline could act: %v", err)
		case <-quiet.C:
			break drain
		}
	}

	err := recv(t, errC, "the blocked send to fail")
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("send error is not a deadline error: %v", err)
	}

	if !errors.Is(err, ErrNotEstablished) {
		t.Fatalf("send error does not wrap ErrNotEstablished: %v", err)
	}

	c := recv(t, r.closeC, "session close")
	if !errors.Is(c.Err, os.ErrDeadlineExceeded) {
		t.Fatalf("close error is not a deadline error: %v", c.Err)
	}
}

// TestPeerBulkPush transfers a large table the documented way: a pusher
// goroutine started by OnEstablished, throttled only by the peer's receive
// rate, while the session stays healthy.
func TestPeerBulkPush(t *testing.T) {
	t.Parallel()

	const numUpdates = 1000

	// LocalPref carries each UPDATE's sequence number.
	updates := make([]*Update, numUpdates)
	for i := range updates {
		updates[i] = &Update{
			Attributes: mustAttributes(
				t,
				OriginIGP,
				ASPath{{ASNs: []uint32{64496}}},
				NextHop(netip.MustParseAddr("192.0.2.1")),
				LocalPref(uint32(i)),
			),
			NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}
	}

	pushedC := make(chan error, 1)
	r := newTCPRig(t, PeerConfig{
		OnEstablished: func(ctx context.Context, p *Peer, _ Session) error {
			// The documented pattern: bulk transmission never runs
			// synchronously in a handler; a pusher goroutine does it.
			go func() {
				for _, u := range updates {
					if err := p.SendUpdate(ctx, u); err != nil {
						pushedC <- err
						return
					}
				}

				pushedC <- nil
			}()
			return nil
		},
	})
	s := r.acceptScript()
	s.establish(scriptOpen())

	for i := range numUpdates {
		u, ok := s.read().(*Update)
		if !ok {
			t.Fatalf("expected an UPDATE at %d", i)
		}

		if got := localPref(t, u); got != uint32(i) {
			t.Fatalf("UPDATE out of order: want %d, got %d", i, got)
		}
	}

	if err := recv(t, pushedC, "the push to complete"); err != nil {
		t.Fatalf("failed to push: %v", err)
	}

	select {
	case c := <-r.closeC:
		t.Fatalf("session closed unexpectedly: %+v", c)
	default:
	}
}

// localPref extracts the LOCAL_PREF attribute from an UPDATE.
func localPref(tb testing.TB, u *Update) uint32 {
	tb.Helper()

	for _, ra := range u.Attributes {
		a, err := ra.Parse()
		if err != nil {
			continue
		}

		if lp, ok := a.(LocalPref); ok {
			return uint32(lp)
		}
	}

	tb.Fatal("UPDATE carries no LOCAL_PREF attribute")
	panic("unreachable")
}

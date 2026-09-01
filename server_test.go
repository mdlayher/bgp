package bgp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

func TestServerAddRemovePeerErrors(t *testing.T) {
	t.Parallel()

	s := testServer(t, ServerConfig{})

	addr := netip.MustParseAddr("192.0.2.2")

	// NewPeer's validation surfaces through AddPeer.
	if _, err := s.AddPeer(addr, PeerConfig{}); err == nil {
		t.Fatal("expected an error for an invalid peer configuration")
	}

	cfg := PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64497,
	}

	if _, err := s.AddPeer(addr, cfg); err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	if _, err := s.AddPeer(addr, cfg); err == nil {
		t.Fatal("expected an error for a duplicate peer address")
	}

	if err := s.RemovePeer(netip.MustParseAddr("203.0.113.1"), nil); err == nil {
		t.Fatal("expected an error for an unknown peer address")
	}

	// Removing a never-started peer has nothing to drain.
	if err := s.RemovePeer(netip.MustParseAddr("192.0.2.2"), nil); err != nil {
		t.Fatalf("failed to remove peer: %v", err)
	}

	if err := s.RemovePeer(netip.MustParseAddr("192.0.2.2"), nil); err == nil {
		t.Fatal("expected an error removing a peer twice")
	}
}

// TestServerManagedPeer verifies the ownership guards: a Server-managed
// peer rejects caller Run and DeliverConn at their call sites.
func TestServerManagedPeer(t *testing.T) {
	t.Parallel()

	s := testServer(t, ServerConfig{})
	p, err := s.AddPeer(netip.MustParseAddr("192.0.2.2"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64497,
		Passive:  true,
	})
	if err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	if err := p.Run(context.Background()); err == nil {
		t.Fatal("expected an error running a managed peer")
	}

	client, _ := testConns(t, "tcp4")
	if err := p.DeliverConn(client); err == nil {
		t.Fatal("expected an error delivering to a managed peer")
	}
}

// TestServerPeers verifies the iterator: ascending address order, and a
// snapshot which tolerates removal during iteration.
func TestServerPeers(t *testing.T) {
	t.Parallel()

	s := testServer(t, ServerConfig{})

	// Added out of order; v4 sorts before v6 under netip.Addr.Compare.
	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.9"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}

	for i, addr := range addrs {
		if _, err := s.AddPeer(addr, PeerConfig{
			LocalASN: 64496,
			LocalID:  Identifier(i + 1),
			PeerASN:  64497,
			Passive:  true,
		}); err != nil {
			t.Fatalf("failed to add peer %s: %v", addr, err)
		}
	}

	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.9"),
		netip.MustParseAddr("2001:db8::1"),
	}

	var got []netip.Addr
	for addr, p := range s.Peers() {
		if p == nil {
			t.Fatalf("nil peer for address %s", addr)
		}

		got = append(got, addr)

		// The sequence is a snapshot: removal during iteration is safe.
		if err := s.RemovePeer(addr, nil); err != nil {
			t.Fatalf("failed to remove peer %s: %v", addr, err)
		}
	}

	if !slices.Equal(want, got) {
		t.Fatalf("unexpected peers:\nwant: %v\n got: %v", want, got)
	}

	for addr := range s.Peers() {
		t.Fatalf("expected no peers, but got: %s", addr)
	}
}

// TestServerRunLifecycle verifies Run's contract on a zero-listener Server:
// a concurrent Run is refused, cancellation is the only exit, and the
// Server is re-runnable afterward.
func TestServerRunLifecycle(t *testing.T) {
	t.Parallel()

	s := testServer(t, ServerConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx) }()
	waitServerUp(t, s)

	if err := s.Run(ctx); err == nil {
		t.Fatal("expected an error for a concurrent Run")
	}

	cancel()
	if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	go func() { runC <- s.Run(ctx) }()
	waitServerUp(t, s)
	cancel()
	if err := recv(t, runC, "second Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected second Run error: %v", err)
	}
}

// TestServerAddBeforeRun verifies start ordering and removal: a peer added
// before Run is started by Run, and RemovePeer is synchronous — when it
// returns, Peer De-configured is already on the wire and the peer's run has
// drained.
func TestServerAddBeforeRun(t *testing.T) {
	t.Parallel()

	l := scriptListener(t)
	s := testServer(t, ServerConfig{})
	ev := newPeerEvents()
	ap := l.Addr().(*net.TCPAddr).AddrPort()
	if _, err := s.AddPeer(ap.Addr(), ev.wire(PeerConfig{
		Dialer:   Dialer{Port: ap.Port()},
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64497,
	})); err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	runServer(t, s)

	// Run started the pre-added peer: it dials the scripted listener.
	sc := acceptScriptOn(t, l)
	sc.establish(scriptOpen())
	recv(t, ev.estC, "session establishment")

	if err := s.RemovePeer(ap.Addr(), nil); err != nil {
		t.Fatalf("failed to remove peer: %v", err)
	}

	n := sc.nextNotification()
	if n.Code != NotificationCease || n.Subcode != SubcodeCeasePeerDeconfigured {
		t.Fatalf("unexpected NOTIFICATION: %+v", n)
	}

	c := recv(t, ev.closeC, "session close")
	if !c.Established || !c.Local {
		t.Fatalf("unexpected Close: %+v", c)
	}

	sc.expectClosed()
}

// TestServerRemovePeerCause verifies the caller-owned removal farewell: the
// cause is sent verbatim in place of Peer De-configured.
func TestServerRemovePeerCause(t *testing.T) {
	t.Parallel()

	l := scriptListener(t)
	s := testServer(t, ServerConfig{})
	ev := newPeerEvents()
	ap := l.Addr().(*net.TCPAddr).AddrPort()
	if _, err := s.AddPeer(ap.Addr(), ev.wire(PeerConfig{
		Dialer:   Dialer{Port: ap.Port()},
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64497,
	})); err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	runServer(t, s)

	sc := acceptScriptOn(t, l)
	sc.establish(scriptOpen())
	recv(t, ev.estC, "session establishment")

	if err := s.RemovePeer(ap.Addr(), must(NewShutdownError(
		SubcodeCeaseAdministrativeShutdown, "goodbye",
	))); err != nil {
		t.Fatalf("failed to remove peer: %v", err)
	}

	n := sc.nextNotification()
	if n.Code != NotificationCease || n.Subcode != SubcodeCeaseAdministrativeShutdown {
		t.Fatalf("unexpected NOTIFICATION: %+v", n)
	}

	if got, ok := n.ShutdownCommunication(); !ok || got != "goodbye" {
		t.Fatalf("unexpected shutdown communication: %q, %t", got, ok)
	}

	sc.expectClosed()
}

// TestServerDemuxTCP proves the accept demultiplexer with real Peers on
// both sides: two remote speakers dial one listener from distinct loopback
// addresses, and each connection lands on the peering configured for its
// source address.
func TestServerDemuxTCP(t *testing.T) {
	t.Parallel()

	addr1 := netip.MustParseAddr("127.0.0.1")
	addr2 := netip.MustParseAddr("127.0.0.2")

	l := loopbackListener(t)
	s := testServer(t, ServerConfig{})
	ev1, ev2 := newPeerEvents(), newPeerEvents()
	for _, p := range []struct {
		ev   *peerEvents
		asn  uint32
		addr netip.Addr
	}{
		{ev: ev1, asn: 64497, addr: addr1},
		{ev: ev2, asn: 64498, addr: addr2},
	} {
		if _, err := s.AddPeer(p.addr, p.ev.wire(PeerConfig{
			LocalASN: 64496,
			LocalID:  MustParseIdentifier("192.0.2.1"),
			PeerASN:  p.asn,
			Passive:  true,
		})); err != nil {
			t.Fatalf("failed to add peer for %s: %v", p.addr, err)
		}
	}

	runServer(t, s, l)

	// The remote speakers, each dialing from its own loopback address: the
	// source address is the demultiplexer's only input.
	remote := func(asn uint32, id string, laddr netip.Addr) *peerRig {
		return dialingPeer(t, l, PeerConfig{
			LocalASN: asn,
			LocalID:  MustParseIdentifier(id),
			PeerASN:  64496,
			Dialer:   Dialer{LocalAddr: netip.AddrPortFrom(laddr, 0)},
		})
	}

	b1 := remote(64497, "192.0.2.2", addr1)
	b2 := remote(64498, "192.0.2.3", addr2)

	// The sessions carry the remote ASNs, proving each connection reached
	// the right peering.
	if sess := recv(t, ev1.estC, "peer 1 establishment"); sess.Peer.ASN != 64497 {
		t.Fatalf("peer 1 established with AS%d", sess.Peer.ASN)
	}

	if sess := recv(t, ev2.estC, "peer 2 establishment"); sess.Peer.ASN != 64498 {
		t.Fatalf("peer 2 established with AS%d", sess.Peer.ASN)
	}

	recv(t, b1.estC, "remote 1 establishment")
	recv(t, b2.estC, "remote 2 establishment")

	// Removal reaches exactly the removed peering's remote.
	if err := s.RemovePeer(addr1, nil); err != nil {
		t.Fatalf("failed to remove peer: %v", err)
	}

	c := recv(t, b1.closeC, "remote 1 close")
	if c.Notification == nil ||
		c.Notification.Code != NotificationCease ||
		c.Notification.Subcode != SubcodeCeasePeerDeconfigured {
		t.Fatalf("unexpected Close notification: %+v", c.Notification)
	}

	if c.Local || !c.Established {
		t.Fatalf("unexpected Close: %+v", c)
	}

	select {
	case c := <-b2.closeC:
		t.Fatalf("remote 2 closed unexpectedly: %+v", c)
	default:
	}
}

// TestServerShutdownCausePropagationTCP pins the mass-shutdown seam: a
// cancellation cause on Run's ctx reaches every peer through the Server's
// derived per-peer contexts, because Go propagates a parent's cause to its
// children.
func TestServerShutdownCausePropagationTCP(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("127.0.0.1")
	l := loopbackListener(t)
	s := testServer(t, ServerConfig{})
	ev := newPeerEvents()
	if _, err := s.AddPeer(addr, ev.wire(PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64497,
		Passive:  true,
	})); err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	cancel := runServer(t, s, l)

	b := dialingPeer(t, l, PeerConfig{
		LocalASN: 64497,
		LocalID:  MustParseIdentifier("192.0.2.2"),
		PeerASN:  64496,
	})
	recv(t, ev.estC, "server peer establishment")
	recv(t, b.estC, "remote establishment")

	cancel(must(NewHardResetError(
		NotificationCease, SubcodeCeaseAdministrativeShutdown, "fleet drain",
	)))

	c := recv(t, b.closeC, "remote close")
	if c.Notification == nil ||
		c.Notification.Code != NotificationCease ||
		c.Notification.Subcode != SubcodeCeaseHardReset || c.Local {
		t.Fatalf("unexpected Close: %+v", c)
	}

	inner, ok := c.Notification.HardReset()
	if !ok {
		t.Fatal("failed to decode the encapsulated reason")
	}

	if got, ok := inner.ShutdownCommunication(); !ok || got != "fleet drain" {
		t.Fatalf("unexpected shutdown communication in the reason: %q, %t", got, ok)
	}
}

// TestServerUnconfiguredPeerTCP verifies the unconfigured-peer path: the
// hook observes the remote's OPEN, or nil for garbage, and either way the
// remote reads Cease / Connection Rejected before the close.
func TestServerUnconfiguredPeerTCP(t *testing.T) {
	t.Parallel()

	type knock struct {
		raddr netip.AddrPort
		asn   uint32
		open  bool
	}

	knockC := make(chan knock, 4)

	l := loopbackListener(t)
	s := testServer(t, ServerConfig{
		OnUnconfiguredPeer: func(_ context.Context, raddr netip.AddrPort, o *Open) {
			k := knock{raddr: raddr, open: o != nil}
			if o != nil {
				k.asn = o.ASN
			}

			knockC <- k
		},
	})
	runServer(t, s, l)

	// expectRejected reads the farewell and then the close.
	expectRejected := func(c *Conn) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(peerTimeout))
		m, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read the farewell: %v", err)
		}

		n, ok := m.(*Notification)
		if !ok || n.Code != NotificationCease || n.Subcode != SubcodeCeaseConnectionRejected {
			t.Fatalf("expected Cease / Connection Rejected, but got: %+v", m)
		}

		if _, err := c.ReadMessage(); err == nil {
			t.Fatal("expected the connection to close")
		}
	}

	var d Dialer

	// A live speaker: its OPEN reaches the hook.
	c := must(dialAddrPort(context.Background(), &d, addrPort(l)))
	t.Cleanup(func() { _ = c.Close() })
	if err := c.WriteMessage(scriptOpen()); err != nil {
		t.Fatalf("failed to write OPEN: %v", err)
	}

	k := recv(t, knockC, "the unconfigured peer hook")
	if !k.open || k.asn != 64497 {
		t.Fatalf("unexpected knock: %+v", k)
	}

	if k.raddr.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("unexpected remote address: %s", k.raddr)
	}

	expectRejected(c)

	// Garbage instead of an OPEN: the hook observes nil, the farewell is
	// sent regardless.
	c = must(dialAddrPort(context.Background(), &d, addrPort(l)))
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.rawConn().Write([]byte("not a BGP message, not even close")); err != nil {
		t.Fatalf("failed to write garbage: %v", err)
	}

	if k := recv(t, knockC, "the unconfigured peer hook"); k.open {
		t.Fatalf("unexpected OPEN in knock: %+v", k)
	}

	expectRejected(c)
}

// TestServerMD5TCP verifies structural key sequencing end to end: a peering
// added before Run has its key on the listening socket by the time the
// remote's signed SYN arrives, and the session establishes.
func TestServerMD5TCP(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"
	addr := netip.MustParseAddr("127.0.0.1")

	l := loopbackListener(t)
	s := testServer(t, ServerConfig{})
	ev := newPeerEvents()
	if _, err := s.AddPeer(addr, ev.wire(PeerConfig{
		LocalASN:    64496,
		LocalID:     MustParseIdentifier("192.0.2.1"),
		PeerASN:     64497,
		Passive:     true,
		MD5Password: password,
	})); err != nil {
		t.Fatalf("failed to add peer: %v", err)
	}

	// Run installs the pre-added peer's key as it starts, so a permission
	// or platform failure would surface as a Run error: probe the listener
	// first and skip, mirroring the conn tests.
	if err := l.SetMD5(addr, password); err != nil {
		if errors.Is(err, errors.ErrUnsupported) || errors.Is(err, syscall.EPERM) {
			t.Skipf("skipping, TCP-MD5 not available in this environment: %v", err)
		}

		t.Fatalf("failed to install TCP-MD5 key: %v", err)
	}

	if err := l.RemoveMD5(addr); err != nil {
		t.Fatalf("failed to remove TCP-MD5 key: %v", err)
	}

	runServer(t, s, l)

	b := dialingPeer(t, l, PeerConfig{
		LocalASN:    64497,
		LocalID:     MustParseIdentifier("192.0.2.2"),
		PeerASN:     64496,
		MD5Password: password,
	})
	recv(t, ev.estC, "server peer establishment")
	recv(t, b.estC, "remote establishment")
}

// TestServerTeardownIdleUnconfigured verifies that a silent unconfigured
// peer does not delay Run's return: cancellation closes the connection
// rather than waiting out the read deadline.
func TestServerTeardownIdleUnconfigured(t *testing.T) {
	t.Parallel()

	l := loopbackListener(t)
	s := testServer(t, ServerConfig{
		OnUnconfiguredPeer: func(context.Context, netip.AddrPort, *Open) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx, l) }()
	waitServerUp(t, s)

	// Connect and say nothing, then wait for the exchange goroutine to
	// take its semaphore slot: the read is now parked on the deadline.
	// No synchronization with the exchange goroutine is needed: if cancel
	// lands before it registers its AfterFunc, registration on a canceled
	// ctx fires the close immediately, so every interleaving fails the
	// parked read promptly.
	var d Dialer
	c := must(dialAddrPort(context.Background(), &d, addrPort(l)))
	t.Cleanup(func() { _ = c.Close() })

	start := time.Now()
	cancel()
	if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if elapsed := time.Since(start); elapsed > unconfiguredPeerTimeout/2 {
		t.Fatalf("teardown waited out the unconfigured peer deadline: %s", elapsed)
	}
}

// TestServerUnconfiguredHookWatchesCtx verifies the hook's ctx: a hook
// blocked on run-scoped cancellation unblocks at teardown, and Run returns
// promptly.
func TestServerUnconfiguredHookWatchesCtx(t *testing.T) {
	t.Parallel()

	enteredC := make(chan struct{}, 1)
	l := loopbackListener(t)
	s := testServer(t, ServerConfig{
		OnUnconfiguredPeer: func(ctx context.Context, _ netip.AddrPort, _ *Open) {
			enteredC <- struct{}{}
			<-ctx.Done()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx, l) }()
	waitServerUp(t, s)

	var d Dialer
	c := must(dialAddrPort(context.Background(), &d, addrPort(l)))
	t.Cleanup(func() { _ = c.Close() })
	if err := c.WriteMessage(scriptOpen()); err != nil {
		t.Fatalf("failed to write OPEN: %v", err)
	}

	recv(t, enteredC, "the hook to start")

	start := time.Now()
	cancel()
	if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if elapsed := time.Since(start); elapsed > teardownTimeout/2 {
		t.Fatalf("teardown blocked on a ctx-watching hook: %s", elapsed)
	}
}

// TestServerStuckUnconfiguredHook verifies the abandonment bound: a hook
// which ignores its ctx delays Run by at most the teardown budget, never
// forever.
func TestServerStuckUnconfiguredHook(t *testing.T) {
	t.Parallel()

	enteredC := make(chan struct{}, 1)
	unblockC := make(chan struct{})
	defer close(unblockC)

	l := loopbackListener(t)
	s := testServer(t, ServerConfig{
		OnUnconfiguredPeer: func(context.Context, netip.AddrPort, *Open) {
			enteredC <- struct{}{}
			<-unblockC
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx, l) }()
	waitServerUp(t, s)

	var d Dialer
	c := must(dialAddrPort(context.Background(), &d, addrPort(l)))
	t.Cleanup(func() { _ = c.Close() })
	if err := c.WriteMessage(scriptOpen()); err != nil {
		t.Fatalf("failed to write OPEN: %v", err)
	}

	recv(t, enteredC, "the hook to start")

	cancel()
	if err := recv(t, runC, "Run to return despite the stuck hook"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}
}

// TestServerRunClosesListeners verifies Run's ownership of its listeners:
// each is closed when Run returns, whether the run went live, was refused,
// or was never valid, so a caller cannot leak a socket through a Server.
func TestServerRunClosesListeners(t *testing.T) {
	t.Parallel()

	s := testServer(t, ServerConfig{})

	invalid := loopbackListener(t)
	if err := s.Run(context.Background(), invalid, nil); err == nil {
		t.Fatal("expected an error for a nil listener")
	}

	if _, err := invalid.Accept(); err == nil {
		t.Fatal("expected the invalid Run's listener to be closed")
	}

	l := loopbackListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx, l) }()
	waitServerUp(t, s)

	refused := loopbackListener(t)
	if err := s.Run(ctx, refused); err == nil {
		t.Fatal("expected an error for a concurrent Run")
	}

	if _, err := refused.Accept(); err == nil {
		t.Fatal("expected the refused Run's listener to be closed")
	}

	cancel()
	if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if _, err := l.Accept(); err == nil {
		t.Fatal("expected the listener to be closed when Run returned")
	}
}

// TestServerChurnTCP hammers AddPeer/RemovePeer/Peers against a running
// Server while unconfigured peers connect: a seed of the deferred torture
// test, contributed by adversarial review.
func TestServerChurnTCP(t *testing.T) {
	t.Parallel()

	l := loopbackListener(t)
	s := testServer(t, ServerConfig{
		OnUnconfiguredPeer: func(context.Context, netip.AddrPort, *Open) {},
	})
	runServer(t, s, l)
	lap := addrPort(l)

	addrFor := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{127, 0, 0, byte(i + 1)})
	}

	cfgFor := func(i int) PeerConfig {
		return PeerConfig{
			LocalASN: 64496,
			LocalID:  Identifier(i + 1),
			PeerASN:  64497,
			Passive:  true,
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for ctx.Err() == nil {
				if _, err := s.AddPeer(addrFor(i), cfgFor(i)); err != nil {
					t.Errorf("failed to add peer %d: %v", i, err)
					return
				}

				if err := s.RemovePeer(addrFor(i), nil); err != nil {
					t.Errorf("failed to remove peer %d: %v", i, err)
					return
				}
			}
		})
	}

	// Iterate the table and use the yielded Peers concurrently.
	wg.Go(func() {
		for ctx.Err() == nil {
			for _, p := range s.Peers() {
				_ = p.SendUpdate(context.Background(), &Update{})
			}
		}
	})

	// Real connections into the demultiplexer: sometimes a configured
	// address (127.0.0.1..8), sometimes not.
	wg.Go(func() {
		for ctx.Err() == nil {
			c, err := net.DialTimeout("tcp4", lap.String(), time.Second)
			if err != nil {
				return
			}

			_ = c.Close()
		}
	})

	wg.Wait()
}

// TestServerRunRestartChurn restarts Run repeatedly while a peer is added
// and removed, exercising the setup/teardown window. Contributed by
// adversarial review; the original paced with a sleep, replaced here by
// deterministic alternation between canceling a live run and racing setup.
func TestServerRunRestartChurn(t *testing.T) {
	t.Parallel()

	s := testServer(t, ServerConfig{})

	addr := netip.MustParseAddr("127.0.0.9")
	cfg := PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64497,
		Passive:  true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Go(func() {
		for ctx.Err() == nil {
			if _, err := s.AddPeer(addr, cfg); err == nil {
				if err := s.RemovePeer(addr, nil); err != nil {
					t.Errorf("failed to remove peer: %v", err)
					return
				}
			}
		}
	})

	for i := 0; ctx.Err() == nil; i++ {
		// Run closes its listener, so each run binds afresh.
		l, err := (&ListenConfig{}).Listen(ctx, netip.MustParseAddrPort("127.0.0.1:0"))
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}

		rctx, rcancel := context.WithCancel(context.Background())
		runC := make(chan error, 1)
		go func() { runC <- s.Run(rctx, l) }()

		// Even iterations cancel a live run; odd iterations cancel
		// immediately, racing setup.
		if i%2 == 0 {
			waitServerUp(t, s)
		}

		rcancel()
		if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected Run error: %v", err)
			break
		}
	}

	cancel()
	wg.Wait()
}

// TestServerAddPeerRequiresAddr verifies that a Server refuses an
// unaddressed peering: its remote address is the demultiplexing key.
func TestServerAddPeerRequiresAddr(t *testing.T) {
	t.Parallel()

	srv := NewServer(ServerConfig{})
	_, err := srv.AddPeer(netip.Addr{}, PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	})
	if err == nil {
		t.Fatal("expected an error from an unaddressed Server peer, but none occurred")
	}
}

// dialingPeer starts a peer under test which dials the Server listener l:
// the Dialer's Port is the listener's ephemeral one.
func dialingPeer(tb testing.TB, l *Listener, cfg PeerConfig) *peerRig {
	tb.Helper()

	ap := addrPort(l)
	cfg.Dialer.Port = ap.Port()
	return testPeer(tb, ap.Addr(), cfg)
}

// testServer builds a Server with a test logger.
func testServer(tb testing.TB, cfg ServerConfig) *Server {
	tb.Helper()

	if cfg.Logger == nil {
		cfg.Logger = testLogger(tb)
	}

	return NewServer(cfg)
}

// loopbackListener binds a loopback Listener on an ephemeral port for a Server
// under test. Run closes it; the cleanup covers a test which never runs.
func loopbackListener(tb testing.TB) *Listener {
	tb.Helper()

	l, err := (&ListenConfig{}).Listen(context.Background(), netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		tb.Fatalf("failed to listen: %v", err)
	}

	tb.Cleanup(func() { _ = l.Close() })
	return l
}

// addrPort returns the bound address of a test listener.
func addrPort(l *Listener) netip.AddrPort {
	return l.Addr().(*net.TCPAddr).AddrPort()
}

// runServer runs s on ls in the background until the end of the test,
// returning the cause-carrying cancel for tests which end the run
// themselves. It waits until the run is live: keys installed and pre-added
// peers started.
func runServer(tb testing.TB, s *Server, ls ...*Listener) context.CancelCauseFunc {
	tb.Helper()

	ctx, cancel := context.WithCancelCause(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- s.Run(ctx, ls...) }()
	tb.Cleanup(func() {
		cancel(nil)
		if err := recv(tb, runC, "server Run to return"); !errors.Is(err, context.Canceled) {
			tb.Errorf("unexpected server Run error: %v", err)
		}
	})

	waitServerUp(tb, s)
	return cancel
}

// waitServerUp blocks until s's Run has gone live: keys installed and
// pre-added peers started. setup claims the Server and publishes the run
// under one hold of s.mu, so once the running marker has closed, taking
// the lock waits out the rest of setup, and the run is then published or
// has already failed.
func waitServerUp(tb testing.TB, s *Server) {
	tb.Helper()

	s.mu.Lock()
	runningC := s.runningC
	s.mu.Unlock()

	select {
	case <-runningC:
	case <-time.After(peerTimeout):
		tb.Fatal("timed out waiting for the server run to start")
	}

	s.mu.Lock()
	live := s.run != nil
	s.mu.Unlock()
	if !live {
		tb.Fatal("the server run failed before going live")
	}
}

// scriptListener creates a local listener for a scripted remote speaker.
func scriptListener(tb testing.TB) net.Listener {
	tb.Helper()

	l, err := nettest.NewLocalListener("tcp")
	if err != nil {
		tb.Fatalf("failed to create listener: %v", err)
	}

	tb.Cleanup(func() { _ = l.Close() })
	return l
}

// acceptScriptOn waits for a peer to dial l and returns the scripted side.
func acceptScriptOn(tb testing.TB, l net.Listener) *script {
	tb.Helper()

	type accepted struct {
		c   net.Conn
		err error
	}

	acceptC := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptC <- accepted{c: c, err: err}
	}()

	a := recv(tb, acceptC, "the peer to dial")
	if a.err != nil {
		tb.Fatalf("failed to accept: %v", a.err)
	}

	return newScript(tb, a.c)
}

// peerEvents records one managed peer's session lifecycle for assertions.
type peerEvents struct {
	estC   chan Session
	closeC chan Close
}

func newPeerEvents() *peerEvents {
	return &peerEvents{
		estC:   make(chan Session, 4),
		closeC: make(chan Close, 4),
	}
}

// wire attaches the recording handlers to cfg.
func (e *peerEvents) wire(cfg PeerConfig) PeerConfig {
	cfg.OnEstablished = func(_ context.Context, _ *Peer, s Session) error {
		e.estC <- s
		return nil
	}

	cfg.OnClose = func(_ *Peer, c Close) { e.closeC <- c }
	return cfg
}

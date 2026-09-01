package bgp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/nettest"
)

// TestPeerCollision exercises RFC 4271, section 6.8 collision resolution
// across identifier orderings, arrival orders, and the RFC 6286 ASN
// tiebreak: exactly one connection survives to Established, and the loser
// sees Cease / Connection Collision Resolution.
func TestPeerCollision(t *testing.T) {
	t.Parallel()

	// The local speaker is ASN 64496, identifier 192.0.2.10.
	localID := MustParseIdentifier("192.0.2.10")

	tests := []struct {
		name    string
		peerID  Identifier
		peerASN uint32
		// openOn names the connection whose peer OPEN triggers resolution.
		openOn openConn
		// confirmFirst drives the dialed connection to OpenConfirm before
		// the accepted connection exists.
		confirmFirst bool
		// wantDialed reports whether the locally dialed connection must
		// survive.
		wantDialed bool
	}{
		{
			name:       "peer lower id, open on dialed",
			peerID:     MustParseIdentifier("192.0.2.2"),
			peerASN:    64497,
			openOn:     openOnDialed,
			wantDialed: true,
		},
		{
			name:       "peer lower id, open on accepted",
			peerID:     MustParseIdentifier("192.0.2.2"),
			peerASN:    64497,
			openOn:     openOnAccepted,
			wantDialed: true,
		},
		{
			name:       "peer higher id, open on dialed",
			peerID:     MustParseIdentifier("192.0.2.20"),
			peerASN:    64497,
			openOn:     openOnDialed,
			wantDialed: false,
		},
		{
			name:       "peer higher id, open on accepted",
			peerID:     MustParseIdentifier("192.0.2.20"),
			peerASN:    64497,
			openOn:     openOnAccepted,
			wantDialed: false,
		},
		{
			// Equal identifiers across ASes are legal (RFC 6286, section
			// 2.3): the tie breaks on the higher ASN. An equal identifier
			// AND an equal ASN is the internal duplicate which negotiate
			// rejects with Bad BGP Identifier; see TestPeerOpenRejected.
			name:       "equal id, peer higher ASN",
			peerID:     localID,
			peerASN:    64497,
			openOn:     openOnDialed,
			wantDialed: false,
		},
		// Two tracked connections are never both in OpenConfirm: the
		// second peer OPEN of an attempt always resolves the collision,
		// whichever connection carries it and whatever state the other is
		// in. handleKeepalive relies on this when it drops the other
		// connection without a verdict. The two confirmFirst cases pin it
		// from both sides of the tie-break.
		{
			name:         "dialed in OpenConfirm loses",
			peerID:       MustParseIdentifier("192.0.2.20"),
			peerASN:      64497,
			openOn:       openOnAccepted,
			confirmFirst: true,
			wantDialed:   false,
		},
		{
			name:         "dialed in OpenConfirm wins",
			peerID:       MustParseIdentifier("192.0.2.2"),
			peerASN:      64497,
			openOn:       openOnAccepted,
			confirmFirst: true,
			wantDialed:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				open := &Open{
					ASN:      tt.peerASN,
					HoldTime: 90 * time.Second,
					ID:       tt.peerID,
				}

				r := newPipeRig(t, PeerConfig{LocalID: localID})
				dialed := r.acceptScript()
				dialed.expectOpen()

				if tt.confirmFirst {
					// The dialed connection reaches OpenConfirm: its OPEN is
					// accepted and confirmed, but the peer withholds the final
					// KEEPALIVE while its own connection arrives.
					dialed.write(open)
					dialed.expectKeepalive()
				}

				accepted := r.deliver()
				accepted.expectOpen()

				trigger, other := dialed, accepted
				if tt.openOn == openOnAccepted {
					trigger, other = accepted, dialed
				}

				trigger.write(open)

				survivor, loser := accepted, dialed
				if tt.wantDialed {
					survivor, loser = dialed, accepted
				}

				loser.expectNotification(&Notification{
					Code:    NotificationCease,
					Subcode: SubcodeCeaseConnectionCollisionResolution,
				})
				loser.expectClosed()

				// Complete the exchange on the survivor: when the survivor's own
				// peer OPEN has not been sent yet, it goes first; when it was
				// confirmed before the collision, its KEEPALIVE was already read.
				if survivor == other && !tt.confirmFirst {
					survivor.write(open)
				}

				if !(tt.confirmFirst && survivor == dialed) {
					survivor.expectKeepalive()
				}

				survivor.write(&Keepalive{})

				sess := recv(t, r.estC, "session establishment")
				if d := diff(t, tt.peerID, sess.Peer.ID); d != "" {
					t.Fatalf("unexpected established peer ID (-want +got):\n%s", d)
				}
			})
		})
	}

	// A confirming KEEPALIVE arriving while the other connection is still
	// in OpenSent establishes the confirmed connection and drops the other,
	// regardless of identifier order: the peer demonstrably accepted our
	// OPEN on the confirmed connection, and an RFC-default peer has already
	// established there, so a tie-break preferring the other connection
	// would tear down the one connection both speakers agree on. Both
	// identifier orderings pin that no tie-break runs; under the section
	// 6.8 comparison the higher-id case would kill the dialed connection.
	ceaseCollision := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseConnectionCollisionResolution,
	}

	for _, peerID := range []Identifier{
		MustParseIdentifier("192.0.2.20"), // higher than localID
		MustParseIdentifier("192.0.2.2"),  // lower than localID
	} {
		t.Run(fmt.Sprintf("keepalive first, peer %s", peerID), func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				open := &Open{
					ASN:      64497,
					HoldTime: 90 * time.Second,
					ID:       peerID,
				}

				r := newPipeRig(t, PeerConfig{LocalID: localID})
				dialed := r.acceptScript()
				dialed.expectOpen()

				// The dialed connection reaches OpenConfirm before the collision
				// connection exists, then the peer confirms it before sending
				// its OPEN on the accepted connection.
				dialed.write(open)
				dialed.expectKeepalive()
				accepted := r.deliver()
				accepted.expectOpen()
				dialed.write(&Keepalive{})

				// The dialed connection establishes; the accepted connection is
				// dropped, whatever the identifiers say.
				accepted.expectNotification(ceaseCollision)
				accepted.expectClosed()
				sess := recv(t, r.estC, "session establishment")
				if d := diff(t, peerID, sess.Peer.ID); d != "" {
					t.Fatalf("unexpected established peer ID (-want +got):\n%s", d)
				}
			})
		})
	}

	// A peer which claims a different identity on each collision connection
	// must not steer the tie-break: the first accepted claim wins, and a
	// contradicting OPEN is rejected.
	contradictions := []struct {
		name   string
		mutate func(o *Open)
		want   *Notification
	}{
		{
			name:   "contradicted identifier",
			mutate: func(o *Open) { o.ID = MustParseIdentifier("192.0.2.20") },
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadBGPIdentifier,
			},
		},
		{
			name:   "contradicted ASN",
			mutate: func(o *Open) { o.ASN = 64498 },
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadPeerAS,
			},
		},
	}

	for _, tt := range contradictions {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				first := &Open{
					ASN:      64497,
					HoldTime: 90 * time.Second,
					ID:       MustParseIdentifier("192.0.2.2"),
				}

				second := &Open{ASN: first.ASN, HoldTime: first.HoldTime, ID: first.ID}
				tt.mutate(second)

				r := newPipeRig(t, PeerConfig{LocalID: localID})
				dialed := r.acceptScript()
				dialed.expectOpen()

				// The dialed connection's OPEN fixes the peer's claimed
				// identity for the attempt.
				dialed.write(first)
				dialed.expectKeepalive()

				accepted := r.deliver()
				accepted.expectOpen()
				accepted.write(second)

				accepted.expectNotification(tt.want)
				accepted.expectClosed()

				// The connection carrying the first claim is undisturbed.
				dialed.write(&Keepalive{})
				recv(t, r.estC, "session establishment")
			})
		})
	}
}

// TestPeerCollisionEstablished verifies CollisionDetectEstablishedState =
// false: a connection which arrives after the session is established is
// dropped immediately, without displacing the session.
func TestPeerCollisionEstablished(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		late := r.deliver()
		late.expectNotification(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseConnectionRejected,
		})
		late.expectClosed()

		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	})
}

// TestPeerSelfPeering drives two Peers to Established against each other
// over real loopback TCP with real timers: the active side dials, the
// passive side accepts, and cancellation tears both down with Cease /
// Administrative Shutdown in the right directions.
func TestPeerSelfPeering(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
	v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

	l, err := nettest.NewLocalListener("tcp")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	defer func() { _ = l.Close() }()
	laddr := l.Addr().(*net.TCPAddr).AddrPort()

	// Each side's OnUpdate hands the received prefixes to the test. The
	// Update references the read buffer, so the handler clones what it
	// keeps, exactly as a real consumer must. Each side's OnKeepalive
	// signals in-session keepalive receipt; the non-blocking send never
	// stalls the receive path once the test has its proof.
	activeUpdC := make(chan []netip.Prefix, 1)
	passiveUpdC := make(chan []netip.Prefix, 1)
	activeKaC := make(chan struct{}, 1)
	passiveKaC := make(chan struct{}, 1)

	// The active side proposes the RFC minimum hold time of 3s, so real
	// keepalives flow within the test's lifetime.
	active := testPeer(t, laddr.Addr(), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		HoldTime: 3 * time.Second,
		PeerASN:  64497,
		Families: []Family{v4u, v6u},
		Dialer:   Dialer{Port: laddr.Port()},
		OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
			activeUpdC <- slices.Clone(u.NLRI)
			return nil
		},
		OnKeepalive: func(_ context.Context, _ *Peer) error {
			select {
			case activeKaC <- struct{}{}:
			default:
			}

			return nil
		},
		Logger: testLogger(t),
	})

	nc, err := l.Accept()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}

	raddr := nc.RemoteAddr().(*net.TCPAddr).AddrPort()

	passive := testPeer(t, raddr.Addr(), PeerConfig{
		LocalASN: 64497,
		LocalID:  MustParseIdentifier("192.0.2.2"),
		HoldTime: 4 * time.Second,
		PeerASN:  64496,
		Families: []Family{v4u},
		Passive:  true,
		OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
			passiveUpdC <- slices.Clone(u.NLRI)
			return nil
		},
		OnKeepalive: func(_ context.Context, _ *Peer) error {
			select {
			case passiveKaC <- struct{}{}:
			default:
			}

			return nil
		},
		Logger: testLogger(t),
	})
	if err := passive.p.DeliverConn(NewConn(nc)); err != nil {
		t.Fatalf("failed to deliver connection: %v", err)
	}

	sa := recv(t, active.estC, "active session establishment")
	sp := recv(t, passive.estC, "passive session establishment")

	// Both sides negotiate the minimum proposed hold time and the common
	// IPv4 unicast family.
	for _, s := range []Session{sa, sp} {
		if s.HoldTime != 3*time.Second {
			t.Fatalf("unexpected negotiated hold time: %s", s.HoldTime)
		}

		if d := diff(t, []Family{v4u}, s.Families); d != "" {
			t.Fatalf("unexpected negotiated families (-want +got):\n%s", d)
		}
	}

	if sa.Peer.ASN != 64497 || sp.Peer.ASN != 64496 {
		t.Fatalf("unexpected peer ASNs: active saw %d, passive saw %d", sa.Peer.ASN, sp.Peer.ASN)
	}

	// Exchange a route in each origin through the send path.
	attrs := mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
		NextHop(netip.MustParseAddr("192.0.2.1")))
	for _, x := range []struct {
		from *peerRig
		to   chan []netip.Prefix
		p    netip.Prefix
	}{
		{from: active, to: passiveUpdC, p: netip.MustParsePrefix("203.0.113.0/24")},
		{from: passive, to: activeUpdC, p: netip.MustParsePrefix("198.51.100.0/24")},
	} {
		if err := x.from.p.SendUpdate(context.Background(), &Update{
			Attributes: attrs,
			NLRI:       []netip.Prefix{x.p},
		}); err != nil {
			t.Fatalf("failed to send UPDATE: %v", err)
		}

		if d := diff(t, []netip.Prefix{x.p}, recv(t, x.to, "route delivery")); d != "" {
			t.Fatalf("unexpected received prefixes (-want +got):\n%s", d)
		}
	}

	// A timer-driven KEEPALIVE (3s hold / 3 = 1s) arriving on each side
	// proves the timers hold the session up, not just the initial exchange:
	// OnKeepalive fires only for in-session keepalives.
	recv(t, activeKaC, "active keepalive receipt")
	recv(t, passiveKaC, "passive keepalive receipt")
	for _, r := range []*peerRig{active, passive} {
		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	}

	// Stopping the active side is an administrative shutdown: it reports
	// sending the Cease, and the passive side reports receiving it.
	active.cancel()

	want := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseAdministrativeShutdown,
	}

	ca := recv(t, active.closeC, "active session close")
	if d := diff(t, want, ca.Notification); d != "" || !ca.Local {
		t.Fatalf("unexpected active close (local=%t) (-want +got):\n%s", !ca.Local, d)
	}

	cp := recv(t, passive.closeC, "passive session close")
	if d := diff(t, want, cp.Notification); d != "" || cp.Local {
		t.Fatalf("unexpected passive close (local=%t) (-want +got):\n%s", !cp.Local, d)
	}
}

// TestPeerSelfPeeringUnix is TestPeerSelfPeering over a Unix socket instead
// of loopback TCP: the same two Peers, the same real timers, and the same
// teardown, driven through the transport seams rather than the TCP paths.
// The active side dials through PeerConfig.DialFunc and the passive side
// takes a delivered *net.UnixConn, which together pin the two properties a
// non-TCP transport depends on — a dial the package does not perform itself,
// and an accept whose remote address no raddr could be matched against.
//
// Nothing in the FSM is transport-aware, so this test's value is the seams,
// not the state machine: it fails if either seam closes back up around TCP.
func TestPeerSelfPeeringUnix(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
	v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

	// The socket lives in the test's own directory, which is removed with
	// it. Unix socket paths are bounded well below PATH_MAX, so the name is
	// kept short.
	path := filepath.Join(t.TempDir(), "bgp.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to listen on a Unix socket: %v", err)
	}

	defer func() { _ = l.Close() }()

	// Each side's OnUpdate hands the received prefixes to the test. The
	// Update references the read buffer, so the handler clones what it
	// keeps, exactly as a real consumer must. Each side's OnKeepalive
	// signals in-session keepalive receipt; the non-blocking send never
	// stalls the receive path once the test has its proof.
	activeUpdC := make(chan []netip.Prefix, 1)
	passiveUpdC := make(chan []netip.Prefix, 1)
	activeKaC := make(chan struct{}, 1)
	passiveKaC := make(chan struct{}, 1)

	// A Unix socket peering has no address space to name its peers in, so
	// each side's addr is zero — the unaddressed-transport allowance — and
	// the DialFunc closes over the socket path, its own notion of where.
	// Who may answer is pinned by PeerASN, exactly as over TCP.

	// The active side proposes the RFC minimum hold time of 3s, so real
	// keepalives flow within the test's lifetime.
	active := testPeer(t, netip.Addr{}, PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		HoldTime: 3 * time.Second,
		PeerASN:  64497,
		Families: []Family{v4u, v6u},
		DialFunc: func(ctx context.Context) (*Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}

			return NewConn(c), nil
		},
		OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
			activeUpdC <- slices.Clone(u.NLRI)
			return nil
		},
		OnKeepalive: func(_ context.Context, _ *Peer) error {
			select {
			case activeKaC <- struct{}{}:
			default:
			}

			return nil
		},
		Logger: testLogger(t),
	})

	nc, err := l.Accept()
	if err != nil {
		t.Fatalf("failed to accept: %v", err)
	}

	// The accepted side of a Unix socket reports an unnamed remote — an
	// autobind address, not the socket's path — so no raddr could ever be
	// matched against it. Pinning that here says why the passive side must
	// accept the connection on the caller's word alone.
	ua, ok := nc.RemoteAddr().(*net.UnixAddr)
	if !ok {
		t.Fatalf("expected a *net.UnixAddr remote address, but got %T", nc.RemoteAddr())
	}

	if ua.Name == path {
		t.Fatalf("expected the accepted remote address not to name the socket, but got %q", ua.Name)
	}

	passive := testPeer(t, netip.Addr{}, PeerConfig{
		LocalASN: 64497,
		LocalID:  MustParseIdentifier("192.0.2.2"),
		HoldTime: 4 * time.Second,
		PeerASN:  64496,
		Families: []Family{v4u},
		Passive:  true,
		OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
			passiveUpdC <- slices.Clone(u.NLRI)
			return nil
		},
		OnKeepalive: func(_ context.Context, _ *Peer) error {
			select {
			case passiveKaC <- struct{}{}:
			default:
			}

			return nil
		},
		Logger: testLogger(t),
	})
	if err := passive.p.DeliverConn(NewConn(nc)); err != nil {
		t.Fatalf("failed to deliver connection: %v", err)
	}

	sa := recv(t, active.estC, "active session establishment")
	sp := recv(t, passive.estC, "passive session establishment")

	// Both sides negotiate the minimum proposed hold time and the common
	// IPv4 unicast family, exactly as they do over TCP: negotiation reads
	// the OPENs, never the transport.
	for _, s := range []Session{sa, sp} {
		if s.HoldTime != 3*time.Second {
			t.Fatalf("unexpected negotiated hold time: %s", s.HoldTime)
		}

		if d := diff(t, []Family{v4u}, s.Families); d != "" {
			t.Fatalf("unexpected negotiated families (-want +got):\n%s", d)
		}
	}

	if sa.Peer.ASN != 64497 || sp.Peer.ASN != 64496 {
		t.Fatalf("unexpected peer ASNs: active saw %d, passive saw %d", sa.Peer.ASN, sp.Peer.ASN)
	}

	// Exchange a route in each origin through the send path.
	attrs := mustAttributes(t, OriginIGP, ASPath{{ASNs: []uint32{64496}}},
		NextHop(netip.MustParseAddr("192.0.2.1")))
	for _, x := range []struct {
		from *peerRig
		to   chan []netip.Prefix
		p    netip.Prefix
	}{
		{from: active, to: passiveUpdC, p: netip.MustParsePrefix("203.0.113.0/24")},
		{from: passive, to: activeUpdC, p: netip.MustParsePrefix("198.51.100.0/24")},
	} {
		if err := x.from.p.SendUpdate(context.Background(), &Update{
			Attributes: attrs,
			NLRI:       []netip.Prefix{x.p},
		}); err != nil {
			t.Fatalf("failed to send UPDATE: %v", err)
		}

		if d := diff(t, []netip.Prefix{x.p}, recv(t, x.to, "route delivery")); d != "" {
			t.Fatalf("unexpected received prefixes (-want +got):\n%s", d)
		}
	}

	// A timer-driven KEEPALIVE (3s hold / 3 = 1s) arriving on each side
	// proves the timers hold the session up, not just the initial exchange:
	// OnKeepalive fires only for in-session keepalives.
	recv(t, activeKaC, "active keepalive receipt")
	recv(t, passiveKaC, "passive keepalive receipt")
	for _, r := range []*peerRig{active, passive} {
		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	}

	// Stopping the active side is an administrative shutdown: it reports
	// sending the Cease, and the passive side reports receiving it. The
	// NOTIFICATION rides the Unix socket like any other write.
	active.cancel()

	want := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseAdministrativeShutdown,
	}

	ca := recv(t, active.closeC, "active session close")
	if d := diff(t, want, ca.Notification); d != "" || !ca.Local {
		t.Fatalf("unexpected active close (local=%t) (-want +got):\n%s", !ca.Local, d)
	}

	cp := recv(t, passive.closeC, "passive session close")
	if d := diff(t, want, cp.Notification); d != "" || cp.Local {
		t.Fatalf("unexpected passive close (local=%t) (-want +got):\n%s", !cp.Local, d)
	}
}

// An openConn names one of a collision's two connections: the one whose
// peer OPEN triggers resolution.
type openConn int

const (
	openOnDialed openConn = iota
	openOnAccepted
)

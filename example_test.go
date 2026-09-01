package bgp_test

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/mdlayher/bgp"
)

// A classic IPv4 unicast speaker: dial one remote peer, announce one route
// when the session is established, and log routes received in return.
func Example() {
	// The route to announce, prepared up front: path attributes are carried
	// in wire form, so parsed attributes are marshaled once and reused for
	// every session.
	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{64496}}},
		bgp.NextHop(netip.MustParseAddr("192.0.2.10")),
	)
	if err != nil {
		log.Fatalf("failed to marshal attributes: %v", err)
	}

	// The peering: the remote speaker's address to dial, then this
	// speaker's identity. An empty Families list advertises no
	// multiprotocol capabilities: the classic IPv4 unicast speaker.
	p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,

		OnEstablished: func(ctx context.Context, p *bgp.Peer, s bgp.Session) error {
			// One announcement and End-of-RIB fit comfortably in a handler; a
			// bulk table push belongs on a goroutine bound to ctx instead. See
			// PeerConfig.
			announce := &bgp.Update{
				Attributes: attrs,
				NLRI:       []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			}

			if err := p.SendUpdate(ctx, announce); err != nil {
				return err
			}

			return p.SendUpdate(ctx, bgp.NewEndOfRIB(bgp.Family{
				AFI:  bgp.AFIIPv4,
				SAFI: bgp.SAFIUnicast,
			}))
		},

		OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
			// u is fully owned: it may be retained or handed to another
			// goroutine freely.
			log.Printf("update: reachable %v, withdrawn %v", u.NLRI, u.Withdrawn)
			return nil
		},

		OnClose: func(_ *bgp.Peer, c bgp.Close) {
			// The session is already down and Run will retry; observe why.
			log.Printf("closed: notification=%+v err=%v", c.Notification, c.Err)
		},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	// Canceling ctx sends the peer Cease / Administrative Shutdown and returns.
	// Run blocks the caller and owns the connection lifecycle: dialing,
	// retrying with backoff, and replacing dead sessions until ctx is canceled.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := p.Run(ctx); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// A multiprotocol IPv6 unicast speaker: the family is negotiated via the
// multiprotocol capability (RFC 4760), and reachability travels in an
// MP_REACH_NLRI attribute rather than the UPDATE's IPv4 NLRI field.
func Example_multiprotocol() {
	v6 := bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}

	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{64496}}},
		bgp.MPReachNLRI{
			Family:  v6,
			NextHop: netip.MustParseAddr("2001:db8::10"),
			NLRI:    bgp.Prefixes{netip.MustParsePrefix("2001:db8:100::/48")},
		},
	)
	if err != nil {
		log.Fatalf("failed to marshal attributes: %v", err)
	}

	p, err := bgp.NewPeer(netip.MustParseAddr("2001:db8::1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,
		Families: []bgp.Family{v6},

		OnEstablished: func(ctx context.Context, p *bgp.Peer, _ bgp.Session) error {
			if err := p.SendUpdate(ctx, &bgp.Update{Attributes: attrs}); err != nil {
				return err
			}

			return p.SendUpdate(ctx, bgp.NewEndOfRIB(v6))
		},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	if err := p.Run(context.Background()); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// A dual-stack speaker: one session negotiates IPv4 and IPv6 unicast, each
// family announced in its own MP_REACH_NLRI and ended with its own
// End-of-RIB. Received routes are found by attribute type with Lookup.
func Example_dualStack() {
	v4 := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	v6 := bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}

	// One announcement per family. Sessions which negotiate multiprotocol
	// support carry IPv4 in MP_REACH_NLRI too, leaving the UPDATE's classic
	// IPv4 fields empty.
	announce := map[bgp.Family]*bgp.Update{}
	for _, r := range []struct {
		family  bgp.Family
		nextHop netip.Addr
		prefix  netip.Prefix
	}{
		{v4, netip.MustParseAddr("192.0.2.10"), netip.MustParsePrefix("198.51.100.0/24")},
		{v6, netip.MustParseAddr("2001:db8::10"), netip.MustParsePrefix("2001:db8:100::/48")},
	} {
		attrs, err := bgp.MarshalAttributes(
			bgp.OriginIGP,
			bgp.ASPath{{ASNs: []uint32{64496}}},
			bgp.MPReachNLRI{Family: r.family, NextHop: r.nextHop, NLRI: bgp.Prefixes{r.prefix}},
		)
		if err != nil {
			log.Fatalf("failed to marshal attributes: %v", err)
		}

		announce[r.family] = &bgp.Update{Attributes: attrs}
	}

	p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,
		Families: []bgp.Family{v4, v6},

		OnEstablished: func(ctx context.Context, p *bgp.Peer, s bgp.Session) error {
			// Announce into each family the peer agreed to; s.Families is
			// the intersection of both speakers' offers.
			for _, f := range s.Families {
				if err := p.SendUpdate(ctx, announce[f]); err != nil {
					return err
				}

				if err := p.SendUpdate(ctx, bgp.NewEndOfRIB(f)); err != nil {
					return err
				}
			}

			return nil
		},

		OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
			// Parse only the attributes of interest; the rest stay raw.
			if reach, ok, err := bgp.Lookup[bgp.MPReachNLRI](u.Attributes); err != nil {
				return err
			} else if ok {
				log.Printf("%s reachable via %s: %v", reach.Family, reach.NextHop, reach.NLRI)
			}

			if unreach, ok, err := bgp.Lookup[bgp.MPUnreachNLRI](u.Attributes); err != nil {
				return err
			} else if ok {
				log.Printf("%s withdrawn: %v", unreach.Family, unreach.NLRI)
			}

			return nil
		},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	if err := p.Run(context.Background()); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// IPv4 routes over an IPv6-only link (RFC 8950): the peering runs over IPv6,
// the extended next hop capability is advertised for IPv4 unicast, and IPv4
// reachability is announced with an IPv6 next hop. This is the shape of BGP
// unnumbered fabrics.
func Example_extendedNextHop() {
	v4 := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}

	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{64496}}},
		bgp.MPReachNLRI{
			Family:  v4,
			NextHop: netip.MustParseAddr("2001:db8::10"),
			NLRI:    bgp.Prefixes{netip.MustParsePrefix("198.51.100.0/24")},
		},
	)
	if err != nil {
		log.Fatalf("failed to marshal attributes: %v", err)
	}

	p, err := bgp.NewPeer(netip.MustParseAddr("2001:db8::1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,
		Families: []bgp.Family{v4},
		// Capabilities beyond the ones Identity's fields express are
		// advertised raw; the Session reports what the peer agreed to.
		Capabilities: []bgp.Capability{bgp.ExtendedNextHopCapability(v4)},

		OnEstablished: func(ctx context.Context, p *bgp.Peer, s bgp.Session) error {
			// Without the peer's agreement an IPv6 next hop for IPv4 is a
			// malformed attribute on its side; end the session rather than
			// announce one. The Cease is this handler's error.
			if !slices.Contains(s.ExtendedNextHop, v4) {
				return errors.New("peer does not accept an IPv6 next hop for IPv4 unicast")
			}

			if err := p.SendUpdate(ctx, &bgp.Update{Attributes: attrs}); err != nil {
				return err
			}

			return p.SendUpdate(ctx, bgp.NewEndOfRIB(v4))
		},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	if err := p.Run(context.Background()); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// A hardened external peering: TCP-MD5 (RFC 2385) authenticates the TCP
// session and GTSM (RFC 5082) rejects packets from beyond the directly
// connected peer. Both are transport properties of the peering, so the
// key is peering config and the TTL floor is dialer config.
func Example_hardened() {
	p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,

		// The key covers both directions: the Peer signs the connections it
		// dials, and a Server installs it on its listeners for the ones it
		// accepts. Without a Server, a passive caller installs it with
		// Listener.SetMD5 before the remote SYN can arrive.
		//
		// A key mismatch never produces a connection: the kernel drops the
		// missigned segments, so the symptom is a dial which times out and
		// is retried, visible in the Logger's retry activity. OnClose does
		// not fire for an attempt with no connection to report.
		MD5Password: "correct horse battery staple",

		// GTSM sends with TTL 255 and drops anything arriving lower: a
		// packet which crossed a router cannot reach the session. The
		// remote must run GTSM too, or its packets are dropped here.
		Dialer: bgp.Dialer{TCPOptions: bgp.TCPOptions{GTSM: true}},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	if err := p.Run(context.Background()); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// Route refresh (RFC 2918) in both directions: advertising the capability
// promises to re-send the table when the peer asks, and asking the peer
// re-fetches its table when local policy changes — without a session reset.
func Example_routeRefresh() {
	v4 := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}

	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{64496}}},
		bgp.NextHop(netip.MustParseAddr("192.0.2.10")),
	)
	if err != nil {
		log.Fatalf("failed to marshal attributes: %v", err)
	}

	// The whole table, sent at establishment and again on every refresh
	// request. A real RIB snapshots under its lock and sends outside it.
	advertise := func(ctx context.Context, p *bgp.Peer) error {
		announce := &bgp.Update{
			Attributes: attrs,
			NLRI:       []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		}

		if err := p.SendUpdate(ctx, announce); err != nil {
			return err
		}

		return p.SendUpdate(ctx, bgp.NewEndOfRIB(v4))
	}

	p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,
		// Advertising the capability requires OnRouteRefresh: the promise
		// must be kept.
		RouteRefresh: true,

		OnEstablished: func(ctx context.Context, p *bgp.Peer, _ bgp.Session) error {
			return advertise(ctx, p)
		},
		OnRouteRefresh: func(ctx context.Context, p *bgp.Peer, r *bgp.RouteRefresh) error {
			// The peer asked for the table again: its inbound policy
			// changed, or it lost state.
			if r.Family != v4 {
				return nil
			}

			return advertise(ctx, p)
		},
		OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
			log.Printf("update: reachable %v, withdrawn %v", u.NLRI, u.Withdrawn)
			return nil
		},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// A reload of local inbound policy re-fetches the peer's routes so the
	// new policy applies to all of them. SendRouteRefresh is safe from any
	// goroutine, and reports an error when the peer did not advertise the
	// capability or no session is established.
	go func() {
		reload := make(chan os.Signal, 1)
		signal.Notify(reload, syscall.SIGHUP)
		for range reload {
			if err := p.SendRouteRefresh(ctx, v4); err != nil {
				log.Printf("failed to request route refresh: %v", err)
			}
		}
	}()

	if err := p.Run(ctx); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// The expert layer: an FSM delivers zero-copy borrowed values to its
// handlers and runs exactly one session attempt per Connect, leaving the
// retry policy to the caller. Most callers want Peer instead.
func ExampleFSM() {
	// The FSM carries no addressing: its transport is a DialFunc, here a
	// Dialer closed over the remote address.
	var d bgp.Dialer
	peer := netip.MustParseAddr("192.0.2.1")

	// Retained attributes must be detached from the read buffer before the
	// handler returns; the prefixes are consumed in place.
	retained := map[netip.Prefix]bgp.RawAttributes{}

	f, err := bgp.NewFSM(bgp.FSMConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,
		DialFunc: func(ctx context.Context) (*bgp.Conn, error) {
			return d.Dial(ctx, peer)
		},

		OnUpdate: func(_ context.Context, _ *bgp.FSM, u *bgp.Update) error {
			// u borrows the connection's read buffer and is valid only for
			// this call: Clone what outlives it, and nothing else.
			for _, prefix := range u.Withdrawn {
				delete(retained, prefix)
			}

			if len(u.NLRI) == 0 {
				return nil
			}

			attrs := u.Attributes.Clone()
			for _, prefix := range u.NLRI {
				retained[prefix] = attrs
			}

			return nil
		},
		OnClose: func(_ *bgp.FSM, c bgp.Close) {
			log.Printf("closed: established=%t notification=%+v err=%v", c.Established, c.Notification, c.Err)
		},
	})
	if err != nil {
		log.Fatalf("failed to create FSM: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Connect returns when the attempt ends, in Idle, and the FSM never
	// pauses there: the idle hold between attempts is the caller's retry
	// policy. Peer.Run is this loop with a jittered hold; a caller who
	// wants, say, to give up after a number of failures writes its own.
	for {
		if err := f.Connect(ctx); err != nil {
			// Only ctx cancellation returns an error; a failed attempt
			// returned nil after reporting its Close.
			log.Printf("stopped: %v", err)
			return
		}

		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

// A passive speaker: the peer never dials, and connections arrive from a
// Listener via DeliverConn.
func ExamplePeer_DeliverConn() {
	// The peering's port is only used for dialing, so a passive peer may
	// leave it zero, but every delivered connection's remote address must
	// match the peering's address.
	p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.1"), bgp.PeerConfig{
		LocalASN: 64496,
		LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
		PeerASN:  64497,
		Passive:  true,

		OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
			log.Printf("update: reachable %v, withdrawn %v", u.NLRI, u.Withdrawn)
			return nil
		},
	})
	if err != nil {
		log.Fatalf("failed to create peer: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// With TCP-MD5 in play, install keys via Listener.SetMD5 before the
	// remote speaker's SYN arrives.
	var lc bgp.ListenConfig
	l, err := lc.Listen(ctx, netip.MustParseAddrPort("192.0.2.10:179"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			// Closing a refused connection is always sound: a live remote
			// speaker retries its open.
			if err := p.DeliverConn(c); err != nil {
				_ = c.Close()
			}
		}
	}()

	if err := p.Run(ctx); err != nil {
		log.Fatalf("failed to run peer: %v", err)
	}
}

// A Server coordinating multiple peerings: one listener demultiplexes
// inbound connections by remote address, unconfigured peers are observed
// and rejected, and shutdown delivers an operator farewell to every
// session.
func ExampleServer() {
	srv := bgp.NewServer(bgp.ServerConfig{
		// Observe connections from addresses with no configured Peer;
		// paired with AddPeer, this hook is the building block for dynamic
		// neighbors.
		OnUnconfiguredPeer: func(_ context.Context, raddr netip.AddrPort, o *bgp.Open) {
			if o != nil {
				log.Printf("unconfigured peer %s claims AS%d", raddr, o.ASN)
			}
		},
	})

	// Each peering stands alone: its own remote speaker, TCP-MD5 key, and
	// standing shutdown farewell. The Server files each peering under its
	// remote address and installs each key on its listeners as Run starts,
	// before any peer runs.
	for _, peering := range []struct {
		addr netip.Addr
		cfg  bgp.PeerConfig
	}{
		{
			addr: netip.MustParseAddr("192.0.2.1"),
			cfg: bgp.PeerConfig{
				LocalASN:              64496,
				LocalID:               bgp.MustParseIdentifier("192.0.2.10"),
				PeerASN:               64497,
				MD5Password:           "correct horse battery staple",
				ShutdownCommunication: "transit-a maintenance, back soon",
			},
		},
		{
			addr: netip.MustParseAddr("192.0.2.2"),
			cfg: bgp.PeerConfig{
				LocalASN: 64496,
				LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
				PeerASN:  64498,
				Passive:  true,
			},
		},
	} {
		if _, err := srv.AddPeer(peering.addr, peering.cfg); err != nil {
			log.Fatalf("failed to add peer: %v", err)
		}
	}

	// A dynamic farewell overrides each peer's static default. Note
	// signal.NotifyContext cannot carry a cancellation cause, so watch the
	// signal directly and cancel with the cause instead.
	drain, err := bgp.NewShutdownError(bgp.SubcodeCeaseAdministrativeShutdown, "emergency drain INC-77")
	if err != nil {
		log.Fatalf("failed to create shutdown error: %v", err)
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		cancel(drain)
	}()

	// The Server accepts on listeners the caller binds, and closes them
	// when Run returns. Bind immediately before Run: a handshake the kernel
	// completes in between meets no key.
	l, err := (&bgp.ListenConfig{}).Listen(ctx, netip.MustParseAddrPort("192.0.2.10:179"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	if err := srv.Run(ctx, l); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}

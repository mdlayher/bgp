//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// Announced NLRI stay in the documentation ranges (RFC 5737, RFC
// 3849) even though the sessions carrying them run on real sockets.
var (
	prefixV4A = netip.MustParsePrefix("198.51.100.0/24")
	prefixV4B = netip.MustParsePrefix("203.0.113.0/24")
	prefixV6A = netip.MustParsePrefix("2001:db8:100::/48")
	prefixV6B = netip.MustParsePrefix("2001:db8:200::/48")
)

// Scenario 2: route exchange in both directions over IPv4, plus the
// flagship re-advertisement loop through FRR.

// TestFRRRoutesLibraryToFRR announces IPv4 prefixes via SendUpdate
// and asserts they land in FRR's table with our attributes intact.
func TestFRRRoutesLibraryToFRR(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
	})

	p, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
	})
	awaitSession(t, estab)

	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{libASN}}},
		bgp.NextHop(hostAddr4),
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.SendUpdate(ctx, &bgp.Update{
		Attributes: attrs,
		NLRI:       []netip.Prefix{prefixV4A, prefixV4B},
	}); err != nil {
		t.Fatalf("failed to send update: %v", err)
	}

	for _, prefix := range []netip.Prefix{prefixV4A, prefixV4B} {
		path := bestPath(t, f.awaitRoute(t, "ipv4", prefix))
		if !path.Valid {
			t.Errorf("FRR considers %s invalid: %+v", prefix, path)
		}

		if got, want := path.ASPath, "64496"; got != want {
			t.Errorf("unexpected AS path for %s: got %q, want %q", prefix, got, want)
		}

		if got, want := path.Origin, "IGP"; got != want {
			t.Errorf("unexpected origin for %s: got %q, want %q", prefix, got, want)
		}

		if !slices.ContainsFunc(path.Nexthops, func(n frrNexthopJSON) bool { return n.IP == hostV4 }) {
			t.Errorf("unexpected next hops for %s: got %+v, want %s", prefix, path.Nexthops, hostV4)
		}
	}
}

// TestFRRRoutesFRRToLibrary has FRR originate an IPv4 prefix via a
// network statement and asserts OnUpdate delivers it with FRR's
// attributes typed-parsed.
func TestFRRRoutesFRRToLibrary(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:        frrASN,
		RouterID:   frrRouterID,
		Neighbors:  []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
		NetworksV4: []netip.Prefix{prefixV4A},
	})

	handler, routes := collectRoutes()
	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		OnUpdate: handler,
	})
	awaitSession(t, estab)

	r := awaitRoute(t, routes, prefixV4A)
	if got, want := r.Origin, bgp.OriginIGP; got != want {
		t.Errorf("unexpected origin: got %s, want %s", got, want)
	}

	if got, want := r.ASPath, []uint32{frrASN}; !slices.Equal(got, want) {
		t.Errorf("unexpected AS path: got %v, want %v", got, want)
	}

	if got, want := r.NextHop, f.Addr; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}
}

// TestFRRReadvertise is the flagship loop: library speaker A (AS
// 64496, IPv4 session) announces a prefix to FRR, which re-advertises
// it to library speaker B (AS 64498, IPv6 session — the two speakers
// share the host's addresses, so they must peer over different
// families for FRR to tell them apart). B must parse FRR-authored
// attributes: its AS_PATH prepend and its next hop rewrite.
func TestFRRReadvertise(t *testing.T) {
	const libASNB uint32 = 64498

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{
			{Addr: hostAddr4, ASN: libASN},
			{Addr: hostAddr6, ASN: libASNB},
		},
	})

	// B first, so FRR's re-advertisement has somewhere to go the
	// moment A's announcement lands.
	handler, routes := collectRoutes()
	_, estabB := runPeer(t, netip.AddrPortFrom(f.Addr6, bgp.Port), bgp.PeerConfig{
		LocalASN: libASNB,
		LocalID:  bgp.MustParseIdentifier("192.0.2.3"),
		PeerASN:  frrASN,
		Families: families,
		OnUpdate: handler,
	})
	awaitSession(t, estabB)

	pA, estabA := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
	})
	awaitSession(t, estabA)

	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{libASN}}},
		bgp.NextHop(hostAddr4),
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := pA.SendUpdate(ctx, &bgp.Update{
		Attributes: attrs,
		NLRI:       []netip.Prefix{prefixV4A},
	}); err != nil {
		t.Fatalf("failed to send update: %v", err)
	}

	r := awaitRoute(t, routes, prefixV4A)
	if got, want := r.ASPath, []uint32{frrASN, libASN}; !slices.Equal(got, want) {
		t.Errorf("unexpected AS path: got %v, want %v", got, want)
	}

	// FRR rewrites the next hop to its own address on the session to
	// B: a v4 next hop carried over the v6 transport.
	if got, want := r.NextHop, f.Addr; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}

	if got, want := r.Origin, bgp.OriginIGP; got != want {
		t.Errorf("unexpected origin: got %s, want %s", got, want)
	}
}

// Scenario 3: IPv6 unicast exchange over an IPv6 session, and RFC
// 8950 IPv4 NLRI with IPv6 next hops.

// TestFRRRoutesIPv6 exchanges IPv6 prefixes in both directions over
// an IPv6 session, asserting FRR's RFC 2545 dual next hop form on
// receipt.
func TestFRRRoutesIPv6(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:        frrASN,
		RouterID:   frrRouterID,
		Neighbors:  []frrNeighbor{{Addr: hostAddr6, ASN: libASN}},
		NetworksV6: []netip.Prefix{prefixV6B},
	})

	handler, routes := collectRoutes()
	p, estab := runPeer(t, netip.AddrPortFrom(f.Addr6, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		OnUpdate: handler,
	})
	awaitSession(t, estab)

	// FRR to us: a directly connected eBGP peer sends the 32 byte
	// dual next hop form, global plus link-local.
	r := awaitRoute(t, routes, prefixV6B)
	if got, want := r.Family, v6Unicast; got != want {
		t.Errorf("unexpected family: got %v, want %v", got, want)
	}

	if got, want := r.NextHop, f.Addr6; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}

	if !r.LinkLocal.Is6() || !r.LinkLocal.IsLinkLocalUnicast() {
		t.Errorf("expected an RFC 2545 link-local next hop, got %s", r.LinkLocal)
	}

	if got, want := r.ASPath, []uint32{frrASN}; !slices.Equal(got, want) {
		t.Errorf("unexpected AS path: got %v, want %v", got, want)
	}

	// Us to FRR.
	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{libASN}}},
		bgp.MPReachNLRI{
			Family:  v6Unicast,
			NextHop: hostAddr6,
			NLRI:    bgp.Prefixes{prefixV6A},
		},
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.SendUpdate(ctx, &bgp.Update{Attributes: attrs}); err != nil {
		t.Fatalf("failed to send update: %v", err)
	}

	path := bestPath(t, f.awaitRoute(t, "ipv6", prefixV6A))
	if got, want := path.ASPath, "64496"; got != want {
		t.Errorf("unexpected AS path: got %q, want %q", got, want)
	}

	if !slices.ContainsFunc(path.Nexthops, func(n frrNexthopJSON) bool { return n.IP == hostV6 }) {
		t.Errorf("unexpected next hops: got %+v, want %s", path.Nexthops, hostV6)
	}
}

// TestFRRExtendedNextHop negotiates RFC 8950 on an IPv6 session and
// exchanges IPv4 NLRI with IPv6 next hops in both directions.
func TestFRRExtendedNextHop(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:        frrASN,
		RouterID:   frrRouterID,
		Neighbors:  []frrNeighbor{{Addr: hostAddr6, ASN: libASN, ExtendedNexthop: true}},
		NetworksV4: []netip.Prefix{prefixV4A},
	})

	handler, routes := collectRoutes()
	p, estab := runPeer(t, netip.AddrPortFrom(f.Addr6, bgp.Port), bgp.PeerConfig{
		LocalASN:     libASN,
		LocalID:      libID,
		PeerASN:      frrASN,
		Families:     families,
		Capabilities: []bgp.Capability{bgp.ExtendedNextHopCapability(v4Unicast)},
		OnUpdate:     handler,
	})
	s := awaitSession(t, estab)

	if !slices.Contains(s.ExtendedNextHop, v4Unicast) {
		t.Fatalf("FRR did not negotiate extended next hop for IPv4 unicast: %v", s.ExtendedNextHop)
	}

	// FRR to us: IPv4 NLRI, IPv6 next hop.
	r := awaitRoute(t, routes, prefixV4A)
	if got, want := r.Family, v4Unicast; got != want {
		t.Errorf("unexpected family: got %v, want %v", got, want)
	}

	if got, want := r.NextHop, f.Addr6; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}

	// Us to FRR: IPv4 NLRI, our IPv6 next hop.
	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{libASN}}},
		bgp.MPReachNLRI{
			Family:  v4Unicast,
			NextHop: hostAddr6,
			NLRI:    bgp.Prefixes{prefixV4B},
		},
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.SendUpdate(ctx, &bgp.Update{Attributes: attrs}); err != nil {
		t.Fatalf("failed to send update: %v", err)
	}

	path := bestPath(t, f.awaitRoute(t, "ipv4", prefixV4B))
	if !slices.ContainsFunc(path.Nexthops, func(n frrNexthopJSON) bool { return n.IP == hostV6 }) {
		t.Errorf("unexpected next hops: got %+v, want %s", path.Nexthops, hostV6)
	}
}

// A route is an owned copy of one announced prefix and the typed
// attributes it arrived with, extracted from an OnUpdate invocation:
// handler values reference the connection's read buffer, so the
// collector copies everything it keeps.
type route struct {
	Prefix    netip.Prefix
	Family    bgp.Family
	Origin    bgp.Origin
	Path      bgp.ASPath // every segment as parsed
	ASPath    []uint32   // flattened AS_SEQUENCE ASNs
	NextHop   netip.Addr
	LinkLocal netip.Addr
}

// collectRoutes returns an OnUpdate handler and a channel delivering
// one route per prefix the handler observes being announced.
func collectRoutes() (func(context.Context, *bgp.Peer, *bgp.Update) error, <-chan route) {
	routes := make(chan route, 64)

	handler := func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
		// Attributes shared by every prefix in this UPDATE.
		var shared route
		var mp *bgp.MPReachNLRI
		for _, ra := range u.Attributes {
			a, err := ra.Parse()
			if err != nil {
				// Unknown attribute types are a plain error by
				// design; a real consumer would keep them raw.
				continue
			}

			switch a := a.(type) {
			case bgp.Origin:
				shared.Origin = a
			case bgp.ASPath:
				for _, seg := range a {
					seg.ASNs = slices.Clone(seg.ASNs)
					shared.Path = append(shared.Path, seg)
					if !seg.Set && !seg.Confed {
						shared.ASPath = append(shared.ASPath, seg.ASNs...)
					}
				}
			case bgp.NextHop:
				shared.NextHop = netip.Addr(a)
			case bgp.MPReachNLRI:
				mp = &a
			}
		}

		for _, p := range u.NLRI {
			r := shared
			r.Prefix = p
			r.Family = v4Unicast
			routes <- r
		}

		if mp != nil {
			// Every family in these tests is prefix shaped; a peer which
			// sent anything else would be sending a family we never
			// negotiated.
			ps, _ := mp.NLRI.(bgp.Prefixes)
			for _, p := range ps {
				r := shared
				r.Prefix = p
				r.Family = mp.Family
				r.NextHop = mp.NextHop
				r.LinkLocal = mp.LinkLocal
				routes <- r
			}
		}

		return nil
	}

	return handler, routes
}

// awaitRoute drains routes until one for prefix arrives, failing t
// after a deadline. Routes for other prefixes are discarded, so one
// collector serves multi-prefix scenarios in any arrival order.
func awaitRoute(t *testing.T, routes <-chan route, prefix netip.Prefix) route {
	t.Helper()

	timeout := time.After(60 * time.Second)
	for {
		select {
		case r := <-routes:
			if r.Prefix == prefix {
				return r
			}
		case <-timeout:
			t.Fatalf("timed out waiting for a route to %s", prefix)
		}
	}
}

// awaitSession receives an established Session, failing t after a
// deadline.
func awaitSession(t *testing.T, estab <-chan bgp.Session) bgp.Session {
	t.Helper()

	select {
	case s := <-estab:
		return s
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for session establishment")
		panic("unreachable")
	}
}

// bestPath returns the single path FRR reports for a prefix, failing
// t if there is not exactly one: every scenario announces each prefix
// from exactly one speaker.
func bestPath(t *testing.T, paths []frrPathJSON) frrPathJSON {
	t.Helper()

	if len(paths) != 1 {
		t.Fatalf("expected exactly one path, got %d: %+v", len(paths), paths)
	}

	return paths[0]
}

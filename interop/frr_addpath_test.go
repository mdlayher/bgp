//go:build interop && linux

package interop

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// Scenario 9: the add-path extension (RFC 7911), negotiated per family
// and per direction against FRR, with multiple paths for one prefix
// carried in both wire forms: the top level IPv4 unicast fields and a
// multiprotocol attribute.

// nextHopV4Alt is a second IPv4 next hop on the harness network which
// no speaker owns. FRR resolves it through its connected route, so a
// path carrying it is valid, and it lets two paths for one prefix
// differ in a way FRR's table shows directly.
var nextHopV4Alt = netip.MustParseAddr("192.168.240.2")

// TestFRRAddPath is the add-path loop: library speaker A negotiates
// Send for IPv4 unicast and announces two paths for one prefix to FRR
// with distinct identifiers, FRR holds both, and re-advertises both to
// library speaker B, which negotiated Receive, with FRR's own
// identifiers. A then withdraws one path by identifier and exactly that
// path disappears from FRR's table and from B. Both speakers' views of
// the negotiation are asserted against FRR's.
func TestFRRAddPath(t *testing.T) {
	const libASNB uint32 = 64498

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{
			{Addr: hostAddr4, ASN: libASN},
			{Addr: hostAddr6, ASN: libASNB, AddPathTxAllPaths: true},
		},
	})

	// B first, so FRR's re-advertisements have somewhere to go the
	// moment A's paths land. B configures Receive for both families
	// and FRR sends toward it for both, so both negotiate.
	paths := collectPaths(t)
	_, estabB := runPeer(t, netip.AddrPortFrom(f.Addr6, bgp.Port), bgp.PeerConfig{
		LocalASN: libASNB,
		LocalID:  bgp.MustParseIdentifier("192.0.2.3"),
		PeerASN:  frrASN,
		Families: families,
		AddPath: []bgp.AddPathFamily{
			{Family: v4Unicast, Receive: true},
			{Family: v6Unicast, Receive: true},
		},
		OnUpdate: paths.handler,
	})
	sB := awaitSession(t, estabB)

	wantB := []bgp.AddPathFamily{
		{Family: v4Unicast, Receive: true},
		{Family: v6Unicast, Receive: true},
	}
	if got := sB.AddPath; !slices.Equal(got, wantB) {
		t.Fatalf("B negotiated unexpected add-path: got %+v, want %+v", got, wantB)
	}

	// A configures both directions for IPv4 unicast only. FRR
	// advertises Receive for every activated family by default but was
	// not configured to send toward A, so the intersection keeps only
	// A's Send: A's Receive is dropped, and the IPv6 unicast Receive
	// FRR offered never appears because A did not configure that
	// family.
	pA, estabA := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		AddPath:  []bgp.AddPathFamily{{Family: v4Unicast, Send: true, Receive: true}},
	})
	sA := awaitSession(t, estabA)

	wantA := []bgp.AddPathFamily{{Family: v4Unicast, Send: true}}
	if got := sA.AddPath; !slices.Equal(got, wantA) {
		t.Fatalf("A negotiated unexpected add-path: got %+v, want %+v", got, wantA)
	}

	// FRR's view of both negotiations, from its side of each session.
	nA := f.awaitEstablished(t, hostAddr4)
	if got, want := nA.Capabilities.AddPath["ipv4Unicast"], (frrAddPathCapJSON{TxReceived: true, RxAdvertised: true, RxReceived: true}); got != want {
		t.Errorf("FRR reports unexpected IPv4 unicast add-path with A: got %+v, want %+v", got, want)
	}

	if got, want := nA.Capabilities.AddPath["ipv6Unicast"], (frrAddPathCapJSON{RxAdvertised: true}); got != want {
		t.Errorf("FRR reports unexpected IPv6 unicast add-path with A: got %+v, want %+v", got, want)
	}

	nB := f.awaitEstablished(t, hostAddr6)
	for _, family := range []string{"ipv4Unicast", "ipv6Unicast"} {
		if got, want := nB.Capabilities.AddPath[family], (frrAddPathCapJSON{TxAdvertised: true, RxAdvertised: true, RxReceived: true}); got != want {
			t.Errorf("FRR reports unexpected %s add-path with B: got %+v, want %+v", family, got, want)
		}
	}

	// A announces two paths for one prefix. Each needs its own UPDATE
	// because the attributes differ: the next hop, and a community
	// which survives FRR's next hop rewrite toward B and so identifies
	// each path on the far side.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sends := []sentPath{
		{id: 1, nextHop: hostAddr4, community: bgp.NewCommunity(uint16(libASN), 1)},
		{id: 2, nextHop: nextHopV4Alt, community: bgp.NewCommunity(uint16(libASN), 2)},
	}

	for _, s := range sends {
		attrs, err := bgp.MarshalAttributes(
			bgp.OriginIGP,
			bgp.ASPath{{ASNs: []uint32{libASN}}},
			bgp.NextHop(s.nextHop),
			bgp.Communities{s.community},
		)
		if err != nil {
			t.Fatalf("failed to marshal attributes: %v", err)
		}

		if err := pA.SendUpdate(ctx, &bgp.Update{
			Attributes: attrs,
			NLRIPaths:  bgp.PathPrefixes{{ID: s.id, Prefix: prefixV4A}},
		}); err != nil {
			t.Fatalf("failed to send path %d: %v", s.id, err)
		}
	}

	// B receives both paths, in either order, with FRR's usual eBGP
	// rewrites: its own AS prepended and its own next hop. Only the
	// community tells the two apart until FRR's table is consulted.
	var gotB []path
	for range sends {
		gotB = append(gotB, paths.await(t, prefixV4A, false))
	}

	if gotB[0].ID == gotB[1].ID {
		t.Fatalf("B received both paths with the same identifier: %+v", gotB)
	}

	// FRR holds both paths keyed by the identifiers A assigned, and
	// records the identifier it sent each one with toward B. Its table
	// is read only now: FRR assigns send identifiers during best path
	// selection, after a path lands in the table, and B having received
	// both paths proves that has happened.
	txIDs := make(map[bgp.Community]uint32)
	for _, p := range f.awaitPrefixPaths(t, "ipv4", prefixV4A, 2) {
		i := slices.IndexFunc(sends, func(s sentPath) bool { return s.id == p.AddPathRxID })
		if i < 0 {
			t.Fatalf("FRR holds a path with an identifier A never sent: %+v", p)
		}

		s := sends[i]
		if !p.Valid {
			t.Errorf("FRR considers path %d invalid: %+v", s.id, p)
		}

		if got, want := p.Community.List, []string{s.community.String()}; !slices.Equal(got, want) {
			t.Errorf("unexpected communities for path %d: got %v, want %v", s.id, got, want)
		}

		if !slices.ContainsFunc(p.Nexthops, func(n frrNexthopJSON) bool { return n.IP == s.nextHop.String() }) {
			t.Errorf("unexpected next hops for path %d: got %+v, want %s", s.id, p.Nexthops, s.nextHop)
		}

		txIDs[s.community] = p.AddPathTxID
	}

	if len(txIDs) != 2 {
		t.Fatalf("FRR did not hold both of A's paths: %v", txIDs)
	}

	// Each path B parsed carries the identifier FRR says it sent it
	// with: the oracle's own accounting checks the decoding.
	for _, p := range gotB {
		if len(p.Communities) != 1 {
			t.Fatalf("B received a path without exactly one community: %+v", p)
		}

		want, ok := txIDs[p.Communities[0]]
		if !ok {
			t.Fatalf("B received a path with a community A never sent: %+v", p)
		}

		if p.ID != want {
			t.Errorf("unexpected identifier for %s path: got %d, want %d", p.Communities[0], p.ID, want)
		}

		if got, want := p.ASPath, []uint32{frrASN, libASN}; !slices.Equal(got, want) {
			t.Errorf("unexpected AS path: got %v, want %v", got, want)
		}

		if got, want := p.NextHop, f.Addr; got != want {
			t.Errorf("unexpected next hop: got %s, want %s", got, want)
		}
	}

	// A withdraws the second path by identifier. B receives a withdraw
	// for exactly its identifier, and FRR drops exactly that one.
	withdrawn := sends[1]
	if err := pA.SendUpdate(ctx, &bgp.Update{
		WithdrawnPaths: bgp.PathPrefixes{{ID: withdrawn.id, Prefix: prefixV4A}},
	}); err != nil {
		t.Fatalf("failed to withdraw path %d: %v", withdrawn.id, err)
	}

	w := paths.await(t, prefixV4A, true)
	if got, want := w.ID, txIDs[withdrawn.community]; got != want {
		t.Errorf("B received a withdraw for the wrong path: got identifier %d, want %d", got, want)
	}

	remaining := f.awaitPrefixPaths(t, "ipv4", prefixV4A, 1)
	if got, want := remaining[0].AddPathRxID, sends[0].id; got != want {
		t.Errorf("FRR kept the wrong path: got identifier %d, want %d", got, want)
	}
}

// TestFRRAddPathMultiprotocol has FRR originate an IPv6 prefix toward
// a library speaker which negotiated add-path Receive, and asserts the
// route arrives typed as PathPrefixes inside MP_REACH_NLRI with the
// identifier FRR reports sending, and that the family's End-of-RIB
// marker still decodes on an add-path session.
func TestFRRAddPathMultiprotocol(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:        frrASN,
		RouterID:   frrRouterID,
		Neighbors:  []frrNeighbor{{Addr: hostAddr4, ASN: libASN, AddPathTxAllPaths: true}},
		NetworksV6: []netip.Prefix{prefixV6A},
	})

	// FRR offers Send for both unicast families; asking for IPv6 unicast
	// alone scopes the negotiation to that family.
	paths := collectPaths(t)
	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		AddPath:  []bgp.AddPathFamily{{Family: v6Unicast, Receive: true}},
		OnUpdate: paths.handler,
	})
	s := awaitSession(t, estab)

	want := []bgp.AddPathFamily{{Family: v6Unicast, Receive: true}}
	if got := s.AddPath; !slices.Equal(got, want) {
		t.Fatalf("negotiated unexpected add-path: got %+v, want %+v", got, want)
	}

	p := paths.await(t, prefixV6A, false)
	if got, want := p.Family, v6Unicast; got != want {
		t.Errorf("unexpected family: got %v, want %v", got, want)
	}

	if got, want := p.NextHop, f.Addr6; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}

	if got, want := p.ASPath, []uint32{frrASN}; !slices.Equal(got, want) {
		t.Errorf("unexpected AS path: got %v, want %v", got, want)
	}

	// FRR's own accounting of the identifier it sent, from its table.
	frrPaths := f.awaitPrefixPaths(t, "ipv6", prefixV6A, 1)
	if got, want := p.ID, frrPaths[0].AddPathTxID; got != want {
		t.Errorf("unexpected identifier: got %d, FRR reports sending %d", got, want)
	}

	paths.awaitEndOfRIB(t, v6Unicast)
}

// A sentPath is one of the paths TestFRRAddPath announces: its
// identifier and the attributes which tell it apart from the other.
type sentPath struct {
	id        uint32
	nextHop   netip.Addr
	community bgp.Community
}

// A path is an owned copy of one add-path NLRI entry an OnUpdate
// handler observed, announced or withdrawn, with the typed attributes
// it traveled with: the route type's add-path counterpart.
type path struct {
	Prefix      netip.Prefix
	ID          uint32
	Family      bgp.Family
	Withdrawn   bool
	ASPath      []uint32 // flattened AS_SEQUENCE ASNs
	NextHop     netip.Addr
	Communities []bgp.Community
}

// A pathCollector is an OnUpdate handler for a session which negotiated
// add-path Receive, delivering one path per NLRI entry it observes and
// one family per End-of-RIB marker. NLRI arriving in the plain form is
// a test failure: on such a session the FSM must deliver path forms.
type pathCollector struct {
	t        *testing.T
	paths    chan path
	endOfRIB chan bgp.Family
}

// collectPaths returns a pathCollector reporting plain-form NLRI to t.
func collectPaths(t *testing.T) *pathCollector {
	return &pathCollector{
		t:        t,
		paths:    make(chan path, 64),
		endOfRIB: make(chan bgp.Family, 8),
	}
}

// handler is the OnUpdate handler.
func (c *pathCollector) handler(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
	if fam, ok := u.EndOfRIB(); ok {
		c.endOfRIB <- fam
		return nil
	}

	if len(u.NLRI) > 0 || len(u.Withdrawn) > 0 {
		c.t.Errorf("IPv4 unicast NLRI arrived in the plain form on an add-path session: %+v", u)
	}

	// Attributes shared by every entry in this UPDATE.
	var shared path
	var mp *bgp.MPReachNLRI
	var mpu *bgp.MPUnreachNLRI
	for _, ra := range u.Attributes {
		a, err := ra.Parse()
		if err != nil {
			// Unknown attribute types are a plain error by design; a
			// real consumer would keep them raw.
			continue
		}

		switch a := a.(type) {
		case bgp.ASPath:
			for _, seg := range a {
				if !seg.Set {
					shared.ASPath = append(shared.ASPath, slices.Clone(seg.ASNs)...)
				}
			}
		case bgp.NextHop:
			shared.NextHop = netip.Addr(a)
		case bgp.Communities:
			shared.Communities = slices.Clone(a)
		case bgp.MPReachNLRI:
			mp = &a
		case bgp.MPUnreachNLRI:
			mpu = &a
		}
	}

	emit := func(ps bgp.PathPrefixes, fam bgp.Family, withdrawn bool) {
		for _, pp := range ps {
			p := shared
			p.Prefix, p.ID, p.Family, p.Withdrawn = pp.Prefix, pp.ID, fam, withdrawn
			c.paths <- p
		}
	}

	emit(u.NLRIPaths, v4Unicast, false)
	emit(u.WithdrawnPaths, v4Unicast, true)

	if mp != nil {
		shared.NextHop = mp.NextHop
		ps, ok := mp.NLRI.(bgp.PathPrefixes)
		if !ok {
			c.t.Errorf("%s NLRI arrived in the %T form on an add-path session", mp.Family, mp.NLRI)
		}

		emit(ps, mp.Family, false)
	}

	if mpu != nil {
		ps, ok := mpu.NLRI.(bgp.PathPrefixes)
		if !ok {
			c.t.Errorf("%s withdrawn NLRI arrived in the %T form on an add-path session", mpu.Family, mpu.NLRI)
		}

		emit(ps, mpu.Family, true)
	}

	return nil
}

// await drains the collector until a path for prefix arrives in the
// requested direction, announced or withdrawn, failing t after a
// deadline. Other paths are discarded, so one collector serves
// multi-prefix scenarios in any arrival order.
func (c *pathCollector) await(t *testing.T, prefix netip.Prefix, withdrawn bool) path {
	t.Helper()

	timeout := time.After(60 * time.Second)
	for {
		select {
		case p := <-c.paths:
			if p.Prefix == prefix && p.Withdrawn == withdrawn {
				return p
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s", pathDesc(prefix, withdrawn))
		}
	}
}

// awaitEndOfRIB drains End-of-RIB markers until fam's arrives, failing
// t after a deadline. FRR sends a marker per family in its own order.
func (c *pathCollector) awaitEndOfRIB(t *testing.T, fam bgp.Family) {
	t.Helper()

	timeout := time.After(60 * time.Second)
	for {
		select {
		case got := <-c.endOfRIB:
			if got == fam {
				return
			}
		case <-timeout:
			t.Fatalf("timed out waiting for the %s End-of-RIB marker", fam)
		}
	}
}

// pathDesc names an awaited path in a failure message.
func pathDesc(prefix netip.Prefix, withdrawn bool) string {
	if withdrawn {
		return fmt.Sprintf("a withdraw of %s", prefix)
	}

	return fmt.Sprintf("a path to %s", prefix)
}

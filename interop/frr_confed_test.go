//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// Scenario 10: AS confederations (RFC 5065). FRR is a confederation
// member and library speaker A is another member, so their session is
// confederation eBGP and FRR's AS_PATH toward A carries
// AS_CONFED_SEQUENCE segments. Library speaker B peers with FRR from
// outside the confederation and sees it as the confederation's public
// AS.
//
// The confederation's public AS is FRR's usual ASN; the two members use
// private ASNs, as members do. The FRR member AS is the one the
// AS_CONFED_SEQUENCE regression fixture in the root package captured.
const (
	frrMemberASN uint32 = 65001
	libMemberASN uint32 = 65002
)

// TestFRRConfederation asserts both AS_PATH forms a confederation member
// sends: FRR's own route reaches A with only the confederation record,
// which names no origin, and a route B announces from outside reaches A
// with the confederation record ahead of the external path, whose
// rightmost AS is still the origin. FRR's OPEN toward B must carry the
// confederation identifier rather than the member AS, or B never
// establishes.
func TestFRRConfederation(t *testing.T) {
	// Not parallel: the harness hosts one FRR instance at a time, on
	// fixed addresses and interface names.

	const libASNB uint32 = 64498

	f := startFRR(t, frrConfig{
		ASN:                frrMemberASN,
		RouterID:           frrRouterID,
		ConfederationID:    frrASN,
		ConfederationPeers: []uint32{libMemberASN},
		Neighbors: []frrNeighbor{
			{
				Addr: hostAddr4,
				ASN:  libMemberASN,
			},
			{
				Addr: hostAddr6,
				ASN:  libASNB,
			},
		},
		NetworksV4: []netip.Prefix{prefixV4A},
	})

	// A: the fellow member, over IPv4. FRR speaks its member AS here.
	handler, routes := collectRoutes()
	_, estabA := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libMemberASN,
		LocalID:  libID,
		PeerASN:  frrMemberASN,
		Families: families,
		OnUpdate: handler,
	})
	awaitSession(t, estabA)

	// FRR's own route: an AS_CONFED_SEQUENCE of its member AS alone,
	// the root package's regression fixture. It originated
	// inside the confederation, so the path names no origin.
	r := awaitRoute(t, routes, prefixV4A)
	want := bgp.ASPath{{
		Confed: true,
		ASNs:   []uint32{frrMemberASN},
	}}
	if d := diff(t, want, r.Path); d != "" {
		t.Fatalf("unexpected AS path (-want +got):\n%s", d)
	}

	if got, want := r.Path.Origin(), (bgp.OriginAS{Empty: true}); got != want {
		t.Errorf("unexpected origin AS: got %+v, want %+v", got, want)
	}

	if got, want := r.NextHop, f.Addr; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}

	// B: outside the confederation, over IPv6. The pin on PeerASN is
	// the assertion: FRR must present the confederation identifier.
	pB, estabB := runPeer(t, netip.AddrPortFrom(f.Addr6, bgp.Port), bgp.PeerConfig{
		LocalASN: libASNB,
		LocalID:  bgp.MustParseIdentifier("192.0.2.3"),
		PeerASN:  frrASN,
		Families: families,
	})
	awaitSession(t, estabB)

	attrs, err := bgp.MarshalAttributes(
		bgp.OriginIGP,
		bgp.ASPath{{ASNs: []uint32{libASNB}}},
		bgp.NextHop(hostAddr4),
	)
	if err != nil {
		t.Fatalf("failed to marshal attributes: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := pB.SendUpdate(ctx, &bgp.Update{
		Attributes: attrs,
		NLRI:       []netip.Prefix{prefixV4B},
	}); err != nil {
		t.Fatalf("failed to send update: %v", err)
	}

	// FRR re-advertises B's route into the confederation: its member
	// AS is recorded in an AS_CONFED_SEQUENCE ahead of B's external
	// path, and the origin skips the confederation record.
	r = awaitRoute(t, routes, prefixV4B)
	want = bgp.ASPath{
		{
			Confed: true,
			ASNs:   []uint32{frrMemberASN},
		},
		{ASNs: []uint32{libASNB}},
	}
	if d := diff(t, want, r.Path); d != "" {
		t.Fatalf("unexpected AS path (-want +got):\n%s", d)
	}

	if got, want := r.Path.Origin(), (bgp.OriginAS{ASN: libASNB}); got != want {
		t.Errorf("unexpected origin AS: got %+v, want %+v", got, want)
	}

	if d := diff(t, []uint32{libASNB}, r.ASPath); d != "" {
		t.Errorf("unexpected flattened AS path (-want +got):\n%s", d)
	}

	if got, want := r.Origin, bgp.OriginIGP; got != want {
		t.Errorf("unexpected origin: got %s, want %s", got, want)
	}

	// Within the confederation FRR handles the next hop as iBGP does:
	// B's next hop is carried unchanged rather than rewritten to FRR's
	// own address as it is toward an external peer.
	if got, want := r.NextHop, hostAddr4; got != want {
		t.Errorf("unexpected next hop: got %s, want %s", got, want)
	}
}

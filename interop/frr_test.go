//go:build interop && linux

package interop

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// Documentation fixtures (RFC 5398 ASNs, RFC 5737 identifiers): the
// library speaker is AS 64496 with identifier 192.0.2.1; FRR is AS
// 64497 with router ID 192.0.2.2. The four-octet scenario uses
// 65551/65536 so the OPEN carries AS_TRANS with the real ASN in the
// four-octet capability.
const (
	libASN uint32 = 64496
	frrASN uint32 = 64497

	libASN4 uint32 = 65551
	frrASN4 uint32 = 65536

	frrRouterID = "192.0.2.2"
)

var (
	libID = bgp.MustParseIdentifier("192.0.2.1")

	// The host's own addresses on the harness bridge: the neighbor
	// addresses routers see for every library speaker.
	hostAddr4 = netip.MustParseAddr(hostV4)
	hostAddr6 = netip.MustParseAddr(hostV6)

	v4Unicast = bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	v6Unicast = bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}

	// families is what both speakers advertise in every scenario 1
	// variant: the FRR template always activates both address
	// families, so the negotiated intersection must be exactly this,
	// in local configuration order.
	families = []bgp.Family{v4Unicast, v6Unicast}
)

// Scenario 1: session establishment and capability negotiation, in
// both roles plus the iBGP and four-octet ASN variants.

func TestFRREstablishActive(t *testing.T)    { testFRREstablish(t, libASN, frrASN, false) }
func TestFRREstablishPassive(t *testing.T)   { testFRREstablish(t, libASN, frrASN, true) }
func TestFRREstablishIBGP(t *testing.T)      { testFRREstablish(t, libASN, libASN, false) }
func TestFRREstablishFourOctet(t *testing.T) { testFRREstablish(t, libASN4, frrASN4, false) }

// testFRREstablish establishes a session between a library speaker
// (AS local) and FRR (AS remote), the library either dialing FRR's
// port 179 (active) or accepting FRR's dial via a Server listener on
// an ephemeral port (passive), then asserts both speakers' views of
// the negotiation.
func testFRREstablish(t *testing.T, local, remote uint32, passive bool) {
	cfg := bgp.PeerConfig{
		LocalASN: local,
		LocalID:  libID,
		PeerASN:  remote,
		Families: families,
	}

	// Both roles produce sessions between FRR's address and the
	// host's own address on the bridge (its gateway).
	host := hostAddr4

	var (
		estab <-chan bgp.Session
		f     *frr
	)

	if passive {
		cfg.Passive = true

		// The Server must be listening before FRR boots so FRR's
		// first connect attempt lands, and its ephemeral port is
		// only known once it is.
		var port uint16
		raddr := netip.AddrPortFrom(netip.MustParseAddr(frrV4), 0)
		_, estab, port = runServer(t, raddr, cfg, bgp.ListenConfig{})
		f = startFRR(t, frrConfig{
			ASN:       remote,
			RouterID:  frrRouterID,
			Neighbors: []frrNeighbor{{Addr: host, ASN: local, Port: port}},
		})
	} else {
		f = startFRR(t, frrConfig{
			ASN:       remote,
			RouterID:  frrRouterID,
			Neighbors: []frrNeighbor{{Addr: host, ASN: local}},
		})

		_, estab = runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), cfg)
	}

	var s bgp.Session
	select {
	case s = <-estab:
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for session establishment")
	}

	// Our view of FRR.
	if got, want := s.Peer.ASN, remote; got != want {
		t.Errorf("unexpected peer ASN: got %d, want %d", got, want)
	}

	if got, want := s.Peer.ID, bgp.MustParseIdentifier(frrRouterID); got != want {
		t.Errorf("unexpected peer identifier: got %s, want %s", got, want)
	}

	// FRR proposes 9 seconds (timers bgp 3 9), we propose the 90
	// second default, and negotiation takes the minimum.
	if got, want := s.HoldTime, 9*time.Second; got != want {
		t.Errorf("unexpected negotiated hold time: got %s, want %s", got, want)
	}

	if got, want := s.Families, families; !slices.Equal(got, want) {
		t.Errorf("unexpected negotiated families: got %v, want %v", got, want)
	}

	// FRR advertises its FQDN capability by default, carrying the
	// instance's pinned kernel hostname (see frrHostname): decoding
	// it exercises the codec against a real implementation.
	// Unknown-capability tolerance is still exercised for free by
	// the other capabilities FRR sends (extended message, enhanced
	// route refresh, paths limit, ...) which this package does not
	// model.
	fi := slices.IndexFunc(s.Peer.Capabilities, func(c bgp.Capability) bool { return c.Code == bgp.CapabilityFQDN })
	if fi < 0 {
		t.Errorf("FRR's OPEN did not carry its default FQDN capability: %v", s.Peer.Capabilities)
	} else if hostname, _, err := s.Peer.Capabilities[fi].FQDN(); err != nil {
		t.Errorf("failed to parse FRR's FQDN capability: %v", err)
	} else if want := frrHostname; hostname != want {
		t.Errorf("unexpected FRR hostname in FQDN capability: got %q, want %q", hostname, want)
	}

	// FRR's view of us. Our side is established, but poll FRR's view
	// anyway: its state machine is not synchronized with ours.
	n := f.awaitEstablished(t, host)
	if got, want := n.RemoteASN, local; got != want {
		t.Errorf("FRR reports unexpected remote ASN: got %d, want %d", got, want)
	}

	if got, want := n.LocalASN, remote; got != want {
		t.Errorf("FRR reports unexpected local ASN: got %d, want %d", got, want)
	}

	if got, want := n.HoldTimeMS, 9000; got != want {
		t.Errorf("FRR reports unexpected hold time: got %dms, want %dms", got, want)
	}

	if got, want := n.Capabilities.FourByteASN, "advertisedAndReceived"; got != want {
		t.Errorf("FRR reports unexpected four-octet AS capability: got %q, want %q", got, want)
	}

	for _, family := range []string{"ipv4Unicast", "ipv6Unicast"} {
		if _, ok := n.Capabilities.Multiprotocol[family]; !ok {
			t.Errorf("FRR did not record multiprotocol %s: %v", family, n.Capabilities.Multiprotocol)
		}
	}
}

// runPeer constructs a Peer for the router at raddr from cfg and runs it on
// a test-scoped goroutine, returning the Peer and a channel which delivers
// each established Session. Teardown (an Administrative Shutdown toward
// the router) happens when t ends.
func runPeer(t *testing.T, raddr netip.AddrPort, cfg bgp.PeerConfig) (*bgp.Peer, <-chan bgp.Session) {
	t.Helper()

	p, estab, _ := runPeerCause(t, raddr, cfg)
	return p, estab
}

// runPeerCause is runPeer, also returning the cancel-cause function
// of Run's context so lifecycle tests can end the peering themselves:
// cancel(nil) for the default Administrative Shutdown, or a
// *MessageError cause for a caller-owned farewell. Test cleanup still
// cancels and joins, harmlessly, after the test's own cancellation.
func runPeerCause(t *testing.T, raddr netip.AddrPort, cfg bgp.PeerConfig) (*bgp.Peer, <-chan bgp.Session, context.CancelCauseFunc) {
	t.Helper()

	estab := make(chan bgp.Session, 1)
	cfg.OnEstablished = func(_ context.Context, _ *bgp.Peer, s bgp.Session) error {
		select {
		case estab <- s:
		default:
		}

		return nil
	}

	cfg.Dialer.Port = raddr.Port()
	p, err := bgp.NewPeer(raddr.Addr(), cfg)
	if err != nil {
		t.Fatalf("failed to construct peer: %v", err)
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := p.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Logf("peer run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel(nil)
		<-done
	})

	return p, estab, cancel
}

// wildcardV4 is the runServer listener address: every IPv4 address,
// ephemeral port.
var wildcardV4 = netip.MustParseAddrPort("0.0.0.0:0")

// runServer runs a Server with a single listener bound by lc and cfg as
// its sole (passive) peer for the router at raddr, returning the Server,
// the established Session channel, and the bound port for the router's
// `neighbor ... port` statement.
func runServer(t *testing.T, raddr netip.AddrPort, cfg bgp.PeerConfig, lc bgp.ListenConfig) (*bgp.Server, <-chan bgp.Session, uint16) {
	t.Helper()

	estab := make(chan bgp.Session, 1)
	cfg.OnEstablished = func(_ context.Context, _ *bgp.Peer, s bgp.Session) error {
		select {
		case estab <- s:
		default:
		}

		return nil
	}

	l, err := lc.Listen(context.Background(), wildcardV4)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	port := l.Addr().(*net.TCPAddr).AddrPort().Port()

	srv := bgp.NewServer(bgp.ServerConfig{})
	if _, err := srv.AddPeer(raddr.Addr(), cfg); err != nil {
		_ = l.Close()
		t.Fatalf("failed to add peer: %v", err)
	}

	// The router is started after this returns, so its SYN always finds
	// the peering's key installed by Run.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Run(ctx, l); !errors.Is(err, context.Canceled) {
			t.Logf("server run: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return srv, estab, port
}

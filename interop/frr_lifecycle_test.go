//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// Scenario 6: lifecycle NOTIFICATIONs in both directions, asserted
// via our Close on receipt and FRR's neighbor JSON on transmission —
// never by log scraping.

// TestFRRShutdownFromFRR applies `neighbor ... shutdown message` on a
// live session and asserts our Close decodes FRR's Administrative
// Shutdown and its RFC 9003 communication.
func TestFRRShutdownFromFRR(t *testing.T) {
	const farewell = "interop: maintenance"

	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
	})

	cfg := bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
	}

	closes := collectCloses(&cfg)
	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), cfg)
	awaitSession(t, estab)

	f.configure(
		t,
		"router bgp 64497",
		"neighbor "+hostV4+" shutdown message "+farewell,
	)

	c := awaitClose(t, closes)
	if !c.Established || c.Local {
		t.Fatalf("expected a received close of an established session: %+v", c)
	}

	if c.Notification == nil {
		t.Fatalf("expected a NOTIFICATION with the close: %+v", c)
	}

	if got, want := c.Notification.Code, bgp.NotificationCease; got != want {
		t.Errorf("unexpected notification code: got %s, want %s", got, want)
	}

	if got, want := c.Notification.Subcode, uint8(bgp.SubcodeCeaseAdministrativeShutdown); got != want {
		t.Errorf("unexpected notification subcode: got %d, want %d", got, want)
	}

	if got, ok := c.Notification.ShutdownCommunication(); !ok || got != farewell {
		t.Errorf("unexpected shutdown communication: got %q, %v, want %q", got, ok, farewell)
	}
}

// TestFRRShutdownToFRR cancels a peer whose static
// ShutdownCommunication is set and asserts FRR records the
// Administrative Shutdown and our text.
func TestFRRShutdownToFRR(t *testing.T) {
	const farewell = "interop: goodbye"

	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
	})

	_, estab, cancel := runPeerCause(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN:              libASN,
		LocalID:               libID,
		PeerASN:               frrASN,
		Families:              families,
		ShutdownCommunication: farewell,
	})
	awaitSession(t, estab)
	cancel(nil)

	// Cease (6) / Administrative Shutdown (2).
	n := f.awaitNotified(t, hostAddr4, "0602")
	if got, want := n.LastShutdownDescription, farewell; got != want {
		t.Errorf("unexpected shutdown description: got %q, want %q", got, want)
	}
}

// TestFRRPeerDeconfigured removes a Server-managed peer and asserts
// FRR sees Cease / Peer De-configured, exactly what a router sends on
// neighbor removal.
func TestFRRPeerDeconfigured(t *testing.T) {
	frrAddr := netip.MustParseAddr(frrV4)

	srv, estab, port := runServer(t, netip.AddrPortFrom(frrAddr, 0), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Passive:  true,
	}, bgp.ListenConfig{})

	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN, Port: port}},
	})
	awaitSession(t, estab)

	if err := srv.RemovePeer(frrAddr, nil); err != nil {
		t.Fatalf("failed to remove peer: %v", err)
	}

	// Cease (6) / Peer De-configured (3).
	f.awaitNotified(t, hostAddr4, "0603")
}

// TestFRRHardReset cancels a peer with a NewHardResetError cause and
// asserts FRR records the RFC 8538 Hard Reset. Both speakers
// advertise graceful restart with the N bit: RFC 8538's procedures —
// including FRR's hard-reset bookkeeping — apply to sessions where
// notification support was negotiated, not bare ones.
func TestFRRHardReset(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:             frrASN,
		RouterID:        frrRouterID,
		Neighbors:       []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
		GracefulRestart: true,
	})

	_, estab, cancel := runPeerCause(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		GracefulRestart: &bgp.GracefulRestartConfig{
			RestartTime:         120 * time.Second,
			NotificationSupport: true,
			Families: []bgp.GracefulRestartFamily{
				{Family: v4Unicast},
				{Family: v6Unicast},
			},
		},
	})
	awaitSession(t, estab)

	const farewell = "interop: hard reset"
	cause, err := bgp.NewHardResetError(
		bgp.NotificationCease,
		bgp.SubcodeCeaseAdministrativeReset,
		farewell,
	)
	if err != nil {
		t.Fatalf("failed to construct hard reset: %v", err)
	}

	cancel(cause)

	// FRR decapsulates per RFC 8538, section 3: it records the
	// *inner* NOTIFICATION — Cease (6) / Administrative Reset (4) —
	// with the hard-reset marker set, and surfaces the RFC 9003
	// communication riding inside the encapsulation. (Without the N
	// bit negotiated, FRR instead records the outer Cease/Hard Reset
	// verbatim and never sets the marker — observed with 10.7.0.)
	n := f.awaitNotified(t, hostAddr4, "0604")
	if !n.LastNotificationHardReset {
		t.Errorf("FRR did not mark the notification as a hard reset: %+v", n)
	}

	if got, want := n.LastShutdownDescription, farewell; got != want {
		t.Errorf("unexpected shutdown description: got %q, want %q", got, want)
	}
}

// Scenario 7: the graceful restart negotiation surface, and
// End-of-RIB delivery after FRR's initial advertisements.
func TestFRRGracefulRestart(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:             frrASN,
		RouterID:        frrRouterID,
		Neighbors:       []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
		NetworksV4:      []netip.Prefix{prefixV4A},
		NetworksV6:      []netip.Prefix{prefixV6B},
		GracefulRestart: true,
	})

	eors := make(chan bgp.Family, 4)
	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		GracefulRestart: &bgp.GracefulRestartConfig{
			RestartTime: 120 * time.Second,
			Families: []bgp.GracefulRestartFamily{
				{Family: v4Unicast},
				{Family: v6Unicast},
			},
		},
		OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
			if family, ok := u.EndOfRIB(); ok {
				eors <- family
			}

			return nil
		},
	})
	s := awaitSession(t, estab)

	// Our view of FRR's capability.
	if s.GracefulRestart == nil {
		t.Fatal("FRR did not advertise graceful restart")
	}

	if s.GracefulRestart.RestartTime <= 0 {
		t.Errorf("unexpected restart time: %s", s.GracefulRestart.RestartTime)
	}

	// FRR's view of ours.
	n := f.awaitEstablished(t, hostAddr4)
	if got, want := n.Capabilities.GracefulRestart, "advertisedAndReceived"; got != want {
		t.Errorf("FRR reports unexpected graceful restart capability: got %q, want %q", got, want)
	}

	// FRR marks the end of its initial table per negotiated family.
	got := make(map[bgp.Family]bool)
	timeout := time.After(60 * time.Second)
	for len(got) < 2 {
		select {
		case family := <-eors:
			got[family] = true
		case <-timeout:
			t.Fatalf("timed out waiting for End-of-RIB markers, saw %v", got)
		}
	}

	if !got[v4Unicast] || !got[v6Unicast] {
		t.Errorf("unexpected End-of-RIB families: %v", got)
	}
}

// Scenario 8: route refresh in both directions.
func TestFRRRouteRefresh(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:        frrASN,
		RouterID:   frrRouterID,
		Neighbors:  []frrNeighbor{{Addr: hostAddr4, ASN: libASN}},
		NetworksV4: []netip.Prefix{prefixV4A},
	})

	refreshes := make(chan bgp.Family, 4)
	handler, routes := collectRoutes()
	p, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		// Route refresh is opt-in, and paired with the handler which
		// keeps the promise it makes.
		RouteRefresh: true,
		OnUpdate:     handler,
		OnRouteRefresh: func(_ context.Context, _ *bgp.Peer, r *bgp.RouteRefresh) error {
			refreshes <- r.Family
			return nil
		},
	})
	s := awaitSession(t, estab)

	if !s.RouteRefresh {
		t.Fatal("FRR did not advertise route refresh")
	}

	// Initial advertisement, then ours again after SendRouteRefresh:
	// FRR re-sends its table on request.
	awaitRoute(t, routes, prefixV4A)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.SendRouteRefresh(ctx, v4Unicast); err != nil {
		t.Fatalf("failed to send route refresh: %v", err)
	}

	awaitRoute(t, routes, prefixV4A)

	// The reverse: a soft clear makes FRR request a refresh from us.
	if err := f.vtysh(t, "clear bgp ipv4 unicast * soft in", nil); err != nil {
		t.Fatalf("failed to soft clear: %v", err)
	}

	select {
	case family := <-refreshes:
		if family != v4Unicast {
			t.Errorf("unexpected refreshed family: got %v, want %v", family, v4Unicast)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for FRR's route refresh request")
	}
}

// collectCloses installs an OnClose hook in cfg, delivering each
// Close on the returned channel. Close values are fully owned, so no
// copying is needed.
func collectCloses(cfg *bgp.PeerConfig) <-chan bgp.Close {
	closes := make(chan bgp.Close, 4)
	cfg.OnClose = func(_ *bgp.Peer, c bgp.Close) {
		select {
		case closes <- c:
		default:
		}
	}

	return closes
}

// awaitClose receives the next Close of an established session,
// failing t after a deadline. Closes of failed attempts are drained
// and discarded.
func awaitClose(t *testing.T, closes <-chan bgp.Close) bgp.Close {
	t.Helper()

	timeout := time.After(60 * time.Second)
	for {
		select {
		case c := <-closes:
			if c.Established {
				return c
			}
		case <-timeout:
			t.Fatal("timed out waiting for a session close")
		}
	}
}

// awaitNotified polls until FRR records a last NOTIFICATION with the
// given four-hex-digit code/subcode (e.g. "0602" for Cease /
// Administrative Shutdown) for the neighbor at addr, and returns that
// view.
func (f *frr) awaitNotified(t *testing.T, addr netip.Addr, codeSubcode string) frrNeighborJSON {
	t.Helper()

	var n frrNeighborJSON
	f.poll(t, "neighbor "+addr.String()+" never recorded notification "+codeSubcode, func() bool {
		var err error
		n, err = f.neighbor(t, addr)
		return err == nil && n.LastErrorCodeSubcode == codeSubcode
	})

	return n
}

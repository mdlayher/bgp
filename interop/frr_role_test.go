//go:build interop && linux

package interop

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// Scenario 11: BGP Role negotiation (RFC 9234) against FRR's
// `local-role`, and the OTC attribute FRR attaches on egress.

// TestFRRRole pairs FRR as a strict Provider with the library as a
// strict Customer. Both sides confirm the pair, and FRR's route toward
// its customer carries an OTC naming FRR, which the library's ingress
// procedure accepts as it stands.
func TestFRRRole(t *testing.T) {
	// Not parallel: the harness hosts one FRR instance at a time, on
	// fixed addresses and interface names.

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{{
			Addr:       hostAddr4,
			ASN:        libASN,
			LocalRole:  "provider",
			RoleStrict: true,
		}},
		NetworksV4: []netip.Prefix{prefixV4A},
	})

	attrs := make(chan bgp.RawAttributes, 1)
	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Role: &bgp.RoleConfig{
			Role:   bgp.RoleCustomer,
			Strict: true,
		},
		OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update, _ *bgp.UpdateDiagnostics) error {
			// A Peer's handlers receive owned values, so the
			// attributes may be retained as they are. Only the first
			// announcement is kept, so a repeat never blocks receipt.
			if len(u.NLRI) > 0 && u.NLRI[0] == prefixV4A {
				select {
				case attrs <- u.Attributes:
				default:
				}
			}

			return nil
		},
	})

	s := awaitSession(t, estab)
	if d := diff(t, new(bgp.RoleProvider), s.Role); d != "" {
		t.Fatalf("unexpected peer role (-want +got):\n%s", d)
	}

	n := f.awaitEstablished(t, hostAddr4)
	if n.LocalRole != "provider" || n.RemoteRole != "customer" {
		t.Errorf("unexpected FRR roles: local %q, remote %q", n.LocalRole, n.RemoteRole)
	}

	var as bgp.RawAttributes
	select {
	case as = <-attrs:
	case <-time.After(settleTimeout):
		t.Fatalf("timed out waiting for %s", prefixV4A)
	}

	otc, ok, err := bgp.Lookup[bgp.OTC](as)
	if err != nil || !ok || otc != bgp.OTC(frrASN) {
		t.Fatalf("unexpected OTC from FRR: got %d, %t, %v, want %d", otc, ok, err, frrASN)
	}

	// From a provider, a route which already carries OTC is neither a
	// leak nor owed another.
	if _, add, leak := bgp.RoleCustomer.Ingress(frrASN, as); add || leak {
		t.Fatalf("unexpected ingress verdict: add %t, leak %t", add, leak)
	}
}

// TestFRRRoleMismatch configures both FRR and the library as Provider,
// a pair RFC 9234 does not allow, and asserts the session is rejected
// with OPEN Message Error / Role Mismatch. Both speakers detect the
// mismatch on the other's OPEN, so either NOTIFICATION may arrive first.
//
// The library is passive and FRR dials it: FRR records a NOTIFICATION
// on the neighbor only for its own outgoing connection, and discards the
// record of an incoming one it rejects in OpenConfirm, as observed with
// 10.7.0.
func TestFRRRoleMismatch(t *testing.T) {
	// Not parallel: the harness hosts one FRR instance at a time, on
	// fixed addresses and interface names.

	cfg := bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Passive:  true,
		Role:     &bgp.RoleConfig{Role: bgp.RoleProvider},
	}

	closes := collectCloses(&cfg)
	_, _, port := runServer(t, cfg, bgp.ListenConfig{})

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{{
			Addr:      hostAddr4,
			ASN:       libASN,
			Port:      port,
			LocalRole: "provider",
		}},
	})

	awaitRoleMismatch(t, closes)

	// OPEN Message Error (2) / Role Mismatch (11).
	f.awaitNotified(t, hostAddr4, "020B")
}

// TestFRRRoleStrict runs the library as a strict Peer against FRR with
// no role configured: only the library's strict mode can reject the
// session, and FRR records the Role Mismatch it sent. The library is
// passive for the reason TestFRRRoleMismatch gives.
func TestFRRRoleStrict(t *testing.T) {
	// Not parallel: the harness hosts one FRR instance at a time, on
	// fixed addresses and interface names.

	cfg := bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Passive:  true,
		Role: &bgp.RoleConfig{
			Role:   bgp.RolePeer,
			Strict: true,
		},
	}

	closes := collectCloses(&cfg)
	_, _, port := runServer(t, cfg, bgp.ListenConfig{})

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{{
			Addr: hostAddr4,
			ASN:  libASN,
			Port: port,
		}},
	})

	if c := awaitRoleMismatch(t, closes); !c.Local {
		t.Fatalf("expected the library to send the Role Mismatch: %+v", c)
	}

	// OPEN Message Error (2) / Role Mismatch (11).
	f.awaitNotified(t, hostAddr4, "020B")
}

// awaitRoleMismatch receives Closes until one of a session attempt
// carries OPEN Message Error / Role Mismatch, failing t after a
// deadline, and returns it.
func awaitRoleMismatch(t *testing.T, closes <-chan bgp.Close) bgp.Close {
	t.Helper()

	timeout := time.After(establishTimeout)
	for {
		select {
		case c := <-closes:
			if c.Established {
				t.Fatalf("expected no session to establish: %+v", c)
			}

			if c.Notification != nil &&
				c.Notification.Code == bgp.NotificationOpenMessageError &&
				c.Notification.Subcode == bgp.SubcodeRoleMismatch {
				return c
			}
		case <-timeout:
			t.Fatal("timed out waiting for a Role Mismatch")
		}
	}
}

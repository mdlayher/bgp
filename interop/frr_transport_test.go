//go:build interop && linux

package interop

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
)

// md5Password is the TCP-MD5 key fixture. BGP MD5 keys are cleartext
// operational strings, not secrets in the cryptographic sense.
const md5Password = "interop-md5"

// Scenario 4: TCP-MD5 in both roles, plus the mismatched-key negative
// case. The passive variant is the e2e proof of the Server's structural
// MD5-before-SYN sequencing against a real remote.

// TestFRRMD5Active dials FRR with matching MD5 keys on both sides.
func TestFRRMD5Active(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN, Password: md5Password}},
	})

	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN:    libASN,
		LocalID:     libID,
		PeerASN:     frrASN,
		Families:    families,
		MD5Password: md5Password,
	})
	awaitSession(t, estab)
	f.awaitEstablished(t, hostAddr4)
}

// TestFRRMD5Passive has FRR dial a Server whose listener carries the
// peering's key, installed before FRR's SYN can arrive.
func TestFRRMD5Passive(t *testing.T) {
	_, estab, port := runServer(t, netip.AddrPortFrom(netip.MustParseAddr(frrV4), 0), bgp.PeerConfig{
		LocalASN:    libASN,
		LocalID:     libID,
		PeerASN:     frrASN,
		Families:    families,
		Passive:     true,
		MD5Password: md5Password,
	}, bgp.ListenConfig{})

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{{
			Addr:     hostAddr4,
			ASN:      libASN,
			Port:     port,
			Password: md5Password,
		}},
	})

	awaitSession(t, estab)
	f.awaitEstablished(t, hostAddr4)
}

// TestFRRMD5Mismatch dials FRR with a different key on each side. The
// kernel drops unmatched MD5 segments silently, so the only
// observable is absence: no session within the window, and FRR never
// leaves its connect states.
func TestFRRMD5Mismatch(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN, Password: md5Password}},
	})

	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN:    libASN,
		LocalID:     libID,
		PeerASN:     frrASN,
		Families:    families,
		MD5Password: "not-" + md5Password,
	})
	awaitNoSession(t, estab)

	if n, err := f.neighbor(t, hostAddr4); err == nil && n.BGPState == "Established" {
		t.Fatalf("FRR established a session despite mismatched MD5 keys: %+v", n)
	}
}

// Scenario 5: GTSM in both roles, plus the missing-GTSM negative
// case.

// TestFRRGTSMActive dials FRR with GTSM on both sides: our Dialer
// sends TTL 255 and FRR's ttl-security requires it.
func TestFRRGTSMActive(t *testing.T) {
	f := startFRR(t, frrConfig{
		ASN:       frrASN,
		RouterID:  frrRouterID,
		Neighbors: []frrNeighbor{{Addr: hostAddr4, ASN: libASN, TTLSecurity: true}},
	})

	_, estab := runPeer(t, netip.AddrPortFrom(f.Addr, bgp.Port), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Dialer:   bgp.Dialer{GTSM: true},
	})
	awaitSession(t, estab)
	f.awaitEstablished(t, hostAddr4)
}

// TestFRRGTSMPassive has FRR dial a GTSM listener: accepted
// connections inherit the whole-socket TTL floor.
func TestFRRGTSMPassive(t *testing.T) {
	_, estab, port := runServer(t, netip.AddrPortFrom(netip.MustParseAddr(frrV4), 0), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Passive:  true,
	}, bgp.ListenConfig{TCPOptions: bgp.TCPOptions{GTSM: true}})

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{{
			Addr:        hostAddr4,
			ASN:         libASN,
			Port:        port,
			TTLSecurity: true,
		}},
	})

	awaitSession(t, estab)
	f.awaitEstablished(t, hostAddr4)
}

// TestFRRGTSMViolation has FRR dial our GTSM listener without
// ttl-security of its own: its SYN arrives with the default TTL,
// below the listener's floor of 255, and our kernel drops it before
// any handshake. Absence again is the assertion.
//
// The violation is deliberately probed in this direction only. The
// reverse — dialing FRR without GTSM while its ttl-security requires
// it — establishes transiently on occasion (observed with 10.7.0):
// FRR installs IP_MINTTL on the accepted socket only after accept, so
// an OPEN exchange completing in the initial burst slips through
// before enforcement, and the session dies at hold expiry instead.
// Our listener has no such race: the Server installs the floor at
// bind, before any SYN can be answered.
func TestFRRGTSMViolation(t *testing.T) {
	_, estab, port := runServer(t, netip.AddrPortFrom(netip.MustParseAddr(frrV4), 0), bgp.PeerConfig{
		LocalASN: libASN,
		LocalID:  libID,
		PeerASN:  frrASN,
		Families: families,
		Passive:  true,
	}, bgp.ListenConfig{TCPOptions: bgp.TCPOptions{GTSM: true}})

	f := startFRR(t, frrConfig{
		ASN:      frrASN,
		RouterID: frrRouterID,
		Neighbors: []frrNeighbor{{
			Addr: hostAddr4,
			ASN:  libASN,
			Port: port,
		}},
	})
	awaitNoSession(t, estab)

	if n, err := f.neighbor(t, hostAddr4); err == nil && n.BGPState == "Established" {
		t.Fatalf("FRR established a session despite a GTSM violation: %+v", n)
	}
}

// awaitNoSession asserts no session establishes within a bounded
// window: the assertion for deliberately broken transport, where the
// kernel drops segments silently and success would otherwise appear
// well inside the window (FRR retries every 5 seconds and our own
// dial retries are faster).
func awaitNoSession(t *testing.T, estab <-chan bgp.Session) {
	t.Helper()

	select {
	case s := <-estab:
		t.Fatalf("unexpected session established with peer AS %d", s.Peer.ASN)
	case <-time.After(10 * time.Second):
	}
}

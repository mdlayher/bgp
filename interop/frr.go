//go:build interop && linux

package interop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"text/template"
	"time"
)

// frrVersion pins the FRR oracle release, enforced against the
// daemons' own reported version at startup. A silent oracle change
// must never be observable as a test result — it would be
// indistinguishable from a regression in this library — so upgrades
// are deliberate bumps of this constant together with the nix flake
// lock that supplies FRR to dev shells and CI, with the quirk-pinning
// scenario as the tripwire.
const frrVersion = "10.7.0"

// frrHostname pins the instance's kernel hostname via its UTS
// namespace. FRR's FQDN capability carries the kernel hostname rather
// than frr.conf's hostname (observed with 10.7.0), so the hostname
// assertion in the establish scenario depends on this pin, not on the
// config template.
const frrHostname = "frr-interop"

// An frrConfig parameterizes testdata/frr/base.conf.tmpl.
type frrConfig struct {
	ASN       uint32
	RouterID  string
	Neighbors []frrNeighbor

	// NetworksV4 and NetworksV6 are prefixes FRR originates via
	// network statements in the respective unicast address family.
	NetworksV4 []netip.Prefix
	NetworksV6 []netip.Prefix

	// GracefulRestart enables `bgp graceful-restart`: FRR advertises
	// the capability and sends End-of-RIB markers after its initial
	// advertisements.
	GracefulRestart bool
}

// An frrNeighbor is one neighbor of an frrConfig.
type frrNeighbor struct {
	// Addr and ASN configure the neighbor statement's address and
	// remote-as.
	Addr netip.Addr
	ASN  uint32

	// Port, if nonzero, overrides the well-known BGP port: how FRR
	// reaches a passive library speaker listening on an ephemeral
	// port, since the unprivileged test binary never binds 179.
	Port uint16

	// ExtendedNexthop advertises the RFC 8950 extended next hop
	// capability toward this neighbor.
	ExtendedNexthop bool

	// Password enables TCP-MD5 (RFC 2385) toward this neighbor with
	// the given key.
	Password string

	// TTLSecurity enables GTSM (RFC 5082) toward this neighbor with
	// `ttl-security hops 1`: the directly connected case.
	TTLSecurity bool
}

// An frr is a running FRR instance on the harness network.
type frr struct {
	// Addr and Addr6 are the instance's addresses: the dial targets
	// of an active library speaker.
	Addr  netip.Addr
	Addr6 netip.Addr

	name string
	vt   *nsFRR
}

// startFRR renders cfg and starts an FRR instance running it, torn
// down when t ends. It returns once bgpd is answering vtysh.
func startFRR(t *testing.T, cfg frrConfig) *frr {
	t.Helper()

	tmpl, err := template.ParseFiles(filepath.Join("testdata", "frr", "base.conf.tmpl"))
	if err != nil {
		t.Fatalf("failed to parse FRR config template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		t.Fatalf("failed to render FRR config: %v", err)
	}

	name := instanceName(t)
	f := &frr{
		Addr:  netip.MustParseAddr(frrV4),
		Addr6: netip.MustParseAddr(frrV6),
		name:  name,
		vt:    rt.startFRR(t, name, buf.Bytes()),
	}

	f.poll(t, "bgpd never answered vtysh", func() bool {
		var v map[string]any
		return f.vtysh(t, "show bgp summary json", &v) == nil
	})

	return f
}

// vtysh runs one vtysh command against the instance and unmarshals its
// JSON output into v, which may be nil to discard the output.
func (f *frr) vtysh(t *testing.T, cmd string, v any) error {
	t.Helper()

	out, err := f.vt.vtysh(cmd)
	if err != nil {
		return fmt.Errorf("vtysh %q: %w: %s", cmd, err, out)
	}

	if v == nil {
		return nil
	}

	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("vtysh %q: failed to unmarshal: %w: %s", cmd, err, out)
	}

	return nil
}

// An frrNeighborJSON is the narrow slice of `show bgp neighbors <addr>
// json` output the tests assert on; FRR's full schema is deliberately
// not modeled.
type frrNeighborJSON struct {
	BGPState     string `json:"bgpState"`
	RemoteASN    uint32 `json:"remoteAs"`
	LocalASN     uint32 `json:"localAs"`
	HoldTimeMS   int    `json:"bgpTimerHoldTimeMsecs"`
	Capabilities struct {
		FourByteASN     string                     `json:"4byteAs"`
		GracefulRestart string                     `json:"gracefulRestart"`
		Multiprotocol   map[string]json.RawMessage `json:"multiprotocolExtensions"`
	} `json:"neighborCapabilities"`

	// The last NOTIFICATION on the session, as FRR recorded it:
	// code/subcode as four hex digits (e.g. "0602" for Cease /
	// Administrative Shutdown), the RFC 8538 Hard Reset marker, and
	// the received RFC 9003 shutdown communication, if any.
	LastErrorCodeSubcode      string `json:"lastErrorCodeSubcode"`
	LastNotificationReason    string `json:"lastNotificationReason"`
	LastNotificationHardReset bool   `json:"lastNotificationHardReset"`
	LastShutdownDescription   string `json:"lastShutdownDescription"`
}

// neighbor fetches FRR's current view of the neighbor at addr.
func (f *frr) neighbor(t *testing.T, addr netip.Addr) (frrNeighborJSON, error) {
	t.Helper()

	var m map[string]frrNeighborJSON
	if err := f.vtysh(t, "show bgp neighbors "+addr.String()+" json", &m); err != nil {
		return frrNeighborJSON{}, err
	}

	n, ok := m[addr.String()]
	if !ok {
		return frrNeighborJSON{}, fmt.Errorf("FRR reports no neighbor %s", addr)
	}

	return n, nil
}

// awaitEstablished polls until FRR reports the neighbor at addr in the
// Established state, and returns that view.
func (f *frr) awaitEstablished(t *testing.T, addr netip.Addr) frrNeighborJSON {
	t.Helper()

	var n frrNeighborJSON
	f.poll(t, fmt.Sprintf("neighbor %s never reached Established", addr), func() bool {
		var err error
		n, err = f.neighbor(t, addr)
		return err == nil && n.BGPState == "Established"
	})

	return n
}

// configure applies configuration lines through vtysh, entering
// configure terminal first; vtysh retains mode across -c arguments,
// so nested lines (router bgp, then neighbor statements) work as they
// would interactively.
func (f *frr) configure(t *testing.T, lines ...string) {
	t.Helper()

	if out, err := f.vt.vtysh(append([]string{"configure terminal"}, lines...)...); err != nil {
		t.Fatalf("failed to configure FRR (%q): %v: %s", lines, err, out)
	}
}

// An frrPathJSON is the narrow slice of one path in `show bgp ...
// unicast json` output the tests assert on.
type frrPathJSON struct {
	Valid    bool             `json:"valid"`
	Origin   string           `json:"origin"`
	ASPath   string           `json:"path"`
	Nexthops []frrNexthopJSON `json:"nexthops"`
}

// An frrNexthopJSON is one next hop of an frrPathJSON.
type frrNexthopJSON struct {
	IP string `json:"ip"`
}

// awaitRoute polls until FRR's BGP table for family ("ipv4" or
// "ipv6") contains prefix, and returns the prefix's paths.
func (f *frr) awaitRoute(t *testing.T, family string, prefix netip.Prefix) []frrPathJSON {
	t.Helper()

	var out struct {
		Routes map[string][]frrPathJSON `json:"routes"`
	}

	cmd := fmt.Sprintf("show bgp %s unicast json", family)
	f.poll(t, fmt.Sprintf("%s never appeared in the %s unicast table", prefix, family), func() bool {
		out.Routes = nil
		if err := f.vtysh(t, cmd, &out); err != nil {
			return false
		}

		return len(out.Routes[prefix.String()]) > 0
	})

	return out.Routes[prefix.String()]
}

// poll invokes fn every 250ms until it reports true, failing t after a
// generous deadline. Polling an external process is the documented
// exception to the repo's no-sleep rule: the router's state machine is
// not ours to synchronize on, and every wait involving only library
// code blocks on a real signal instead.
func (f *frr) poll(t *testing.T, msg string, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out polling %s: %s", f.name, msg)
		}

		time.Sleep(250 * time.Millisecond)
	}
}

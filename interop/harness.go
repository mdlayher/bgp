//go:build interop

// Package interop tests github.com/mdlayher/bgp against a real BGP
// implementation: FRRouting, the suite's oracle, hosted as native
// daemons inside nested network namespaces (Linux only; see netns.go).
// Nothing beyond unprivileged user namespaces is required, but
// iproute2 must be on $PATH and the daemons — zebra and bgpd, both
// required for the full suite — must be exactly FRR frrVersion: see
// the constant. The repository's nix dev shell provides all of it:
//
//	nix develop -c go test -tags interop -race ./interop
//
// $BGP_INTEROP_FRR names the daemon directory explicitly (e.g.
// /usr/lib/frr, or a Nix store path's libexec/frr); without it, the
// suite discovers the daemons in the usual install locations — see
// detectFRR.
//
// The suite is compiled only with the interop build tag:
//
//	go test -tags interop -race ./interop
//
// A missing oracle is a hard failure, never a skip: the tag is itself
// the explicit opt-in, and a green run which tested nothing would be
// worse than a red one.
//
// When $BGP_INTEROP_LOGDIR is set, each FRR instance's logs are saved
// there on teardown; a failed test additionally dumps them into the
// test output.
package interop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Addresses on the harness network: the veth pair joining the test
// binary's namespace to the oracle's. Real sockets are the documented
// exception to the documentation-range fixture convention: the network
// itself uses RFC 1918 and ULA space, while the ASNs, identifiers, and
// announced NLRI in scenarios stay in the documentation ranges.
const (
	netV4 = "192.168.240.0/24"
	netV6 = "fd00:2026:8::/64"

	// The host's own addresses on the network: the addresses the
	// hosted router dials to reach a library speaker running in the
	// test binary.
	hostV4 = "192.168.240.1"
	hostV6 = "fd00:2026:8::1"

	// The FRR instance's static addresses. Tests run serially, so a
	// single pair serves every scenario.
	frrV4 = "192.168.240.10"
	frrV6 = "fd00:2026:8::10"
)

// instanceName derives a unique, filesystem-legal instance name from t.
func instanceName(t *testing.T) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, t.Name())

	return fmt.Sprintf("bgp-interop-%s-%d", name, os.Getpid())
}

// saveLogs implements the log contract for one FRR instance: logs land
// in $BGP_INTEROP_LOGDIR when it is set, and in the test output when
// the test failed. Logs are failure diagnostics only: assertions
// always come from our own sessions or from structured vtysh JSON.
func saveLogs(t *testing.T, name string, logs []byte) {
	t.Helper()

	if dir := os.Getenv("BGP_INTEROP_LOGDIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(dir, name+".log"), logs, 0o644)
		}
	}

	if t.Failed() {
		t.Logf("%s logs:\n%s", name, logs)
	}
}

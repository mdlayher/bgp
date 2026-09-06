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
// An establishment wait outlasts the library's connect retry cadence
// on purpose (see establishTimeout), so a run in which several of them
// fire wants a package timeout above go test's ten minute default; CI
// passes -timeout 20m.
//
// When $BGP_INTEROP_LOGDIR is set, each FRR instance's logs are saved
// there on teardown; a failed test additionally dumps them into the
// test output, alongside the library speaker's own log of the same
// session. See saveLogs and speakerLog.
package interop

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// The suite's two deadlines, each stated once here rather than
// repeated at every call site.
const (
	// settleTimeout bounds a wait on something already in motion: a
	// route reaching a table, a NOTIFICATION being recorded, an
	// End-of-RIB marker arriving on a live session, a daemon binding
	// its sockets. Seconds is the honest scale for all of them, and
	// the minute is headroom for a loaded machine.
	settleTimeout = 60 * time.Second

	// establishTimeout bounds a wait for a session to come up, and is
	// deliberately longer than one connect retry cadence. The library
	// paces active opens at RFC 4271's 120 seconds jittered down to
	// 90, and exposes no knob to shorten it, so a deadline inside that
	// window turns a single lost dial into a failure rather than a
	// slower success. startFRR's readiness gate is what keeps a dial
	// from being lost; this is the backstop for the transport losing
	// one anyway.
	establishTimeout = 150 * time.Second
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

// speakerLog returns a debug logger for a library speaker, recording
// its dials, state transitions, and retry activity into the test
// output when the test fails. It is the mirror of saveLogs for our own
// side of the wire: without it a session which never establishes is
// mute, since the evidence of a refused dial or a rejected OPEN lives
// only here.
func speakerLog(t *testing.T) *slog.Logger {
	t.Helper()

	w := &syncBuffer{}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}

		if b := w.bytes(); len(b) > 0 {
			t.Logf("library speaker logs:\n%s", b)
		}
	})

	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// A syncBuffer is a bytes.Buffer safe for the concurrent writes of a
// slog.Handler: the FSM, its readers, and the caller's goroutines all
// log.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

// bytes returns a copy of what has been logged so far, so the caller
// never reads a buffer a straggling goroutine may still be writing.
func (b *syncBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return bytes.Clone(b.buf.Bytes())
}

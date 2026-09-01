package bgprib_test

import (
	"context"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/bgp"
	"github.com/mdlayher/bgp/internal/bgprib"
)

// The torture prefix pools: each family's churn space, disjoint from the
// static Loc-RIB prefixes the TCP test announces.
var (
	torFamilies = []bgp.Family{v4u, v6u}

	torPoolV4 = func() []netip.Prefix {
		ps := make([]netip.Prefix, 12)
		for i := range ps {
			ps[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)
		}

		return ps
	}()

	torPoolV6 = func() []netip.Prefix {
		ps := make([]netip.Prefix, 12)
		for i := range ps {
			a := netip.MustParseAddr("2001:db8::").As16()
			a[15] = byte(i)
			ps[i] = netip.PrefixFrom(netip.AddrFrom16(a), 128)
		}

		return ps
	}()

	// torAttrs is a shared valid attribute set for IPv4 announcements: the
	// Table copies on insert, so sharing across workers is safe.
	torAttrs = func() []bgp.RawAttribute {
		ras, err := bgp.MarshalAttributes(bgp.OriginIGP, bgp.NextHop(netip.MustParseAddr("192.0.2.1")))
		if err != nil {
			panic(err)
		}

		return ras
	}()
)

const (
	sweepArmed int32 = iota
	sweepStopped
	sweepFired
)

// TestTableTorture hammers one Table from many goroutines: eight workers
// each drive a peer through randomized session lifecycles — random graceful
// restart capabilities on both sides of each session, random route churn,
// random closes, and a chaos goroutine firing retention sweeps into the
// workers' races — while readers concurrently validate every snapshot. Every
// worker ends with a flush, so the table must drain to empty.
func TestTableTorture(t *testing.T) {
	t.Parallel()

	master := rand.New(rand.NewPCG(tortureSeed(t), 0))

	tb := newTable(t, bgprib.Config{AfterFunc: chaosAfterFunc(t, master.Uint64())})

	const workers, iters = 8, 60
	peers := make([]*bgp.Peer, workers)
	for i := range peers {
		peers[i] = testPeer(t)
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		seed := master.Uint64()
		readers.Go(func() {
			rng := rand.New(rand.NewPCG(seed, 0))
			for {
				select {
				case <-stop:
					return
				default:
				}

				p := peers[rng.IntN(len(peers))]
				f := torFamilies[rng.IntN(len(torFamilies))]
				if err := checkSnapshot(tb.Routes(p, f)); err != nil {
					t.Errorf("reader: %v", err)
					return
				}

				_, _ = tb.Best(v4u, torPoolV4[rng.IntN(len(torPoolV4))])
			}
		})
	}

	var ws sync.WaitGroup
	for i := range workers {
		seed, p := master.Uint64(), peers[i]
		ws.Go(func() { tortureWorker(t, tb, p, seed, iters) })
	}

	ws.Wait()
	close(stop)
	readers.Wait()

	for i, p := range peers {
		for _, f := range torFamilies {
			if rs := tb.Routes(p, f); len(rs) != 0 {
				t.Fatalf("peer %d family %v not empty after final flush: %v", i, f, rs)
			}
		}
	}
}

// TestTableTortureTCP churns randomized routes between two real Peers over
// TCP. Each side advertises random capability attachments: graceful restart
// variants, and unknown codes the other side must step over. Three
// concurrent senders per side churn disjoint prefix partitions in both
// families, with occasional route refreshes. After a settle pass, each
// table must converge exactly to the other side's static set plus its final
// announcements.
//
// Then B is killed and restarted with a fresh random capability roll, so
// both sides run the real retention path: stale marking from a live Close,
// forwarding-preserved flushes, End-of-RIB sweeps, and chaos sweeps. A
// second churn must converge exactly again, with nothing from the first
// life surviving unre-announced.
func TestTableTortureTCP(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping, test uses real TCP connections and timers")
	}

	rng := rand.New(rand.NewPCG(tortureSeed(t), 1))

	var (
		staticA = netip.MustParsePrefix("203.0.113.1/32")
		staticB = netip.MustParsePrefix("203.0.113.2/32")
	)

	tableA := newTable(t, bgprib.Config{
		Local:     tortureStatic(staticA),
		AfterFunc: chaosAfterFunc(t, rng.Uint64()),
	})

	tableB := newTable(t, bgprib.Config{
		Local:     tortureStatic(staticB),
		AfterFunc: chaosAfterFunc(t, rng.Uint64()),
	})

	rig := newTortureTCPRig(t, rng, tableA, tableB, staticA, staticB)

	peerB1, cancelB1, estB1 := rig.startB("B1")
	rig.curB.Store(peerB1)
	rig.waitEstablished(rig.estA, "A")
	rig.waitEstablished(estB1, "B1")

	stopReaders := rig.startReaders()

	rig.phase("first life", peerB1)

	// Kill B: its shutdown NOTIFICATION reaches A's retention decision for
	// real. Whatever the random capabilities negotiated (flush, or stale
	// marking followed by a chaos sweep), no fresh B route may survive.
	cancelB1()
	waitFor(t, "table A to quiesce after B's shutdown", func() bool {
		for _, f := range torFamilies {
			for _, r := range tableA.Routes(rig.peerA, f) {
				if !r.Stale {
					return false
				}
			}
		}

		return true
	})

	// B's second life rolls fresh capabilities, so A's re-establishment
	// path (forwarding-preserved flushes, End-of-RIB sweeps of surviving
	// stale routes) runs against a different negotiation than the close
	// did. The second churn must converge exactly: nothing from B's first
	// life survives without being re-announced.
	peerB2, _, estB2 := rig.startB("B2")
	rig.curB.Store(peerB2)
	rig.waitEstablished(estB2, "B2")
	rig.waitEstablished(rig.estA, "A (second session)")

	rig.phase("second life", peerB2)

	stopReaders()
}

// tortureSeed returns a random seed, or the BGPRIB_SEED override, logging it
// so a failure can be reproduced.
func tortureSeed(t *testing.T) uint64 {
	t.Helper()

	seed := rand.Uint64()
	if s := os.Getenv("BGPRIB_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("failed to parse BGPRIB_SEED: %v", err)
		}

		seed = v
	}

	t.Logf("torture seed: %d (rerun with BGPRIB_SEED=%d)", seed, seed)
	return seed
}

// A sweepEntry models one armed sweep timer with time.AfterFunc's contract,
// minus the clock: it fires at most once, and never after a stop which won.
type sweepEntry struct {
	state atomic.Int32
	f     func()
}

// chaosAfterFunc returns a Config.AfterFunc which replaces a Table's sweep
// timers with hand-fired fakes: a chaos goroutine fires each armed sweep
// after a random number of yields, so the stop-vs-fire race and the late-fire
// generation guard are exercised constantly with no wall-clock waits. The
// duration is deliberately ignored — only whether a sweep fires matters here;
// that it fires *when* advertised is TestTableRestartTimerExpiry's job.
func chaosAfterFunc(t *testing.T, seed uint64) func(time.Duration, func()) func() bool {
	armC := make(chan *sweepEntry, 4096)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		rng := rand.New(rand.NewPCG(seed, 0))
		for {
			select {
			case <-stop:
				return
			case e := <-armC:
				// Sometimes yield first, so a worker's next establish can
				// win the stop race; a lost CAS means it did, and the sweep
				// must never run.
				for range rng.IntN(4) {
					runtime.Gosched()
				}

				if e.state.CompareAndSwap(sweepArmed, sweepFired) {
					e.f()
				}
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	return func(_ time.Duration, f func()) func() bool {
		e := &sweepEntry{f: f}
		armC <- e
		return func() bool { return e.state.CompareAndSwap(sweepArmed, sweepStopped) }
	}
}

// checkSnapshot verifies a snapshot's invariants: strictly sorted (which
// implies unique) prefixes, each with attributes.
func checkSnapshot(rs []bgprib.Route) error {
	for i, r := range rs {
		if len(r.Attributes) == 0 {
			return fmt.Errorf("route %s has no attributes", r.Prefix)
		}

		if i == 0 {
			continue
		}

		prev := rs[i-1].Prefix
		if c := prev.Addr().Compare(r.Prefix.Addr()); c > 0 || (c == 0 && prev.Bits() >= r.Prefix.Bits()) {
			return fmt.Errorf("snapshot not strictly sorted at %s", r.Prefix)
		}
	}

	return nil
}

// tortureWorker drives one peer's randomized lifecycle loop. Handler calls
// for one peer are serialized, per the documented contract; concurrency comes
// from the other workers, the readers, and the sweep timers.
func tortureWorker(t *testing.T, tb *bgprib.Table, p *bgp.Peer, seed uint64, iters int) {
	rng := rand.New(rand.NewPCG(seed, 0))
	ctx := context.Background()

	for range iters {
		s, localN := tortureSession(rng)
		if err := tb.OnEstablished(ctx, p, s); err != nil {
			t.Errorf("failed to establish: %v", err)
			return
		}

		for range 5 + rng.IntN(12) {
			u, err := tortureUpdate(rng)
			if err != nil {
				t.Errorf("failed to build UPDATE: %v", err)
				return
			}

			if err := tb.OnUpdate(ctx, p, u); err != nil {
				t.Errorf("valid UPDATE rejected: %v", err)
				return
			}
		}

		if rng.IntN(6) == 0 {
			f := torFamilies[rng.IntN(len(torFamilies))]
			if err := tb.OnRouteRefresh(ctx, p, &bgp.RouteRefresh{Family: f}); err != nil {
				t.Errorf("route refresh rejected: %v", err)
				return
			}
		}

		before := make(map[bgp.Family]map[netip.Prefix]bool)
		for _, f := range torFamilies {
			set := make(map[netip.Prefix]bool)
			for _, r := range tb.Routes(p, f) {
				set[r.Prefix] = true
			}

			before[f] = set
		}

		cl := tortureClose(rng)
		tb.OnClose(p, cl)
		if !checkPostClose(t, tb, p, s.GracefulRestart, localN, cl, before) {
			return
		}
	}

	// End with a session whose close must flush, so the final table is
	// provably empty. No graceful restart capability means no retention and
	// no armed sweep.
	if err := tb.OnEstablished(ctx, p, session(false, nil, v4u, v6u)); err != nil {
		t.Errorf("failed to establish final session: %v", err)
		return
	}

	tb.OnClose(p, bgp.Close{Err: net.ErrClosed, Established: true})

	// And an attempt failure after the flush must observe — and leave —
	// nothing.
	tb.OnClose(p, bgp.Close{Err: net.ErrClosed})
	for _, f := range torFamilies {
		if rs := tb.Routes(p, f); len(rs) != 0 {
			t.Errorf("routes after final flush in %v: %v", f, rs)
			return
		}
	}
}

// checkPostClose asserts the retention oracle right after a close: a flushed
// close leaves nothing, a retained close leaves only stale routes which
// existed before it, and only in capability-listed families. A sweep firing
// in between only deletes, so every check tolerates absence.
func checkPostClose(t *testing.T, tb *bgprib.Table, p *bgp.Peer, gr *bgp.GracefulRestart, localN bool, cl bgp.Close, before map[bgp.Family]map[netip.Prefix]bool) bool {
	hardReset := cl.Notification != nil &&
		cl.Notification.Code == bgp.NotificationCease &&
		cl.Notification.Subcode == bgp.SubcodeCeaseHardReset
	retain := gr != nil && gr.RestartTime > 0 &&
		(cl.Notification == nil || (localN && gr.NotificationSupport && !hardReset))

	listed := make(map[bgp.Family]bool)
	if gr != nil {
		for _, gf := range gr.Families {
			listed[gf.Family] = true
		}
	}

	for _, f := range torFamilies {
		rs := tb.Routes(p, f)
		if !retain || !listed[f] {
			if len(rs) != 0 {
				t.Errorf("family %v not flushed after close %+v: %v", f, cl, rs)
				return false
			}

			continue
		}

		for _, r := range rs {
			if !r.Stale {
				t.Errorf("family %v route %v fresh after retained close", f, r.Prefix)
				return false
			}

			if !before[f][r.Prefix] {
				t.Errorf("family %v route %v appeared during close", f, r.Prefix)
				return false
			}
		}
	}

	return true
}

// tortureSession synthesizes a random established session: random peer
// graceful restart claims, and a local OPEN with a random capability set the
// Table must pick its own N bit out of — including malformed and unknown
// capabilities to step over. The returned bool is the local N bit oracle.
func tortureSession(rng *rand.Rand) (bgp.Session, bool) {
	o := &bgp.Open{
		ASN:      65001,
		HoldTime: 90 * time.Second,
		ID:       bgp.MustParseIdentifier("192.0.2.1"),
	}

	if rng.IntN(2) == 0 {
		o.Capabilities = append(o.Capabilities, bgp.Capability{Code: bgp.CapabilityRouteRefresh})
	}

	if rng.IntN(4) == 0 {
		// A malformed graceful restart capability, which must be skipped.
		o.Capabilities = append(o.Capabilities, bgp.Capability{
			Code: bgp.CapabilityGracefulRestart,
			Data: []byte{0xff},
		})
	}

	var localN bool
	if rng.IntN(10) < 8 {
		localN = rng.IntN(2) == 0
		c, err := bgp.GracefulRestartCapability(bgp.GracefulRestart{
			NotificationSupport: localN,
			RestartTime:         60 * time.Second,
		})
		if err != nil {
			panic(err)
		}

		o.Capabilities = append(o.Capabilities, c)
	}

	if rng.IntN(2) == 0 {
		o.Capabilities = append(o.Capabilities, bgp.Capability{Code: 222, Data: []byte{1, 2, 3}})
	}

	var gr *bgp.GracefulRestart
	if rng.IntN(5) > 0 {
		gr = &bgp.GracefulRestart{
			Restarting:          rng.IntN(2) == 0,
			NotificationSupport: rng.IntN(2) == 0,
		}

		if rng.IntN(6) > 0 {
			// A nonzero restart time enables retention; the chaos hook
			// fires sweeps regardless of the duration.
			gr.RestartTime = time.Duration(1+rng.IntN(8)) * time.Millisecond
		}

		for _, f := range torFamilies {
			if rng.IntN(4) > 0 {
				gr.Families = append(gr.Families, bgp.GracefulRestartFamily{
					Family:              f,
					ForwardingPreserved: rng.IntN(3) > 0,
				})
			}
		}
	}

	return bgp.Session{
		Local:           o,
		Families:        torFamilies,
		GracefulRestart: gr,
		HoldTime:        90 * time.Second,
	}, localN
}

// tortureUpdate builds a random, valid UPDATE: End-of-RIB, withdrawals,
// announcements, or an IPv4 mix, in either family.
func tortureUpdate(rng *rand.Rand) (*bgp.Update, error) {
	pick := func(pool []netip.Prefix) []netip.Prefix {
		idx := rng.Perm(len(pool))[:1+rng.IntN(3)]
		ps := make([]netip.Prefix, len(idx))
		for i, j := range idx {
			ps[i] = pool[j]
		}

		return ps
	}

	v6 := rng.IntN(2) == 0
	switch r := rng.IntN(10); {
	case r == 0:
		return bgp.NewEndOfRIB(torFamilies[rng.IntN(len(torFamilies))]), nil

	case r < 4: // withdraw
		if !v6 {
			return &bgp.Update{Withdrawn: pick(torPoolV4)}, nil
		}

		ras, err := bgp.MarshalAttributes(bgp.MPUnreachNLRI{Family: v6u, NLRI: bgp.Prefixes(pick(torPoolV6))})
		if err != nil {
			return nil, err
		}

		return &bgp.Update{Attributes: ras}, nil

	default: // announce
		if !v6 {
			u := &bgp.Update{NLRI: pick(torPoolV4), Attributes: torAttrs}
			if rng.IntN(3) == 0 {
				u.Withdrawn = pick(torPoolV4)
			}

			return u, nil
		}

		ras, err := bgp.MarshalAttributes(bgp.OriginIGP, bgp.MPReachNLRI{
			Family:  v6u,
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    bgp.Prefixes(pick(torPoolV6)),
		})
		if err != nil {
			return nil, err
		}

		return &bgp.Update{Attributes: ras}, nil
	}
}

// tortureClose synthesizes a random session end: transport death, a
// NOTIFICATION, or a Hard Reset.
func tortureClose(rng *rand.Rand) bgp.Close {
	local := rng.IntN(2) == 0
	switch rng.IntN(5) {
	case 0:
		return bgp.Close{
			Notification: &bgp.Notification{Code: bgp.NotificationCease, Subcode: bgp.SubcodeCeaseHardReset},
			Local:        local,
			Established:  true,
		}
	case 1, 2:
		return bgp.Close{
			Notification: &bgp.Notification{Code: bgp.NotificationCease, Subcode: bgp.SubcodeCeaseAdministrativeShutdown},
			Local:        local,
			Established:  true,
		}
	default:
		return bgp.Close{Err: net.ErrClosed, Established: true}
	}
}

// A tortureTCPRig is TestTableTortureTCP's fixed side: speaker A running
// against its table and listener, plus the shared state every churn phase
// and each of speaker B's lives works with. Speaker B is created per life
// by startB, so every restart renegotiates a fresh random capability roll.
type tortureTCPRig struct {
	t                *testing.T
	rng              *rand.Rand
	tableA, tableB   *bgprib.Table
	staticA, staticB netip.Prefix
	peerA            *bgp.Peer
	estA             <-chan struct{}
	ln               *bgp.Listener
	curB             atomic.Pointer[bgp.Peer]
	readers          sync.WaitGroup
}

// newTortureTCPRig listens on loopback, builds and runs speaker A with a
// random capability roll, and feeds accepted connections to it.
func newTortureTCPRig(t *testing.T, rng *rand.Rand, tableA, tableB *bgprib.Table, staticA, staticB netip.Prefix) *tortureTCPRig {
	rig := &tortureTCPRig{
		t:       t,
		rng:     rng,
		tableA:  tableA,
		tableB:  tableB,
		staticA: staticA,
		staticB: staticB,
	}

	ln, err := (&bgp.ListenConfig{}).Listen(t.Context(), netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	rig.ln = ln

	cfgA := wire(tableA, bgp.PeerConfig{
		LocalASN:        65001,
		LocalID:         bgp.MustParseIdentifier("192.0.2.1"),
		Passive:         true,
		Families:        torFamilies,
		Capabilities:    tortureCaps(rng),
		RouteRefresh:    true,
		GracefulRestart: tortureGRConfig(rng),
		Logger:          logger(t, "A"),
	})

	rig.estA = establishSignal(&cfgA)
	peerA, err := bgp.NewPeer(netip.MustParseAddr("127.0.0.1"), cfgA)
	if err != nil {
		t.Fatalf("failed to create peer A: %v", err)
	}

	rig.peerA = peerA

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			if err := peerA.DeliverConn(c); err != nil {
				_ = c.Close()
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-acceptDone
	})

	runPeer(t, peerA)
	return rig
}

// startB creates and runs one life of speaker B with a fresh random
// capability roll, dialing the rig's listener.
func (r *tortureTCPRig) startB(name string) (*bgp.Peer, context.CancelFunc, <-chan struct{}) {
	cfg := wire(r.tableB, bgp.PeerConfig{
		LocalASN:        65002,
		LocalID:         bgp.MustParseIdentifier("192.0.2.2"),
		Families:        torFamilies,
		Capabilities:    tortureCaps(r.rng),
		RouteRefresh:    true,
		GracefulRestart: tortureGRConfig(r.rng),
		Logger:          logger(r.t, name),
	})

	est := establishSignal(&cfg)
	ap := netip.MustParseAddrPort(r.ln.Addr().String())
	cfg.Dialer.Port = ap.Port()
	p, err := bgp.NewPeer(ap.Addr(), cfg)
	if err != nil {
		r.t.Fatalf("failed to create peer %s: %v", name, err)
	}

	return p, runPeer(r.t, p), est
}

// waitEstablished waits for one establishment signal from c.
func (r *tortureTCPRig) waitEstablished(c <-chan struct{}, name string) {
	r.t.Helper()
	select {
	case <-c:
	case <-time.After(30 * time.Second):
		r.t.Fatalf("timed out waiting for peer %s to establish", name)
	}
}

// startReaders hammers both tables' snapshots from a goroutine until the
// returned stop is called: the churn must never produce a torn snapshot.
func (r *tortureTCPRig) startReaders() (stop func()) {
	stopC := make(chan struct{})
	r.readers.Go(func() {
		for {
			select {
			case <-stopC:
				return
			default:
			}

			for _, f := range torFamilies {
				if err := checkSnapshot(r.tableA.Routes(r.peerA, f)); err != nil {
					r.t.Errorf("reader A: %v", err)
					return
				}

				if err := checkSnapshot(r.tableB.Routes(r.curB.Load(), f)); err != nil {
					r.t.Errorf("reader B: %v", err)
					return
				}
			}

			_, _ = r.tableA.Best(v4u, r.staticA)
		}
	})

	return func() {
		close(stopC)
		r.readers.Wait()
	}
}

// phase churns both sides concurrently, then waits for each table to
// converge on exactly the other speaker's final state. Three senders per
// side each own a disjoint third of the pools, so per-prefix ordering is
// per-goroutine FIFO and the final state is well defined.
func (r *tortureTCPRig) phase(name string, peerB *bgp.Peer) {
	r.t.Helper()

	const senders = 3
	finalsA, finalsB := make([]churnFinal, senders), make([]churnFinal, senders)
	var churners sync.WaitGroup
	for i := range senders {
		lo, hi := i*4, (i+1)*4
		sa, sb := r.rng.Uint64(), r.rng.Uint64()
		outA, outB := &finalsA[i], &finalsB[i]
		churners.Go(func() { tortureChurn(r.t, r.peerA, sa, torPoolV4[lo:hi], torPoolV6[lo:hi], outA) })
		churners.Go(func() { tortureChurn(r.t, peerB, sb, torPoolV4[lo:hi], torPoolV6[lo:hi], outB) })
	}

	churners.Wait()

	wantA, wantB := tortureExpect(r.staticB, finalsB), tortureExpect(r.staticA, finalsA)
	waitFor(r.t, name+": table A to converge on B's final routes", func() bool {
		return tortureConverged(r.tableA, r.peerA, wantA)
	})
	waitFor(r.t, name+": table B to converge on A's final routes", func() bool {
		return tortureConverged(r.tableB, peerB, wantB)
	})
}

// tortureStatic is the one-prefix static Loc-RIB of a torture speaker.
func tortureStatic(p netip.Prefix) map[bgp.Family][]*bgp.Update {
	return map[bgp.Family][]*bgp.Update{v4u: {{
		NLRI:       []netip.Prefix{p},
		Attributes: torAttrs,
	}}}
}

// tortureCaps rolls random capability attachments: unknown codes with
// random data sometimes. Route refresh is always on, but through
// PeerConfig, since the package owns that capability's encoding.
func tortureCaps(rng *rand.Rand) []bgp.Capability {
	var cs []bgp.Capability
	for i := range 2 {
		if rng.IntN(2) == 0 {
			data := make([]byte, 1+rng.IntN(8))
			for j := range data {
				data[j] = byte(rng.Uint64())
			}

			cs = append(cs, bgp.Capability{Code: bgp.CapabilityCode(200 + i), Data: data})
		}
	}

	return cs
}

// tortureGRConfig rolls a random graceful restart configuration, or none.
func tortureGRConfig(rng *rand.Rand) *bgp.GracefulRestartConfig {
	if rng.IntN(4) == 0 {
		return nil
	}

	g := &bgp.GracefulRestartConfig{
		NotificationSupport: rng.IntN(2) == 0,
		RestartTime:         time.Duration(rng.IntN(60)) * time.Second,
	}

	for _, f := range torFamilies {
		if rng.IntN(3) > 0 {
			g.Families = append(g.Families, bgp.GracefulRestartFamily{
				Family:              f,
				ForwardingPreserved: rng.IntN(2) == 0,
			})
		}
	}

	if rng.IntN(2) == 0 {
		g.Restarting = func() bool { return true }
	}

	return g
}

// establishSignal wraps a config's OnEstablished with a one-shot signal, so
// senders start only on a live session.
func establishSignal(cfg *bgp.PeerConfig) <-chan struct{} {
	c := make(chan struct{}, 1)
	inner := cfg.OnEstablished
	cfg.OnEstablished = func(ctx context.Context, p *bgp.Peer, s bgp.Session) error {
		select {
		case c <- struct{}{}:
		default:
		}

		return inner(ctx, p, s)
	}

	return c
}

// runPeer runs p until the returned cancel is called, joined at cleanup.
func runPeer(t *testing.T, p *bgp.Peer) context.CancelFunc {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return cancel
}

// A churnFinal is one sender's final intended state per family.
type churnFinal struct{ v4, v6 map[netip.Prefix]bool }

// tortureChurn runs one sender: random announcements, withdrawals, and
// occasional route refreshes over its own disjoint prefix partitions, then
// a settle pass driving every owned prefix to a random final state,
// recorded in out.
func tortureChurn(t *testing.T, p *bgp.Peer, seed uint64, ownV4, ownV6 []netip.Prefix, out *churnFinal) {
	rng := rand.New(rand.NewPCG(seed, 0))
	ctx := t.Context()
	out.v4, out.v6 = make(map[netip.Prefix]bool), make(map[netip.Prefix]bool)

	send := func(u *bgp.Update) bool {
		if err := p.SendUpdate(ctx, u); err != nil {
			t.Errorf("send failed: %v", err)
			return false
		}

		return true
	}

	announce := func(f bgp.Family, pre netip.Prefix) bool {
		if f == v4u {
			return send(&bgp.Update{NLRI: []netip.Prefix{pre}, Attributes: torAttrs})
		}

		ras, err := bgp.MarshalAttributes(bgp.OriginIGP, bgp.MPReachNLRI{
			Family:  v6u,
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    bgp.Prefixes{pre},
		})
		if err != nil {
			t.Errorf("failed to build announcement: %v", err)
			return false
		}

		return send(&bgp.Update{Attributes: ras})
	}

	withdraw := func(f bgp.Family, pre netip.Prefix) bool {
		if f == v4u {
			return send(&bgp.Update{Withdrawn: []netip.Prefix{pre}})
		}

		ras, err := bgp.MarshalAttributes(bgp.MPUnreachNLRI{Family: v6u, NLRI: bgp.Prefixes{pre}})
		if err != nil {
			t.Errorf("failed to build withdrawal: %v", err)
			return false
		}

		return send(&bgp.Update{Attributes: ras})
	}

	for range 25 {
		f, own := v4u, ownV4
		if rng.IntN(2) == 0 {
			f, own = v6u, ownV6
		}

		pre := own[rng.IntN(len(own))]
		ok := false
		if rng.IntN(2) == 0 {
			ok = announce(f, pre)
		} else {
			ok = withdraw(f, pre)
		}

		if !ok {
			return
		}

		if rng.IntN(8) == 0 {
			if err := p.SendRouteRefresh(ctx, torFamilies[rng.IntN(len(torFamilies))]); err != nil {
				t.Errorf("route refresh failed: %v", err)
				return
			}
		}

		for range rng.IntN(3) {
			runtime.Gosched()
		}
	}

	// Settle: drive every owned prefix to a random final state.
	for f, own := range map[bgp.Family][]netip.Prefix{v4u: ownV4, v6u: ownV6} {
		final := out.v4
		if f == v6u {
			final = out.v6
		}

		for _, pre := range own {
			if rng.IntN(2) == 0 {
				if !announce(f, pre) {
					return
				}

				final[pre] = true
			} else if !withdraw(f, pre) {
				return
			}
		}
	}
}

// tortureExpect is a table's convergence target: the other speaker's static
// route plus its senders' final announcements.
func tortureExpect(staticP netip.Prefix, finals []churnFinal) map[bgp.Family]map[netip.Prefix]bool {
	want := map[bgp.Family]map[netip.Prefix]bool{
		v4u: {staticP: true},
		v6u: {},
	}

	for _, f := range finals {
		maps.Copy(want[v4u], f.v4)
		maps.Copy(want[v6u], f.v6)
	}

	return want
}

// tortureConverged reports whether p's Adj-RIB-In in tb matches want
// exactly: every wanted prefix present, fresh, and attributed, and nothing
// else.
func tortureConverged(tb *bgprib.Table, p *bgp.Peer, want map[bgp.Family]map[netip.Prefix]bool) bool {
	for f, set := range want {
		rs := tb.Routes(p, f)
		if len(rs) != len(set) {
			return false
		}

		for _, r := range rs {
			if !set[r.Prefix] || r.Stale || len(r.Attributes) == 0 {
				return false
			}
		}
	}

	return true
}

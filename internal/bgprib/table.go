// Package bgprib is the simplest possible RIB: maps guarded by one mutex.
//
// It exists as the permanent in-tree proof that a RIB living outside the bgp
// package can be built against the Peer boundary alone, including graceful
// restart helper behavior from Close and Session.GracefulRestart. It
// touches only the bgp package's exported API, and it is
// deliberately naive: no best-path selection ever runs here — the local
// routes are the caller's static assertion of its best paths — and nothing
// about its storage is tuned. Do not reuse it as a real RIB.
//
// Its outbound side is the recommended RIB shape in miniature: one pusher
// goroutine per session, fed through a dirty set with
// families as the grain, because the static Loc-RIB makes "current truth per
// family" the whole family. A real RIB keys the set by prefix.
package bgprib

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mdlayher/bgp"
)

// A Config configures a Table.
type Config struct {
	// Local is the static Loc-RIB: the caller-asserted best paths per
	// family, as ready-to-send UPDATEs. Each UPDATE must announce at least
	// one prefix in its family — IPv4 unicast prefixes in Update.NLRI,
	// any other family's inside an MP_REACH_NLRI attribute. The Table
	// announces them to every peer on session establishment and on route
	// refresh, and answers Best from them. The map and its UPDATEs are
	// retained and must not be mutated after New.
	Local map[bgp.Family][]*bgp.Update

	// AfterFunc, if set, schedules the graceful restart sweep which
	// flushes a restarting peer's stale routes at its advertised restart
	// time. It mirrors time.AfterFunc's contract — the returned stop
	// reports whether it prevented the sweep from running — and a nil
	// AfterFunc uses time.AfterFunc. Tests substitute a controllable
	// clock.
	AfterFunc func(d time.Duration, f func()) (stop func() bool)
}

// A Route is one entry in a peer's Adj-RIB-In snapshot, fully owned by the
// caller.
type Route struct {
	// Prefix is the announced prefix.
	Prefix netip.Prefix

	// Attributes are the path attributes exactly as received, including any
	// MP_REACH_NLRI container; interpreting them is the caller's business.
	Attributes []bgp.RawAttribute

	// Stale reports that the route was learned from a session which has
	// since ended under graceful restart, and survives only until the
	// restarted peer's End-of-RIB, its restart time, or a session which no
	// longer preserves the family.
	Stale bool
}

// A Table is a deliberately naive multi-peer RIB: a per-peer Adj-RIB-In and a
// static Loc-RIB, all behind a single mutex. Its handler-shaped methods are
// wired into each peer's PeerConfig by the caller; see the package comment.
type Table struct {
	// Immutable after New.
	local map[bgp.Family][]*bgp.Update
	best  map[bgp.Family]map[netip.Prefix]*bgp.Update

	// afterFunc schedules the graceful restart sweep; see Config.AfterFunc.
	afterFunc func(d time.Duration, f func()) (stop func() bool)

	// wg tracks the Adj-RIB-Out pusher goroutines, one per session, each
	// bound to its session ctx, so a shutting-down caller can wait for
	// them to quiesce.
	wg sync.WaitGroup

	mu    sync.Mutex
	peers map[*bgp.Peer]*peerState
}

// A peerState is one peer's Adj-RIB-In and graceful restart retention state.
type peerState struct {
	// gr is the peer's graceful restart capability from the last
	// established session, and localN whether this speaker advertised the
	// RFC 8538 N bit on it (from Session.Local); together they decide
	// retention at close time.
	gr     *bgp.GracefulRestart
	localN bool

	// gen invalidates a scheduled sweep which lost a stop race: the sweep
	// runs only if no establish or close intervened since it was armed.
	gen       int
	stopSweep func() bool

	// pending and wake carry the session pusher's work: the dirty set of
	// families owing an Adj-RIB-Out replay, and its capacity-1 wake
	// signal. Both are remade by each OnEstablished; pending is guarded
	// by Table.mu.
	pending map[bgp.Family]bool
	wake    chan struct{}

	routes map[bgp.Family]map[netip.Prefix]*adjRoute
}

type adjRoute struct {
	attrs []bgp.RawAttribute
	stale bool
}

// New validates the static Loc-RIB and produces a Table serving any number of
// peers.
func New(cfg Config) (*Table, error) {
	after := cfg.AfterFunc
	if after == nil {
		after = func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		}
	}

	t := &Table{
		local:     cfg.Local,
		best:      make(map[bgp.Family]map[netip.Prefix]*bgp.Update),
		afterFunc: after,
		peers:     make(map[*bgp.Peer]*peerState),
	}

	for f, us := range cfg.Local {
		idx := make(map[netip.Prefix]*bgp.Update)
		for _, u := range us {
			ps, err := updatePrefixes(f, u)
			if err != nil {
				return nil, err
			}

			if len(ps) == 0 {
				return nil, fmt.Errorf("bgprib: local UPDATE announces no prefixes in family %v", f)
			}

			for _, p := range ps {
				idx[p] = u
			}
		}

		t.best[f] = idx
	}

	return t, nil
}

// updatePrefixes lists the prefixes u announces in family f: Update.NLRI
// for IPv4 unicast, MP_REACH_NLRI contents for every other family.
func updatePrefixes(f bgp.Family, u *bgp.Update) ([]netip.Prefix, error) {
	if (f == bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}) {
		return u.NLRI, nil
	}

	var out []netip.Prefix
	for _, ra := range u.Attributes {
		if ra.Type != bgp.AttrMPReachNLRI {
			continue
		}

		a, err := ra.Parse()
		if err != nil {
			return nil, fmt.Errorf("bgprib: local UPDATE for family %v: %w", f, err)
		}

		if m := a.(bgp.MPReachNLRI); m.Family == f {
			out = append(out, nlriPrefixes(m.NLRI)...)
		}
	}

	return out, nil
}

// nlriPrefixes lists the prefixes an NLRI carries, or nothing when the family
// is not prefix shaped. EVPN records and the raw NLRI of an unmodeled family
// are not routes this deliberately naive RIB knows how to store, and a Table
// only ever asks about families it was built with.
func nlriPrefixes(n bgp.NLRI) []netip.Prefix {
	ps, _ := n.(bgp.Prefixes)
	return ps
}

// Best returns the local UPDATE announcing prefix p in family f: the
// caller-asserted best path from the static Loc-RIB. The UPDATE is shared and
// must not be mutated.
func (t *Table) Best(f bgp.Family, p netip.Prefix) (*bgp.Update, bool) {
	u, ok := t.best[f][p]
	return u, ok
}

// Routes returns a snapshot of peer p's Adj-RIB-In for family f, sorted by
// prefix and fully owned by the caller.
func (t *Table) Routes(p *bgp.Peer, f bgp.Family) []Route {
	t.mu.Lock()
	defer t.mu.Unlock()

	ps, ok := t.peers[p]
	if !ok {
		return nil
	}

	out := make([]Route, 0, len(ps.routes[f]))
	for pre, r := range ps.routes[f] {
		out = append(out, Route{
			Prefix:     pre,
			Attributes: bgp.RawAttributes(r.attrs).Clone(),
			Stale:      r.stale,
		})
	}

	slices.SortFunc(out, func(a, b Route) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}

		return a.Prefix.Bits() - b.Prefix.Bits()
	})
	return out
}

// OnEstablished implements PeerConfig.OnEstablished: it settles graceful
// restart retention from the previous session and starts the Adj-RIB-Out
// push. Wire it, and its four siblings, into each peer's PeerConfig.
func (t *Table) OnEstablished(ctx context.Context, p *bgp.Peer, s bgp.Session) error {
	t.mu.Lock()
	ps := t.state(p)
	ps.gen++
	if ps.stopSweep != nil {
		ps.stopSweep()
		ps.stopSweep = nil
	}

	ps.gr = s.GracefulRestart
	ps.localN = notificationSupport(s.Local)

	// RFC 4724, section 4.2: stale routes survive re-establishment only for
	// families the new capability lists with Forwarding Preserved; flush
	// the rest immediately rather than waiting for End-of-RIB.
	preserved := make(map[bgp.Family]bool)
	if s.GracefulRestart != nil {
		for _, gf := range s.GracefulRestart.Families {
			preserved[gf.Family] = gf.ForwardingPreserved
		}
	}

	for f, rs := range ps.routes {
		if preserved[f] {
			continue
		}

		for pre, r := range rs {
			if r.stale {
				delete(rs, pre)
			}
		}
	}

	// The session's pusher starts with every negotiated family dirty and
	// the wake primed, so its first round is the initial Adj-RIB-Out dump.
	pending := make(map[bgp.Family]bool, len(s.Families))
	for _, f := range s.Families {
		pending[f] = true
	}

	wake := make(chan struct{}, 1)
	wake <- struct{}{}
	ps.pending, ps.wake = pending, wake
	t.mu.Unlock()

	// Watch ctx per the handler contract: a session already tearing down
	// gets no pusher. The retention state above is settled either way;
	// OnClose owes the close-side half.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Bulk transmission must not run synchronously in a handler; the ctx is
	// session-scoped, so the pusher dies with the session.
	t.wg.Go(func() { t.push(ctx, p, pending, wake) })
	return nil
}

// push is the session's only pusher goroutine, so its per-call FIFO is
// whole-session order. Each wake drains the dirty family set, sending the
// static Loc-RIB for each family followed by its End-of-RIB marker, until
// the session dies. The snapshot is cleared before sending: a family
// re-marked mid-push is replayed in the next round, never lost.
func (t *Table) push(ctx context.Context, p *bgp.Peer, pending map[bgp.Family]bool, wake <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}

		t.mu.Lock()
		fams := slices.SortedFunc(maps.Keys(pending), func(a, b bgp.Family) int {
			if c := cmp.Compare(a.AFI, b.AFI); c != 0 {
				return c
			}

			return cmp.Compare(a.SAFI, b.SAFI)
		})
		clear(pending)
		t.mu.Unlock()

		for _, f := range fams {
			for _, u := range t.local[f] {
				if err := p.SendUpdate(ctx, u); err != nil {
					return
				}
			}

			if err := p.SendUpdate(ctx, bgp.NewEndOfRIB(f)); err != nil {
				return
			}
		}
	}
}

// OnUpdate implements PeerConfig.OnUpdate: End-of-RIB sweeps a family's stale
// routes; any other UPDATE is applied to the peer's Adj-RIB-In. The Update
// references the connection's read buffer, so everything retained is copied.
//
// ctx is deliberately unused: the handler never blocks, which satisfies the
// watch-ctx contract by returning promptly, and an UPDATE already received
// is never wrong to apply.
func (t *Table) OnUpdate(_ context.Context, p *bgp.Peer, u *bgp.Update) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ps := t.state(p)

	if f, ok := u.EndOfRIB(); ok {
		for pre, r := range ps.routes[f] {
			if r.stale {
				delete(ps.routes[f], pre)
			}
		}

		return nil
	}

	// Partition the attributes: MP containers carry this UPDATE's non-IPv4
	// routes, while the full copied slice is what each route retains.
	attrs := bgp.RawAttributes(u.Attributes).Clone()
	var reach []bgp.MPReachNLRI
	for _, ra := range attrs {
		a, err := ra.Parse()
		if err != nil {
			// RFC 7606 is out of scope (see rfc-status): a malformed
			// attribute is terminal for the session, exactly RFC 4271.
			return err
		}

		switch m := a.(type) {
		case bgp.MPReachNLRI:
			reach = append(reach, m)
		case bgp.MPUnreachNLRI:
			for _, pre := range nlriPrefixes(m.NLRI) {
				delete(ps.routes[m.Family], pre)
			}
		}
	}

	v4u := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	for _, pre := range u.Withdrawn {
		delete(ps.routes[v4u], pre)
	}

	for _, pre := range u.NLRI {
		ps.family(v4u)[pre] = &adjRoute{attrs: attrs}
	}

	for _, m := range reach {
		for _, pre := range nlriPrefixes(m.NLRI) {
			ps.family(m.Family)[pre] = &adjRoute{attrs: attrs}
		}
	}

	return nil
}

// OnRouteRefresh implements PeerConfig.OnRouteRefresh: it marks the requested
// family dirty and wakes the session's pusher, which replays the static
// Loc-RIB for it, End-of-RIB included. The replay goes through the one
// pusher rather than a new goroutine, so it cannot interleave with another
// push on the same session.
func (t *Table) OnRouteRefresh(ctx context.Context, p *bgp.Peer, r *bgp.RouteRefresh) error {
	// Watch ctx per the handler contract: a dying session's pusher is
	// already exiting, so mark no work for it.
	if err := ctx.Err(); err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	ps, ok := t.peers[p]
	if !ok || ps.pending == nil {
		return nil
	}

	ps.pending[r.Family] = true
	select {
	case ps.wake <- struct{}{}:
	default:
	}

	return nil
}

// OnKeepalive implements PeerConfig.OnKeepalive as a no-op: a Table has no
// use for liveness beyond what the FSM already maintains, and exists to prove
// the full handler surface wires up.
func (t *Table) OnKeepalive(context.Context, *bgp.Peer) error { return nil }

// OnClose implements PeerConfig.OnClose: the graceful restart retention
// decision. An eligible close marks the peer's routes stale and arms a sweep
// at the peer's advertised restart time; any other close flushes the peer.
func (t *Table) OnClose(p *bgp.Peer, c bgp.Close) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !c.Established {
		// A failed attempt between sessions: retention state, including any
		// armed sweep, must survive it untouched.
		return
	}

	ps, ok := t.peers[p]
	if !ok {
		return
	}

	ps.gen++

	if !retain(ps.gr, ps.localN, c) {
		delete(t.peers, p)
		return
	}

	// RFC 4724, section 4.2: retain, as stale, only the families the
	// peer's capability listed.
	listed := make(map[bgp.Family]bool)
	for _, gf := range ps.gr.Families {
		listed[gf.Family] = true
	}

	for f, rs := range ps.routes {
		if !listed[f] {
			delete(ps.routes, f)
			continue
		}

		for _, r := range rs {
			r.stale = true
		}
	}

	// Everything retained is now stale, so an expired restart time flushes
	// the peer wholesale. gen guards the stop race: time.AfterFunc's Stop
	// cannot un-run a callback already in flight.
	gen := ps.gen
	ps.stopSweep = t.afterFunc(ps.gr.RestartTime, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if ps, ok := t.peers[p]; ok && ps.gen == gen {
			delete(t.peers, p)
		}
	})
}

// retain decides graceful restart retention for a close: the helper's side of
// RFC 4724, with RFC 8538's amendment for sessions ended by a NOTIFICATION.
// gr is the peer's capability and localN this speaker's N bit, both from the
// session which just ended.
func retain(gr *bgp.GracefulRestart, localN bool, c bgp.Close) bool {
	if gr == nil || gr.RestartTime <= 0 {
		return false
	}

	if c.Notification == nil {
		// Plain RFC 4724: the transport died without a NOTIFICATION.
		return true
	}

	// RFC 8538: a NOTIFICATION in either direction preserves retention only
	// when both speakers advertised the N bit, and never for a Hard Reset.
	if !localN || !gr.NotificationSupport {
		return false
	}

	n := c.Notification
	return n.Code != bgp.NotificationCease || n.Subcode != bgp.SubcodeCeaseHardReset
}

// notificationSupport reports whether an OPEN advertised the RFC 8538 N bit
// in a well-formed graceful restart capability.
func notificationSupport(o *bgp.Open) bool {
	if o == nil {
		return false
	}

	for _, c := range o.Capabilities {
		if c.Code != bgp.CapabilityGracefulRestart {
			continue
		}

		if gr, err := c.GracefulRestart(); err == nil {
			return gr.NotificationSupport
		}
	}

	return false
}

// Wait blocks until every Adj-RIB-Out pusher goroutine has exited. Each
// pusher is bound to its session ctx and dies with its session, so a caller
// shutting down calls Wait after its peers' Run calls have returned.
func (t *Table) Wait() { t.wg.Wait() }

// state returns p's peerState, creating it on first use.
func (t *Table) state(p *bgp.Peer) *peerState {
	ps, ok := t.peers[p]
	if !ok {
		ps = &peerState{routes: make(map[bgp.Family]map[netip.Prefix]*adjRoute)}
		t.peers[p] = ps
	}

	return ps
}

// family returns the peer's table for f, creating it on first use.
func (ps *peerState) family(f bgp.Family) map[netip.Prefix]*adjRoute {
	rs, ok := ps.routes[f]
	if !ok {
		rs = make(map[netip.Prefix]*adjRoute)
		ps.routes[f] = rs
	}

	return rs
}

package bgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Timer defaults, from RFC 4271, sections 8.2.2 and 10, and RFC 6286.
const (
	// defaultHoldTime is the hold time proposed when Identity.HoldTime
	// is zero: RFC 4271's suggested value, which is also the common industry
	// default.
	defaultHoldTime = 90 * time.Second

	// minHoldTime is the smallest nonzero hold time RFC 4271, section 6.2
	// permits a speaker to accept.
	minHoldTime = 3 * time.Second

	// connectRetryTime is the base interval between dial attempts, jittered
	// per RFC 4271, section 10. Its timer is armed when a dial begins, so
	// it bounds an in-flight dial as well as the pause after a failed one:
	// dials begin on this cadence regardless of how the last one ended.
	connectRetryTime = 120 * time.Second

	// idleHoldTime is the base pause a Peer takes after a session failure
	// before its next attempt, jittered; exponential backoff is deliberately
	// deferred. The FSM itself never pauses in Idle: Connect returns the
	// moment the machine enters it, and the pause before the next Connect
	// belongs to the caller's retry loop.
	idleHoldTime = 5 * time.Second

	// openHoldTime bounds the wait for a peer's OPEN and the KEEPALIVE which
	// confirms ours: the "large value" of RFC 4271, section 8.2.2.
	openHoldTime = 4 * time.Minute

	// teardownTimeout bounds each blocking step the FSM goroutine takes
	// against an uncooperative party: every write it makes on a connection
	// (the OPEN exchange and NOTIFICATIONs), and the wait for a stuck
	// handler's reader goroutine during session teardown. endSession spends
	// the budget up to twice in sequence (the write deadline, then the
	// reader join), so a worst-case teardown is two timeouts, not one.
	teardownTimeout = 5 * time.Second
)

// An Identity carries the protocol identity and negotiation surface of one
// peering: who the two speakers are, the hold time proposal, and the
// capabilities the local OPEN advertises. LocalASN and LocalID are required;
// the zero value of every other field is usable.
//
// FSMConfig and PeerConfig embed an Identity rather than naming it, so its
// fields are set inline in either config's literal and an Identity assembled
// once can be assigned wholesale to both.
type Identity struct {
	// LocalASN is the local autonomous system number, which must be nonzero
	// (RFC 7607). Four byte ASNs are handled natively; see [Open.ASN].
	LocalASN uint32

	// LocalID is the local BGP identifier, which must be nonzero.
	LocalID Identifier

	// HoldTime is the hold time proposed in the local OPEN message. The zero
	// value proposes the default of 90 seconds; nonzero values must be at
	// least 3 seconds, and are truncated to whole seconds, the wire
	// encoding's precision. The negotiated hold time is the minimum of the two
	// speakers' proposals, reported by [Session.HoldTime]. Proposing or
	// accepting a hold time of zero, which RFC 4271 permits to disable
	// keepalives entirely, is unsupported: without a hold timer a dead
	// connection is never detected.
	HoldTime time.Duration

	// PeerASN is the remote autonomous system number, or zero to accept
	// any. A peer whose OPEN carries a different ASN is rejected with Bad
	// Peer AS. With PeerID it pins who may answer. Where the peer is, is
	// addressing (NewPeer's addr, or an FSM's DialFunc), not identity.
	PeerASN uint32

	// PeerID is the remote BGP identifier, or zero to accept any. A peer
	// whose OPEN carries a different identifier is rejected with Bad BGP
	// Identifier (RFC 4271, section 6.2). Pinning both PeerASN and PeerID
	// to the local values is rejected at construction: an internal peer
	// bearing the local identifier can never establish (RFC 6286).
	PeerID Identifier

	// Families lists the address families to advertise via multiprotocol
	// capabilities (RFC 4760). An empty list advertises no multiprotocol
	// capabilities at all: the classic IPv4 unicast speaker.
	Families []Family

	// Capabilities carries any further capabilities verbatim: extended
	// next hop, FQDN, and anything this package does not model. The
	// capabilities this package encodes itself (multiprotocol, route
	// refresh, graceful restart, and the automatic four-octet AS) have
	// their own fields and are rejected here.
	Capabilities []Capability

	// RouteRefresh advertises the route refresh capability (RFC 2918): a
	// promise that this speaker will re-advertise a family's routes when
	// the peer asks. Keeping it is the caller's RIB's job, so RouteRefresh
	// requires OnRouteRefresh. Session.RouteRefresh reports the peer's
	// advertisement, which gates SendRouteRefresh.
	RouteRefresh bool

	// GracefulRestart, if set, advertises the graceful restart capability
	// (RFC 4724, with the RFC 8538 N bit). It must not also appear in
	// Capabilities: the Restart State bit varies per session attempt, so
	// the FSM owns the encoding. Only the negotiation surface lives in
	// this package; see [GracefulRestart] for what remains the caller's.
	GracefulRestart *GracefulRestartConfig
}

// An FSMConfig configures an FSM. The embedded Identity's LocalASN and LocalID
// are required, and an FSM which is not Passive requires a DialFunc; the zero
// value of every other field is usable. The conveniences of a TCP speaker,
// such as a built-in Dialer, TCP-MD5, and a standing shutdown communication,
// are PeerConfig's.
type FSMConfig struct {
	// Identity is the peering's protocol identity and negotiation surface,
	// shared verbatim with [PeerConfig]; see [Identity].
	Identity

	// DialFunc performs the active open, and is required unless Passive:
	// the FSM owns when to dial, and this function owns how and where,
	// since the FSM carries no addressing. For plain TCP it is a
	// one-line closure around [Dialer.Dial]; TCP-MD5 is a Peer-level option
	// (PeerConfig.MD5Password).
	//
	// DialFunc must honor ctx: the FSM cancels an abandoned dial and
	// closes the connection a late one produces.
	//
	// The connection DialFunc returns must behave like a net.Conn in three
	// respects the FSM depends on: Close unblocks a blocked read, so a
	// hold timer can tear the connection down; SetWriteDeadline is
	// honored, so no write can stall teardown or a send indefinitely; and
	// one goroutine may read while another writes.
	DialFunc func(ctx context.Context) (*Conn, error)

	// Passive suppresses the active open: connections are only accepted
	// via DeliverConn, and the attempt waits in Active for one.
	Passive bool

	// OnEstablished, if set, is called when a session reaches
	// Established, with its negotiated parameters. It is the first
	// handler of each session.
	//
	// Every handler runs on the session's receive path, and a nil
	// handler ignores its event. ctx is session-scoped: a child of
	// Connect's ctx, canceled when the session leaves Established. The
	// contract below applies to every handler:
	//
	//   - Values passed to handlers reference the connection's read
	//     buffer and are only valid for the duration of the call. Callers
	//     which retain data must copy it; the Clone methods detach a
	//     whole message at once. See [ParseMessage].
	//   - Blocking in a handler pauses receipt, so TCP backpressure
	//     reaches the peer. It never pauses transmission or timers.
	//   - All handler invocations for an FSM are serialized, across
	//     consecutive sessions too. Per session, OnEstablished is first
	//     and OnClose is last. OnClose fires only after the receive path
	//     has quiesced, so an Adj-RIB-In flush can never race a late
	//     OnUpdate.
	//   - A single invocation must return within the negotiated hold time
	//     ([Session.HoldTime]): the peer cannot be answered with keepalives
	//     forever while the receive path is stalled, so a longer stall
	//     tears the session down with Cease / Out of Resources. Bulk
	//     transmission must therefore not run synchronously inside
	//     OnEstablished; start a goroutine bound to ctx instead, and
	//     return.
	//   - A handler must watch ctx: teardown cancels it and waits a
	//     bounded time for the handler to return. A handler which ignores
	//     the cancellation is abandoned on its goroutine so the FSM can
	//     continue, Close.Err reports the abandonment, and the stuck
	//     invocation forfeits the ordering guarantees above: it may
	//     overlap OnClose and a later session's handlers.
	//   - A non-nil handler error terminates the session. If the error is
	//     a *MessageError (per errors.AsType), its code, subcode, and data
	//     become the NOTIFICATION sent to the peer; any other error sends
	//     Cease.
	OnEstablished func(ctx context.Context, f *FSM, s Session) error

	// OnUpdate, if set, is called for each UPDATE received while the
	// session is Established: the feed for an Adj-RIB-In.
	//
	// See [FSMConfig.OnEstablished] for the full handler contract.
	OnUpdate func(ctx context.Context, f *FSM, u *Update) error

	// OnRouteRefresh, if set, is called for each ROUTE-REFRESH message
	// (RFC 2918) received while the session is Established: the peer
	// asks this speaker to re-advertise a family's routes. Advertising
	// the route refresh capability requires this handler; see
	// Identity.RouteRefresh.
	//
	// See [FSMConfig.OnEstablished] for the full handler contract.
	OnRouteRefresh func(ctx context.Context, f *FSM, r *RouteRefresh) error

	// OnKeepalive, if set, is called for each KEEPALIVE received while
	// the session is Established; the KEEPALIVE which confirms the OPEN
	// exchange is OnEstablished's moment instead. A KEEPALIVE carries no
	// content, so the handler receives none. Most callers leave it nil:
	// the FSM already maintains the hold timer, and this hook only
	// observes peer liveness.
	//
	// See [FSMConfig.OnEstablished] for the full handler contract.
	OnKeepalive func(ctx context.Context, f *FSM) error

	// OnClose, if set, is called when a session ends, including when
	// Connect's ctx is canceled. It is also called when a session attempt
	// ends with something to report: a connection had begun the OPEN
	// exchange, or sending an OPEN failed. An attempt with nothing
	// observable in flight, such as one whose dial never produced a
	// connection, ends without OnClose. [Close.Established] distinguishes a
	// session end from a failed attempt. Connect returns nil exactly when
	// OnClose has reported the attempt's Close; see [FSM.Connect].
	OnClose func(f *FSM, c Close)

	// OnStateChange, if set, observes every transition of the state
	// machine, for metrics and diagnostics: from and to are RFC 4271,
	// section 8 states, aggregated across a collision's two connections
	// (see [State], including when the aggregate may regress). Every Connect
	// call emits a bookended stream. The first transition leaves Idle. The
	// last returns to it, emitted after any Close is reported, as the
	// attempt's final hook. The transition to Established precedes
	// OnEstablished.
	//
	// The hook observes only: it returns no error, and intermediate states
	// are diagnostics, not program inputs. Session logic belongs on
	// OnEstablished, OnClose, and [ErrNotEstablished]. It runs on the FSM
	// goroutine and must return promptly.
	OnStateChange func(f *FSM, from, to State)

	// OnMessage, if set, observes every message the peering exchanges on
	// the wire, in both directions, on every connection the FSM owns: the
	// tap for a monitoring protocol, a route collector's message log, or
	// a capture. See [MessageEvent] for exactly which frames fire.
	//
	// The tap observes only: it returns no error and can steer nothing.
	// The event's Raw and Message are lent under the handler contract
	// above, valid for the duration of the call; a Peer's tap receives
	// owned copies instead. A received message's event precedes that
	// message's handler.
	//
	// The tap runs on the goroutine which read or wrote the message: the
	// connection's reader for a received message, and for a sent one the
	// FSM goroutine before Established or the session's writer within it.
	// Invocations are serialized per connection per origin, and
	// concurrent otherwise: a collision's two readers, or a reader
	// against a writer, may overlap. The tap must therefore be safe for
	// concurrent use. It must also return promptly: it stalls receipt,
	// the FSM's timers, or the session's sends while it runs.
	OnMessage func(f *FSM, e MessageEvent)

	// Logger, if set, records state transitions and retry activity.
	Logger *slog.Logger
}

// A GracefulRestartConfig configures the graceful restart capability an FSM
// or Peer advertises (RFC 4724, with the RFC 8538 N bit). The static fields
// are validated at construction; only the Restart State bit varies per
// session attempt, through Restarting.
type GracefulRestartConfig struct {
	// RestartTime is the retention deadline advertised to the peer: how
	// long it should keep this speaker's routes while this speaker is
	// away. At most 4095 seconds, truncated to whole seconds.
	RestartTime time.Duration

	// NotificationSupport advertises the RFC 8538 N bit: this speaker
	// supports graceful restart procedures across sessions ended by a
	// NOTIFICATION, Hard Reset excepted.
	NotificationSupport bool

	// Families lists the families carried in the capability, each with its
	// forwarding-preserved claim. The claim is the caller's assertion; the
	// package does not verify forwarding state.
	Families []GracefulRestartFamily

	// Restarting, if set, decides the OPEN's Restart State (R) bit: true
	// while this session attempt is the recovery from a restart, false
	// once recovery is complete. It is consulted once per session attempt,
	// on the FSM goroutine, and must return promptly. A nil Restarting
	// never sets the bit.
	Restarting func() bool
}

// An FSM runs the RFC 4271 finite state machine for one peering. It owns
// the whole connection lifecycle:
//
//   - Dialing and accepting connections.
//   - Resolving simultaneous-open collisions.
//   - The OPEN exchange.
//   - The established session, with keepalives and the hold timer.
//
// Received UPDATEs go to the caller's handlers; the FSM stores no routes.
//
// The FSM is the expert, zero-copy layer. Values passed to its handlers
// borrow the connection's read buffer under the contract described on
// FSMConfig. One Connect executes one session attempt and returns when the
// machine comes back to Idle. Most callers want Peer, which wraps an FSM,
// hands its handlers fully owned values, and supplies the retry loop.
type FSM struct {
	cfg FSMConfig
	log *slog.Logger

	// tap is cfg.OnMessage bound to this FSM, installed on every Conn the
	// FSM adopts; nil when unobserved, so an untapped Conn pays nothing.
	tap func(MessageEvent)

	// Derived once by NewFSM from the validated configuration: opens holds
	// the immutable local OPEN variants written at the start of every
	// connection: opens[0] with the graceful restart Restart State bit
	// clear and opens[1] with it set. Both are proven to marshal at
	// construction, so NewFSM validates every OPEN the FSM will ever
	// send. Without a GracefulRestart configuration the entries share one
	// OPEN. families is the local address family set for negotiation: the
	// configured families, or the implicit IPv4 unicast of a speaker which
	// advertises no multiprotocol capabilities (RFC 4760).
	opens    [2]*Open
	families []Family

	// shutdownCause, when non-nil, is the standing farewell sent when Connect's
	// ctx is canceled without a *MessageError cause of its own: Peer's
	// implementation of PeerConfig.ShutdownCommunication. It is set before
	// the FSM runs and never mutated; the FSM's own public surface is the
	// cancellation cause alone.
	shutdownCause *MessageError

	// jitter is a hook for deterministic retry timing in tests.
	jitter func() float64

	// mu guards runningC and the sending side of connC, so DeliverConn
	// cannot leak a connection into an FSM whose Connect has returned.
	//
	// runningC is closed while the FSM is out of Idle, meaning a Connect
	// is in progress, and replaced with a fresh open channel when it
	// returns: a
	// select with a default observes the state without blocking, and a
	// receive blocks until the FSM is accepting.
	mu       sync.Mutex
	runningC chan struct{}
	connC    chan *Conn

	// established is the established session's connection, published for
	// the send methods when a session comes up and cleared before it is
	// torn down. It is also the attempt's own record of establishment; see
	// attempt.currentState.
	established atomic.Pointer[fsmConn]
}

// [ErrNotEstablished] is returned by SendUpdate and SendRouteRefresh when there
// is no established session, and wrapped (per errors.Is) in the error of a
// send whose connection write failed, since that failure ends the session. It
// is the only session state a caller observes directly: a route pusher winds
// down on it, and the next session's OnEstablished starts a fresh one. A
// message which fails to marshal returns its error alone, without
// [ErrNotEstablished]: the session is unaffected.
var ErrNotEstablished = errors.New("bgp: session is not established")

// errFSMIdle is DeliverConn's refusal while the FSM is in Idle: no Connect
// is in progress to take the connection. Peer distinguishes it from other
// delivery errors: between attempts, Peer adopts the connection to end its
// idle hold early, or answers it with Cease / Connection
// Rejected itself when no hold is ready to take it.
var errFSMIdle = errors.New("bgp: FSM is idle")

// NewFSM validates the configuration and produces an FSM, in Idle. Nothing
// runs until Connect.
func NewFSM(c FSMConfig) (*FSM, error) {
	if c.LocalASN == 0 {
		return nil, errors.New("bgp: local ASN must be nonzero")
	}

	if c.LocalID == 0 {
		return nil, errors.New("bgp: local BGP identifier must be nonzero")
	}

	if id := c.Identity; id.PeerID != 0 && id.PeerID == id.LocalID && id.PeerASN == id.LocalASN {
		return nil, errors.New("bgp: an internal peer pinned to the local BGP identifier can never establish (RFC 6286)")
	}

	if c.HoldTime != 0 && c.HoldTime < minHoldTime {
		return nil, fmt.Errorf("bgp: hold time must be zero or at least %s: %s", minHoldTime, c.HoldTime)
	}

	// The zero value proposes the default, and the wire encodes whole
	// seconds: negotiation must run on the value the peer actually hears.
	if c.HoldTime == 0 {
		c.HoldTime = defaultHoldTime
	}

	c.HoldTime = c.HoldTime.Truncate(time.Second)

	if !c.Passive && c.DialFunc == nil {
		return nil, errors.New("bgp: an FSM which is not Passive requires a DialFunc; a closure over Dialer.Dial is the plain TCP implementation, and Peer supplies one automatically")
	}

	if c.DialFunc != nil && c.Passive {
		return nil, errors.New("bgp: a Passive FSM never dials, so it cannot carry a DialFunc")
	}

	for _, cc := range c.Capabilities {
		switch cc.Code {
		case CapabilityFourOctetAS:
			return nil, errors.New("bgp: the Four-Octet AS Number capability is generated automatically and must not be set")
		case CapabilityMultiprotocol:
			return nil, errors.New("bgp: multiprotocol capabilities are generated from Families and must not be set")
		case CapabilityGracefulRestart:
			return nil, errors.New("bgp: the graceful restart capability is generated from GracefulRestart and must not be set")
		case CapabilityRouteRefresh:
			return nil, errors.New("bgp: the route refresh capability is generated from RouteRefresh and must not be set")
		}
	}

	if c.RouteRefresh && c.OnRouteRefresh == nil {
		return nil, errors.New("bgp: RouteRefresh promises to re-advertise routes and requires OnRouteRefresh to keep it")
	}

	// The configuration is retained beyond this call; snapshot the slices so
	// later caller mutations cannot race the FSM.
	c.Families = slices.Clone(c.Families)
	c.Capabilities = slices.Clone(c.Capabilities)
	c.GracefulRestart = c.GracefulRestart.Clone()

	log := c.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	fams := c.Families
	if len(fams) == 0 {
		fams = implicitFamilies
	}

	// The log identity is the pinned identifier when there is one; an
	// unpinned peering logs bare. The FSM carries no addressing, so a Peer
	// scopes its own logger by address instead.
	if c.PeerID != 0 {
		log = log.With("peer_id", c.PeerID)
	}

	f := &FSM{
		cfg:      c,
		families: fams,
		log:      log,
		jitter:   rand.Float64,
		runningC: make(chan struct{}),
		connC:    make(chan *Conn, 1),
	}

	if h := c.OnMessage; h != nil {
		f.tap = func(e MessageEvent) { h(f, e) }
	}

	// Build and prove every OPEN the FSM can send. The only per-attempt
	// content is the graceful restart Restart State bit, whose domain is
	// exactly {false, true}: both variants are validated here, so a bad
	// configuration is a constructor error rather than a failure on every
	// session attempt.
	var err error
	if f.opens[0], err = buildOpen(c.Identity, false); err != nil {
		return nil, err
	}

	f.opens[1] = f.opens[0]
	if c.GracefulRestart != nil {
		if f.opens[1], err = buildOpen(c.Identity, true); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// Connect starts the state machine from Idle (RFC 4271's Start event) and
// blocks until it returns to Idle: one session attempt. The attempt spans
// dialing on the connect retry cadence, accepting, and resolving
// collisions, through the established session until it ends. The dial
// cadence lives inside the attempt, so Connect against an unreachable
// peer cycles the Connect and Active states indefinitely, exactly as RFC
// 4271's machine does. ctx bounds it.
//
// Every path back to Idle returns, under one contract:
//
//   - A failed attempt or an ended session returns nil. OnClose has
//     reported its Close, exactly once. A caller's retry loop needs no
//     other signal, and per-close-reason policy belongs in OnClose.
//   - When ctx ends (the ManualStop event), Connect returns ctx's error
//     instead. A Close is reported only when something observable was in
//     flight: a connection which had begun the OPEN exchange.
//
// The FSM never pauses in Idle. An idle hold before the next Connect is
// the caller's retry policy, and [Peer.Run] is the standard loop.
//
// An FSM is sequentially reusable: Connect may be called again after it
// returns, never concurrently, and the *FSM identity is stable across
// attempts.
//
// Cancellation sends any established session Cease / Administrative
// Shutdown. A [*MessageError] cancellation cause is sent verbatim instead
// (context.WithCancelCause, matched with errors.AsType). The cause is a
// complete, caller-owned farewell, which is how a caller shuts down with
// a Hard Reset (RFC 8538) or a dynamic communication ([NewShutdownError]).
func (f *FSM) Connect(ctx context.Context) error {
	return f.connect(ctx, nil)
}

// connect implements Connect. A non-nil seed is a connection accepted while
// the FSM was idle (Peer's idle hold adopting an inbound open),
// planted in connC before the attempt begins, exactly as if DeliverConn had
// won the race with the first dispatch.
func (f *FSM) connect(ctx context.Context, seed *Conn) error {
	f.mu.Lock()
	select {
	case <-f.runningC:
		f.mu.Unlock()
		if seed != nil {
			_ = seed.Close()
		}

		return errors.New("bgp: FSM is not idle: Connect is already in progress")
	default:
		close(f.runningC)
	}

	if seed != nil {
		// The buffer has room: the last connect's exit drained it, and
		// DeliverConn refuses while the FSM is idle.
		f.connC <- seed
	}

	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.runningC = make(chan struct{})
		// Close any connection delivered before the state flipped: no
		// future Connect must inherit it.
		select {
		case c := <-f.connC:
			_ = c.Close()
		default:
		}
	}()

	return f.attempt(ctx)
}

// DeliverConn hands an inbound connection to the FSM: the passive open.
// The FSM must not be idle (a Connect must be in progress) and must be able
// to take a connection; on error, the caller retains ownership and should
// close the connection. On success the FSM owns it, though it may still
// refuse it, such as when a session is already established.
//
// DeliverConn does not wait for Connect: a caller which starts Connect
// concurrently may see an error until it is active. Closing the refused
// connection is always sound, because a live remote speaker retries its
// open.
//
// The FSM checks no address: it carries no addressing, so the caller's
// choice of FSM is the admission decision, and the PeerASN and PeerID pins
// negotiation enforces are the identity checks. A caller which needs to
// authenticate the remote beyond that must do so before it delivers the
// connection; [Peer] layers a TCP remote-address check for the peering it
// addresses.
//
// The connection must behave like a net.Conn in the three respects the FSM
// depends on; see [FSMConfig.DialFunc], which documents them.
func (f *FSM) DeliverConn(c *Conn) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.runningC:
	default:
		return errFSMIdle
	}

	select {
	case f.connC <- c:
		f.adopt(c)
		return nil
	default:
		return errors.New("bgp: FSM already has a pending connection")
	}
}

// adopt marks c as the FSM's own: from here every message it frames is
// reported to the tap. It runs at the two points a Conn enters the FSM,
// a successful dial and delivery, before the FSM reads or writes on it.
func (f *FSM) adopt(c *Conn) {
	if f.tap != nil {
		c.setTap(f.tap)
	}
}

// SendUpdate sends an UPDATE message on the established session, blocking
// until the session's writer accepts the message and the write completes.
// There is no queue, so a bulk push is throttled by the peer's receive
// rate. SendUpdate may be called from any goroutine, and messages sent by
// one goroutine are written in order.
//
// ctx is honored until the message is accepted for writing. After that the
// call is committed until the write completes or the session ends. The
// commitment is bounded: the write runs under a deadline of the negotiated
// hold time, so a peer which stops reading fails the write and ends the
// session rather than parking the caller indefinitely.
//
// The error reports the send's outcome:
//
//   - [ErrNotEstablished]: no session is up.
//   - An error wrapping [ErrNotEstablished]: the session died during the
//     write.
//   - The marshal error alone: the UPDATE failed to marshal, and the
//     session stays healthy.
//
// SendUpdate does not police the UPDATE's contents: the families
// advertised, and the attributes attached, are the caller's protocol
// business.
func (f *FSM) SendUpdate(ctx context.Context, u *Update) error {
	fc := f.established.Load()
	if fc == nil {
		return ErrNotEstablished
	}

	return f.send(ctx, fc, u)
}

// SendRouteRefresh sends a ROUTE-REFRESH message (RFC 2918) on the
// established session, requesting that the peer re-advertise its routes for
// the given family. The peer must have advertised the route refresh
// capability, reported by Session.RouteRefresh; SendRouteRefresh returns an
// error rather than send an unnegotiated message. Its blocking and ordering
// behavior is SendUpdate's.
func (f *FSM) SendRouteRefresh(ctx context.Context, fam Family) error {
	fc := f.established.Load()
	if fc == nil {
		return ErrNotEstablished
	}

	if !fc.sess.RouteRefresh {
		return errors.New("bgp: peer did not advertise the route refresh capability")
	}

	return f.send(ctx, fc, &RouteRefresh{Family: fam})
}

// ResetSession ends the established session with a NOTIFICATION, leaving
// the FSM free to attempt a new one: the session reset behind a bounce,
// and the entry point for liveness signals such as a BFD session (RFC
// 5880) reporting the forwarding path down.
//
// cause picks the NOTIFICATION, like a cancellation cause:
//
//   - A nil cause sends Cease / Administrative Reset.
//   - A non-nil cause is sent verbatim. A BFD-driven caller sends
//     SubcodeCeaseBFDDown (RFC 9384), or wraps it in a Hard Reset
//     ([NewHardResetError]) when the session negotiated graceful restart
//     notification support, so the peer does not retain routes over
//     broken forwarding.
//
// ResetSession is synchronous: a nil return means the session is down and
// its OnClose has fired. ctx is honored until the FSM accepts the reset.
// After that the call is committed until the teardown, itself bounded,
// completes. ResetSession returns [ErrNotEstablished] when no session is
// established, so a reset racing the session's own death is visible but
// harmless.
//
// ResetSession must not be called from the FSM's handlers: the teardown
// it waits for joins the handlers' own goroutine, so the call stalls the
// bounded reader join and the Close reports a stuck handler. A handler
// ends its session by returning an error instead. That is the stronger
// contract, since no handler fires after an error return. A handler
// reacting to something other than the message in hand starts a goroutine
// (go f.ResetSession).
func (f *FSM) ResetSession(ctx context.Context, cause *MessageError) error {
	fc := f.established.Load()
	if fc == nil {
		return ErrNotEstablished
	}

	n := &Notification{Code: NotificationCease, Subcode: SubcodeCeaseAdministrativeReset}
	if cause != nil {
		n = cause.Notification()
	}

	req := resetReq{n: n, done: make(chan struct{})}
	select {
	case fc.resetC <- req:
	case <-fc.sessCtx.Done():
		return ErrNotEstablished
	case <-ctx.Done():
		return ctx.Err()
	}

	<-req.done
	return nil
}

// send hands m to fc's writer goroutine and waits for the write's result.
func (f *FSM) send(ctx context.Context, fc *fsmConn, m Message) error {
	// An already-canceled ctx wins deterministically, rather than racing an
	// idle writer in the select below.
	if err := ctx.Err(); err != nil {
		return err
	}

	doneC := make(chan error, 1)
	req := sendReq{m: m, doneC: doneC}
	select {
	case fc.writer.sendC <- req:
	case <-fc.sessCtx.Done():
		return ErrNotEstablished
	case <-ctx.Done():
		return ctx.Err()
	}

	// The writer accepted the message: the send is committed, and the
	// writer always answers, even when the session dies mid-write.
	err := <-doneC
	if err != nil && !isMarshalError(err) {
		// A connection write failure ends the session, since the writer
		// has already forwarded it to the FSM, so wrap [ErrNotEstablished]:
		// errors.Is then separates a dying session, which a route pusher
		// answers by winding down, from a message of the caller's own
		// which does not marshal, which leaves the session healthy.
		return fmt.Errorf("%w: %w", ErrNotEstablished, err)
	}

	return err
}

// shutdownCease builds the NOTIFICATION sent when Connect's ctx is canceled. A
// *MessageError cancellation cause is a complete, caller-owned farewell,
// sent verbatim; otherwise the standing shutdownCause, if any (Peer's
// ShutdownCommunication); otherwise a plain Administrative Shutdown.
func (f *FSM) shutdownCease(ctx context.Context) *Notification {
	if me, ok := errors.AsType[*MessageError](context.Cause(ctx)); ok {
		return me.Notification()
	}

	if f.shutdownCause != nil {
		return f.shutdownCause.Notification()
	}

	return &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseAdministrativeShutdown,
	}
}

// implicitFamilies is the address family set of a speaker which advertises
// no multiprotocol capabilities at all: the classic IPv4 unicast speaker of
// RFC 4760. It is shared and must not be mutated.
var implicitFamilies = []Family{{AFI: AFIIPv4, SAFI: SAFIUnicast}}

// jittered scales d by a random factor in [0.75, 1.0], the jitter RFC 4271,
// section 10 applies to retry timers so peers do not synchronize.
func (f *FSM) jittered(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.75 + 0.25*f.jitter()))
}

// onClose reports the end of a session or session attempt to the caller.
func (f *FSM) onClose(c Close) {
	f.log.Info("session closed",
		"notification", c.Notification, "local", c.Local, "err", c.Err)
	if h := f.cfg.OnClose; h != nil {
		h(f, c)
	}
}

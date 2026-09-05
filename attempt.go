package bgp

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The concurrency shape of an FSM, per the FSM plan: one goroutine (Connect's)
// owns every state transition, every timer, and every write. One reader
// goroutine per live TCP connection (at most two, during collision handling)
// blocks in Conn.ReadMessage and forwards messages to the FSM goroutine.
// Once a session is established, the caller's handlers run directly on the
// reader, so a slow handler stalls receipt and TCP backpressure reaches the
// peer while keepalives keep flowing outbound. The only shared state outside
// the channels is three atomics. Each connection carries a last-received
// timestamp, which makes the hold timer a periodic check rather than a
// per-message channel send, and an in-handler flag for hold-expiry
// attribution. The FSM itself carries the established connection, published
// for the send methods, which run on caller goroutines (FSM.established).
// New shared state needs the same level of justification.

// An attempt is the state of one session attempt: the connections being tracked,
// the dial in flight, and the attempt's timers. FSM.attempt owns one per
// attempt and drives it from a single select loop; every method runs
// on the FSM goroutine.
type attempt struct {
	f *FSM

	// open is the attempt's local OPEN: the graceful restart Restarting
	// variant when the caller's hook claims a restart, consulted once per
	// attempt so both connections of a collision advertise the same claim,
	// like the peer identity in claimed.
	open *Open

	// eventC carries every tracked connection's events.
	eventC chan connEvent

	// tracked holds the tracked connections, indexed by origin: both
	// slots filled only while a collision is unresolved.
	tracked [2]*fsmConn

	// The active open runs in its own goroutine, since dialing blocks; dialC
	// is nil when no dial is in flight, and buffered so an abandoned dial
	// never leaks. cancelDial cancels the current dial's context; it is a
	// no-op until the first dial.
	cancelDial context.CancelFunc
	dialC      <-chan dialResult

	// connectRetryC paces active opens (RFC 4271, section 8.2.2): armed when a
	// dial begins, it bounds the dial itself and schedules the next one
	// after a failure. The timer exists, stopped, from construction, so no
	// arm needs a nil check. connectRetryC is nil and never selected until
	// the first dial arms the timer, so a passive attempt never dials. The
	// hold timers live on each connection; see fsmConn.holdT.
	connectRetryT *time.Timer
	connectRetryC <-chan time.Time

	// claimed is the peer identity of the first OPEN accepted in this
	// attempt; every later OPEN must agree. See bgpOpen.
	claimed *Open

	// state is the last aggregate state reported through OnStateChange,
	// StateIdle where every attempt begins. See currentState.
	state State
}

// ceaseCollisionResolution is the NOTIFICATION a collision's loser is sent.
// It is shared and must not be mutated.
var ceaseCollisionResolution = &Notification{
	Code:    NotificationCease,
	Subcode: SubcodeCeaseConnectionCollisionResolution,
}

// A dialResult is the outcome of one active open.
type dialResult struct {
	c   *Conn
	err error
}

// errAttemptOver ends an attempt's loop: the session or session attempt
// finished and its Close was already reported, so Connect returns nil. It is a
// signal in the manner of http.ErrServerClosed, not a failure, and attempt
// translates it to nil so it never escapes the FSM.
var errAttemptOver = errors.New("bgp: session attempt over")

// attempt runs one session attempt: connecting in both directions, the OPEN
// exchange, collision resolution, and, once a connection is confirmed, the
// Established loop. A session failure is reported via onClose and returns
// nil, concluding Connect. The returned error is non-nil only when ctx ends.
func (f *FSM) attempt(ctx context.Context) error {
	a := &attempt{
		f:          f,
		open:       f.opens[0],
		eventC:     make(chan connEvent),
		cancelDial: func() {},
		state:      StateIdle,
	}

	if g := f.cfg.GracefulRestart; g != nil && g.Restarting != nil && g.Restarting() {
		a.open = f.opens[1]
	}

	a.connectRetryT = time.NewTimer(connectRetryTime)
	a.connectRetryT.Stop()
	// An abandoned dial is canceled and its too-late connection closed; the
	// timer is stopped. Every tracked connection was killed and joined by
	// the exit path itself, and the writer joined by endSession; see
	// TestFSMGoroutinesEndWithConnect.
	defer func() {
		a.abandonDial()
		a.connectRetryT.Stop()
	}()

	if !f.cfg.Passive {
		a.dial(ctx)
	}

	a.syncState()
	for {
		// A nil return continues the loop, reporting the aggregate state
		// the event left behind. Any error ends the attempt: errAttemptOver
		// normally, anything else terminally. There is no representable
		// "error but keep going" state. Every exit is the machine entering
		// Idle, reported as the attempt's final hook after any Close; an
		// ending attempt already reported Established through keepAliveMsg.
		err := a.dispatch(ctx)
		if err == nil {
			a.syncState()
			continue
		}

		a.setState(StateIdle)
		if errors.Is(err, errAttemptOver) {
			return nil
		}

		return err
	}
}

// dispatch waits for one input and handles it: the RFC 4271, section 8.1
// events this machine models, by name where one applies.
func (a *attempt) dispatch(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return a.manualStop(ctx)
	case r := <-a.dialC:
		// The dial is over: release its context, and take its outcome as
		// Tcp_CR_Acked or TcpConnectionFails. A failed dial leaves the
		// connect retry timer running so the next dial begins on its
		// cadence.
		a.dialC = nil
		a.cancelDial()
		if r.err != nil {
			a.f.log.Info("failed to dial", "err", r.err)
			return nil
		}

		return a.tcpCRAcked(r.c)
	case <-a.connectRetryC:
		a.connectRetryC = nil
		return a.connectRetryTimerExpires(ctx)
	case c := <-a.f.connC:
		return a.tcpConnectionConfirmed(c)
	case <-a.holdChan(originDialed):
		return a.holdTimerExpires(a.tracked[originDialed])
	case <-a.holdChan(originAccepted):
		return a.holdTimerExpires(a.tracked[originAccepted])
	case <-a.keepaliveChan(originDialed):
		return a.keepaliveTimerExpires(a.tracked[originDialed])
	case <-a.keepaliveChan(originAccepted):
		return a.keepaliveTimerExpires(a.tracked[originAccepted])
	case ev := <-a.eventC:
		return a.event(ctx, ev)
	}
}

// connectRetryTimerExpires handles a connect retry tick (RFC 4271, section
// 8.2.2): the cadence restarts a dial which has outlived it, stands by while a
// connection owns the attempt, or begins the next dial.
func (a *attempt) connectRetryTimerExpires(ctx context.Context) error {
	switch {
	case a.dialC != nil && a.empty():
		// The in-flight dial outlived the connect retry time: drop it and
		// begin another (RFC 4271, section 8.2.2, event 9).
		a.abandonDial()
		a.dial(ctx)

	case a.dialC != nil:
		// An accepted connection is mid-exchange and owns the attempt while
		// the dial is still in flight, so no new dial starts. The cadence is
		// re-armed rather than stranded: tcpCRAcked's failure path has no
		// timer of its own, and the next tick restarts a dial which has
		// failed by then. A tracked dialed connection never reaches here:
		// its successful dial stopped the timer.
		a.restartConnectRetryTimer()

	default:
		// No dial in flight: keep the active open's cadence even while an
		// accepted connection is mid-exchange. A peer which completes a TCP
		// handshake and then stalls in OpenSent must not suppress this
		// speaker's active open for the rest of the attempt.
		a.dial(ctx)
	}

	return nil
}

// holdChan and keepaliveChan return the hold or keepalive timer channel of
// the connection tracked in origin d, or nil, never selected, when the
// slot is empty. A connection's keepalive timer is stopped until OpenConfirm,
// so its channel is selected harmlessly before then.
func (a *attempt) holdChan(d origin) <-chan time.Time {
	if fc := a.tracked[d]; fc != nil {
		return fc.holdC
	}

	return nil
}

func (a *attempt) keepaliveChan(d origin) <-chan time.Time {
	if fc := a.tracked[d]; fc != nil {
		return fc.keepaliveC
	}

	return nil
}

// restartConnectRetryTimer starts or restarts the connect retry timer at the
// jittered cadence: dial arms it as each dial begins, and the retry arm re-arms
// it when it declines to dial, so the next tick re-evaluates.
func (a *attempt) restartConnectRetryTimer() {
	a.connectRetryT.Reset(a.f.jittered(connectRetryTime))
	a.connectRetryC = a.connectRetryT.C
}

// resumeConnectRetryTimer re-arms the connect retry timer after the dialed
// connection is lost while the attempt continues, in the spirit of RFC 4271,
// section 8.2.2's TcpConnectionFails handling. The timer was stopped when
// the dial succeeded. Without a re-arm here, an attempt riding only on an
// accepted connection would have no active open until the attempt itself
// failed: up to a full openHoldTime against a peer stalled in OpenSent.
//
// No dial or timer can be live here. A dialed connection is only ever
// tracked after its successful dial stopped the timer, and no dial starts
// while the dialed slot is occupied. A passive attempt never has a dialed
// connection to lose.
func (a *attempt) resumeConnectRetryTimer() {
	a.restartConnectRetryTimer()
	a.f.log.Debug("resuming connect retry timer")
}

// abandonDial cancels the dial in flight, if any, and stops waiting for it.
// A drain goroutine takes over the abandoned dial and closes the connection
// a too-late dial produces. This is the only way a dial is given up. Its
// two callers are the connect retry cadence, which abandons a dial that
// outlived its tick before starting another, and an attempt's deferred
// teardown.
//
// The drain must not run on the FSM goroutine. A caller's DialFunc is bound
// by a contract this package cannot enforce: a DialFunc which ignores its
// canceled context would wedge the attempt for as long as it pleased,
// stalling the FSM's timers, its events, and cancellation. Two details
// keep the handoff safe. dialC is buffered, so the dial goroutine never
// blocks handing off even when nothing is left to receive. The drain
// closes over the channel value rather than the field, so the next dial
// may reassign both freely.
func (a *attempt) abandonDial() {
	a.cancelDial()

	ch := a.dialC
	if ch == nil {
		return
	}

	a.dialC = nil

	go func() {
		if r := <-ch; r.c != nil {
			_ = r.c.Close()
		}
	}()
}

// conns returns the live tracked connections.
func (a *attempt) conns() []*fsmConn {
	var cs []*fsmConn
	for _, fc := range a.tracked {
		if fc != nil {
			cs = append(cs, fc)
		}
	}

	return cs
}

// untrack forgets a torn-down connection: each caller holds the connection
// it just killed, and untracks it once.
func (a *attempt) untrack(fc *fsmConn) {
	a.tracked[fc.origin] = nil
}

// other returns the connection tracked in the origin opposite fc, if any.
func (a *attempt) other(fc *fsmConn) *fsmConn {
	return a.tracked[fc.origin.other()]
}

// currentState is the attempt's aggregate state: the furthest-progressed of
// everything live, per RFC 4271, section 8. A collision tracks two
// connections at once, and section 6.8 models the second as a second FSM. A
// single stream must therefore aggregate, and may regress when the further
// connection dies or loses the collision while the other survives. With no
// connection at all, a dial in flight is the Connect state and awaiting one
// (a passive attempt, or the pause before the next retry tick) is Active,
// matching section 8.2.2's TcpConnectionFails handling.
//
// Establishment is read from FSM.established, which the tracked connections
// alone cannot tell: the established connection stays tracked. It is
// published before the state is reported and cleared only as the attempt
// ends, so on this goroutine it is exact.
func (a *attempt) currentState() State {
	if a.f.established.Load() != nil {
		return StateEstablished
	}

	for _, fc := range a.conns() {
		if fc.state == StateOpenConfirm {
			return StateOpenConfirm
		}
	}

	switch {
	case !a.empty():
		return StateOpenSent
	case a.dialC != nil:
		return StateConnect
	default:
		return StateActive
	}
}

// syncState reports the current aggregate state through OnStateChange when
// it changed, and setState a given one: the transition to Idle which
// concludes the attempt. Both run on the FSM goroutine, so the hook must
// return promptly.
func (a *attempt) syncState() { a.setState(a.currentState()) }

func (a *attempt) setState(to State) {
	if to == a.state {
		return
	}

	from := a.state
	a.state = to
	a.f.log.Debug("state transition", "from", from, "to", to)
	if h := a.f.cfg.OnStateChange; h != nil {
		h(a.f, from, to)
	}
}

// empty reports whether no connection is tracked.
func (a *attempt) empty() bool {
	return a.tracked[originDialed] == nil && a.tracked[originAccepted] == nil
}

// fail ends the attempt: every remaining connection is torn down and the
// failure is reported, then Run retries after the idleceive path has quiesced.
func (a *attempt) fail(c Close) error {
	for _, fc := range a.conns() {
		fc.kill()
	}

	a.tracked = [2]*fsmConn{}
	a.f.onClose(c)
	return errAttemptOver
}

// drop tears fc down after sending n; when fc was the last connection, the
// attempt fails with cl. A dialed connection dropped mid-attempt resumes
// the active open's cadence; see resumeConnectRetryTimer.
func (a *attempt) drop(fc *fsmConn, n *Notification, cl Close) error {
	if n != nil {
		a.f.sendNotification(fc.c, n)
	}

	fc.kill()
	a.untrack(fc)
	if a.empty() {
		return a.fail(cl)
	}

	if fc.origin == originDialed {
		a.resumeConnectRetryTimer()
	}

	return nil
}

// reject answers a connection's unexpected message with the RFC 6608
// subcode for its state and tears the connection down.
func (a *attempt) reject(fc *fsmConn) error {
	n := &Notification{Code: NotificationFSMError, Subcode: fc.state.fsmSubcode()}
	a.f.log.Info("unexpected message", "origin", fc.origin, "notification", n)
	return a.drop(fc, n, Close{Notification: n, Local: true})
}

// rejectOpen answers a peer's unacceptable OPEN with merr's NOTIFICATION and
// tears the connection down.
func (a *attempt) rejectOpen(fc *fsmConn, merr *MessageError) error {
	a.f.log.Info("OPEN rejected", "origin", fc.origin, "err", merr)
	n := merr.Notification()
	return a.drop(fc, n, Close{Notification: n, Err: merr, Local: true})
}

// dial begins the active open, arming the connect retry timer as it does:
// the timer bounds the dial itself, not just the pause after a failure, so
// a black-holed peer is re-dialed on the connect retry cadence rather than
// after the OS gives up on the SYN (RFC 4271, section 8.2.2).
func (a *attempt) dial(ctx context.Context) {
	a.f.log.Debug("dialing", "state", StateConnect)

	ctx, cancel := context.WithCancel(ctx)
	a.cancelDial = cancel

	// The goroutine closes over this dial's own context and channel, not the
	// attempt fields: the FSM goroutine reassigns those for later dials.
	ch := make(chan dialResult, 1)
	a.dialC = ch
	a.restartConnectRetryTimer()

	// NewFSM requires a DialFunc unless Passive, and a Passive attempt
	// never dials, so the seam is always populated here.
	dial := a.f.cfg.DialFunc

	go func() {
		c, err := dial(ctx)
		if err == nil {
			a.f.adopt(c)
		}

		ch <- dialResult{c: c, err: err}
	}()
}

// tcpCRAcked is RFC 4271's Tcp_CR_Acked event: the active open produced a
// connection, which enters the OPEN exchange and stops the connect retry
// timer (section 8.2.2). If the OPEN write fails while an accepted connection
// holds the attempt, the timer resumes: the dialed side produced nothing,
// and the attempt must not ride the accepted connection alone.
func (a *attempt) tcpCRAcked(c *Conn) error {
	a.connectRetryT.Stop()
	a.connectRetryC = nil

	if err := a.start(c, originDialed); err != nil {
		if a.empty() {
			return a.fail(Close{Err: err, Local: true})
		}

		a.resumeConnectRetryTimer()
	}

	return nil
}

// tcpConnectionConfirmed is RFC 4271's event of that name: a connection the
// peer opened, delivered by DeliverConn.
func (a *attempt) tcpConnectionConfirmed(c *Conn) error {
	if old := a.tracked[originAccepted]; old != nil {
		// An occupant which has completed its OPEN exchange carries a live
		// peer; the newcomer is refused.
		if old.state != StateOpenSent {
			a.f.log.Debug("refused connection: one is already accepted")
			a.f.rejectConn(c)
			return nil
		}

		// The occupant is still awaiting the peer's OPEN, and another
		// connection has arrived for the same peering. The FSM checks no
		// address: a Peer matches the remote before delivering, and a raw
		// DeliverConn caller vouches by choosing this FSM. The usual
		// reading is therefore a peer which crashed after the TCP
		// handshake and reconnected. Its new connection is the fresher
		// evidence of liveness, so it takes the slot. Refusing it would lock
		// the peer out until the stale occupant's openHoldTime expired.
		// The Cease is best effort, for an occupant somehow still alive.
		a.f.log.Info("replaced stale accepted connection", "state", old.state)
		a.f.sendNotification(old.c, &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseConnectionRejected,
		})
		old.kill()
		a.untrack(old)
	}

	// A failed OPEN on an accepted connection ends the attempt only on a
	// passive peer, which has no other path to a session and, never
	// having dialed, no other connection tracked. An active peer's dial
	// and connect retry machinery is still running, so its attempt
	// continues and nothing is reported until the attempt itself ends.
	if err := a.start(c, originAccepted); err != nil && a.f.cfg.Passive {
		return a.fail(Close{Err: err, Local: true})
	}

	return nil
}

// start begins the OPEN exchange on a new connection in either origin,
// entering OpenSent. A write failure closes the connection, which is never
// tracked, and returns the underlying error so the caller can report why.
func (a *attempt) start(c *Conn, o origin) error {
	if err := writeBounded(c, a.open); err != nil {
		a.f.log.Info("failed to send OPEN", "err", err)
		_ = c.Close()
		return fmt.Errorf("bgp: failed to send OPEN: %w", err)
	}

	a.tracked[o] = a.f.newFSMConn(c, o, a.eventC)
	a.f.log.Info("OPEN sent", "state", StateOpenSent, "origin", o)
	return nil
}

// manualStop is RFC 4271's ManualStop event: ctx ended, so a Cease precedes
// the close on any connection which has begun the OPEN exchange, and OnClose
// reports the end of the attempt exactly as it would for a failure. An
// attempt with no connection ends silently: nothing observable had begun.
func (a *attempt) manualStop(ctx context.Context) error {
	if cs := a.conns(); len(cs) > 0 {
		n := a.f.shutdownCease(ctx)
		for _, fc := range cs {
			a.f.sendNotification(fc.c, n)
		}

		// fail kills the connections and reports the Close; its
		// errAttemptOver verdict is superseded by ctx's error below.
		_ = a.fail(Close{Notification: n, Local: true})
	}

	return ctx.Err()
}

// holdTimerExpires drops a connection whose peer went silent for the hold time:
// the OpenSent "large value", or the negotiated hold once the peer's OPEN
// was accepted (RFC 4271, section 8.2.2). A collision connection in the
// other origin keeps its own budget and the attempt continues on it;
// when the expired connection was the last, the attempt fails.
func (a *attempt) holdTimerExpires(fc *fsmConn) error {
	n := &Notification{Code: NotificationHoldTimerExpired}
	a.f.log.Info("hold timer expired", "origin", fc.origin, "state", fc.state)
	return a.drop(fc, n, Close{Notification: n, Local: true})
}

// keepaliveTimerExpires sends a periodic KEEPALIVE on a connection in
// OpenConfirm: the peer's hold timer must be fed while it withholds the
// confirming KEEPALIVE, or the peer tears the connection down first every time.
// There is no writer goroutine before Established, so the write runs bounded on
// the FSM goroutine.
func (a *attempt) keepaliveTimerExpires(fc *fsmConn) error {
	if err := writeBounded(fc.c, &Keepalive{}); err != nil {
		a.f.log.Info("connection failed", "origin", fc.origin, "err", err)
		return a.drop(fc, nil, Close{Err: err, Local: true})
	}

	fc.keepaliveT.Reset(a.f.jittered(fc.sess.HoldTime / 3))
	return nil
}

// event dispatches one reader goroutine report.
//
// Every event is from a tracked connection: kill joins the reader on this
// goroutine, and eventC is unbuffered with this goroutine its only receiver, so
// a killed connection never has an event in flight once it is untracked.
func (a *attempt) event(ctx context.Context, ev connEvent) error {
	fc := ev.fc
	if err := ev.err; err != nil {
		// The connection died or delivered garbage: a *MessageError is
		// terminal for a Conn, so answer and close either way. Before
		// Established only the reader reports, so garbage is this speaker's
		// close (it answers) and a dead transport is the peer's.
		sent := notificationFromErr(err)
		a.f.log.Info("connection failed", "origin", fc.origin, "err", err)
		return a.drop(fc, sent, Close{Notification: sent, Err: err, Local: sent != nil})
	}

	switch m := ev.msg.(type) {
	case *Open:
		return a.bgpOpen(fc, m)
	case *Keepalive:
		return a.keepAliveMsg(ctx, fc)
	case *Notification:
		// NotifMsg: the peer refused the OPEN exchange.
		n := m.Clone()
		a.f.log.Info("NOTIFICATION received", "origin", fc.origin, "notification", n)
		return a.drop(fc, nil, Close{Notification: n})
	default:
		// UpdateMsg, or ROUTE-REFRESH, before the session is established.
		return a.reject(fc)
	}
}

// bgpOpen validates a peer's OPEN, resolves a collision when a second
// connection is tracked, and confirms the survivor into OpenConfirm.
func (a *attempt) bgpOpen(fc *fsmConn, o *Open) error {
	if fc.state != StateOpenSent {
		return a.reject(fc)
	}

	sess, merr := a.f.negotiate(a.open, o)
	if merr != nil {
		return a.rejectOpen(fc, merr)
	}

	// A collision tie-break must run on one peer identity. The first OPEN
	// accepted in an attempt fixes the peer's claim, and a later OPEN which
	// contradicts it is rejected: a peer must not steer which connection
	// survives by advertising a different identity on each one.
	if c := a.claimed; c == nil {
		a.claimed = sess.Peer
	} else if sess.Peer.ASN != c.ASN || sess.Peer.ID != c.ID {
		subcode, field := SubcodeBadBGPIdentifier, "identifier"
		if sess.Peer.ASN != c.ASN {
			subcode, field = SubcodeBadPeerAS, "ASN"
		}

		return a.rejectOpen(fc, openError(subcode, nil,
			"peer %s contradicts the identity accepted earlier in this attempt (%s, AS %d)",
			field, c.ID, c.ASN))
	}

	fc.sess = sess
	fc.sess.LocalAddr = fc.c.LocalAddr()
	fc.sess.RemoteAddr = fc.c.RemoteAddr()

	// Publish the add-path receive set before the confirming KEEPALIVE
	// below can be written: the peer sends no UPDATE until that KEEPALIVE
	// establishes its session, so the connection's reader parses every
	// add-path NLRI entry with its path identifier.
	if len(sess.AddPath) > 0 {
		var recv []Family
		for _, af := range sess.AddPath {
			if af.Receive {
				recv = append(recv, af.Family)
			}
		}

		fc.c.setAddPath(recv)
	}

	// A second tracked connection is a collision (RFC 4271, section 6.8),
	// resolved now that the peer's identifier is known: the connection
	// initiated by the speaker with the higher identifier lives.
	//
	// An identifier tie breaks toward the higher ASN (RFC 6286, section 2.3),
	// and the loser is dropped with Cease / Connection Collision Resolution.
	// The tie-break reads the attempt's fixed identity claim, so the verdict
	// cannot depend on which connection carried the peer's OPEN. It runs on
	// OPEN receipt only, while neither connection has completed its exchange; a
	// collision still unresolved when a confirming KEEPALIVE arrives is settled
	// by the establishment itself, in the established connection's favor; see
	// keepAliveMsg.
	if a.other(fc) != nil {
		loser := a.tracked[originAccepted]
		if !dialedSurvives(a.f.cfg.LocalID, a.claimed.ID, a.f.cfg.LocalASN, a.claimed.ASN) {
			loser = a.tracked[originDialed]
		}

		a.f.log.Info("connection collision resolved", "survivor", loser.origin.other())
		// Never the last connection, so drop cannot fail the attempt.
		_ = a.drop(loser, ceaseCollisionResolution, Close{Local: true})
		if loser == fc {
			return nil
		}
	}

	// OPEN accepted: confirm it, enter OpenConfirm. Per RFC 4271, section
	// 8.2.2, the hold timer drops from the OpenSent "large value" to the
	// negotiated hold time, and the keepalive timer starts: the peer's own
	// hold timer must be fed while it withholds the confirming KEEPALIVE.
	if err := writeBounded(fc.c, &Keepalive{}); err != nil {
		a.f.log.Info("connection failed", "origin", fc.origin, "err", err)
		return a.drop(fc, nil, Close{Err: err, Local: true})
	}

	fc.state = StateOpenConfirm
	fc.holdT.Reset(fc.sess.HoldTime)
	fc.keepaliveT.Reset(a.f.jittered(fc.sess.HoldTime / 3))
	a.f.log.Info("OPEN accepted", "state", StateOpenConfirm, "origin", fc.origin)
	fc.instructionC <- instructionContinue
	return nil
}

// keepAliveMsg confirms the OPEN exchange: the session is established on
// fc. A leftover connection in the other origin is a still-unresolved
// collision, settled by the establishment itself rather than the section
// 6.8 tie-break: the confirming KEEPALIVE proves the peer accepted this
// speaker's OPEN on fc, and a peer running the RFC 4271 default
// (CollisionDetectEstablishedState false), this package included, has by
// then established on fc itself and refuses every other connection. A
// tie-break preferring the other connection here would tear down the one
// connection both speakers agree on and flap the session.
func (a *attempt) keepAliveMsg(ctx context.Context, fc *fsmConn) error {
	if fc.state != StateOpenConfirm {
		return a.reject(fc)
	}

	// The other connection is still in OpenSent, since a second connection
	// never outlives the OPEN-time collision resolution in bgpOpen. Nothing
	// observable has begun on it, so it is dropped without a verdict to
	// disagree over.
	if other := a.other(fc); other != nil {
		a.f.log.Info("connection collision resolved by establishment", "survivor", fc.origin)
		a.f.sendNotification(other.c, ceaseCollisionResolution)
		other.kill()
		a.untrack(other)
	}

	// Establishment: create the session context, start the writer, and
	// publish the connection to the send methods, all before
	// instructionSession releases the reader into the caller's handlers.
	fc.sessCtx, fc.cancelSess = context.WithCancel(ctx)
	fc.writer = &sessionWriter{
		sendC:      make(chan sendReq),
		keepaliveC: make(chan struct{}, 1),
		exited:     make(chan struct{}),
	}

	fc.resetC = make(chan resetReq)
	go a.f.writeSession(fc)
	a.f.established.Store(fc)

	// The transition to Established is reported before the reader is
	// released into the caller's handlers, so it precedes OnEstablished.
	a.syncState()

	fc.instructionC <- instructionSession
	if err := a.established(ctx, fc); err != nil {
		return err
	}

	return errAttemptOver
}

// established runs the Established state on the FSM goroutine: keepalive
// transmission, hold timer supervision, and teardown. The caller's handlers
// run concurrently on fc's reader goroutine, which forwards only terminal
// events here. Like attempt, a session failure reports via onClose and
// returns nil, concluding Connect.
func (a *attempt) established(ctx context.Context, fc *fsmConn) error {
	hold := fc.sess.HoldTime
	a.f.log.Info("session established", "state", StateEstablished,
		"origin", fc.origin, "hold_time", hold, "families", fc.sess.Families)

	// The connection's own timers carry over from OpenConfirm, restarted
	// for the session (RFC 4271, section 8.2.2 restarts the hold timer on
	// the KEEPALIVE which established): same timers, same cadence, but from
	// here the keepalives go through the writer goroutine.
	keepaliveT, holdT := fc.keepaliveT, fc.holdT
	keepaliveT.Reset(a.f.jittered(hold / 3))
	defer keepaliveT.Stop()
	holdT.Reset(hold)
	defer holdT.Stop()

	for {
		select {
		case <-ctx.Done():
			a.f.endSession(fc, Close{Notification: a.f.shutdownCease(ctx), Local: true})
			return ctx.Err()

		case c := <-a.f.connC:
			// CollisionDetectEstablishedState is false (the RFC 4271 default):
			// a new connection never displaces an established session.
			a.f.log.Debug("refused connection: session is established")
			a.f.rejectConn(c)

		case r := <-a.dialC:
			// The attempt's active open completed after an accepted
			// connection established the session: refuse it like any other
			// connection, rather than holding it open, unread, until the
			// session ends. Nil dialC so the deferred teardown does not drain it again.
			a.cancelDial()
			a.dialC = nil
			if r.c != nil {
				a.f.log.Debug("refused dialed connection: session is established")
				a.f.rejectConn(r.c)
			}

		case <-keepaliveT.C:
			// The keepalive goes through the writer goroutine:
			// a non-blocking send, dropping the tick when one is already
			// pending, so the FSM never blocks on the write path. A write
			// failure comes back as a terminal event on eventC.
			select {
			case fc.writer.keepaliveC <- struct{}{}:
			default:
				// A keepalive is already pending, so the writer has not
				// written for a full interval: it is draining a large send,
				// or wedged against a peer which stopped reading. The log
				// is the local signal for the wedged case, whose writes the
				// writer's deadline bounds; see writeSession.
				a.f.log.Debug("dropped keepalive: writer is busy")
			}

			keepaliveT.Reset(a.f.jittered(hold / 3))

		case <-holdT.C:
			elapsed := time.Duration(fc.sinceBase() - fc.lastRecv.Load())
			if elapsed < hold {
				holdT.Reset(hold - elapsed)
				continue
			}

			// A reader stuck inside a caller handler is this speaker
			// shedding load, not the peer going silent: Hold Timer Expired
			// would lie in the peer operator's logs.
			n := &Notification{Code: NotificationHoldTimerExpired}
			if fc.inHandler.Load() {
				n = &Notification{Code: NotificationCease, Subcode: SubcodeCeaseOutOfResources}
			}

			a.f.endSession(fc, Close{Notification: n, Local: true})
			return nil

		case req := <-fc.resetC:
			// ResetSession: a caller-initiated end. The attempt concludes
			// like any session close, and the caller's retry loop owns
			// what happens next; done releases the caller only after the
			// teardown, OnClose included.
			a.f.log.Info("session reset", "notification", req.n)
			a.f.endSession(fc, Close{Notification: req.n, Local: true})
			close(req.done)
			return nil

		case ev := <-a.eventC:
			// The established connection's own terminal event: every other
			// connection was killed and joined before establishment, so no
			// other reader exists to send one; see event.
			a.f.endSession(fc, sessionClose(ev))
			return nil
		}
	}
}

// errStuckHandler reports a caller handler which did not return within the
// teardown bound after its session context was canceled. The FSM abandons
// the reader goroutine to continue; see endSession.
var errStuckHandler = errors.New("bgp: a handler ignored its canceled session context; its goroutine is abandoned")

// endSession tears an established session down, in order. The send methods
// are cut off first. The writer goroutine is quiesced, so that when this
// speaker owes the peer a NOTIFICATION nothing follows it on the wire. The
// session context is canceled so a blocked handler can return. OnClose fires
// last, after the receive path has quiesced.
func (f *FSM) endSession(fc *fsmConn, cl Close) {
	// Every established session ends here, and only attempt teardowns
	// report a Close anywhere else.
	cl.Established = true

	f.established.Store(nil)

	// The write deadline comes first: it bounds a writer blocked mid-write
	// by an unresponsive peer, and then bounds the NOTIFICATION write below
	// under the same absolute budget.
	_ = fc.c.SetWriteDeadline(time.Now().Add(teardownTimeout))
	fc.cancelSess()
	close(fc.fsmDone)
	<-fc.writer.exited

	// The writer has exited, so the NOTIFICATION is the connection's last
	// message: a KEEPALIVE queued on the writer when the session ended is either
	// already on the wire or dropped.
	if cl.Notification != nil && cl.Local {
		if err := fc.c.WriteMessage(cl.Notification); err != nil {
			f.log.Debug("failed to send NOTIFICATION", "err", err)
		}
	}

	_ = fc.c.Close()

	// The reader join is bounded: a handler which ignores its canceled ctx
	// would otherwise park the FSM goroutine forever, wedging the whole
	// FSM to preserve an ordering guarantee that is already unsatisfiable.
	// An abandoned reader invokes no further handlers: when the stuck
	// handler returns, the reader's next read fails on the closed
	// connection and its forward observes the closed fsmDone channel. But
	// the stuck invocation itself may overlap OnClose and a later
	// session's handlers, so Close.Err reports the abandonment.
	t := time.NewTimer(teardownTimeout)
	defer t.Stop()
	select {
	case <-fc.readerDone:
	case <-t.C:
		cl.Err = errors.Join(cl.Err, errStuckHandler)
	}

	f.onClose(cl)
}

// sessionClose maps a terminal reader event to the Close which ends an
// established session: the NOTIFICATION, its origin, and the underlying
// error.
func sessionClose(ev connEvent) Close {
	switch {
	case ev.handlerErr != nil:
		// A handler ended the session: a *MessageError picks the
		// NOTIFICATION, and any other error sends a plain Cease.
		n := notificationFromErr(ev.handlerErr)
		if n == nil {
			n = &Notification{Code: NotificationCease}
		}

		return Close{Notification: n, Err: ev.handlerErr, Local: true}

	case ev.err != nil:
		// The connection died, or delivered garbage: a *MessageError is
		// terminal for a Conn, so answer and close either way. Garbage is
		// this speaker's close, as is a transport its writer gave up on; a
		// transport the reader found dead is the peer's.
		n := notificationFromErr(ev.err)
		return Close{Notification: n, Err: ev.err, Local: n != nil || ev.local}

	default:
		switch m := ev.msg.(type) {
		case *Notification:
			return Close{Notification: m.Clone()}
		default:
			// A second OPEN mid-session.
			return Close{Notification: &Notification{
				Code:    NotificationFSMError,
				Subcode: SubcodeUnexpectedMessageEstablished,
			}, Local: true}
		}
	}
}

// notificationFromErr maps an error to the NOTIFICATION answering it: a
// *MessageError picks its own, and any other error has none.
func notificationFromErr(err error) *Notification {
	if merr, ok := errors.AsType[*MessageError](err); ok {
		return merr.Notification()
	}

	return nil
}

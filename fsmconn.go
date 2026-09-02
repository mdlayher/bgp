package bgp

import (
	"context"
	"sync/atomic"
	"time"
)

// A connection's OPEN exchange holds one of two States, OpenSent or
// OpenConfirm (fsmConn.state). The remaining RFC states have no
// per-connection representation: Idle is the FSM between Connects, Connect
// and Active are phases of FSM.attempt, and Established is
// attempt.established. The attempt aggregates them all for OnStateChange;
// see attempt.currentState.

// An origin is a connection's initiator: this speaker dialed it, or the
// peer connected and it was accepted. It doubles as the connection's slot
// index in attempt.tracked.
type origin uint8

const (
	originDialed origin = iota
	originAccepted
)

// String implements fmt.Stringer, for logging.
func (d origin) String() string {
	if d == originDialed {
		return "dialed"
	}

	return "accepted"
}

// other returns the opposite origin.
func (d origin) other() origin {
	if d == originDialed {
		return originAccepted
	}

	return originDialed
}

// An fsmConn is one live connection tracked by the FSM goroutine. At most
// two exist at once: one dialed and one accepted, while a connection
// collision (RFC 4271, section 6.8) is unresolved.
type fsmConn struct {
	c      *Conn
	origin origin
	state  State

	// eventC carries this connection's events to the FSM goroutine.
	// instructionC carries the FSM's instruction back after each
	// pre-Established event: the reader does not touch the read buffer again
	// until instructed, so the FSM may use a forwarded message's borrowed
	// memory safely.
	eventC       chan<- connEvent
	instructionC chan readerInstruction

	// fsmDone is closed by the FSM goroutine to abandon the connection; it
	// unblocks a reader waiting to forward an event or awaiting an
	// instruction. readerDone is closed by the reader as it exits.
	fsmDone    chan struct{}
	readerDone chan struct{}

	// holdT bounds the peer's silence on this connection, per RFC 4271,
	// section 8.2.2: armed at the OpenSent "large value" (openHoldTime)
	// when the connection starts — each connection carries a full budget,
	// so a late collision connection does not inherit an earlier one's
	// nearly spent timer — reset to the negotiated hold time on entering
	// OpenConfirm, and reset again as the session's hold timer at
	// establishment. keepaliveT feeds the peer's own hold timer at a
	// jittered third of the negotiated hold: like attempt.connectRetryT it
	// exists, stopped, from construction, so no arm needs a nil check, and
	// is armed when the peer's OPEN is accepted. kill stops both.
	holdT      *time.Timer
	holdC      <-chan time.Time
	keepaliveT *time.Timer
	keepaliveC <-chan time.Time

	// Session state, populated by the FSM goroutine: sess when the peer's
	// OPEN is accepted, the rest at establishment, before the
	// instructionSession instruction and FSM.established publish them
	// to the reader and the send methods.
	sess       Session
	sessCtx    context.Context
	cancelSess context.CancelFunc

	// writer links callers and the FSM to the writer goroutine;
	// nil before Established. resetC carries ResetSession requests to the
	// FSM goroutine, unbuffered so a send's acceptance is the FSM's receipt;
	// nil before Established too.
	writer *sessionWriter
	resetC chan resetReq

	// base anchors lastRecv: set once before the reader starts, never
	// mutated. Elapsed time is time.Since's monotonic reading, so a wall
	// clock step cannot distort the hold timer.
	base time.Time

	// The two reader-owned atomics; see the package concurrency note above.
	lastRecv  atomic.Int64 // nanoseconds since base of the last received message
	inHandler atomic.Bool
}

// sinceBase returns the current offset from fc.base, for lastRecv.
func (fc *fsmConn) sinceBase() int64 {
	return int64(time.Since(fc.base))
}

// kill tears a pre-session connection down: fsmDone unblocks any pending
// forward, the closed connection unblocks a pending read, and kill then
// waits for the reader goroutine to exit. An established session has a
// session context and a writer goroutine as well; endSession owns that
// teardown order.
func (fc *fsmConn) kill() {
	fc.holdT.Stop()
	fc.keepaliveT.Stop()
	close(fc.fsmDone)
	_ = fc.c.Close()
	<-fc.readerDone
}

// A connEvent is a reader goroutine's report to the FSM goroutine. Exactly
// one field besides fc is set: a received message, a read error (terminal
// for the connection), or a handler error (terminal for the session).
type connEvent struct {
	fc         *fsmConn
	msg        Message
	err        error
	handlerErr error

	// local marks err as detected by this speaker's writer rather than the
	// connection's reader: the local side gave up on the transport.
	local bool
}

// A readerInstruction instructs a reader goroutine after a forwarded event.
type readerInstruction int

const (
	// instructionContinue: read the next message.
	instructionContinue readerInstruction = iota

	// instructionSession: the session is established; run the caller's
	// handlers.
	instructionSession
)

// newFSMConn wraps c for FSM tracking and starts its reader goroutine.
func (f *FSM) newFSMConn(c *Conn, o origin, eventC chan<- connEvent) *fsmConn {
	holdT := time.NewTimer(openHoldTime)
	keepaliveT := time.NewTimer(openHoldTime)
	keepaliveT.Stop()
	fc := &fsmConn{
		c:            c,
		origin:       o,
		state:        StateOpenSent,
		eventC:       eventC,
		instructionC: make(chan readerInstruction),
		fsmDone:      make(chan struct{}),
		readerDone:   make(chan struct{}),
		holdT:        holdT,
		holdC:        holdT.C,
		keepaliveT:   keepaliveT,
		keepaliveC:   keepaliveT.C,
		base:         time.Now(),
	}

	fc.lastRecv.Store(fc.sinceBase())
	go f.readConn(fc)
	return fc
}

// readConn is a connection's reader goroutine. Until the session is
// established it forwards every message to the FSM goroutine and pauses for
// an instruction, so a forwarded message's borrowed read buffer stays valid
// while the FSM uses it.
func (f *FSM) readConn(fc *fsmConn) {
	defer close(fc.readerDone)

	for {
		m, err := fc.c.ReadMessage()
		fc.lastRecv.Store(fc.sinceBase())
		if !f.forward(fc, connEvent{fc: fc, msg: m, err: err}) || err != nil {
			return
		}

		select {
		case ins := <-fc.instructionC:
			if ins == instructionSession {
				f.readSession(fc)
				return
			}
		case <-fc.fsmDone:
			return
		}
	}
}

// readSession is the reader goroutine's Established loop: the caller's
// handlers run here, on the receive path, so a slow handler pauses receipt
// and TCP backpressure reaches the peer. Only terminal events are forwarded
// to the FSM goroutine; a KEEPALIVE resets the hold timer through lastRecv
// and reaches only the optional OnKeepalive hook.
func (f *FSM) readSession(fc *fsmConn) {
	// handle runs one caller handler, forwarding its error to the FSM
	// goroutine as a terminal event; it reports whether the loop continues.
	handle := func(h func() error) bool {
		err := f.callHandler(fc, h)
		if err != nil {
			f.forward(fc, connEvent{fc: fc, handlerErr: err})
		}

		return err == nil
	}

	if h := f.cfg.OnEstablished; h != nil {
		if !handle(func() error { return h(fc.sessCtx, f, fc.sess) }) {
			return
		}
	}

	for {
		m, err := fc.c.ReadMessage()
		fc.lastRecv.Store(fc.sinceBase())
		if err != nil {
			f.forward(fc, connEvent{fc: fc, err: err})
			return
		}

		switch m := m.(type) {
		case *Keepalive:
			if h := f.cfg.OnKeepalive; h != nil && !handle(func() error { return h(fc.sessCtx, f) }) {
				return
			}
		case *Update:
			if h := f.cfg.OnUpdate; h != nil && !handle(func() error { return h(fc.sessCtx, f, m) }) {
				return
			}
		case *RouteRefresh:
			if h := f.cfg.OnRouteRefresh; h != nil && !handle(func() error { return h(fc.sessCtx, f, m) }) {
				return
			}
		default:
			// OPEN or NOTIFICATION mid-session: terminal either way, and the
			// FSM goroutine owns the response.
			f.forward(fc, connEvent{fc: fc, msg: m})
			return
		}
	}
}

// A resetReq is one caller's ResetSession request: the NOTIFICATION ending
// the session, and done, closed by the FSM goroutine once the teardown has
// completed and OnClose has fired.
type resetReq struct {
	n    *Notification
	done chan struct{}
}

// A sendReq is one caller message handed to a session's writer goroutine.
// doneC is buffered and always answered: the writer never blocks reporting
// a result, and a caller which was accepted never waits forever.
type sendReq struct {
	m     Message
	doneC chan<- error
}

// A sessionWriter links callers and the FSM to an established session's
// writer goroutine: sendC is the callers' unbuffered rendezvous, keepaliveC
// carries the FSM's keepalive nudges without blocking it — distinct from
// fsmConn.keepaliveC, the timer tick which prompts them — and exited is
// closed by the writer as it exits. It exists only while a session does; see
// fsmConn.writer.
type sessionWriter struct {
	sendC      chan sendReq
	keepaliveC chan struct{}
	exited     chan struct{}
}

// writeSession is an established session's writer goroutine: it
// serializes caller sends and the FSM's keepalives onto the connection, so a
// caller blocked in a slow write never blocks the FSM goroutine. A
// connection write error is terminal: the writer forwards it to the FSM
// goroutine, exactly as a reader would, and exits.
//
// Every write runs under a deadline of the negotiated hold time. A peer
// which stops reading but keeps sending KEEPALIVEs would otherwise wedge
// the writer forever while feeding this speaker's hold timer, leaving the
// session's liveness to the peer's own hold timer alone. A speaker which
// cannot accept one message within a full hold time is not a functioning
// peer, whatever it transmits; the expired write is terminal like any other
// write failure.
func (f *FSM) writeSession(fc *fsmConn) {
	defer close(fc.writer.exited)

	write := func(m Message) error {
		_ = fc.c.SetWriteDeadline(time.Now().Add(fc.sess.HoldTime))
		return fc.c.WriteMessage(m)
	}

	for {
		select {
		case req := <-fc.writer.sendC:
			err := write(req.m)
			req.doneC <- err
			if err != nil && !isMarshalError(err) {
				f.forward(fc, connEvent{fc: fc, err: err, local: true})
				return
			}
		case <-fc.writer.keepaliveC:
			if err := write(&Keepalive{}); err != nil {
				f.forward(fc, connEvent{fc: fc, err: err, local: true})
				return
			}
		case <-fc.fsmDone:
			return
		}
	}
}

// forward sends ev to the FSM goroutine, reporting false when the FSM has
// abandoned the connection instead of receiving it.
func (f *FSM) forward(fc *fsmConn, ev connEvent) bool {
	select {
	case fc.eventC <- ev:
		return true
	case <-fc.fsmDone:
		return false
	}
}

// callHandler invokes a caller handler with the connection's in-handler flag
// set, so a hold timer expiring during the call is attributed to this
// speaker's stalled receive path rather than to the peer's silence.
func (f *FSM) callHandler(fc *fsmConn, h func() error) error {
	fc.inHandler.Store(true)
	defer fc.inHandler.Store(false)
	return h()
}

// sendNotification writes n on c, best effort under writeBounded's deadline:
// a NOTIFICATION always precedes a close, and teardown must not block on an
// unresponsive peer.
func (f *FSM) sendNotification(c *Conn, n *Notification) {
	if err := writeBounded(c, n); err != nil {
		f.log.Debug("failed to send NOTIFICATION", "err", err)
	}
}

// rejectConn refuses a connection this speaker will not use, answering the
// peer's open with Cease / Connection Rejected (RFC 4486) before the close,
// so the peer's FSM can release the connection without waiting out a timer.
func (f *FSM) rejectConn(c *Conn) {
	f.sendNotification(c, &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseConnectionRejected,
	})
	_ = c.Close()
}

// writeBounded writes m on c under a write deadline, then clears it: every
// write on the FSM goroutine must be bounded, or an unresponsive peer stalls
// the FSM's timers and events. The connection may outlive the write, so the
// deadline must not linger.
func writeBounded(c *Conn, m Message) error {
	_ = c.SetWriteDeadline(time.Now().Add(teardownTimeout))
	err := c.WriteMessage(m)
	_ = c.SetWriteDeadline(time.Time{})
	return err
}

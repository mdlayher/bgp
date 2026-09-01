package bgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// A PeerConfig configures a Peer. The embedded Identity's LocalASN and LocalID
// are required; the zero value of every other field is usable. The remote
// address is NewPeer's addr parameter, not configuration.
type PeerConfig struct {
	// Identity is the peering's protocol identity and negotiation surface,
	// shared verbatim with [FSMConfig]; see [Identity].
	Identity

	// MD5Password optionally enables TCP-MD5 (RFC 2385) on the peering with
	// the given key, which must match the key configured by the peer. An
	// empty password disables TCP-MD5.
	//
	// The key is a property of the peering and covers both directions of
	// connection: the Peer signs the connections it dials, and a Server
	// installs the key on its listening sockets before the peer runs. A
	// caller accepting connections without a Server must install the key on
	// its own Listener via [Listener.SetMD5], before the remote SYN arrives.
	//
	// Keys are plain strings by design: BGP MD5 keys are cleartext
	// operational strings in every router configuration, not secrets in the
	// cryptographic sense.
	//
	// TCP-MD5 is only supported on Linux. Elsewhere, connections fail with
	// an error which wraps [errors.ErrUnsupported].
	MD5Password string

	// Dialer supplies the transport of the active open: its TCPOptions,
	// the local bind address, and the port the peer is dialed on. It is
	// ignored when DialFunc is set, and on a Passive peer.
	Dialer Dialer

	// DialFunc, when non-nil, performs the active open in place of Dialer:
	// the seam for a transport which is not TCP, passed through to the
	// Peer's FSM. The transport addresses its own target, so NewPeer's
	// addr may be zero. DialFunc must honor ctx, and the connection it
	// returns must behave like a net.Conn in the three respects the FSM
	// depends on; see [FSMConfig.DialFunc]. Setting DialFunc together with
	// MD5Password, or on a Passive peer, is an error.
	DialFunc func(ctx context.Context) (*Conn, error)

	// Passive suppresses the active open: the peering only accepts
	// connections, through DeliverConn or a Server's listeners.
	Passive bool

	// OnEstablished, if set, is called when a session reaches
	// Established, with its negotiated parameters. It is the first
	// handler of each session.
	//
	// Every handler runs on the session's receive path, and a nil
	// handler ignores its event. ctx is session-scoped: a child of Run's
	// ctx, canceled when the session leaves Established. The contract
	// below applies to every handler:
	//
	//   - Every value a handler receives is fully owned: unlike the FSM's
	//     zero-copy handlers, an Update or RouteRefresh here is a deep
	//     copy the caller may retain indefinitely and hand to other
	//     goroutines freely.
	//   - Blocking in a handler pauses receipt, so TCP backpressure
	//     reaches the peer. It never pauses transmission or timers. A
	//     slow consumer which must not stall the session hands its owned
	//     values to its own goroutine through a queue of its choosing:
	//     the handler blocking on a full queue is exactly how
	//     backpressure is meant to reach the wire.
	//   - All handler invocations for a Peer are serialized, across
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
	//     the cancellation is abandoned on its goroutine so the Peer can
	//     continue, Close.Err reports the abandonment, and the stuck
	//     invocation forfeits the ordering guarantees above: it may
	//     overlap OnClose and a later session's handlers.
	//   - A non-nil handler error terminates the session. If the error is
	//     a *MessageError (per errors.AsType), its code, subcode, and data
	//     become the NOTIFICATION sent to the peer; any other error sends
	//     Cease.
	OnEstablished func(ctx context.Context, p *Peer, s Session) error

	// OnUpdate, if set, is called for each UPDATE received while the
	// session is Established: the feed for an Adj-RIB-In. The Update is
	// a fully owned deep copy.
	//
	// See [PeerConfig.OnEstablished] for the full handler contract.
	OnUpdate func(ctx context.Context, p *Peer, u *Update) error

	// OnRouteRefresh, if set, is called for each ROUTE-REFRESH message
	// (RFC 2918) received while the session is Established: the peer
	// asks this speaker to re-advertise a family's routes. Advertising
	// the route refresh capability requires this handler; see
	// Identity.RouteRefresh.
	//
	// See [PeerConfig.OnEstablished] for the full handler contract.
	OnRouteRefresh func(ctx context.Context, p *Peer, r *RouteRefresh) error

	// OnKeepalive, if set, is called for each KEEPALIVE received while
	// the session is Established; the KEEPALIVE which confirms the OPEN
	// exchange is OnEstablished's moment instead. A KEEPALIVE carries no
	// content, so the handler receives none. Most callers leave it nil:
	// the hold timer is maintained regardless, and this hook only
	// observes peer liveness.
	//
	// See [PeerConfig.OnEstablished] for the full handler contract.
	OnKeepalive func(ctx context.Context, p *Peer) error

	// OnClose, if set, is called when a session ends, including when
	// Run's ctx is canceled. It is also called when a session attempt
	// ends with something to report: a connection had begun the OPEN
	// exchange, or sending an OPEN failed. An attempt with nothing
	// observable in flight, such as one whose dial never produced a
	// connection, ends without OnClose. [Close.Established] distinguishes a
	// session end from a failed attempt. The session is already down and
	// will be retried by Run, so OnClose only observes.
	//
	// OnClose runs on the peer's own goroutine, and a Server's removal
	// verbs wait for that goroutine: calling them from OnClose deadlocks,
	// the classic self-join. A handler which notices its own peering died
	// removes it from a new goroutine (go s.RemovePeer(addr, nil)).
	OnClose func(p *Peer, c Close)

	// ShutdownCommunication optionally attaches a standing farewell to the
	// Cease with subcode Administrative Shutdown sent when Run's ctx is
	// canceled, whether or not a session is established: an RFC 9003
	// shutdown communication for the remote operator to read. It must be
	// valid UTF-8 of at most 255 bytes, validated by NewPeer, never
	// truncated. The remote speaker's own communication, if any, can be
	// decoded from [Close.Notification] via
	// [Notification.ShutdownCommunication].
	//
	// A cancellation cause overrides it: when Run's ctx was canceled with
	// a *MessageError cause (context.WithCancelCause, per errors.AsType),
	// that NOTIFICATION is sent verbatim instead. That is how a caller
	// shuts down with a Hard Reset (RFC 8538) or a dynamic communication
	// (NewShutdownError), and how a Server ends a removed peering.
	ShutdownCommunication string

	// OnStateChange, if set, observes every transition of the underlying
	// state machine, forwarded verbatim from the FSM; see
	// FSMConfig.OnStateChange for the contract. The Peer's idle hold
	// between attempts happens while the state is Idle.
	OnStateChange func(p *Peer, from, to State)

	// OnMessage, if set, observes every message the peering exchanges on
	// the wire, in both directions, forwarded from the FSM with the
	// event's Raw and Message fully owned; see FSMConfig.OnMessage for
	// the contract, in particular that the tap must be safe for
	// concurrent use and return promptly.
	OnMessage func(p *Peer, e MessageEvent)

	// Logger, if set, records state transitions and retry activity.
	Logger *slog.Logger
}

// A Peer runs one BGP peering with one remote speaker, forever. It wraps an
// FSM, which handles dialing, collision resolution, the OPEN exchange,
// keepalives, and the hold timer, as described in RFC 4271. Session attempts
// are retried with a short jittered idle hold between them until Run's ctx
// is canceled. Received UPDATEs go to the caller's handlers as fully owned
// deep copies. The Peer stores no routes.
//
// Peer is the mainstream layer, and a RIB plugs in here: its handlers carry no
// buffer-lifetime rules, at the cost of one Update.Clone per received message.
// A caller which needs zero-copy delivery, or its own retry policy, builds on
// FSM directly.
type Peer struct {
	fsm *FSM
	log *slog.Logger

	// addr is NewPeer's remote address: the dial target, the address a
	// delivered TCP connection must match, and the key a Server files the
	// peering under. Zero on a transport which does not address peers by
	// IP.
	addr netip.Addr

	// managed reports that a Server owns this peer's lifecycle: Run and
	// DeliverConn reject callers, and the Server uses the unexported entry
	// points. Set by Server.AddPeer before the Peer escapes it, never
	// mutated afterward.
	managed bool

	// holdC hands a connection delivered during the idle hold to the retry
	// loop, which ends the hold early and seeds the next attempt with it.
	// Unbuffered: a send succeeds only while idleHold is
	// waiting, so ownership transfers exactly when the hold will act.
	holdC chan *Conn

	// mu guards runningC, which is closed while a Run is active and remade
	// when it stops, exactly as on FSM.
	mu       sync.Mutex
	runningC chan struct{}
}

// NewPeer validates the configuration and produces a Peer for the peering with
// the remote speaker at addr. Nothing runs until Run.
//
// addr is addressing, not identity. It serves three roles:
//
//   - The dial target of the active open.
//   - The remote address a TCP connection handed to DeliverConn must
//     match.
//   - The key a Server files the peering under.
//
// Who may answer there is pinned by PeerASN and PeerID, and the port
// dialed is Dialer.Port. An active peer using the built-in Dialer requires
// addr. A Passive peer, or a DialFunc transport, may leave it zero, and
// DeliverConn then checks no address.
func NewPeer(addr netip.Addr, c PeerConfig) (*Peer, error) {
	if c.DialFunc != nil && c.MD5Password != "" {
		return nil, errors.New("bgp: TCP-MD5 is a TCP socket option and cannot apply to a DialFunc transport")
	}

	if c.DialFunc != nil && c.Passive {
		return nil, errors.New("bgp: a Passive peer never dials, so it cannot carry a DialFunc")
	}

	// addr is addressing: normalized when set, and required only by the
	// built-in Dialer, which has nothing else to dial.
	addr = addr.Unmap()
	if !c.Passive && c.DialFunc == nil && !addr.IsValid() {
		return nil, errors.New("bgp: an active peer using the built-in Dialer requires a peer address to dial")
	}

	// The standing farewell is validated and encoded once, like the OPENs:
	// a bad communication is a constructor error, not a shutdown surprise.
	var shutdownCause *MessageError
	if c.ShutdownCommunication != "" {
		var err error
		shutdownCause, err = NewShutdownError(SubcodeCeaseAdministrativeShutdown, c.ShutdownCommunication)
		if err != nil {
			return nil, err
		}
	}

	log := c.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	// The log identity is the peering's address when there is one, and the
	// address-scoped logger is handed down to the FSM, which emits the
	// session logs: the FSM itself knows no addressing, so this is where
	// its logs gain the address. An unaddressed peering falls back to the
	// pinned identifier, which the FSM scopes by itself.
	fsmLog := c.Logger
	if addr.IsValid() {
		log = log.With("peer", addr)
		fsmLog = log
	} else if c.PeerID != 0 {
		log = log.With("peer_id", c.PeerID)
	}

	p := &Peer{
		log:      log,
		addr:     addr,
		holdC:    make(chan *Conn),
		runningC: make(chan struct{}),
	}

	fc := FSMConfig{
		Identity: c.Identity,
		DialFunc: c.DialFunc,
		Passive:  c.Passive,
		Logger:   fsmLog,
	}

	if !c.Passive && fc.DialFunc == nil {
		// The active open's transport: the Dialer, with addr as its target
		// and the peering's TCP-MD5 key applied, compiled down to the FSM's
		// one seam.
		d, md5 := c.Dialer, c.MD5Password
		fc.DialFunc = func(ctx context.Context) (*Conn, error) {
			return d.dial(ctx, addr, md5)
		}
	}

	// Each caller handler is wrapped so its values are fully owned: the
	// FSM's borrowed Update and RouteRefresh are detached by Clone before
	// the caller sees them, and Session and Close are owned already. A nil
	// caller handler stays nil on the FSM, so unobserved events cost no
	// copy.
	if h := c.OnEstablished; h != nil {
		fc.OnEstablished = func(ctx context.Context, _ *FSM, s Session) error {
			return h(ctx, p, s)
		}
	}

	if h := c.OnUpdate; h != nil {
		fc.OnUpdate = func(ctx context.Context, _ *FSM, u *Update) error {
			return h(ctx, p, u.Clone())
		}
	}

	if h := c.OnRouteRefresh; h != nil {
		fc.OnRouteRefresh = func(ctx context.Context, _ *FSM, r *RouteRefresh) error {
			return h(ctx, p, r.Clone())
		}
	}

	if h := c.OnKeepalive; h != nil {
		fc.OnKeepalive = func(ctx context.Context, _ *FSM) error {
			return h(ctx, p)
		}
	}

	if h := c.OnClose; h != nil {
		fc.OnClose = func(_ *FSM, cl Close) {
			h(p, cl)
		}
	}

	if h := c.OnStateChange; h != nil {
		fc.OnStateChange = func(_ *FSM, from, to State) {
			h(p, from, to)
		}
	}

	if h := c.OnMessage; h != nil {
		fc.OnMessage = func(_ *FSM, e MessageEvent) {
			h(p, e.clone())
		}
	}

	f, err := NewFSM(fc)
	if err != nil {
		return nil, err
	}

	f.shutdownCause = shutdownCause
	p.fsm = f
	return p, nil
}

// Run drives the peering until ctx is canceled: one FSM Connect after
// another, forever, with a short jittered idle hold after each failure. A
// session failure goes to OnClose and is retried. Cancellation is the only
// exit. "Give up after N failures" is caller policy via cancellation, and
// any other retry policy is a caller loop over FSM.Connect instead.
//
// Run always returns a non-nil error:
//
//   - ctx's error, once canceled.
//   - An error when the Peer is already running, or is managed by a
//     Server, which runs its peers itself.
func (p *Peer) Run(ctx context.Context) error {
	if p.managed {
		return errors.New("bgp: the peer is managed by a Server, which runs it")
	}

	return p.run(ctx)
}

// run implements Run, and is the Server's entry point for managed peers.
func (p *Peer) run(ctx context.Context) error {
	p.mu.Lock()
	select {
	case <-p.runningC:
		p.mu.Unlock()
		return errors.New("bgp: peer is already running")
	default:
		close(p.runningC)
	}

	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.runningC = make(chan struct{})
	}()

	var seed *Conn
	for {
		if err := p.fsm.connect(ctx, seed); err != nil {
			return err
		}

		var err error
		if seed, err = p.idleHold(ctx); err != nil {
			return err
		}
	}
}

// idleHold pauses after a session failure before the next Connect: the
// Idle state's hold. A connection delivered meanwhile ends the hold early
// and is returned to seed the next attempt: the remote's open is
// fresher evidence of liveness than the pause is worth, and refusing it
// would lock two speakers whose sessions closed together into exchanging
// rejections from alternating holds forever.
func (p *Peer) idleHold(ctx context.Context) (*Conn, error) {
	d := p.fsm.jittered(idleHoldTime)
	p.log.Debug("idle hold started", "duration", d)

	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case c := <-p.holdC:
		p.log.Debug("adopted connection during idle hold")
		return c, nil
	case <-t.C:
		return nil, nil
	}
}

// DeliverConn hands an inbound connection to the peer: the passive open.
// The Peer must be running. On error, the caller retains ownership and
// should close the connection; on success the Peer owns it. A connection
// delivered during the idle hold between session attempts ends the hold
// early and seeds the next attempt. Only in the narrow window where no
// hold is ready to take it is it answered with Cease / Connection Rejected
// and closed.
//
// A TCP connection's remote address must match NewPeer's addr when addr is
// set. Any other address type, and any connection when addr is unset, is
// accepted as it stands. The PeerASN and PeerID pins negotiation enforces
// are then the identity checks. A caller which needs to authenticate the
// remote beyond that must do so before it delivers the connection.
//
// The transport requirements are the FSM's; see [FSM.DeliverConn]. A Peer
// managed by a Server returns an error: the Server's listeners deliver its
// connections.
func (p *Peer) DeliverConn(c *Conn) error {
	if p.managed {
		return errors.New("bgp: the peer is managed by a Server, which delivers its connections")
	}

	return p.deliverConn(c)
}

// deliverConn implements DeliverConn, and is the Server's entry point for
// managed peers.
func (p *Peer) deliverConn(c *Conn) error {
	// The address check applies to a TCP connection, whose remote address
	// is comparable to addr. Any other address type has nothing to
	// compare (a Unix socket's accepted side carries no peer name at all),
	// so the caller's choice of Peer is the only check there is. The FSM
	// below checks nothing: it carries no addressing.
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if want := p.addr; want.IsValid() {
			if addr := ta.AddrPort().Addr().Unmap(); addr != want {
				return fmt.Errorf("bgp: connection from %s does not match peer address %s", addr, want)
			}
		}
	}

	p.mu.Lock()
	select {
	case <-p.runningC:
		p.mu.Unlock()
	default:
		p.mu.Unlock()
		return errors.New("bgp: peer is not running")
	}

	err := p.fsm.DeliverConn(c)
	if errors.Is(err, errFSMIdle) {
		// The Peer is running but its FSM is between attempts: the idle
		// hold. The hold adopts the connection and ends early, seeding
		// the next attempt. When no hold is waiting, because the
		// retry loop is between the FSM's exit and the hold's arm, the
		// remote is answered rather than silently dropped, so its own
		// FSM can release the connection without waiting out a timer;
		// it will retry into the next attempt.
		select {
		case p.holdC <- c:
			return nil
		default:
		}

		p.log.Debug("refused connection during idle hold")
		p.fsm.rejectConn(c)
		return nil
	}

	return err
}

// SendUpdate sends an UPDATE message on the established session. The
// blocking, ordering, and error contract is [FSM.SendUpdate]'s. The message
// is the caller's own and is written as given, never copied: ownership
// wrapping applies to received values, not sent ones.
func (p *Peer) SendUpdate(ctx context.Context, u *Update) error {
	return p.fsm.SendUpdate(ctx, u)
}

// SendRouteRefresh sends a ROUTE-REFRESH message (RFC 2918) on the
// established session. The contract is [FSM.SendRouteRefresh]'s.
func (p *Peer) SendRouteRefresh(ctx context.Context, f Family) error {
	return p.fsm.SendRouteRefresh(ctx, f)
}

// ResetSession ends the established session with a NOTIFICATION: the bounce.
// The cause and blocking contract are [FSM.ResetSession]'s. The peering
// then continues, and the retry loop establishes a fresh session after the
// idle hold. [Server.RemovePeer], by contrast, ends the peering. Like the
// send methods, ResetSession works on a Server-managed Peer.
func (p *Peer) ResetSession(ctx context.Context, cause *MessageError) error {
	return p.fsm.ResetSession(ctx, cause)
}

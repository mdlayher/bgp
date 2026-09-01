package bgp

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	// unconfiguredPeerTimeout bounds the entire exchange with an
	// unconfigured peer: reading its OPEN for OnUnconfiguredPeer and
	// writing the Connection Rejected farewell. A legitimate speaker sends
	// its OPEN one round trip after connecting, so the budget tolerates a
	// satellite-grade RTT plus one TCP retransmission and nothing slower.
	unconfiguredPeerTimeout = 2 * time.Second

	// unconfiguredPeerLimit caps the concurrent goroutines spent on
	// unconfigured peers; connections beyond it are closed immediately, so
	// a flood of strangers cannot mint goroutines.
	unconfiguredPeerLimit = 32
)

// A ServerConfig configures a Server. The listeners it accepts on are
// Run's parameters.
type ServerConfig struct {
	// OnUnconfiguredPeer, if set, observes each connection from an address
	// with no configured Peer. o is the OPEN the remote sent, or nil when
	// none arrived in time; like handler values, it references the
	// connection's read buffer and is only valid for the duration of the
	// call. The hook observes only: the Server owns the connection, always
	// answers Cease / Connection Rejected, and closes it. It may be
	// invoked concurrently.
	//
	// ctx is run-scoped: canceled when Run shuts down. Like the Peer
	// handlers, the hook must watch it and return promptly. A hook which
	// ignores the cancellation is abandoned on its goroutine after a
	// bounded wait so Run can still return.
	//
	// Combined with AddPeer, the hook is the building block for dynamic
	// neighbors: observe the unconfigured peer, add a Peer for its
	// address, and the remote's retry connects normally moments later. A
	// removed peering's remote keeps retrying and arrives here too, so
	// consult intent (configuration, a deny list) before re-adding.
	//
	// When the hook is nil, connections from unconfigured peers are
	// rejected the same way, without waiting for an OPEN.
	OnUnconfiguredPeer func(ctx context.Context, raddr netip.AddrPort, o *Open)

	// Logger configures a logger for server events. The default is to
	// discard all logs. Each Peer carries its own PeerConfig.Logger.
	Logger *slog.Logger
}

// A Server coordinates any number of Peers with one remote speaker each:
//
//   - It accepts connections on the listeners handed to Run.
//   - It hands each accepted connection to the Peer configured for its
//     remote address, and rejects connections from unconfigured peers.
//   - It runs every peer's connection lifecycle.
//
// Like a Peer, a Server stores no routes and makes no routing decisions.
//
// Each peering's TCP-MD5 key is the Server's to install: on every listener of
// the peering's address family, before the peer runs and before any
// connection is accepted. See [Server.Run] for the listen backlog's caveat.
type Server struct {
	cfg ServerConfig
	log *slog.Logger

	// unconfSem bounds concurrent unconfigured-peer goroutines across runs.
	unconfSem chan struct{}

	mu       sync.Mutex
	runningC chan struct{} // closed while Run is active, remade on exit
	peers    map[netip.Addr]*serverPeer
	run      *serverRun // live between setup and teardown, nil otherwise
}

// A serverRun is the state of one Run: the context every goroutine of the
// run descends from, the live listeners, and the join groups — acceptWG
// for the accept loops, joined unconditionally, and unconfWG for
// unconfigured-peer exchanges, joined with a bound because they invoke a
// caller's hook. It holds WaitGroups, so it is never copied.
type serverRun struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ls       []*Listener
	acceptWG sync.WaitGroup
	unconfWG sync.WaitGroup
}

// A serverPeer is the Server's record of one configured peering.
type serverPeer struct {
	p   *Peer
	md5 string

	// cancel and wg are set each time the peer starts under a Run: cancel
	// ends the peer with a NOTIFICATION cause, and wg is done when its Run
	// has returned.
	cancel context.CancelCauseFunc
	wg     *sync.WaitGroup
}

// NewServer creates a Server with its configuration. Peers are configured
// separately via AddPeer, and listeners are handed to Run.
func NewServer(cfg ServerConfig) *Server {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	return &Server{
		cfg:       cfg,
		log:       log,
		unconfSem: make(chan struct{}, unconfiguredPeerLimit),
		runningC:  make(chan struct{}),
		peers:     make(map[netip.Addr]*serverPeer),
	}
}

// AddPeer configures a peering with the remote speaker at addr. The
// configuration is validated by NewPeer, and the peering's key (if any) is
// installed on every matching-family listener. When the Server is running,
// the peer starts immediately; peers added before Run are started by Run.
// The returned Peer is valid for SendUpdate and SendRouteRefresh; its Run
// and DeliverConn belong to the Server and return errors if called.
//
// addr is required: the Server demultiplexes inbound connections by it, so
// its peers cannot use NewPeer's unaddressed allowances. At most one peer
// may exist per remote address, and AddPeer returns an error for a
// duplicate. Configuration changes are RemovePeer then AddPeer: a Peer is
// immutable.
func (s *Server) AddPeer(addr netip.Addr, cfg PeerConfig) (*Peer, error) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil, errors.New("bgp: a Server files each peering under its remote address, so addr is required")
	}

	p, err := NewPeer(addr, cfg)
	if err != nil {
		return nil, err
	}

	// Claimed before the Peer escapes: Run and DeliverConn reject callers,
	// so only the Server's own entry points drive a managed peer.
	p.managed = true

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.peers[addr]; ok {
		return nil, fmt.Errorf("bgp: a peer already exists for address %s", addr)
	}

	// While running, the key goes onto the listening sockets before the
	// peer can run: no SYN this Server delivers precedes its key. Before
	// Run, the same ordering is Run's job.
	if err := s.installMD5Locked(addr, cfg.MD5Password); err != nil {
		// Leave no trace of the failed add.
		s.removeMD5Locked(addr, cfg.MD5Password)
		return nil, err
	}

	sp := &serverPeer{p: p, md5: cfg.MD5Password}
	s.peers[addr] = sp
	if s.run != nil {
		s.startPeerLocked(sp)
	}

	return p, nil
}

// RemovePeer removes the peering with the given remote address: an
// established session ends with a NOTIFICATION, the peer's Run is waited
// for, and the peering's keys are removed from the Server's listeners. When
// RemovePeer returns, the peering is fully gone.
//
// A nil cause ends the session with Cease / Peer De-configured (RFC 4486). A
// non-nil cause is sent verbatim in its place, like any cancellation cause
// (see [PeerConfig.ShutdownCommunication]): removal with Cease / Administrative
// Reset (see [NewShutdownError]) followed by AddPeer is the bounce, the "clear"
// of router CLIs, and per-peer farewells on a mass shutdown are removals
// before canceling Run's ctx. Each call blocks for its own drain, so a large
// fleet issues them concurrently.
//
// RemovePeer must not be called from the removed peer's own handlers or
// OnClose: it waits for the peer's run to return, and the peer's run is the
// goroutine invoking them: the classic self-join deadlock. A handler which
// notices its own peering died removes it from a new goroutine (go
// s.RemovePeer(addr, nil)).
//
// After removal, the remote speaker keeps retrying its open, and those
// connections arrive as unconfigured peers; see [ServerConfig.OnUnconfiguredPeer].
func (s *Server) RemovePeer(addr netip.Addr, cause *MessageError) error {
	if cause == nil {
		cause = newMessageError(
			NotificationCease, SubcodeCeasePeerDeconfigured, nil,
			"peering configuration removed",
		)
	}

	addr = addr.Unmap()

	s.mu.Lock()
	sp, ok := s.peers[addr]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("bgp: no peer exists for address %s", addr)
	}

	delete(s.peers, addr)
	// Removing the key first means the remote's reconnection attempts drop
	// at the kernel while the peer drains, rather than racing the drain.
	s.removeMD5Locked(addr, sp.md5)
	cancel, wg := sp.cancel, sp.wg
	s.mu.Unlock()

	if cancel != nil {
		cancel(cause)
		wg.Wait()
	}

	return nil
}

// Peers iterates over the configured peerings in ascending remote address
// order. The sequence is a snapshot taken when iteration begins: it is safe
// to call AddPeer or RemovePeer during iteration, and concurrent changes
// are not reflected.
func (s *Server) Peers() iter.Seq2[netip.Addr, *Peer] {
	return func(yield func(netip.Addr, *Peer) bool) {
		type entry struct {
			addr netip.Addr
			p    *Peer
		}

		s.mu.Lock()
		snap := make([]entry, 0, len(s.peers))
		for addr, sp := range s.peers {
			snap = append(snap, entry{addr: addr, p: sp.p})
		}

		s.mu.Unlock()

		slices.SortFunc(snap, func(a, b entry) int { return a.addr.Compare(b.addr) })
		for _, e := range snap {
			if !yield(e.addr, e.p) {
				return
			}
		}
	}
}

// Run accepts connections on the given listeners and runs every configured
// peer until ctx is canceled: delivering each connection to the Peer for its
// remote address, and rejecting unconfigured peers. The Server owns each
// Listener for the duration of the call and closes every one before returning,
// on every path; no listeners at all is valid, for a Server whose peers only
// dial. Session failures are retried by each Peer forever. An infrastructure
// failure, such as a key which cannot be installed or a listener whose
// Accept fails, takes Run down with an error. Run always returns a non-nil
// error: ctx's error, an infrastructure error, or an error if the Server is
// already running.
//
// Each peering's TCP-MD5 key is installed on the listeners of its address
// family as Run starts, before any connection is accepted. The listen
// backlog predates Run, though: a handshake the kernel completed between the
// caller's Listen and Run met no key, the same window a live AddPeer has on
// any bound socket. Keep Listen and Run adjacent.
//
// Like [Peer.Run], cancellation sends every established session Cease /
// Administrative Shutdown, or the ctx's *MessageError cancellation cause; see
// PeerConfig.ShutdownCommunication.
//
// Run returns once every peer it manages has stopped, with one exception: a
// peer being removed concurrently is joined by its RemovePeer call rather than
// by Run, so that removal's drain may still be in flight when Run returns.
func (s *Server) Run(ctx context.Context, ls ...*Listener) error {
	// Ownership is whole: the listeners are closed on every return, the
	// refused and failed ones included. teardown closes a live run's first,
	// to unblock its accept loops; the second close is a no-op.
	defer closeListeners(ls)

	run, err := s.setup(ctx, ls)
	if err != nil {
		return err
	}

	defer s.release()

	err = s.serve(run)

	// Canceling the run's context tears down every peer and accept loop
	// at once.
	run.cancel()
	s.teardown(run)
	return err
}

// release remakes the running marker as Run returns.
func (s *Server) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runningC = make(chan struct{})
}

// setup starts a run from the caller's ctx and listeners: it claims the
// Server, installs every configured peering's keys on the listeners,
// publishes the run, and starts every peer added before Run. On error
// nothing is left up and the Server is unclaimed.
//
// One hold of s.mu covers the claim through publication, so the peer table
// cannot change between the keys the listeners receive and the table the
// run sees, and a waiter which has seen the running marker close and then
// takes the lock finds the run published or gone. The setsockopt calls
// under the lock are brief and bounded by the table.
func (s *Server) setup(ctx context.Context, ls []*Listener) (*serverRun, error) {
	for _, l := range ls {
		if l == nil {
			return nil, errors.New("bgp: a Server cannot run on a nil Listener")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.runningC:
		return nil, errors.New("bgp: server is already running")
	default:
		close(s.runningC)
	}

	// Keys go on before any peer runs and before any accept loop exists:
	// no connection this run delivers precedes its key. Run documents the
	// caller's backlog window.
	for _, l := range ls {
		for addr, sp := range s.peers {
			if !l.serves(addr) {
				continue
			}

			if sp.md5 == "" {
				continue
			}

			if err := l.SetMD5(addr, sp.md5); err != nil {
				s.runningC = make(chan struct{})
				return nil, fmt.Errorf("bgp: failed to install key for peer %s: %w", addr, err)
			}
		}
	}

	// Everything the Server starts descends from the run's context.
	run := &serverRun{ls: ls}
	run.ctx, run.cancel = context.WithCancel(ctx)
	s.run = run
	for _, sp := range s.peers {
		s.startPeerLocked(sp)
	}

	return run, nil
}

// serve accepts connections on every listener until the run's context is
// canceled or a listener fails: the first infrastructure error wins and is
// fatal. The returned error is Run's.
func (s *Server) serve(run *serverRun) error {
	errC := make(chan error, len(run.ls))
	for _, l := range run.ls {
		run.acceptWG.Go(func() {
			if err := s.acceptLoop(run, l); err != nil {
				select {
				case errC <- err:
				default:
				}
			}
		})
	}

	select {
	case <-run.ctx.Done():
		// Nothing else cancels the run before serve returns, so this is
		// the caller's ctx ending, and their error is the run's.
		return run.ctx.Err()
	case err := <-errC:
		return err
	}
}

// teardown, after the run's context is canceled, joins every peer and every
// goroutine serve spawned, and unpublishes the run. Peers removed
// concurrently are RemovePeer's to join.
func (s *Server) teardown(run *serverRun) {
	closeListeners(run.ls)

	s.mu.Lock()
	wgs := make([]*sync.WaitGroup, 0, len(s.peers))
	for _, sp := range s.peers {
		if sp.wg != nil {
			wgs = append(wgs, sp.wg)
		}
	}

	s.run = nil
	s.mu.Unlock()

	for _, wg := range wgs {
		wg.Wait()
	}

	run.acceptWG.Wait()

	// Unconfigured-peer goroutines lose their connections at cancellation,
	// so this join is normally immediate; a hook which ignores its ctx is
	// abandoned after a bounded wait, mirroring the Peer handler contract,
	// so a stuck hook cannot wedge Run. The waiter itself exits when the
	// stuck hook eventually returns.
	unconfDone := make(chan struct{})
	go func() {
		run.unconfWG.Wait()
		close(unconfDone)
	}()
	select {
	case <-unconfDone:
	case <-time.After(teardownTimeout):
		s.log.Warn("abandoned a stuck OnUnconfiguredPeer hook at teardown")
	}
}

// closeListeners closes each listener, unblocking its accept loop.
func closeListeners(ls []*Listener) {
	for _, l := range ls {
		if l != nil {
			_ = l.Close()
		}
	}
}

// startPeerLocked starts a configured peer under the current Run. The
// caller must hold s.mu with s.run live.
func (s *Server) startPeerLocked(sp *serverPeer) {
	ctx, cancel := context.WithCancelCause(s.run.ctx)
	sp.cancel, sp.wg = cancel, new(sync.WaitGroup)

	sp.wg.Go(func() {
		// run returns only on cancellation: the managed guard rejects a
		// competing caller Run, and the Server starts each peer at most
		// once per Run.
		_ = sp.p.run(ctx)
	})
}

// installMD5Locked installs a peering's TCP-MD5 key on every live listener
// of the peer's address family; before Run, there are none, and Run's
// setup installs instead. The caller must hold s.mu.
func (s *Server) installMD5Locked(addr netip.Addr, key string) error {
	if key == "" || s.run == nil {
		return nil
	}

	for _, l := range s.run.ls {
		if !l.serves(addr) {
			continue
		}

		if err := l.SetMD5(addr, key); err != nil {
			return fmt.Errorf("bgp: failed to install TCP-MD5 key for peer %s: %w", addr, err)
		}
	}

	return nil
}

// removeMD5Locked removes a peering's TCP-MD5 key from every live listener
// of the peer's address family, best-effort. The caller must hold s.mu.
func (s *Server) removeMD5Locked(addr netip.Addr, key string) {
	if key == "" || s.run == nil {
		return
	}

	for _, l := range s.run.ls {
		if !l.serves(addr) {
			continue
		}

		_ = l.RemoveMD5(addr)
	}
}

// acceptLoop accepts connections on one listener until teardown closes it,
// delivering each to the peer configured for its remote address. An Accept
// failure during teardown is the expected exit, and resource-exhaustion
// failures are retried; anything else is an infrastructure error, fatal to
// Run.
func (s *Server) acceptLoop(run *serverRun, l *Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if run.ctx.Err() != nil {
				return nil
			}

			// A kernel-aborted connection or file descriptor exhaustion
			// is not listener death; see acceptTransient. The pause keeps
			// an exhausted process from spinning, and cancellation cuts
			// it short so teardown never waits on it.
			abort, exhausted := acceptTransient(err)
			if abort {
				continue
			}

			if exhausted {
				s.log.Warn("out of file descriptors accepting a connection, retrying", "err", err)
				select {
				case <-time.After(100 * time.Millisecond):
				case <-run.ctx.Done():
					return nil
				}

				continue
			}

			return fmt.Errorf("bgp: accept on %s failed: %w", l.Addr(), err)
		}

		s.deliver(run, c)
	}
}

// deliver routes one accepted connection to the peer configured for its
// remote address, or rejects it as an unconfigured peer.
func (s *Server) deliver(run *serverRun, c *Conn) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		// Impossible from the Server's own TCP listeners.
		_ = c.Close()
		return
	}

	raddr := ta.AddrPort()
	addr := raddr.Addr().Unmap()

	s.mu.Lock()
	sp, ok := s.peers[addr]
	s.mu.Unlock()

	if !ok {
		s.rejectUnconfigured(run, c, netip.AddrPortFrom(addr, raddr.Port()))
		return
	}

	if err := sp.p.deliverConn(c); err != nil {
		// The peer is between attempts or its delivery slot is taken:
		// closing is always sound, because a live remote retries its open.
		s.log.Debug("closed undeliverable connection", "peer", addr, "err", err)
		_ = c.Close()
	}
}

// rejectUnconfigured ends a connection from an unconfigured peer: the
// OnUnconfiguredPeer hook observes its OPEN when one is configured, and the
// remote is answered with Cease / Connection Rejected either way. The
// whole exchange is bounded by unconfiguredPeerTimeout on its own
// goroutine, and by unconfiguredPeerLimit across goroutines.
func (s *Server) rejectUnconfigured(run *serverRun, c *Conn, raddr netip.AddrPort) {
	select {
	case s.unconfSem <- struct{}{}:
	default:
		// Load shedding, not judgment about the peer, so the farewell is
		// Cease / Out of Resources — the same subcode the FSM uses when
		// shedding. A 21 byte write into a fresh connection's empty send
		// buffer cannot block, and writeBounded caps it regardless, so
		// the accept loop is never stalled.
		s.log.Debug("closed connection from unconfigured peer over concurrency limit", "raddr", raddr)
		_ = writeBounded(c, &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseOutOfResources,
		})
		_ = c.Close()
		return
	}

	s.log.Debug("rejecting connection from unconfigured peer", "raddr", raddr)

	run.unconfWG.Go(func() {
		// Cancellation must not wait out the deadline on a silent remote:
		// closing the connection fails the read and the write immediately.
		stop := context.AfterFunc(run.ctx, func() { _ = c.Close() })
		defer func() {
			stop()
			_ = c.Close()
			<-s.unconfSem
		}()
		_ = c.SetDeadline(time.Now().Add(unconfiguredPeerTimeout))

		if f := s.cfg.OnUnconfiguredPeer; f != nil {
			// One message under the deadline: the OPEN, if the remote is a
			// live speaker. Anything else observes as nil.
			var o *Open
			if m, err := c.ReadMessage(); err == nil {
				o, _ = m.(*Open)
			}

			f(run.ctx, raddr, o)
		}

		// The farewell real routers send (RFC 4486): it tells the remote
		// operator why this session will never come up.
		_ = c.WriteMessage(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseConnectionRejected,
		})
	})
}

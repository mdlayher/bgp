package bgp

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestFSMGoroutinesEndWithConnect enforces the invariant FSM.attempt's deferred teardown
// rests on: every goroutine an attempt starts — a reader per connection, the
// session's writer, the dial and the drain of an abandoned one — has exited
// by the time Connect returns. The teardown therefore stops only the dial
// and the retry timer, trusting each exit path to have killed and joined its
// connections, and endSession to have joined the writer.
//
// Each scenario runs in a synctest bubble over in-memory pipes: a goroutine
// which outlives Connect leaves the bubble blocked, which fails the test
// deterministically, and fake time turns every wait into a hang detector.
func TestFSMGoroutinesEndWithConnect(t *testing.T) {
	t.Parallel()

	ceaseCollision := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseConnectionCollisionResolution,
	}

	ceaseShutdown := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseAdministrativeShutdown,
	}

	tests := []struct {
		name    string
		passive bool
		dial    func(ctx context.Context) (*Conn, error)
		run     func(t *testing.T, r *fsmRig)
	}{
		{
			name: "established then canceled",
			run: func(t *testing.T, r *fsmRig) {
				s := r.nextDial()
				s.establish(scriptOpen())
				recv(t, r.estC, "session establishment")

				r.cancel()
				s.expectNotification(ceaseShutdown)
				s.expectClosed()
				if err := r.wait(); !errors.Is(err, context.Canceled) {
					t.Fatalf("unexpected Connect error: %v", err)
				}

				if c := recv(t, r.closeC, "session close"); !c.Established {
					t.Fatalf("expected an established close, got: %+v", c)
				}
			},
		},
		{
			name:    "passive established then peer notification",
			passive: true,
			run: func(t *testing.T, r *fsmRig) {
				s := r.deliver()
				s.establish(scriptOpen())
				recv(t, r.estC, "session establishment")

				s.write(&Notification{Code: NotificationCease, Subcode: SubcodeCeaseAdministrativeReset})
				s.expectClosed()
				if err := r.wait(); err != nil {
					t.Fatalf("unexpected Connect error: %v", err)
				}

				if c := recv(t, r.closeC, "session close"); c.Local {
					t.Fatalf("expected a received close, got: %+v", c)
				}
			},
		},
		{
			name: "collision resolved at OPEN",
			run: func(t *testing.T, r *fsmRig) {
				dialed := r.nextDial()
				dialed.expectOpen()
				accepted := r.deliver()
				accepted.expectOpen()

				// The peer's identifier is the higher, so its own connection
				// — the accepted one — survives.
				accepted.write(scriptOpen())
				dialed.expectNotification(ceaseCollision)
				dialed.expectClosed()
				accepted.expectKeepalive()
				accepted.write(&Keepalive{})
				recv(t, r.estC, "session establishment")

				r.cancel()
				accepted.expectNotification(ceaseShutdown)
				accepted.expectClosed()
				if err := r.wait(); !errors.Is(err, context.Canceled) {
					t.Fatalf("unexpected Connect error: %v", err)
				}
			},
		},
		{
			name: "collision settled by establishment",
			run: func(t *testing.T, r *fsmRig) {
				dialed := r.nextDial()
				dialed.expectOpen()
				dialed.write(scriptOpen())
				dialed.expectKeepalive()
				accepted := r.deliver()
				accepted.expectOpen()

				// The confirming KEEPALIVE establishes the dialed connection
				// and drops the accepted one, still in OpenSent.
				dialed.write(&Keepalive{})
				accepted.expectNotification(ceaseCollision)
				accepted.expectClosed()
				recv(t, r.estC, "session establishment")

				r.cancel()
				dialed.expectNotification(ceaseShutdown)
				dialed.expectClosed()
				if err := r.wait(); !errors.Is(err, context.Canceled) {
					t.Fatalf("unexpected Connect error: %v", err)
				}
			},
		},
		{
			name: "dial abandoned by the retry cadence",
			// A dial which never completes, blocking until its context
			// ends.
			dial: func(ctx context.Context) (*Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			run: func(t *testing.T, r *fsmRig) {
				// The first dial never completes; the retry tick abandons it
				// and begins a second, whose drain goroutine must also end
				// with the attempt. The tick is minutes of fake time away,
				// past recv's own timeout, so the waits are bare: a hang is
				// the bubble's deadlock to report.
				<-r.dialStarted
				<-r.dialStarted

				r.cancel()
				if err := r.wait(); !errors.Is(err, context.Canceled) {
					t.Fatalf("unexpected Connect error: %v", err)
				}

				// Nothing observable began, so nothing was reported.
				select {
				case c := <-r.closeC:
					t.Fatalf("unexpected close: %+v", c)
				default:
				}
			},
		},
		{
			name: "session connection lost",
			run: func(t *testing.T, r *fsmRig) {
				s := r.nextDial()
				s.establish(scriptOpen())
				recv(t, r.estC, "session establishment")

				_ = s.nc.Close()
				if err := r.wait(); err != nil {
					t.Fatalf("unexpected Connect error: %v", err)
				}

				if c := recv(t, r.closeC, "session close"); c.Err == nil || !c.Established {
					t.Fatalf("expected an established close with an error, got: %+v", c)
				}
			},
		},
		{
			name: "session hold timer expired",
			run: func(t *testing.T, r *fsmRig) {
				s := r.nextDial()
				s.establish(scriptOpen())
				recv(t, r.estC, "session establishment")

				// The peer goes silent and fake time runs: keepalives flow
				// out every ten seconds until the hold time expires at
				// thirty. The reads carry no deadline, since fake time
				// would expire one before the keepalive it waits for.
				_ = s.c.SetReadDeadline(time.Time{})
				for {
					m, err := s.c.ReadMessage()
					if err != nil {
						t.Fatalf("failed to read message: %v", err)
					}

					if n, ok := m.(*Notification); ok {
						want := &Notification{Code: NotificationHoldTimerExpired}
						if d := diff(t, want, n); d != "" {
							t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
						}

						break
					}
				}

				s.expectClosed()
				if err := r.wait(); err != nil {
					t.Fatalf("unexpected Connect error: %v", err)
				}

				recv(t, r.closeC, "session close")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newFSMRig(t, FSMConfig{Passive: tt.passive, DialFunc: tt.dial})
				tt.run(t, r)

				// Connect has returned: the session's connection is
				// unpublished, so the send methods see no session.
				if err := r.f.SendUpdate(context.Background(), &Update{}); !errors.Is(err, ErrNotEstablished) {
					t.Fatalf("expected ErrNotEstablished after Connect returned, got: %v", err)
				}
			})
		})
	}
}

// rigConnectRetry is the rig's jitter-free connect retry interval: the
// lower bound of FSM.jittered, three quarters of connectRetryTime.
const rigConnectRetry = 3 * connectRetryTime / 4

// TestFSMRetryDeclineKeepsCadence verifies RFC 4271, section 8.2.2's connect
// retry handling when a tick finds a dial still in flight beside a tracked
// accepted connection: the tick declines to dial but re-arms the timer, so
// that when the hanging dial later fails — Tcp_CR_Acked's failure path in
// dispatch has no timer of its own — the next tick starts a fresh dial
// instead of stranding the active open while the accepted connection stalls
// in OpenSent.
func TestFSMRetryDeclineKeepsCadence(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// The first dial hangs until released, then fails; every later
		// dial fails at once.
		release := make(chan struct{})
		r := newFSMRig(t, FSMConfig{DialFunc: func(ctx context.Context) (*Conn, error) {
			select {
			case <-release:
				return nil, errors.New("dial timed out")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}})
		<-r.dialStarted

		// An accepted connection arrives and stalls in OpenSent, with a
		// full open hold time ahead of it: the fake time below stays well
		// inside that budget.
		accepted := r.deliver()
		accepted.expectOpen()

		// The first tick finds the dial in flight: it must decline to dial
		// and re-arm. Wait settles the bubble so the tick has been handled
		// before the dial is released.
		time.Sleep(rigConnectRetry)
		synctest.Wait()

		select {
		case <-r.dialStarted:
			t.Fatal("a second dial began while the first was still in flight")
		default:
		}

		// The hanging dial fails, long after its own tick came and went.
		close(release)
		synctest.Wait()

		// The re-armed tick begins a fresh dial.
		time.Sleep(rigConnectRetry)
		<-r.dialStarted

		// The accepted connection carried the attempt throughout: ctx
		// cancellation finds it live and bids it farewell.
		r.cancel()
		accepted.expectNotification(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeShutdown,
		})
		accepted.expectClosed()

		if err := r.wait(); !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected Connect error: %v", err)
		}
	})
}

// TestFSMHooksRefuseReentry enforces that a handler which calls back into
// its own FSM cannot re-enter it: Connect from any hook reports the attempt
// already in progress rather than nesting another, and a send from OnClose
// reports ErrNotEstablished, because the session is already down by the
// time the close is reported. The hooks run on two goroutines — OnClose
// and OnStateChange on the FSM's, the rest on the reader's — so each is
// exercised in place, and the map of visited hooks proves every one fired.
func TestFSMHooksRefuseReentry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var (
			mu      sync.Mutex
			visited = make(map[string]bool)
		)

		reenter := func(hook string, f *FSM) {
			mu.Lock()
			defer mu.Unlock()
			visited[hook] = true
			if err := f.Connect(context.Background()); err == nil {
				t.Errorf("Connect from %s: expected an error, but none occurred", hook)
			}
		}

		dials := make(chan *script, 1)
		f := must(NewFSM(FSMConfig{
			LocalASN: 64496,
			LocalID:  MustParseIdentifier("192.0.2.1"),
			Logger:   testLogger(t),
			DialFunc: func(context.Context) (*Conn, error) {
				client, server := memPipe()
				dials <- newScript(t, server)
				return NewConn(client), nil
			},

			OnEstablished: func(_ context.Context, f *FSM, _ Session) error {
				reenter("OnEstablished", f)
				return nil
			},

			OnUpdate: func(_ context.Context, f *FSM, _ *Update) error {
				reenter("OnUpdate", f)
				return nil
			},

			OnKeepalive: func(_ context.Context, f *FSM) error {
				reenter("OnKeepalive", f)
				return nil
			},

			OnStateChange: func(f *FSM, _, _ State) { reenter("OnStateChange", f) },

			OnClose: func(f *FSM, _ Close) {
				reenter("OnClose", f)
				if err := f.SendUpdate(context.Background(), &Update{}); !errors.Is(err, ErrNotEstablished) {
					t.Errorf("SendUpdate from OnClose: expected ErrNotEstablished, got: %v", err)
				}
			},
		}))

		ctx, cancel := context.WithCancel(context.Background())
		doneC := make(chan error, 1)
		go func() { doneC <- f.Connect(ctx) }()

		s := recv(t, dials, "the FSM to dial")
		s.establish(scriptOpen())

		s.write(&Keepalive{})
		s.write(&Update{})
		// The reader has handled both messages once it is blocked again.
		synctest.Wait()

		cancel()
		s.expectNotification(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeShutdown,
		})
		s.expectClosed()

		if err := recv(t, doneC, "Connect to return"); !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected Connect error: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		for _, hook := range []string{"OnEstablished", "OnUpdate", "OnKeepalive", "OnStateChange", "OnClose"} {
			if !visited[hook] {
				t.Errorf("%s never fired", hook)
			}
		}
	})
}

// TestFSMDialCompletesAfterEstablished pins the established loop's dialC
// case: an active open which completes only after an accepted connection
// established the session is refused with Cease / Connection Rejected, and
// the session is undisturbed.
func TestFSMDialCompletesAfterEstablished(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		scripts := make(chan *script, 1)
		r := newFSMRig(t, FSMConfig{DialFunc: func(ctx context.Context) (*Conn, error) {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			client, server := memPipe()
			scripts <- newScript(t, server)
			return NewConn(client), nil
		}})
		<-r.dialStarted

		// An accepted connection carries the attempt to Established while
		// the dial is still parked.
		accepted := r.deliver()
		accepted.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// The parked dial completes into the established session: its
		// connection is bid farewell, and the session is undisturbed.
		close(release)
		dialed := recv(t, scripts, "the parked dial to complete")
		dialed.expectNotification(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseConnectionRejected,
		})
		dialed.expectClosed()

		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	})
}

// TestFSMAcceptedOpenConfirmKeepalives pins the accepted origin of the
// OpenConfirm keepalive cadence: a delivered connection whose peer withholds
// the confirming KEEPALIVE is fed periodic KEEPALIVEs, exactly as a dialed
// one is.
func TestFSMAcceptedOpenConfirmKeepalives(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newFSMRig(t, FSMConfig{Passive: true})

		s := r.deliver()
		s.expectOpen()
		s.write(scriptOpen())
		s.expectKeepalive()

		// One keepalive interval of the negotiated 30s hold passes in
		// OpenConfirm; the peer's hold timer must be fed.
		time.Sleep(10 * time.Second)
		s.expectKeepalive()
	})
}

// TestFSMAbandonedDialConnClosed pins the abandoned dial's drain: a DialFunc
// which produces a connection only after the attempt ended has it closed by
// the drain goroutine rather than leaked.
func TestFSMAbandonedDialConnClosed(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		scripts := make(chan *script, 1)
		r := newFSMRig(t, FSMConfig{DialFunc: func(context.Context) (*Conn, error) {
			<-release
			client, server := memPipe()
			scripts <- newScript(t, server)
			return NewConn(client), nil
		}})
		<-r.dialStarted

		// The attempt ends while the dial is still parked, abandoning it.
		r.cancel()
		if err := r.wait(); !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected Connect error: %v", err)
		}

		// The too-late connection is closed by the drain.
		close(release)
		recv(t, scripts, "the parked dial to complete").expectClosed()
	})
}

// TestFSMDialedOpenSendFailure pins tcpCRAcked's failure path: a dialed
// connection whose OPEN write fails, with no other connection tracked, ends
// the attempt with the write error and nothing on the wire to report.
func TestFSMDialedOpenSendFailure(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newFSMRig(t, FSMConfig{DialFunc: func(context.Context) (*Conn, error) {
			client, _ := memPipe()
			return NewConn(&writeFailConn{Conn: client, failAt: 1}), nil
		}})

		c := recv(t, r.closeC, "attempt close")
		if c.Err == nil || c.Notification != nil {
			t.Fatalf("expected a write error close without NOTIFICATION, got: %+v", c)
		}
	})
}

// TestFSMSecondOpenRejected pins bgpOpen's state guard: a second OPEN on a
// connection already in OpenConfirm is answered with the RFC 6608 FSM error
// for that state, and the connection is torn down.
func TestFSMSecondOpenRejected(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newFSMRig(t, FSMConfig{})

		s := r.nextDial()
		s.expectOpen()
		s.write(scriptOpen())
		s.expectKeepalive()

		want := &Notification{
			Code:    NotificationFSMError,
			Subcode: SubcodeUnexpectedMessageOpenConfirm,
		}

		s.write(scriptOpen())
		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}
	})
}

// TestFSMConfirmKeepaliveWriteFailure pins bgpOpen's confirm path: when the
// KEEPALIVE which confirms an accepted OPEN cannot be written, the
// connection is dropped with the write error and no NOTIFICATION.
func TestFSMConfirmKeepaliveWriteFailure(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		scripts := make(chan *script, 1)
		r := newFSMRig(t, FSMConfig{DialFunc: func(context.Context) (*Conn, error) {
			client, server := memPipe()
			scripts <- newScript(t, server)

			// Write 1 is the OPEN; write 2 is the confirming KEEPALIVE,
			// and fails.
			return NewConn(&writeFailConn{Conn: client, failAt: 2}), nil
		}})

		s := recv(t, scripts, "the FSM to dial")
		s.expectOpen()
		s.write(scriptOpen())

		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if c.Err == nil || c.Notification != nil {
			t.Fatalf("expected a write error close without NOTIFICATION, got: %+v", c)
		}
	})
}

// TestFSMAcceptedOpenHoldExpiry pins the accepted origin of the open
// hold time: a delivered connection whose OPEN exchange stalls is dropped
// with Hold Timer Expired at its own deadline, like a dialed one.
func TestFSMAcceptedOpenHoldExpiry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newFSMRig(t, FSMConfig{Passive: true})

		s := r.deliver()
		s.expectOpen()
		time.Sleep(openHoldTime)

		want := &Notification{Code: NotificationHoldTimerExpired}
		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}
	})
}

// TestFSMDialedOpenSendFailureResumesRetry pins tcpCRAcked's other failure
// path: a dialed OPEN write which fails while an accepted connection holds
// the attempt resumes the connect retry cadence rather than ending the
// attempt, so the accepted connection does not carry it alone.
func TestFSMDialedOpenSendFailureResumesRetry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		r := newFSMRig(t, FSMConfig{DialFunc: func(context.Context) (*Conn, error) {
			<-release
			client, _ := memPipe()
			return NewConn(&writeFailConn{Conn: client, failAt: 1}), nil
		}})
		<-r.dialStarted

		// An accepted connection stalls in OpenSent while the dial parks.
		accepted := r.deliver()
		accepted.expectOpen()

		// The released dial's OPEN write fails at once: the attempt
		// continues on the accepted connection, and the timer resumes.
		close(release)
		synctest.Wait()

		select {
		case c := <-r.closeC:
			t.Fatalf("attempt ended unexpectedly: %+v", c)
		default:
		}

		// The next tick begins a fresh dial.
		time.Sleep(rigConnectRetry)
		<-r.dialStarted
	})
}

// TestFSMKeepaliveWriteFailure pins keepaliveTimerExpires' failure path: a
// KEEPALIVE write which fails in OpenConfirm drops the connection with the
// write error, without a NOTIFICATION, and ends the attempt.
func TestFSMKeepaliveWriteFailure(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		scripts := make(chan *script, 1)
		r := newFSMRig(t, FSMConfig{DialFunc: func(context.Context) (*Conn, error) {
			client, server := memPipe()
			scripts <- newScript(t, server)

			// Write 1 is the OPEN and write 2 the confirming KEEPALIVE;
			// write 3 is the first keepalive tick's, and fails.
			return NewConn(&writeFailConn{Conn: client, failAt: 3}), nil
		}})

		s := recv(t, scripts, "the FSM to dial")
		s.expectOpen()
		s.write(scriptOpen())
		s.expectKeepalive()

		// The first keepalive interval of the negotiated 30s hold expires
		// in OpenConfirm; its write fails.
		time.Sleep(10 * time.Second)

		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if c.Err == nil || c.Notification != nil {
			t.Fatalf("expected a write error close without NOTIFICATION, got: %+v", c)
		}
	})
}

// An fsmRig runs one FSM under test inside a synctest bubble, over
// in-memory pipes: each dial's scripted side arrives on dials, and deliver
// hands in an accepted connection. Connect runs on its own goroutine from
// construction; cancel ends it and wait returns its error.
//
// The rig's FSM has no jitter: the connect retry timer fires exactly
// rigConnectRetry after each arm, so a test can sleep fake time onto a tick.
type fsmRig struct {
	tb testing.TB
	f  *FSM

	dials       chan *script
	dialStarted chan struct{}
	estC        chan Session
	closeC      chan Close

	cancel context.CancelFunc
	doneC  chan error
}

// newFSMRig starts an FSM from cfg, defaulting its identity: a Passive one
// accepts only, and cfg.DialFunc, when non-nil, replaces the rig's own
// pipe-producing one. Every dial signals dialStarted first, whichever
// function runs it, and the rig's recorders run ahead of any handler cfg
// carries.
func newFSMRig(tb testing.TB, cfg FSMConfig) *fsmRig {
	tb.Helper()

	r := &fsmRig{
		tb:          tb,
		dials:       make(chan *script, 4),
		dialStarted: make(chan struct{}, 4),
		estC:        make(chan Session, 4),
		closeC:      make(chan Close, 4),
		doneC:       make(chan error, 1),
	}

	if cfg.LocalASN == 0 {
		cfg.LocalASN = 64496
	}

	if cfg.LocalID == 0 {
		cfg.LocalID = MustParseIdentifier("192.0.2.1")
	}

	if cfg.Logger == nil {
		cfg.Logger = testLogger(tb)
	}

	userEst, userClose := cfg.OnEstablished, cfg.OnClose
	cfg.OnEstablished = func(ctx context.Context, f *FSM, s Session) error {
		r.estC <- s
		if userEst != nil {
			return userEst(ctx, f, s)
		}

		return nil
	}

	cfg.OnClose = func(f *FSM, c Close) {
		r.closeC <- c
		if userClose != nil {
			userClose(f, c)
		}
	}

	if !cfg.Passive {
		dial := cfg.DialFunc
		cfg.DialFunc = func(ctx context.Context) (*Conn, error) {
			r.dialStarted <- struct{}{}
			if dial != nil {
				return dial(ctx)
			}

			client, server := memPipe()
			r.dials <- newScript(tb, server)
			return NewConn(client), nil
		}
	}

	r.f = must(NewFSM(cfg))
	r.f.jitter = func() float64 { return 0 }

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.doneC <- r.f.Connect(ctx) }()
	return r
}

// nextDial returns the scripted side of the FSM's next dial.
func (r *fsmRig) nextDial() *script {
	r.tb.Helper()
	return recv(r.tb, r.dials, "the FSM to dial")
}

// deliver hands the FSM an accepted connection and returns its scripted
// side. Connect runs concurrently, so the bubble first settles: once every
// other goroutine is durably blocked, Connect is in its select and accepting.
func (r *fsmRig) deliver() *script {
	r.tb.Helper()

	synctest.Wait()
	client, server := memPipe()
	if err := r.f.DeliverConn(NewConn(client)); err != nil {
		r.tb.Fatalf("failed to deliver connection: %v", err)
	}

	return newScript(r.tb, server)
}

// wait returns Connect's result.
func (r *fsmRig) wait() error {
	r.tb.Helper()
	return recv(r.tb, r.doneC, "Connect to return")
}

// A writeFailConn fails its nth Write, driving a pre-established write
// failure on an exact message. Pre-established writes all run on the FSM
// goroutine, so the counter needs no synchronization.
type writeFailConn struct {
	net.Conn
	writes, failAt int
}

func (c *writeFailConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes >= c.failAt {
		return 0, errors.New("synthetic write failure")
	}

	return c.Conn.Write(p)
}

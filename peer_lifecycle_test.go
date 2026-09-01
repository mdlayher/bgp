package bgp

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestPeerManualStopOpenSent verifies that canceling Run's ctx before a
// session is established still reports through OnClose: the connection had
// begun the OPEN exchange, so the attempt's end is observable.
func TestPeerManualStopOpenSent(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		// The connection is in OpenSent when the ctx ends.
		s.expectOpen()
		r.cancel()

		want := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeShutdown,
		}

		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !c.Local || c.Err != nil {
			t.Fatalf("expected a sent notification without error, got: %+v", c)
		}
	})
}

// TestPeerRetryAfterClose verifies Run's retry loop and the cross-session
// ordering guarantee: OnClose of one session strictly precedes OnEstablished
// of the next.
func TestPeerRetryAfterClose(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})

		s1 := r.acceptScript()
		s1.establish(scriptOpen())
		recv(t, r.estC, "first session establishment")

		s1.write(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeReset,
		})
		recv(t, r.closeC, "first session close")

		// Run idles before retrying: the idle hold passes, and the next
		// dial begins.
		time.Sleep(idleHoldTime)
		s2 := r.acceptScript()
		s2.establish(scriptOpen())
		recv(t, r.estC, "second session establishment")

		want := []string{"established", "close", "established"}
		for i, w := range want {
			if got := recv(t, r.events, "handler event"); got != w {
				t.Fatalf("unexpected handler event %d: want %q, got %q", i, w, got)
			}
		}
	})
}

// TestPeerDialRetry verifies the connect retry cadence of RFC 4271, section
// 8.2.2: the retry timer is armed when a dial begins, a failed dial waits
// out the remainder of the interval, and the timer's expiry starts the next
// dial — even while an unrelated inbound connection is mid-exchange.
func TestPeerDialRetryRefused(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{DialFunc: refuseFirstDial()})

		// The first dial was refused at once; the timer armed as it
		// began runs out the whole interval before the next.
		time.Sleep(connectRetryTime)
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")
	})
}

func TestPeerDialRetryStalledInbound(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{DialFunc: refuseFirstDial()})

		// An inbound connection arrives and stalls in OpenSent: the
		// Peer sends its OPEN and the scripted peer never answers. A
		// peer which merely completes a TCP handshake must not
		// suppress the active open's cadence.
		stalled := r.deliver()
		stalled.expectOpen()

		time.Sleep(connectRetryTime)
		r.acceptScript().expectOpen()
	})
}

// TestPeerDialedDeathResumesRetry and TestPeerCollisionLossResumesRetry
// verify that losing the dialed connection mid-attempt resumes the active
// open's cadence: a successful dial stops the connect retry timer, and
// without a re-arm on the dialed connection's death the attempt would ride
// the accepted connection alone — a peer stalled in OpenSent could then
// suppress this speaker's active open for the rest of the attempt, up to a
// full openHoldTime.
func TestPeerDialedDeathResumesRetry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})

		dialed := r.acceptScript()
		dialed.expectOpen()

		// An accepted connection arrives and stalls in OpenSent.
		accepted := r.deliver()
		accepted.expectOpen()

		// The dialed connection dies; the attempt continues on the
		// accepted connection, and the timer resumes. Wait settles
		// the bubble so the loss is handled before the interval runs.
		_ = dialed.nc.Close()
		synctest.Wait()

		// The next tick begins a fresh dial while the accepted
		// connection still stalls.
		time.Sleep(connectRetryTime)
		r.acceptScript().expectOpen()
	})
}

func TestPeerCollisionLossResumesRetry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// The negotiated hold time must outlast the retry interval,
		// or the surviving connection would hold-expire before the
		// re-dial.
		const hold = 3 * time.Minute

		r := newPipeRig(t, PeerConfig{HoldTime: hold})

		dialed := r.acceptScript()
		dialed.expectOpen()

		accepted := r.deliver()
		accepted.expectOpen()

		// The peer's OPEN arrives on the accepted connection bearing
		// the higher identifier: the dialed connection loses the
		// tie-break, and the timer resumes.
		accepted.write(&Open{
			ASN:      64497,
			HoldTime: hold,
			ID:       MustParseIdentifier("192.0.2.20"),
		})

		dialed.expectNotification(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseConnectionCollisionResolution,
		})
		dialed.expectClosed()

		accepted.expectKeepalive()

		// The accepted connection stalls in OpenConfirm; the next
		// tick begins a fresh dial anyway.
		time.Sleep(connectRetryTime)
		r.acceptScript().expectOpen()
	})
}

// The TestPeerOpenHoldExpiry tests verify the open hold time of RFC 4271,
// section 8.2.2: a connection whose OPEN exchange stalls is dropped with
// Hold Timer Expired at its own deadline, and each connection carries its
// own budget.
func TestPeerOpenHoldExpiryLastConnection(t *testing.T) {
	t.Parallel()

	want := &Notification{Code: NotificationHoldTimerExpired}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		// The scripted peer never answers the OPEN.
		s.expectOpen()
		time.Sleep(openHoldTime)

		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !c.Local || c.Err != nil {
			t.Fatalf("expected a sent notification without error, got: %+v", c)
		}
	})
}

func TestPeerOpenHoldExpiryNegotiatedHold(t *testing.T) {
	t.Parallel()

	want := &Notification{Code: NotificationHoldTimerExpired}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		// Accepting the peer's OPEN drops the hold timer from the
		// OpenSent "large value" to the negotiated 30s and arms the
		// keepalive timer; the peer then withholds its confirming
		// KEEPALIVE.
		s.expectOpen()
		s.write(scriptOpen())
		s.expectKeepalive()

		// Two keepalive intervals pass in OpenConfirm; each must feed
		// the peer's hold timer with a KEEPALIVE on the wire.
		for range 2 {
			time.Sleep(10 * time.Second)
			s.expectKeepalive()
		}

		// The third interval spends the negotiated hold: the
		// connection dies at 30 seconds, not at the 4 minute open hold
		// time.
		time.Sleep(10 * time.Second)
		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}
	})
}

func TestPeerOpenHoldExpiryCollisionBudget(t *testing.T) {
	t.Parallel()

	want := &Notification{Code: NotificationHoldTimerExpired}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		dialed := r.acceptScript()
		dialed.expectOpen()

		// Half the dialed connection's budget passes before the
		// collision connection arrives; the newcomer's budget is its
		// own, not the remainder of the first.
		time.Sleep(openHoldTime / 2)
		accepted := r.deliver()
		accepted.expectOpen()

		// The dialed connection expires at its own deadline...
		time.Sleep(openHoldTime / 2)
		dialed.expectNotification(want)
		dialed.expectClosed()

		// ...while the accepted connection, with half its budget
		// left, can still carry the attempt to Established.
		accepted.write(scriptOpen())
		accepted.expectKeepalive()
		accepted.write(&Keepalive{})
		recv(t, r.estC, "session establishment")
	})
}

// TestPeerDialFuncIgnoresCancellation verifies that Run returns when its ctx
// is canceled even though a caller's DialFunc is still parked, ignoring the
// canceled context it was handed. The FSM abandons such a dial rather than
// waiting for it: the attempt's teardown hands the drain to a goroutine,
// which closes the connection if one ever arrives. A blocking drain here
// would make one uncooperative DialFunc enough to wedge Run forever.
func TestPeerDialFuncIgnoresCancellation(t *testing.T) {
	t.Parallel()

	// dialing signals that the DialFunc has been entered; release lets it
	// return, and is closed only as the test ends, so the dial is genuinely
	// still in flight when Run is canceled.
	dialing := make(chan struct{}, 1)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	p := must(NewPeer(netip.Addr{}, PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Logger:   testLogger(t),
		DialFunc: func(ctx context.Context) (*Conn, error) {
			dialing <- struct{}{}
			// Deliberately ignore ctx: this is the misbehavior under test.
			<-release
			return nil, errors.New("dial abandoned")
		},
	}))

	ctx, cancel := context.WithCancel(context.Background())
	runC := make(chan error, 1)
	go func() { runC <- p.Run(ctx) }()

	recv(t, dialing, "the DialFunc to be entered")
	cancel()

	if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}
}

// TestPeerDialFuncOutlivesRetry verifies that the connect retry cadence can
// abandon an in-flight dial whose DialFunc ignores its canceled context: the
// tick must start the next dial rather than block the FSM goroutine waiting
// for the old one (RFC 4271, section 8.2.2, event 9). A blocking drain here
// wedges the attempt against exactly the black-holed peer the cadence exists
// to re-dial.
func TestPeerDialFuncOutlivesRetry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		dials := make(chan struct{}, 4)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })

		newPipeRig(t, PeerConfig{
			DialFunc: func(ctx context.Context) (*Conn, error) {
				dials <- struct{}{}
				// Deliberately ignore ctx: this is the misbehavior under
				// test.
				<-release
				return nil, errors.New("dial abandoned")
			},
		})

		// The first dial arms the retry timer before it calls DialFunc,
		// so the interval runs from the dial's start.
		recv(t, dials, "the first dial")
		time.Sleep(connectRetryTime)
		recv(t, dials, "the retry to begin a second dial")
	})
}

// TestPeerShutdownCommunication verifies the RFC 9003 path end to end: the
// configured message rides the Administrative Shutdown Cease, and both
// operators can decode it.
func TestPeerShutdownCommunication(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const msg = "maintenance, back at 02:00 UTC"

		r := newPipeRig(t, PeerConfig{ShutdownCommunication: msg})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		r.cancel()

		n := s.nextNotification()
		if got, ok := n.ShutdownCommunication(); !ok || got != msg {
			t.Fatalf("unexpected shutdown communication on the wire: %q, %t", got, ok)
		}

		if n.Code != NotificationCease || n.Subcode != SubcodeCeaseAdministrativeShutdown {
			t.Fatalf("unexpected NOTIFICATION: %+v", n)
		}

		c := recv(t, r.closeC, "session close")
		if got, ok := c.Notification.ShutdownCommunication(); !ok || got != msg {
			t.Fatalf("unexpected shutdown communication in Close: %q, %t", got, ok)
		}

		if !c.Local {
			t.Fatal("close notification must be sent by this speaker, not received")
		}
	})
}

// TestPeerShutdownCause verifies the teardown-reason seam: a *MessageError
// cancellation cause is sent verbatim as the session's farewell, winning
// over the configured static shutdown communication.
func TestPeerShutdownCause(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{ShutdownCommunication: "static farewell"})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		r.cancelCause(must(NewShutdownError(
			SubcodeCeaseAdministrativeReset, "dynamic farewell",
		)))

		n := s.nextNotification()
		if n.Code != NotificationCease || n.Subcode != SubcodeCeaseAdministrativeReset {
			t.Fatalf("unexpected NOTIFICATION: %+v", n)
		}

		if got, ok := n.ShutdownCommunication(); !ok || got != "dynamic farewell" {
			t.Fatalf("unexpected shutdown communication on the wire: %q, %t", got, ok)
		}

		c := recv(t, r.closeC, "session close")
		if got, ok := c.Notification.ShutdownCommunication(); !ok || got != "dynamic farewell" {
			t.Fatalf("unexpected shutdown communication in Close: %q, %t", got, ok)
		}

		if !c.Local {
			t.Fatal("close notification must be sent by this speaker, not received")
		}
	})
}

// TestPeerHardResetCause verifies the Hard Reset cancellation-cause seam
// end to end: a Hard Reset cancellation cause reaches the wire in the RFC 8538,
// section 3 conformant form, encapsulated reason and communication
// included.
func TestPeerHardResetCause(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		r.cancelCause(must(NewHardResetError(
			NotificationCease, SubcodeCeaseAdministrativeShutdown, "rebooting",
		)))

		n := s.nextNotification()
		if n.Code != NotificationCease || n.Subcode != SubcodeCeaseHardReset {
			t.Fatalf("unexpected NOTIFICATION: %+v", n)
		}

		inner, ok := n.HardReset()
		if !ok {
			t.Fatal("failed to decode the encapsulated reason")
		}

		if inner.Code != NotificationCease || inner.Subcode != SubcodeCeaseAdministrativeShutdown {
			t.Fatalf("unexpected encapsulated reason: %+v", inner)
		}

		if got, ok := inner.ShutdownCommunication(); !ok || got != "rebooting" {
			t.Fatalf("unexpected shutdown communication in the reason: %q, %t", got, ok)
		}

		c := recv(t, r.closeC, "session close")
		if c.Notification == nil || c.Notification.Subcode != SubcodeCeaseHardReset {
			t.Fatalf("unexpected Close notification: %+v", c.Notification)
		}

		if !c.Local {
			t.Fatal("close notification must be sent by this speaker, not received")
		}
	})
}

// TestPeerConnectRetryStoppedWhileDialed pins the invariant
// resumeConnectRetryTimer arms without a guard: from the moment a dial
// succeeds until the dialed connection is lost, the connect retry timer is
// stopped, so no retry tick can start a second dial into an occupied slot;
// and the timer resumes exactly when the dialed connection is lost while
// the attempt continues on an accepted one.
func TestPeerConnectRetryStoppedWhileDialed(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})

		dialed := r.acceptScript()
		dialed.expectOpen()

		// Nearly the whole open hold time passes with the peer stalled in
		// OpenSent — almost two retry intervals: a stopped timer cannot
		// fire, so no dial begins. Wait settles the bubble, so a dial the
		// ticks had started would already be on the channel.
		time.Sleep(openHoldTime - time.Second)
		synctest.Wait()

		select {
		case <-r.dials:
			t.Fatal("a dial began while a dialed connection was tracked")
		default:
		}

		// Completing the exchange proves the connection is still the
		// attempt's.
		dialed.write(scriptOpen())
		dialed.expectKeepalive()

		// An accepted connection joins the attempt, and the peer then
		// ends the dialed one: the attempt continues on the accepted
		// connection, and the timer resumes. The next tick dials again.
		accepted := r.deliver()
		accepted.expectOpen()

		dialed.write(&Notification{Code: NotificationCease, Subcode: SubcodeCeaseAdministrativeReset})
		dialed.expectClosed()
		synctest.Wait()

		time.Sleep(connectRetryTime)
		r.acceptScript().expectOpen()
	})
}

// TestPeerHooksRefuseReentry is TestFSMHooksRefuseReentry one layer up: Run
// from any Peer hook reports the peer already running rather than nesting a
// second retry loop, and a send from OnClose reports ErrNotEstablished.
func TestPeerHooksRefuseReentry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var (
			mu      sync.Mutex
			visited = make(map[string]bool)
		)

		reenter := func(hook string, p *Peer) {
			mu.Lock()
			defer mu.Unlock()
			visited[hook] = true
			if err := p.Run(context.Background()); err == nil {
				t.Errorf("Run from %s: expected an error, but none occurred", hook)
			}
		}

		r := newPipeRig(t, PeerConfig{
			OnEstablished: func(_ context.Context, p *Peer, _ Session) error {
				reenter("OnEstablished", p)
				return nil
			},

			OnUpdate: func(_ context.Context, p *Peer, _ *Update) error {
				reenter("OnUpdate", p)
				return nil
			},

			OnKeepalive: func(_ context.Context, p *Peer) error {
				reenter("OnKeepalive", p)
				return nil
			},

			OnStateChange: func(p *Peer, _, _ State) { reenter("OnStateChange", p) },

			OnClose: func(p *Peer, _ Close) {
				reenter("OnClose", p)
				if err := p.SendUpdate(context.Background(), &Update{}); !errors.Is(err, ErrNotEstablished) {
					t.Errorf("SendUpdate from OnClose: expected ErrNotEstablished, got: %v", err)
				}
			},
		})

		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		s.write(&Keepalive{})
		s.write(&Update{})
		// The reader has handled both messages once it is blocked again.
		synctest.Wait()

		r.cancel()
		s.expectNotification(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeShutdown,
		})
		s.expectClosed()
		recv(t, r.closeC, "session close")

		// The rig's recorder runs before the test's OnClose; settle so the
		// hook has finished before its record is read.
		synctest.Wait()

		mu.Lock()
		defer mu.Unlock()
		for _, hook := range []string{"OnEstablished", "OnUpdate", "OnKeepalive", "OnStateChange", "OnClose"} {
			if !visited[hook] {
				t.Errorf("%s never fired", hook)
			}
		}
	})
}

// refuseFirstDial is a PeerConfig.DialFunc for newPipeRig which refuses the
// first dial, promptly and deterministically, and lets every later one fall
// through to the rig's pipe.
func refuseFirstDial() func(context.Context) (*Conn, error) {
	var dials int
	return func(context.Context) (*Conn, error) {
		dials++
		if dials == 1 {
			return nil, errors.New("connection refused by test")
		}

		return nil, nil
	}
}

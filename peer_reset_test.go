package bgp

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

// TestPeerResetSessionAdministrativeReset verifies the default reset: a nil
// cause ends the established session with Cease / Administrative Reset, the
// close is reported, and the Peer's retry loop establishes a fresh session —
// the bounce, not a removal.
func TestPeerResetSessionAdministrativeReset(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())

		sess := recv(t, r.estC, "session establishment")
		if sess.LocalAddr == nil || sess.RemoteAddr == nil {
			t.Fatalf("expected session connection addresses, got local %v, remote %v",
				sess.LocalAddr, sess.RemoteAddr)
		}

		if err := r.p.ResetSession(t.Context(), nil); err != nil {
			t.Fatalf("failed to reset session: %v", err)
		}

		want := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeReset,
		}

		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		s.expectClosed()

		// ResetSession is synchronous: the close was reported before it
		// returned.
		var c Close
		select {
		case c = <-r.closeC:
		default:
			t.Fatal("expected the close to be reported before ResetSession returned")
		}

		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !c.Local || !c.Established || c.Err != nil {
			t.Fatalf("expected an established session closed locally without error, got: %+v", c)
		}

		// The peering continues: the next attempt establishes after the
		// idle hold.
		time.Sleep(idleHoldTime)
		s2 := r.acceptScript()
		s2.establish(scriptOpen())
		recv(t, r.estC, "second session establishment")
	})
}

// TestPeerResetSessionBFDDown wires ResetSession the way a BFD-driven caller
// would: OnEstablished starts a watcher bound to the session ctx, and the
// fake BFD session reporting down resets the BGP session with Cease / BFD
// Down (RFC 9384).
func TestPeerResetSessionBFDDown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// The fake BFD session: a real one would run between the session's
		// LocalAddr and RemoteAddr endpoints; the FSM needs only its down
		// signal.
		bfdDownC := make(chan struct{})

		r := newPipeRig(t, PeerConfig{
			OnEstablished: func(ctx context.Context, p *Peer, s Session) error {
				// The watcher runs on its own goroutine, as ResetSession's
				// handler ban requires.
				go func() {
					select {
					case <-bfdDownC:
						cause := &MessageError{
							Code:    NotificationCease,
							Subcode: SubcodeCeaseBFDDown,
						}

						_ = p.ResetSession(ctx, cause)
					case <-ctx.Done():
					}
				}()
				return nil
			},
		})

		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		close(bfdDownC)

		want := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseBFDDown,
		}

		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}
	})
}

// TestPeerIdleHoldAdoptsDeliveredConn verifies the hold's adoption contract:
// a connection
// delivered during the idle hold ends the hold early and seeds the next
// attempt, rather than being answered with Cease / Connection Rejected —
// the escape from the mutual-rejection livelock two speakers whose
// sessions closed together would otherwise alternate into forever.
func TestPeerIdleHoldAdoptsDeliveredConn(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// End the session; the retry loop enters its idle hold.
		if err := r.p.ResetSession(t.Context(), nil); err != nil {
			t.Fatalf("failed to reset session: %v", err)
		}

		_ = s.nextNotification()
		s.expectClosed()
		recv(t, r.closeC, "session close")

		// Mid-hold, the remote's open arrives. Adoption means the next
		// attempt runs it to establishment now, not after the hold.
		time.Sleep(idleHoldTime / 4)
		start := time.Now()
		s2 := r.deliver()
		s2.establish(scriptOpen())
		recv(t, r.estC, "adopted session establishment")

		// Fake time: establishment consumed no clock at all, while
		// waiting out the hold would have consumed most of it.
		if d := time.Since(start); d != 0 {
			t.Fatalf("expected the adopted connection to establish without waiting out the idle hold, took %s", d)
		}
	})
}

// TestPeerResetSessionNotEstablished verifies that a reset with no
// established session reports ErrNotEstablished: a signal racing the
// session's own death is visible but harmless.
func TestPeerResetSessionNotEstablished(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		// The connection is in OpenSent: no session to reset.
		s.expectOpen()
		if err := r.p.ResetSession(t.Context(), nil); !errors.Is(err, ErrNotEstablished) {
			t.Fatalf("expected ErrNotEstablished, got: %v", err)
		}
	})
}

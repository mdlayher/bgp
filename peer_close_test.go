package bgp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// TestPeerCloseLocalWriter pins Close.Local for a transport failure on
// write: a write this speaker's writer gave up on is a local close, and it
// carries no NOTIFICATION.
func TestPeerCloseLocalWriter(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var fw *failWriteConn
		dials := make(chan *script, 1)
		r := newPipeRig(t, PeerConfig{
			DialFunc: func(context.Context) (*Conn, error) {
				local, remote := memPipe()
				fw = &failWriteConn{Conn: local}
				dials <- newScript(t, remote)
				return NewConn(fw), nil
			},
		})

		s := recv(t, dials, "the peer to dial")
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		fw.fail.Store(true)
		update := &Update{NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
		if err := r.p.SendUpdate(context.Background(), update); !errors.Is(err, errInjectedWrite) {
			t.Fatalf("unexpected SendUpdate error: %v", err)
		}

		c := recv(t, r.closeC, "session close")
		if !c.Local || c.Notification != nil || !errors.Is(c.Err, errInjectedWrite) || !c.Established {
			t.Fatalf("unexpected close: %+v", c)
		}

		s.expectClosed()
	})
}

// TestPeerCloseLocalReader pins Close.Local for a transport failure on read:
// a connection the reader found closed is the peer's close, and it carries
// no NOTIFICATION.
func TestPeerCloseLocalReader(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// The peer drops the connection without a word.
		_ = s.nc.Close()

		c := recv(t, r.closeC, "session close")
		if c.Local || c.Notification != nil || c.Err == nil || !c.Established {
			t.Fatalf("unexpected close: %+v", c)
		}
	})
}

// A handler error which coincides with a shutdown does not replace the
// shutdown's farewell with a bare Cease.
//
// The coincidence is a race between the reader and FSM goroutines, and a
// bubble schedules the FSM first every time: this pins the contract, not the
// losing resolution, which no in-process test reaches.
func TestPeerShutdownOutranksHandlerError(t *testing.T) {
	t.Parallel()

	const farewell = "going down for maintenance"

	cause, err := NewShutdownError(SubcodeCeaseAdministrativeShutdown, farewell)
	if err != nil {
		t.Fatalf("failed to build the shutdown error: %v", err)
	}

	synctest.Test(t, func(t *testing.T) {
		// The caller's own shutdown, not the session context: a handler
		// waiting on that could only return after the FSM had acted on it.
		var closed atomic.Bool

		r := newPipeRig(t, PeerConfig{
			ShutdownCommunication: farewell,

			OnEstablished: func(context.Context, *Peer, Session) error {
				if closed.Load() {
					return errors.New("the caller's table is closed")
				}

				return nil
			},
		})

		s := r.acceptScript()
		s.expectOpen()
		s.write(scriptOpen())
		s.expectKeepalive()

		// The confirming KEEPALIVE releases the reader into a handler which
		// refuses as the cancellation reaches the FSM.
		closed.Store(true)
		s.write(&Keepalive{})
		r.cancel()

		if d := diff(t, cause.Notification(), s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		c := recv(t, r.closeC, "session close")
		if d := diff(t, cause.Notification(), c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		// The Close a shutdown alone produces.
		if !c.Local || c.Err != nil {
			t.Fatalf("unexpected close: %+v", c)
		}
	})
}

// A peer still sending when the session ends reads the NOTIFICATION and then
// end of file, and its writes succeed until it closes its own end: the
// teardown half closes and drains rather than resetting the connection. The
// kernel's behavior is the point, so the transport is a real socket. The
// reader drains whether the handler holding it off the socket returns nil or
// the cancellation it obeyed.
func TestPeerCloseDrainsBeforeClosing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  func(ctx context.Context) error
	}{
		{
			name: "handler returns nil",
			err:  func(context.Context) error { return nil },
		},
		{
			name: "handler returns cancellation",
			err:  func(ctx context.Context) error { return ctx.Err() },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			const farewell = "going down for maintenance"

			cause, err := NewShutdownError(SubcodeCeaseAdministrativeShutdown, farewell)
			if err != nil {
				t.Fatalf("failed to build the shutdown error: %v", err)
			}

			entered := make(chan struct{}, 1)

			r := newTCPRig(t, PeerConfig{
				ShutdownCommunication: farewell,

				// Parked on ctx, so the shutdown releases the reader.
				OnKeepalive: func(ctx context.Context, _ *Peer) error {
					// Non-blocking: the handler runs again for the
					// KEEPALIVEs below once ctx is canceled, and only the
					// first entry is awaited.
					select {
					case entered <- struct{}{}:
					default:
					}

					<-ctx.Done()
					return tt.err(ctx)
				},
			})

			s := r.acceptScript()
			s.establish(scriptOpen())
			recv(t, r.estC, "session establishment")

			s.write(&Keepalive{})
			recv(t, entered, "handler entry")

			// Unread at the close: the reader is parked.
			for range 16 {
				s.write(&Keepalive{})
			}

			r.cancel()

			if d := diff(t, cause.Notification(), s.nextNotification()); d != "" {
				t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
			}

			if _, err := s.c.ReadMessage(); !errors.Is(err, io.EOF) {
				t.Fatalf("expected the sending half to close, but got: %v", err)
			}

			// Only writes see a reset: a peer holding this speaker's end of
			// file reads that rather than the reset, but its writes fail.
			for i := range 64 {
				if err := s.c.WriteMessage(&Keepalive{}); err != nil {
					t.Fatalf("failed to write message %d after the NOTIFICATION: %v", i, err)
				}
			}

			// The peer's close ends the drain before its deadline.
			_ = s.nc.Close()

			c := recv(t, r.closeC, "session close")
			if d := diff(t, cause.Notification(), c.Notification); d != "" {
				t.Fatalf("unexpected close notification (-want +got):\n%s", d)
			}

			if !c.Local || c.Err != nil {
				t.Fatalf("unexpected close: %+v", c)
			}
		})
	}
}

// errInjectedWrite is the error a failing failWriteConn returns.
var errInjectedWrite = errors.New("injected write failure")

// A failWriteConn is a net.Conn whose writes fail on demand, so a test can
// make this speaker's writer give up on a transport the peer still holds
// open.
type failWriteConn struct {
	net.Conn
	fail atomic.Bool
}

func (c *failWriteConn) Write(p []byte) (int, error) {
	if c.fail.Load() {
		return 0, errInjectedWrite
	}

	return c.Conn.Write(p)
}

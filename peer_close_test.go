package bgp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// A failWriteConn is a net.Conn whose writes fail on demand, so a test can
// make this speaker's writer give up on a transport the peer still holds
// open.
type failWriteConn struct {
	net.Conn
	fail atomic.Bool
}

var errInjectedWrite = errors.New("injected write failure")

func (c *failWriteConn) Write(p []byte) (int, error) {
	if c.fail.Load() {
		return 0, errInjectedWrite
	}

	return c.Conn.Write(p)
}

// TestPeerCloseLocal pins Close.Local for the two transport failures a
// session can end with: a write this speaker's writer gave up on is a local
// close, and a connection the reader found closed is the peer's. Neither
// carries a NOTIFICATION.
func TestPeerCloseLocal(t *testing.T) {
	t.Parallel()

	t.Run("writer", func(t *testing.T) {
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
	})

	t.Run("reader", func(t *testing.T) {
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
	})
}

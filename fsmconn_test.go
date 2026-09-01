package bgp

import (
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// TestFSMConnKillJoinsReader enforces the invariant attempt.event and
// attempt.established rest on: kill returns only after the connection's
// reader goroutine has exited, so a killed connection never has an event in
// flight once it is untracked, and no identity guard is needed on eventC.
//
// The ordering is checked deterministically under synctest: the reader is
// held hostage inside Read after the close, so kill can only be either
// blocked on its join or — the defect — already returned, and Wait settles
// which before the hostage is released.
func TestFSMConnKillJoinsReader(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := must(NewFSM(FSMConfig{
			LocalASN: 64496,
			LocalID:  MustParseIdentifier("192.0.2.1"),
			Passive:  true,
		}))

		hc := newHostageConn()
		eventC := make(chan connEvent)
		fc := f.newFSMConn(NewConn(hc), originAccepted, eventC)

		// kill runs where the FSM goroutine would, with nothing receiving
		// on eventC, exactly as in attempt.
		killed := make(chan struct{})
		go func() {
			fc.kill()
			close(killed)
		}()

		// Every goroutine is now durably blocked: the reader inside Read,
		// past the close but before the release, and kill on its join —
		// or, if kill does not join, nowhere, having returned.
		synctest.Wait()
		select {
		case <-killed:
			t.Fatal("kill returned before the reader goroutine exited")
		default:
		}

		// Release the reader: its failed read forwards a terminal event,
		// which the closed fsmDone abandons, and it exits. A kill which did
		// not join cannot reach here; one which did now returns.
		close(hc.release)
		<-killed

		select {
		case <-fc.readerDone:
		default:
			t.Fatal("kill returned without the reader goroutine having exited")
		}

		// The reader is gone, so a non-blocking receive is conclusive: no
		// event from the killed connection is, or can ever be, in flight.
		select {
		case ev := <-eventC:
			t.Fatalf("event forwarded from a killed connection: %+v", ev)
		default:
		}
	})
}

// A hostageConn is a net.Conn whose Read blocks until Close, and then until
// the test releases it: it holds a reader goroutine inside Read so a test can
// observe what its owner does while the reader has not yet exited.
type hostageConn struct {
	closed, release chan struct{}
	once            sync.Once
}

func newHostageConn() *hostageConn {
	return &hostageConn{
		closed:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (c *hostageConn) Read([]byte) (int, error) {
	<-c.closed
	<-c.release
	return 0, net.ErrClosed
}

func (c *hostageConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *hostageConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (*hostageConn) LocalAddr() net.Addr              { return nil }
func (*hostageConn) RemoteAddr() net.Addr             { return nil }
func (*hostageConn) SetDeadline(time.Time) error      { return nil }
func (*hostageConn) SetReadDeadline(time.Time) error  { return nil }
func (*hostageConn) SetWriteDeadline(time.Time) error { return nil }

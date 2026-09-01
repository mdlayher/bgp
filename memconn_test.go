package bgp

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// memPipe returns the two ends of an in-memory connection for synctest
// bubbles. Unlike net.Pipe, a memConn buffers without bound, as loopback TCP
// effectively does at test sizes: a write completes at once, so an FSM
// keepalive written while the scripted side is mid-Sleep never blocks the
// writer and distorts the timing under test. Reads block on channels, so a
// bubble sees them as durably blocked and fake time advances across them.
//
// Read deadlines are honored; writes never block, so write deadlines never
// bite. Kernel behaviors — socket buffers filling, resets — are what the
// real-socket tests are for.
func memPipe() (a, b *memConn) {
	ab, ba := newMemBuf(), newMemBuf()
	return &memConn{in: ab, out: ba, done: make(chan struct{})},
		&memConn{in: ba, out: ab, done: make(chan struct{})}
}

// A memConn is one end of a memPipe: it reads from in and writes to out.
type memConn struct {
	in, out *memBuf

	// done closes on Close, unblocking this end's pending reads.
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

// A memBuf is one origin of a memPipe: bytes appended by the writer and
// consumed by the reader. ready is replaced and the old one closed on every
// change, a broadcast to a waiting reader.
type memBuf struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
	ready  chan struct{}
}

func newMemBuf() *memBuf { return &memBuf{ready: make(chan struct{})} }

func (b *memBuf) signal() {
	close(b.ready)
	b.ready = make(chan struct{})
}

func (c *memConn) Read(p []byte) (int, error) {
	for {
		c.in.mu.Lock()
		if n := copy(p, c.in.buf); n > 0 {
			c.in.buf = c.in.buf[n:]
			c.in.mu.Unlock()
			return n, nil
		}

		if c.in.closed {
			c.in.mu.Unlock()
			return 0, io.EOF
		}

		ready := c.in.ready
		c.in.mu.Unlock()

		// The deadline is re-read on every wakeup, so SetReadDeadline's
		// nudge applies it to a read already in progress.
		var (
			timer   *time.Timer
			timeout <-chan time.Time
		)

		c.mu.Lock()
		if d := c.deadline; !d.IsZero() {
			timer = time.NewTimer(time.Until(d))
			timeout = timer.C
		}

		c.mu.Unlock()

		var err error
		select {
		case <-ready:
		case <-timeout:
			err = os.ErrDeadlineExceeded
		case <-c.done:
			err = net.ErrClosed
		}

		if timer != nil {
			timer.Stop()
		}

		if err != nil {
			return 0, err
		}
	}
}

func (c *memConn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}

	c.out.mu.Lock()
	defer c.out.mu.Unlock()
	if c.out.closed {
		return 0, io.ErrClosedPipe
	}

	c.out.buf = append(c.out.buf, p...)
	c.out.signal()
	return len(p), nil
}

// Close ends both directions: this end's reads fail at once, and the other
// end reads EOF once it has drained what was written.
func (c *memConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		for _, b := range []*memBuf{c.out, c.in} {
			b.mu.Lock()
			b.closed = true
			b.signal()
			b.mu.Unlock()
		}
	})
	return nil
}

func (c *memConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	// A pending read re-evaluates its deadline on the next wakeup: nudge it.
	c.in.mu.Lock()
	c.in.signal()
	c.in.mu.Unlock()
	return nil
}

// SetWriteDeadline is a no-op: writes never block.
func (*memConn) SetWriteDeadline(time.Time) error { return nil }

// A memConn carries no address, so Peer applies no remote-address check to
// a delivered one, exactly as for any non-TCP transport.
func (*memConn) LocalAddr() net.Addr  { return memAddr{} }
func (*memConn) RemoteAddr() net.Addr { return memAddr{} }

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

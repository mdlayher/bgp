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
// bite. Kernel behaviors, such as socket buffers filling or resets, are what
// the real-socket tests are for.
func memPipe() (a, b *memConn) {
	ab, ba := newMemBuf(), newMemBuf()
	a = &memConn{
		in:   ab,
		out:  ba,
		done: make(chan struct{}),
	}

	b = &memConn{
		in:   ba,
		out:  ab,
		done: make(chan struct{}),
	}

	return a, b
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

// read copies buffered bytes into p. When none are buffered and the writer
// has not closed, it returns the channel which closes on the next change.
func (b *memBuf) read(p []byte) (int, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if n := copy(p, b.buf); n > 0 {
		b.buf = b.buf[n:]
		return n, nil, nil
	}

	if b.closed {
		return 0, nil, io.EOF
	}

	return 0, b.ready, nil
}

// write appends p for the reader.
func (b *memBuf) write(p []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return io.ErrClosedPipe
	}

	b.buf = append(b.buf, p...)
	b.signalLocked()
	return nil
}

// close marks the buffer closed and wakes a waiting reader.
func (b *memBuf) close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.closed = true
	b.signalLocked()
}

// nudge wakes a waiting reader without a change to the buffer.
func (b *memBuf) nudge() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.signalLocked()
}

// signalLocked broadcasts a change to a waiting reader. b.mu must be held.
func (b *memBuf) signalLocked() {
	close(b.ready)
	b.ready = make(chan struct{})
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

func (c *memConn) Read(p []byte) (int, error) {
	for {
		n, ready, err := c.in.read(p)
		if n > 0 || err != nil {
			return n, err
		}

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

	if err := c.out.write(p); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close ends both directions: this end's reads fail at once, and the other
// end reads EOF once it has drained what was written.
func (c *memConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.out.close()
		c.in.close()
	})
	return nil
}

func (c *memConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	// A pending read re-evaluates its deadline on the next wakeup: nudge it.
	c.in.nudge()
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

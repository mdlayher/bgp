package bgp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// readBufferSize is the size in bytes of a Conn's buffered reader. BGP's hot
// path is initial convergence, where many UPDATE messages arrive in each TCP
// segment, so a large buffer amortizes read syscalls across messages. It is
// far larger than MaxMessageSize, so any single message can always be
// buffered in its entirety.
const readBufferSize = 64 * 1024

// A Conn sends and receives BGP messages over an underlying connection.
//
// Conn only frames messages on and off the connection. It implements no
// protocol logic: no timers, no session state, no replies on the caller's
// behalf.
//
// As with net.Conn, one goroutine may read and one may write, concurrently.
type Conn struct {
	// c is the underlying connection, whose methods are all safe for
	// concurrent use.
	c net.Conn

	// rmu guards the read side, and wmu the write side, so that a reader and
	// a writer may proceed concurrently.
	rmu sync.Mutex
	br  *bufio.Reader

	wmu sync.Mutex
	wb  []byte

	// tap, when set, observes every framed message in both directions;
	// see FSMConfig.OnMessage. It is installed once, under both locks, by
	// the FSM which adopts the Conn.
	tap func(MessageEvent)
}

// NewConn creates a Conn which sends and receives BGP messages over c, which
// may be any net.Conn. For the TCP socket options a BGP speaker typically
// needs, such as TCP-MD5 or GTSM, use Dialer or ListenConfig instead.
func NewConn(c net.Conn) *Conn {
	return &Conn{
		c:  c,
		br: bufio.NewReaderSize(c, readBufferSize),
		wb: make([]byte, 0, MaxMessageSize),
	}
}

// setTap installs the message tap. It takes both locks so a concurrent
// reader or writer sees the tap on its next message, never a torn store.
func (c *Conn) setTap(tap func(MessageEvent)) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.tap = tap
}

// observeLocked reports one framed message to the tap, if any. The caller
// must hold rmu or wmu: setTap takes both, so a locked read of c.tap is
// never torn. Raw is lent for the duration of the call: on the read side it
// is the buffered reader's memory, on the write side the reused write
// buffer.
func (c *Conn) observeLocked(dir Direction, raw []byte, m Message, err error) {
	if c.tap == nil {
		return
	}

	c.tap(MessageEvent{
		Direction:  dir,
		Raw:        raw,
		Message:    m,
		Err:        err,
		LocalAddr:  c.c.LocalAddr(),
		RemoteAddr: c.c.RemoteAddr(),
	})
}

// ReadMessage reads the next Message, blocking until a complete message
// arrives, the read deadline expires, or an error occurs.
//
// Like bufio.Scanner, ReadMessage returns values which reference an internal
// buffer: the Message, and every byte slice reachable from it, are valid
// only until the next call. To retain data longer, copy it; see
// ParseMessage.
//
// A malformed message produces a *MessageError describing the Notification
// RFC 4271 requires in response, and is not consumed: the Conn is no longer
// synchronized with its peer and must be closed.
//
// A connection closed by the peer between messages produces io.EOF; one
// closed mid-message produces io.ErrUnexpectedEOF.
func (c *Conn) ReadMessage() (Message, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	// Frame directly out of the buffered reader: Peek a header, Peek the
	// complete message the header describes, then Discard it. Nothing is
	// copied between the reader's buffer and the parsed Message.
	h, err := c.br.Peek(headerLen)
	if err != nil {
		if len(h) > 0 && errors.Is(err, io.EOF) {
			// A truncated header is not a clean end of stream.
			err = io.ErrUnexpectedEOF
		}

		return nil, err
	}

	length := int(binary.BigEndian.Uint16(h[markerLen : markerLen+2]))
	if length < headerLen || length > MaxMessageSize {
		// The length field cannot describe a message, so there is nothing to
		// consume: framing is lost and the caller must close the connection.
		// The header is the whole frame the tap can be shown.
		err := headerError(SubcodeBadMessageLength, h[markerLen:markerLen+2],
			"message length %d is not between %d and %d bytes",
			length, headerLen, MaxMessageSize)
		c.observeLocked(DirectionReceived, h, nil, err)
		return nil, err
	}

	b, err := c.br.Peek(length)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}

		return nil, err
	}

	// ParseMessage validates the marker and length again. The duplicated work
	// is cheap, and keeps ParseMessage the package's only parser.
	m, err := ParseMessage(b)
	c.observeLocked(DirectionReceived, b, m, err)
	if err != nil {
		return nil, err
	}

	if _, err := c.br.Discard(length); err != nil {
		return nil, err
	}

	return m, nil
}

// WriteMessage writes m in a single write, blocking until the write
// completes, the write deadline expires, or an error occurs.
//
// A marshal failure is returned wrapped, so errors.Is and errors.As reach
// the original error; no byte reaches the connection.
func (c *Conn) WriteMessage(m Message) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	// Marshal into the reused write buffer, retaining any capacity it gained.
	b, err := m.AppendBinary(c.wb[:0])
	if err != nil {
		return &marshalError{err: err}
	}

	c.wb = b

	_, err = c.c.Write(b)
	c.observeLocked(DirectionSent, b, m, err)
	return err
}

// SetDeadline implements the net.Conn method of the same name.
func (c *Conn) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

// SetReadDeadline implements the net.Conn method of the same name. It bounds
// the time spent in ReadMessage.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

// SetWriteDeadline implements the net.Conn method of the same name. It bounds
// the time spent in WriteMessage.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }

// LocalAddr returns the local network address of the connection.
func (c *Conn) LocalAddr() net.Addr { return c.c.LocalAddr() }

// RemoteAddr returns the remote network address of the connection.
func (c *Conn) RemoteAddr() net.Addr { return c.c.RemoteAddr() }

// Close closes the connection. Any blocked ReadMessage or WriteMessage call
// is unblocked and returns an error.
func (c *Conn) Close() error { return c.c.Close() }

// A marshalError wraps a message marshal failure from WriteMessage: the
// message never reached the connection, so the failure belongs to the
// message's producer and says nothing about the connection's health. The
// session writer classifies errors by this origin, not by error type.
type marshalError struct{ err error }

func (e *marshalError) Error() string { return e.err.Error() }
func (e *marshalError) Unwrap() error { return e.err }

// isMarshalError reports whether err is a caller's marshal failure rather
// than a connection write failure: a failed marshal belongs to the caller
// and leaves the session healthy, while a failed write is terminal.
// Classification is by origin, via marshalError, so a custom transport's
// write errors are terminal whether or not they implement net.Error.
func isMarshalError(err error) bool {
	_, ok := errors.AsType[*marshalError](err)
	return ok
}

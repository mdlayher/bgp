package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

func TestConnRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    Message
	}{
		{
			name: "keepalive",
			m:    &Keepalive{},
		},
		{
			name: "open",
			m: &Open{
				ASN:      65536,
				HoldTime: 90 * time.Second,
				ID:       MustParseIdentifier("192.0.2.1"),
				Capabilities: []Capability{
					MultiprotocolCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
					MultiprotocolCapability(Family{AFI: AFIIPv6, SAFI: SAFIUnicast}),
					{Code: CapabilityRouteRefresh},
				},
			},
		},
		{
			name: "update IPv4",
			m: &Update{
				Withdrawn: []netip.Prefix{
					netip.MustParsePrefix("198.51.100.0/24"),
				},
				Attributes: mustAttributes(
					t,
					OriginIGP,
					ASPath{{ASNs: []uint32{64496, 64497}}},
					NextHop(netip.MustParseAddr("192.0.2.1")),
					MED(100),
					Communities{NewCommunity(64496, 1)},
				),
				NLRI: []netip.Prefix{
					netip.MustParsePrefix("203.0.113.0/24"),
					netip.MustParsePrefix("192.0.2.0/25"),
				},
			},
		},
		{
			name: "update multiprotocol",
			m: &Update{
				Attributes: mustAttributes(
					t,
					OriginIGP,
					ASPath{{ASNs: []uint32{64496}}},
					MPReachNLRI{
						Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
						NextHop: netip.MustParseAddr("2001:db8::1"),
						NLRI: Prefixes{
							netip.MustParsePrefix("2001:db8:1::/48"),
						},
					},
					MPUnreachNLRI{
						Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
						NLRI: Prefixes{
							netip.MustParsePrefix("2001:db8:2::/48"),
						},
					},
				),
			},
		},
		{
			name: "update end-of-RIB",
			m:    &Update{},
		},
		{
			name: "notification",
			m: &Notification{
				Code:    NotificationMessageHeaderError,
				Subcode: SubcodeBadMessageLength,
				Data:    []byte{0xff, 0xff},
			},
		},
		{
			name: "notification no data",
			m: &Notification{
				Code:    NotificationCease,
				Subcode: 2,
			},
		},
		{
			name: "route refresh",
			m: &RouteRefresh{
				Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
			},
		},
	}

	for _, network := range localNetworks(t) {
		t.Run(network, func(t *testing.T) {
			t.Parallel()

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()

					client, server := testConns(t, network)

					if err := client.WriteMessage(tt.m); err != nil {
						t.Fatalf("failed to write message: %v", err)
					}

					got, err := server.ReadMessage()
					if err != nil {
						t.Fatalf("failed to read message: %v", err)
					}

					if d := diff(t, tt.m, got); d != "" {
						t.Fatalf("unexpected message (-want +got):\n%s", d)
					}

					// The read message must also re-marshal to the same bytes
					// which were placed on the wire.
					wantB, err := tt.m.AppendBinary(nil)
					if err != nil {
						t.Fatalf("failed to marshal want: %v", err)
					}

					gotB, err := got.AppendBinary(nil)
					if err != nil {
						t.Fatalf("failed to marshal got: %v", err)
					}

					if d := diff(t, wantB, gotB); d != "" {
						t.Fatalf("unexpected message bytes (-want +got):\n%s", d)
					}
				})
			}
		})
	}
}

func TestConnReadMessageBurst(t *testing.T) {
	t.Parallel()

	// Many small messages written back to back exercise the buffered framing
	// path: several messages typically arrive in a single TCP segment.
	const n = 64

	want := make([]Message, 0, n)
	for i := range n {
		want = append(want, &Notification{
			Code:    NotificationCease,
			Subcode: uint8(i),
			Data:    bytes.Repeat([]byte{byte(i)}, i),
		})
	}

	want = append(want, &Keepalive{})

	client, server := testConns(t, "tcp")

	errC := make(chan error, 1)
	go func() {
		for _, m := range want {
			if err := client.WriteMessage(m); err != nil {
				errC <- err
				return
			}
		}

		errC <- nil
	}()

	got := make([]Message, 0, len(want))
	for range want {
		m, err := server.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read message: %v", err)
		}

		// The returned Message is only valid until the next ReadMessage
		// call, so retain a copy instead.
		got = append(got, detachMessage(t, m))
	}

	if err := <-errC; err != nil {
		t.Fatalf("failed to write messages: %v", err)
	}

	if d := diff(t, want, got); d != "" {
		t.Fatalf("unexpected messages (-want +got):\n%s", d)
	}
}

func TestConnReadMessageErrors(t *testing.T) {
	t.Parallel()

	// header produces a BGP message header with the given wire length and
	// type, without regard for whether either is valid.
	header := func(length uint16, typ MessageType) []byte {
		b := bytes.Repeat([]byte{0xff}, markerLen)
		b = binary.BigEndian.AppendUint16(b, length)
		return append(b, byte(typ))
	}

	tests := []struct {
		name    string
		b       []byte
		code    NotificationCode
		subcode uint8
		data    []byte
	}{
		{
			name:    "length too short",
			b:       header(headerLen-1, MessageTypeKeepalive),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, 0x12},
		},
		{
			name:    "length zero",
			b:       header(0, MessageTypeKeepalive),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, 0x00},
		},
		{
			name:    "length too long",
			b:       header(MaxMessageSize+1, MessageTypeKeepalive),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x10, 0x01},
		},
		{
			name: "bad marker",
			b: append(
				append(bytes.Repeat([]byte{0xff}, markerLen-1), 0x00),
				0x00, headerLen, byte(MessageTypeKeepalive),
			),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeConnectionNotSynchronized,
		},
		{
			name:    "unknown message type",
			b:       header(headerLen, 0xff),
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageType,
			data:    []byte{0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, server := testConns(t, "tcp")

			if _, err := client.rawConn().Write(tt.b); err != nil {
				t.Fatalf("failed to write bytes: %v", err)
			}

			_, err := server.ReadMessage()

			merr, ok := errors.AsType[*MessageError](err)
			if !ok {
				t.Fatalf("expected *MessageError, but got: %v", err)
			}

			if d := diff(t, tt.code, merr.Code); d != "" {
				t.Fatalf("unexpected NOTIFICATION code (-want +got):\n%s", d)
			}

			if d := diff(t, tt.subcode, merr.Subcode); d != "" {
				t.Fatalf("unexpected NOTIFICATION subcode (-want +got):\n%s", d)
			}

			if d := diff(t, tt.data, merr.Data); d != "" {
				t.Fatalf("unexpected NOTIFICATION data (-want +got):\n%s", d)
			}

			// The error must describe a Notification the caller can send
			// verbatim, and must remain intact after the read buffer moves on.
			n := merr.Notification()
			want := &Notification{Code: tt.code, Subcode: tt.subcode, Data: tt.data}
			if d := diff(t, want, n); d != "" {
				t.Fatalf("unexpected Notification (-want +got):\n%s", d)
			}
		})
	}
}

func TestConnReadMessageEOF(t *testing.T) {
	t.Parallel()

	keepalive, err := (&Keepalive{}).AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal KEEPALIVE: %v", err)
	}

	tests := []struct {
		name string
		b    []byte
		err  error
	}{
		{
			name: "clean close",
			err:  io.EOF,
		},
		{
			name: "partial header",
			b:    keepalive[:markerLen],
			err:  io.ErrUnexpectedEOF,
		},
		{
			name: "partial body",
			// A NOTIFICATION header which promises more body than arrives.
			b: append(
				append(bytes.Repeat([]byte{0xff}, markerLen), 0x00, 0x20),
				byte(MessageTypeNotification), 0x06, 0x02,
			),
			err: io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, server := testConns(t, "tcp")

			if len(tt.b) > 0 {
				if _, err := client.rawConn().Write(tt.b); err != nil {
					t.Fatalf("failed to write bytes: %v", err)
				}
			}

			if err := client.Close(); err != nil {
				t.Fatalf("failed to close client: %v", err)
			}

			if _, err := server.ReadMessage(); !errors.Is(err, tt.err) {
				t.Fatalf("expected %v, but got: %v", tt.err, err)
			}
		})
	}
}

func TestConnReadMessageDeadline(t *testing.T) {
	t.Parallel()

	_, server := testConns(t, "tcp")

	if err := server.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}

	_, err := server.ReadMessage()

	if nerr, ok := errors.AsType[net.Error](err); !ok || !nerr.Timeout() {
		t.Fatalf("expected timeout error, but got: %v", err)
	}

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded, but got: %v", err)
	}

	// Clearing the deadline must return the Conn to service.
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("failed to clear read deadline: %v", err)
	}
}

func TestConnReadMessageDribble(t *testing.T) {
	t.Parallel()

	want := &Update{
		Attributes: mustAttributes(
			t,
			OriginIGP,
			ASPath{{ASNs: []uint32{64496, 64497, 64498}}},
			NextHop(netip.MustParseAddr("192.0.2.1")),
		),
		NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}

	b, err := want.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal UPDATE: %v", err)
	}

	// A synchronous in-memory pipe rather than testConns: each Write
	// rendezvouses with a Read, so the reader is guaranteed to observe the
	// message in fragments. Real TCP can coalesce the chunks in the kernel
	// no matter how the writer paces them.
	peer, nc := net.Pipe()
	server := NewConn(nc)
	t.Cleanup(func() {
		_ = peer.Close()
		_ = server.Close()
	})

	// Bound both sides so a reassembly bug fails fast instead of wedging.
	deadline := time.Now().Add(5 * time.Second)
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatalf("failed to set peer deadline: %v", err)
	}

	if err := server.SetReadDeadline(deadline); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}

	errC := make(chan error, 1)
	go func() {
		// Dribble the message onto the wire so that it can never arrive in a
		// single read.
		for i := 0; i < len(b); i += 3 {
			end := min(i+3, len(b))
			if _, err := peer.Write(b[i:end]); err != nil {
				errC <- err
				return
			}
		}

		errC <- nil
	}()

	got, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}

	if err := <-errC; err != nil {
		t.Fatalf("failed to write message: %v", err)
	}

	if d := diff[Message](t, want, got); d != "" {
		t.Fatalf("unexpected message (-want +got):\n%s", d)
	}
}

func TestConnReadMessageZeroCopy(t *testing.T) {
	t.Parallel()

	first := &Notification{
		Code:    NotificationCease,
		Subcode: 2,
		Data:    []byte("first message diagnostic data"),
	}

	second := &Notification{
		Code:    NotificationCease,
		Subcode: 3,
		Data:    []byte("second message diagnostic data"),
	}

	client, server := testConns(t, "tcp")

	fb, err := first.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal NOTIFICATION: %v", err)
	}

	if _, err := client.rawConn().Write(fb); err != nil {
		t.Fatalf("failed to write bytes: %v", err)
	}

	// Peek the complete message so that the read buffer holds it and cannot
	// slide underneath the parsed Message, then capture a view of the buffer
	// which the parsed Notification must alias.
	buf, err := server.br.Peek(len(fb))
	if err != nil {
		t.Fatalf("failed to peek: %v", err)
	}

	view := buf[headerLen+2:]

	m, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}

	n, ok := m.(*Notification)
	if !ok {
		t.Fatalf("expected *Notification, but got: %T", m)
	}

	if d := diff(t, first, n); d != "" {
		t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
	}

	// Within its validity window, Data is a view of the Conn's read buffer
	// rather than a copy of it.
	if len(n.Data) == 0 || &view[0] != &n.Data[0] {
		t.Fatal("Notification.Data does not alias the Conn read buffer")
	}

	if len(n.Data) != cap(n.Data) {
		t.Fatalf("Notification.Data is not bounded to the message: len=%d, cap=%d",
			len(n.Data), cap(n.Data))
	}

	// Callers which retain data past that window must copy it. Verify the
	// copy survives a subsequent read, which is the contract Conn documents.
	retained := bytes.Clone(n.Data)

	sb, err := second.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal NOTIFICATION: %v", err)
	}

	if _, err := client.rawConn().Write(sb); err != nil {
		t.Fatalf("failed to write bytes: %v", err)
	}

	m, err = server.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message: %v", err)
	}

	if d := diff[Message](t, second, m); d != "" {
		t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
	}

	if d := diff(t, first.Data, retained); d != "" {
		t.Fatalf("unexpected retained data (-want +got):\n%s", d)
	}
}

func TestConnWriteMessageBufferReuse(t *testing.T) {
	t.Parallel()

	client, server := testConns(t, "tcp")

	// A large message followed by a small one must not leak bytes of the
	// former into the latter through the reused write buffer.
	big := &Notification{
		Code: NotificationCease,
		Data: bytes.Repeat([]byte{0xaa}, 1024),
	}

	small := &Notification{Code: NotificationCease, Subcode: 1}

	for _, want := range []Message{big, small, big} {
		if err := client.WriteMessage(want); err != nil {
			t.Fatalf("failed to write message: %v", err)
		}

		got, err := server.ReadMessage()
		if err != nil {
			t.Fatalf("failed to read message: %v", err)
		}

		if d := diff(t, want, got); d != "" {
			t.Fatalf("unexpected message (-want +got):\n%s", d)
		}
	}
}

func TestConnWriteMessageError(t *testing.T) {
	t.Parallel()

	client, _ := testConns(t, "tcp")

	// An unmarshalable message must not reach the wire.
	if err := client.WriteMessage(&Open{HoldTime: 1 * time.Second}); err == nil {
		t.Fatal("expected an error, but none occurred")
	}
}

func FuzzReadMessage(f *testing.F) {
	// Seed with a valid encoding of every message type, so the fuzzer starts
	// from well-formed framing and mutates outward.
	seeds := []Message{
		&Keepalive{},
		&Open{
			ASN:      64496,
			HoldTime: 90 * time.Second,
			ID:       MustParseIdentifier("192.0.2.1"),
			Capabilities: []Capability{
				MultiprotocolCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
			},
		},
		&Update{
			Withdrawn:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Attributes: mustAttributes(f, OriginIGP, ASPath{{ASNs: []uint32{64496}}}),
			NLRI:       []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		},
		&Notification{Code: NotificationCease, Subcode: 2, Data: []byte{0x01}},
		&RouteRefresh{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}},
	}

	var all []byte
	for _, m := range seeds {
		b, err := m.AppendBinary(nil)
		if err != nil {
			f.Fatalf("failed to marshal seed: %v", err)
		}

		f.Add(b)
		all = append(all, b...)
	}

	// Several back to back messages exercise the framing loop itself.
	f.Add(all)

	f.Fuzz(func(t *testing.T, b []byte) {
		// Cap the input so a single iteration stays fast: framing is fully
		// exercised well below this bound, and an enormous input of valid
		// messages only spends wall clock re-reading them.
		if len(b) > 16*MaxMessageSize {
			t.Skip("input too large")
		}

		// An in-memory pipe rather than real TCP: the fuzzer runs one worker
		// per CPU, and the resulting loopback connection churn stalls dials
		// for long enough to be misreported as a hang. Kernel buffering
		// behavior is covered by the Conn tests instead.
		peer, c := net.Pipe()
		defer func() { _ = peer.Close() }()
		defer func() { _ = c.Close() }()

		// Both sides are bounded so a pathological input cannot stall an
		// iteration.
		deadline := time.Now().Add(5 * time.Second)
		if err := peer.SetDeadline(deadline); err != nil {
			t.Fatalf("failed to set peer deadline: %v", err)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Errors are irrelevant: the reader may stop at any point.
			// Closing the write side delivers EOF to the reader.
			_, _ = peer.Write(b)
			_ = peer.Close()
		}()

		conn := NewConn(c)
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatalf("failed to set read deadline: %v", err)
		}

		for {
			m, err := conn.ReadMessage()
			if err != nil {
				// Any error ends the stream: ReadMessage never consumes a
				// message it could not parse, so retrying would loop forever.
				break
			}

			if m == nil {
				t.Fatal("nil Message with nil error")
			}

			// Marshaling a parsed Message must not panic either, and is the
			// cheapest way to touch every field the parser produced.
			if _, err := m.AppendBinary(nil); err != nil {
				continue
			}
		}

		// The reader may stop mid-stream, leaving the writer blocked on the
		// unbuffered pipe; closing the read side unblocks it.
		_ = c.Close()
		<-done
	})
}

// BenchmarkConnReadMessage frames and parses an entire route collector
// updates file through a Conn: the receive path of initial convergence. The
// underlying connection replays the stream from memory, so the benchmark
// measures framing and parsing rather than the kernel.
func BenchmarkConnReadMessage(b *testing.B) {
	msgs := corpusMessages(b)

	var stream []byte
	for _, m := range msgs {
		stream = append(stream, m...)
	}

	b.SetBytes(int64(len(stream)))
	b.ReportAllocs()

	c := NewConn(&replayConn{b: stream})
	for b.Loop() {
		for range msgs {
			if _, err := c.ReadMessage(); err != nil {
				b.Fatalf("failed to read message: %v", err)
			}
		}
	}
}

func TestTCPOptionsCheck(t *testing.T) {
	t.Parallel()

	// Validation precedes any socket, so neither Dial nor Listen needs one
	// to fail, and the remote address is never contacted.
	raddr := netip.MustParseAddrPort("127.0.0.1:179")

	tests := []struct {
		name string
		o    TCPOptions
	}{
		{
			// The code point is six bits wide.
			name: "DSCP too large",
			o:    TCPOptions{DSCP: maxDSCP + 1},
		},
		{
			name: "negative user timeout",
			o:    TCPOptions{UserTimeout: -time.Second},
		},
		{
			// The kernel counts milliseconds in 32 bits.
			name: "user timeout too large",
			o:    TCPOptions{UserTimeout: maxUserTimeout + time.Millisecond},
		},
		{
			name: "negative send buffer",
			o:    TCPOptions{SendBuffer: -1},
		},
		{
			name: "negative receive buffer",
			o:    TCPOptions{RecvBuffer: -1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := &Dialer{TCPOptions: tt.o}
			if _, err := d.Dial(context.Background(), raddr.Addr()); err == nil {
				t.Fatal("expected an error from Dial, but none occurred")
			}

			lc := &ListenConfig{TCPOptions: tt.o}
			if _, err := lc.Listen(context.Background(), raddr); err == nil {
				t.Fatal("expected an error from Listen, but none occurred")
			}
		})
	}
}

func TestListenerExplicitBind(t *testing.T) {
	t.Parallel()

	// A Listener is always bound to exactly one address family, so its socket
	// options apply to every connection it accepts: the zero Addr is rejected
	// rather than producing a dual-stack wildcard listener.
	if _, err := (&ListenConfig{}).Listen(context.Background(), netip.AddrPort{}); err == nil {
		t.Fatal("expected an error, but none occurred")
	}

	// The family wildcard listens on every IPv4 address, and a port of zero
	// selects an ephemeral port, which Addr reports.
	l, err := (&ListenConfig{}).Listen(
		context.Background(),
		netip.AddrPortFrom(netip.IPv4Unspecified(), 0),
	)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	defer func() { _ = l.Close() }()

	type accepted struct {
		c   *Conn
		err error
	}

	acceptC := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptC <- accepted{c: c, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := dialAddrPort(ctx, &Dialer{}, netip.AddrPortFrom(
		netip.MustParseAddr("127.0.0.1"), listenerAddrPort(t, l).Port(),
	))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	defer func() { _ = client.Close() }()

	a := <-acceptC
	if a.err != nil {
		t.Fatalf("failed to accept: %v", a.err)
	}

	defer func() { _ = a.c.Close() }()

	if err := client.WriteMessage(&Keepalive{}); err != nil {
		t.Fatalf("failed to write KEEPALIVE: %v", err)
	}

	if _, err := a.c.ReadMessage(); err != nil {
		t.Fatalf("failed to read KEEPALIVE: %v", err)
	}
}

// TestListenerMD5Arguments verifies the argument checks shared by every
// platform: they precede the socket option, so they apply even where TCP-MD5
// itself is unsupported.
func TestListenerMD5Arguments(t *testing.T) {
	t.Parallel()

	l, err := (&ListenConfig{}).Listen(context.Background(), netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	t.Cleanup(func() { _ = l.Close() })

	// An empty password is not a removal: RemoveMD5 is.
	if err := l.SetMD5(netip.MustParseAddr("192.0.2.1"), ""); err == nil {
		t.Fatal("expected an error for an empty password, but none occurred")
	}

	if err := l.SetMD5(netip.Addr{}, "password"); err == nil {
		t.Fatal("expected an error for an invalid address, but none occurred")
	}

	if err := l.RemoveMD5(netip.Addr{}); err == nil {
		t.Fatal("expected an error for an invalid address, but none occurred")
	}
}

// dialAddrPort dials ap with d: the Dialer's Port is ap's, so a test reaches
// an ephemeral listener port while Dial itself takes only an address.
func dialAddrPort(ctx context.Context, d *Dialer, ap netip.AddrPort) (*Conn, error) {
	dd := *d
	dd.Port = ap.Port()
	return dd.Dial(ctx, ap.Addr())
}

// replayConn is a net.Conn which serves an in-memory byte stream on repeat,
// so a benchmark measures Conn framing rather than kernel behavior.
type replayConn struct {
	b   []byte
	off int
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.off == len(c.b) {
		c.off = 0
	}

	n := copy(p, c.b[c.off:])
	c.off += n
	return n, nil
}

func (c *replayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return nil }
func (c *replayConn) RemoteAddr() net.Addr             { return nil }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

// listenerAddrPort returns the address a Listener is bound to.
func listenerAddrPort(tb testing.TB, l *Listener) netip.AddrPort {
	tb.Helper()

	a, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		tb.Fatalf("unexpected listener address type: %T", l.Addr())
	}

	return a.AddrPort()
}

// localNetworks returns the TCP network variants this host supports: IPv4
// loopback always, plus IPv6 when available, so tests exercise both address
// families.
func localNetworks(tb testing.TB) []string {
	tb.Helper()

	networks := []string{"tcp4"}
	if nettest.SupportsIPv6() {
		networks = append(networks, "tcp6")
	} else {
		tb.Log("IPv6 is unavailable, skipping tcp6")
	}

	return networks
}

// testConns creates a pair of Conns joined by a real loopback TCP connection
// on the given network, and registers cleanup for both. Real TCP is used
// rather than net.Pipe so that kernel buffering, partial reads, and deadlines
// behave as they do in production.
func testConns(tb testing.TB, network string) (client, server *Conn) {
	tb.Helper()

	l, err := nettest.NewLocalListener(network)
	if err != nil {
		tb.Fatalf("failed to create listener: %v", err)
	}

	defer func() { _ = l.Close() }()

	type accepted struct {
		c   net.Conn
		err error
	}

	acceptC := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptC <- accepted{c: c, err: err}
	}()

	cc, err := net.Dial(network, l.Addr().String())
	if err != nil {
		tb.Fatalf("failed to dial: %v", err)
	}

	a := <-acceptC
	if a.err != nil {
		_ = cc.Close()
		tb.Fatalf("failed to accept: %v", a.err)
	}

	client, server = NewConn(cc), NewConn(a.c)
	tb.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// rawConn exposes a Conn's underlying connection, so that tests may place
// arbitrary bytes on the wire.
func (c *Conn) rawConn() net.Conn { return c.c }

// detachMessage copies every byte slice reachable from m, producing a Message
// which outlives the next Conn.ReadMessage call.
func detachMessage(tb testing.TB, m Message) Message {
	tb.Helper()

	b, err := m.AppendBinary(nil)
	if err != nil {
		tb.Fatalf("failed to marshal message: %v", err)
	}

	out, err := ParseMessage(b)
	if err != nil {
		tb.Fatalf("failed to parse message: %v", err)
	}

	return out
}

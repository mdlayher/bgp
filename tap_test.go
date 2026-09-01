package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mdlayher/bgp/internal/mrt"
)

// A tapLog collects MessageEvents from a tap, which may fire from several
// goroutines at once, and reports each direction's stream in order.
type tapLog struct {
	mu     sync.Mutex
	events []MessageEvent
}

func (l *tapLog) tap(e MessageEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

// types returns the message types observed in dir, in order, with a nil
// Message rendered as its error's type so malformed frames stand out.
func (l *tapLog) types(dir Direction) []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []string
	for _, e := range l.events {
		if e.Direction != dir {
			continue
		}

		switch {
		case e.Message != nil:
			out = append(out, e.Message.messageType().String())
		case e.Err != nil:
			out = append(out, "error")
		default:
			out = append(out, "nil")
		}
	}

	return out
}

// find returns the first event in dir whose Message is of type T.
func find[T Message](tb testing.TB, l *tapLog, dir Direction) MessageEvent {
	tb.Helper()

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.events {
		if _, ok := e.Message.(T); ok && e.Direction == dir {
			return e
		}
	}

	tb.Fatalf("no %s event of type %T", dir, *new(T))
	panic("unreachable")
}

// TestConnTap exercises the tap at the Conn: both directions of a well-formed
// message, the two malformed read cases, a failed write, and the marshal
// failure which never reaches the wire and so never fires.
func TestConnTap(t *testing.T) {
	t.Parallel()

	a, b := memPipe()
	ca, cb := NewConn(a), NewConn(b)

	var la, lb tapLog
	ca.setTap(la.tap)
	cb.setTap(lb.tap)

	open := scriptOpen()
	if err := ca.WriteMessage(open); err != nil {
		t.Fatalf("failed to write OPEN: %v", err)
	}

	if _, err := cb.ReadMessage(); err != nil {
		t.Fatalf("failed to read OPEN: %v", err)
	}

	raw := mustMessage(t, open)
	for _, tt := range []struct {
		name string
		l    *tapLog
		dir  Direction
	}{
		{name: "sent", l: &la, dir: DirectionSent},
		{name: "received", l: &lb, dir: DirectionReceived},
	} {
		if n := len(tt.l.events); n != 1 {
			t.Fatalf("%s: expected 1 event, got %d", tt.name, n)
		}

		e := tt.l.events[0]
		if e.Direction != tt.dir || !bytes.Equal(e.Raw, raw) || e.Err != nil {
			t.Fatalf("%s: unexpected event: %+v", tt.name, e)
		}

		if d := diff(t, open, e.Message.(*Open)); d != "" {
			t.Fatalf("%s: unexpected message (-want +got):\n%s", tt.name, d)
		}

		if e.LocalAddr != (memAddr{}) || e.RemoteAddr != (memAddr{}) {
			t.Fatalf("%s: unexpected addresses: %v %v", tt.name, e.LocalAddr, e.RemoteAddr)
		}
	}

	// A marshal failure never fires: no byte reached the connection.
	if err := ca.WriteMessage(&Open{HoldTime: time.Second}); err == nil {
		t.Fatal("expected a marshal error, but none occurred")
	}

	if n := len(la.events); n != 1 {
		t.Fatalf("a marshal failure fired the tap: %d events", n)
	}

	// A well-framed UPDATE whose body is malformed fires with the whole
	// frame and the parse error.
	bad := rawMessage(MessageTypeUpdate, []byte{0, 0, 0, 5})
	if _, err := a.Write(bad); err != nil {
		t.Fatalf("failed to write raw message: %v", err)
	}

	if _, err := cb.ReadMessage(); err == nil {
		t.Fatal("expected a parse error, but none occurred")
	}

	e := lb.events[len(lb.events)-1]
	if e.Message != nil || !bytes.Equal(e.Raw, bad) {
		t.Fatalf("unexpected malformed event: %+v", e)
	}

	if me, ok := errors.AsType[*MessageError](e.Err); !ok || me.Subcode != SubcodeMalformedAttributeList {
		t.Fatalf("unexpected malformed event error: %v", e.Err)
	}

	// A header whose length field is invalid fires with the header alone:
	// framing is lost beyond it. A fresh pipe, since the malformed UPDATE
	// above was never consumed.
	a, b = memPipe()
	ca, cb = NewConn(a), NewConn(b)
	cb.setTap(lb.tap)

	hdr := bytes.Repeat([]byte{0xff}, markerLen)
	hdr = binary.BigEndian.AppendUint16(hdr, 5)
	hdr = append(hdr, byte(MessageTypeKeepalive), 0xaa, 0xbb)
	if _, err := a.Write(hdr); err != nil {
		t.Fatalf("failed to write raw header: %v", err)
	}

	if _, err := cb.ReadMessage(); err == nil {
		t.Fatal("expected a header error, but none occurred")
	}

	e = lb.events[len(lb.events)-1]
	if !bytes.Equal(e.Raw, hdr[:headerLen]) {
		t.Fatalf("unexpected bad-length event raw bytes: % x", e.Raw)
	}

	if me, ok := errors.AsType[*MessageError](e.Err); !ok || me.Subcode != SubcodeBadMessageLength {
		t.Fatalf("unexpected bad-length event error: %v", e.Err)
	}

	// A failed write fires with its error.
	_ = b.Close()
	if err := ca.WriteMessage(&Keepalive{}); err == nil {
		t.Fatal("expected a write error, but none occurred")
	}

	ca.setTap(la.tap)
	if err := ca.WriteMessage(&Keepalive{}); err == nil {
		t.Fatal("expected a write error, but none occurred")
	}

	e = la.events[len(la.events)-1]
	if e.Direction != DirectionSent || e.Err == nil || !bytes.Equal(e.Raw, mustMessage(t, &Keepalive{})) {
		t.Fatalf("unexpected failed write event: %+v", e)
	}

	// EOF between messages is not a frame, nor is a truncated one.
	for _, partial := range [][]byte{nil, mustMessage(t, &Keepalive{})[:headerLen-1]} {
		a, b = memPipe()
		cb = NewConn(b)
		cb.setTap(lb.tap)
		if _, err := a.Write(partial); err != nil {
			t.Fatalf("failed to write partial frame: %v", err)
		}

		_ = a.Close()

		before := len(lb.events)
		if _, err := cb.ReadMessage(); !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Fatalf("unexpected read error after close: %v", err)
		}

		if len(lb.events) != before {
			t.Fatal("a closed connection fired the tap")
		}
	}
}

// TestPeerOnMessage drives a dialed session through the OPEN exchange, an
// UPDATE each way, and a peer-sent NOTIFICATION, then a second session
// whose UPDATE is malformed, checking each direction's stream and that a
// received message's event precedes its handler.
func TestPeerOnMessage(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var l tapLog
		sawUpdate := make(chan bool, 1)
		r := newPipeRig(t, PeerConfig{
			OnMessage: func(_ *Peer, e MessageEvent) { l.tap(e) },
			OnUpdate: func(_ context.Context, _ *Peer, _ *Update) error {
				// The tap ran on this goroutine before the handler.
				sawUpdate <- len(l.types(DirectionReceived)) > 0 &&
					l.types(DirectionReceived)[len(l.types(DirectionReceived))-1] == "UPDATE"
				return nil
			},
		})

		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		update := &Update{Withdrawn: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
		s.write(update)
		if !recv(t, sawUpdate, "OnUpdate") {
			t.Fatal("OnUpdate ran before the UPDATE's tap event")
		}

		if err := r.p.SendUpdate(context.Background(), update); err != nil {
			t.Fatalf("failed to send UPDATE: %v", err)
		}

		if d := diff(t, update, s.read().(*Update)); d != "" {
			t.Fatalf("unexpected UPDATE at the peer (-want +got):\n%s", d)
		}

		s.write(&Notification{Code: NotificationCease, Subcode: SubcodeCeaseAdministrativeReset})
		recv(t, r.closeC, "session close")

		want := map[Direction][]string{
			DirectionSent:     {"OPEN", "KEEPALIVE", "UPDATE"},
			DirectionReceived: {"OPEN", "KEEPALIVE", "UPDATE", "NOTIFICATION"},
		}

		for dir, w := range want {
			if d := diff(t, w, l.types(dir)); d != "" {
				t.Fatalf("unexpected %s stream (-want +got):\n%s", dir, d)
			}
		}

		// The sent UPDATE is what the caller sent, verbatim and owned.
		e := find[*Update](t, &l, DirectionSent)
		if d := diff(t, update, e.Message.(*Update)); d != "" {
			t.Fatalf("unexpected sent UPDATE (-want +got):\n%s", d)
		}

		if !bytes.Equal(e.Raw, mustMessage(t, update)) {
			t.Fatalf("unexpected sent UPDATE bytes: % x", e.Raw)
		}

		// The next attempt: a malformed UPDATE fires with its error, and
		// the NOTIFICATION answering it is observed on the sent stream.
		l.mu.Lock()
		l.events = nil
		l.mu.Unlock()

		time.Sleep(idleHoldTime)
		s = r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		s.writeRaw(rawMessage(MessageTypeUpdate, []byte{0, 0, 0, 5}))
		s.expectNotification(&Notification{
			Code:    NotificationUpdateMessageError,
			Subcode: SubcodeMalformedAttributeList,
		})
		recv(t, r.closeC, "session close")

		want = map[Direction][]string{
			DirectionSent:     {"OPEN", "KEEPALIVE", "NOTIFICATION"},
			DirectionReceived: {"OPEN", "KEEPALIVE", "error"},
		}

		for dir, w := range want {
			if d := diff(t, w, l.types(dir)); d != "" {
				t.Fatalf("unexpected %s stream (-want +got):\n%s", dir, d)
			}
		}
	})
}

// TestPeerOnMessageDelivered covers the second adoption point: a connection
// handed in through DeliverConn is tapped from its first message.
func TestPeerOnMessageDelivered(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var l tapLog
		r := newPipeRig(t, PeerConfig{
			// Every dial stalls until canceled: the delivered connection
			// is the attempt's only one.
			DialFunc: func(ctx context.Context) (*Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			OnMessage: func(_ *Peer, e MessageEvent) { l.tap(e) },
		})

		s := r.deliver()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		want := map[Direction][]string{
			DirectionSent:     {"OPEN", "KEEPALIVE"},
			DirectionReceived: {"OPEN", "KEEPALIVE"},
		}

		for dir, w := range want {
			if d := diff(t, w, l.types(dir)); d != "" {
				t.Fatalf("unexpected %s stream (-want +got):\n%s", dir, d)
			}
		}
	})
}

// TestPeerOnMessageOwnsValues pins the Peer's copy: the FSM lends the frame
// and message, and the caller's tap receives detached copies of both.
func TestPeerOnMessageOwnsValues(t *testing.T) {
	t.Parallel()

	var got MessageEvent
	p := must(NewPeer(netip.MustParseAddr("127.0.0.1"), PeerConfig{
		LocalASN:  64496,
		LocalID:   MustParseIdentifier("192.0.2.1"),
		Passive:   true,
		OnMessage: func(_ *Peer, e MessageEvent) { got = e },
	}))

	buf := []byte{0x01, 0x02, 0x03, 0x04}
	borrowed := &Update{
		Attributes: RawAttributes{{Type: AttrCommunities, Data: buf}},
	}

	p.fsm.cfg.OnMessage(p.fsm, MessageEvent{
		Direction: DirectionReceived,
		Raw:       buf,
		Message:   borrowed,
	})

	if got.Message == Message(borrowed) {
		t.Fatal("the caller's tap received the borrowed Message itself")
	}

	buf[0] = 0xff
	if got.Raw[0] != 0x01 {
		t.Fatal("the caller's Raw shares memory with the borrowed frame")
	}

	if got.Message.(*Update).Attributes[0].Data[0] != 0x01 {
		t.Fatal("the caller's Message shares memory with the borrowed buffer")
	}
}

// TestPeerOnMessageMRT is the seam's end-to-end proof: a route collector's
// message log written from the tap and the state hook alone, over a real
// TCP session, read back with the MRT reader and compared to the frames
// the peer actually exchanged.
func TestPeerOnMessageMRT(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		buf  bytes.Buffer
		w    = mrt.NewWriter(&buf)
		want [][]byte
	)

	// session derives the MRT session header from the event's endpoints
	// and the peering's identity. MRT names the sender "peer", so a sent
	// message is recorded from the local speaker's side.
	session := func(e MessageEvent, s Session) mrt.Session {
		la, ra := e.LocalAddr.(*net.TCPAddr).AddrPort().Addr(), e.RemoteAddr.(*net.TCPAddr).AddrPort().Addr()
		ms := mrt.Session{PeerASN: s.Peer.ASN, LocalASN: s.Local.ASN, Peer: ra, Local: la}
		if e.Direction == DirectionSent {
			ms.PeerASN, ms.LocalASN, ms.Peer, ms.Local = ms.LocalASN, ms.PeerASN, ms.Local, ms.Peer
		}

		return ms
	}

	var sess Session
	r := newTCPRig(t, PeerConfig{
		OnEstablished: func(_ context.Context, _ *Peer, s Session) error {
			mu.Lock()
			defer mu.Unlock()
			sess = s
			return nil
		},
		OnMessage: func(_ *Peer, e MessageEvent) {
			mu.Lock()
			defer mu.Unlock()
			if e.Err != nil {
				return
			}

			// Before establishment the identity is the configured one; the
			// ASNs are all the writer needs from it.
			s := sess
			if s.Peer == nil {
				s = Session{Peer: &Open{ASN: 64497}, Local: &Open{ASN: 64496}}
			}

			if err := w.WriteMessage(time.Now(), session(e, s), e.Raw); err != nil {
				t.Errorf("failed to write MRT record: %v", err)
			}

			want = append(want, bytes.Clone(e.Raw))
		},
		OnStateChange: func(_ *Peer, from, to State) {
			mu.Lock()
			defer mu.Unlock()
			ms := mrt.Session{
				PeerASN: 64497, LocalASN: 64496,
				Peer: netip.MustParseAddr("127.0.0.1"), Local: netip.MustParseAddr("127.0.0.1"),
			}
			if err := w.WriteStateChange(time.Now(), ms, uint16(from), uint16(to)); err != nil {
				t.Errorf("failed to write MRT state change: %v", err)
			}
		},
	})

	s := r.acceptScript()
	s.establish(scriptOpen())
	recv(t, r.estC, "session establishment")

	update := &Update{NLRI: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	s.write(update)
	if err := r.p.SendUpdate(context.Background(), update); err != nil {
		t.Fatalf("failed to send UPDATE: %v", err)
	}

	_ = s.read()
	s.write(&Notification{Code: NotificationCease, Subcode: SubcodeCeaseAdministrativeShutdown})
	recv(t, r.closeC, "session close")

	mu.Lock()
	defer mu.Unlock()

	rd := mrt.NewReader(&buf)
	var got [][]byte
	for {
		m, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatalf("failed to read MRT record: %v", err)
		}

		got = append(got, m)
	}

	if d := diff(t, want, got); d != "" {
		t.Fatalf("unexpected MRT messages (-want +got):\n%s", d)
	}

	// Sanity: the log holds both OPENs, both KEEPALIVEs, both UPDATEs, and
	// the NOTIFICATION, each of which parses back.
	if len(got) < 7 {
		t.Fatalf("expected at least 7 messages, got %d", len(got))
	}

	for i, b := range got {
		if _, err := ParseMessage(b); err != nil {
			t.Fatalf("MRT message %d does not parse: %v", i, err)
		}
	}
}

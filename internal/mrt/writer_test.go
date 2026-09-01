package mrt

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestWriterRoundTrip(t *testing.T) {
	t.Parallel()

	// RFC 5737/3849 addresses, RFC 5398 ASNs, and the epoch timestamp the Reader
	// tests' hand-built records use, so the encodings can be compared. The
	// messages are opaque to both the Writer and the Reader.
	v4 := Session{
		PeerASN: 65536, LocalASN: 65537,
		Peer:  netip.MustParseAddr("192.0.2.2"),
		Local: netip.MustParseAddr("192.0.2.1"),
	}
	v6 := Session{
		PeerASN: 65536, LocalASN: 65537,
		Peer:  netip.MustParseAddr("2001:db8::2"),
		Local: netip.MustParseAddr("2001:db8::1"),
	}

	ts := time.Unix(0, 0)
	msgs := [][]byte{{0xde, 0xad}, {0xbe, 0xef, 0x00}, {0x01}}

	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteMessage(ts, v4, msgs[0]); err != nil {
		t.Fatalf("failed to write IPv4 message: %v", err)
	}

	// A state change sits between messages and is invisible to the Reader.
	if err := w.WriteStateChange(ts, v4, 5, 6); err != nil {
		t.Fatalf("failed to write state change: %v", err)
	}

	if err := w.WriteMessage(ts, v6, msgs[1]); err != nil {
		t.Fatalf("failed to write IPv6 message: %v", err)
	}

	if err := w.WriteMessage(ts, v4, msgs[2]); err != nil {
		t.Fatalf("failed to write IPv4 message: %v", err)
	}

	// The records match the hand-built encoding the Reader tests use.
	want := record(typeBGP4MP, subtypeMessageAS4, messageAS4(1, [][]byte{{192, 0, 2, 2}, {192, 0, 2, 1}}, msgs[0]))
	if got := buf.Bytes()[:len(want)]; !bytes.Equal(want, got) {
		t.Fatalf("unexpected first record:\n want: % x\n  got: % x", want, got)
	}

	// The state change carries the two states after the session header.
	sc := record(typeBGP4MP, subtypeStateChangeAS4,
		messageAS4(1, [][]byte{{192, 0, 2, 2}, {192, 0, 2, 1}}, []byte{0, 5, 0, 6}))
	if got := buf.Bytes()[len(want) : len(want)+len(sc)]; !bytes.Equal(sc, got) {
		t.Fatalf("unexpected state change record:\n want: % x\n  got: % x", sc, got)
	}

	r := NewReader(&buf)
	var got [][]byte
	for {
		m, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatalf("failed to read message: %v", err)
		}

		got = append(got, m)
	}

	if d := cmp.Diff(msgs, got); d != "" {
		t.Fatalf("unexpected messages (-want +got):\n%s", d)
	}
}

func TestWriterSessionErrors(t *testing.T) {
	t.Parallel()

	w := NewWriter(io.Discard)
	tests := []struct {
		name string
		s    Session
	}{
		{name: "zero"},
		{
			name: "mixed families",
			s: Session{
				Peer:  netip.MustParseAddr("192.0.2.2"),
				Local: netip.MustParseAddr("2001:db8::1"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := w.WriteMessage(time.Time{}, tt.s, nil); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

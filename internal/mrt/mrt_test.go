package mrt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReaderNext(t *testing.T) {
	t.Parallel()

	// Documentation values throughout: ASN 65536 (RFC 5398), TEST-NET-1 and
	// 2001:db8:: addresses (RFC 5737/3849). The embedded message need not be
	// valid BGP; the Reader treats it as opaque.
	msg := []byte{0xde, 0xad, 0xbe, 0xef}

	v4 := messageAS4(1, [][]byte{{192, 0, 2, 1}, {192, 0, 2, 2}}, msg)
	v6 := messageAS4(2, [][]byte{
		{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}, msg)

	tests := []struct {
		name string
		b    []byte
		msgs [][]byte
	}{
		{
			name: "empty",
		},
		{
			name: "IPv4 peer",
			b:    record(typeBGP4MP, subtypeMessageAS4, v4),
			msgs: [][]byte{msg},
		},
		{
			name: "IPv6 peer",
			b:    record(typeBGP4MP, subtypeMessageAS4, v6),
			msgs: [][]byte{msg},
		},
		{
			name: "extended timestamp",
			b: record(typeBGP4MPET, subtypeMessageAS4,
				append([]byte{0x00, 0x01, 0x02, 0x03}, v4...)),
			msgs: [][]byte{msg},
		},
		{
			name: "skips other records",
			b: bytes.Join([][]byte{
				// A state change, a 2-octet ASN message, and a table dump
				// style record all carry no 4-octet ASN BGP message.
				record(typeBGP4MP, 0, make([]byte, 20)),
				record(typeBGP4MP, 1, make([]byte, 20)),
				record(13, 2, make([]byte, 20)),
				record(typeBGP4MP, subtypeMessageAS4, v4),
			}, nil),
			msgs: [][]byte{msg},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := NewReader(bytes.NewReader(tt.b))

			var msgs [][]byte
			for {
				m, err := r.Next()
				if errors.Is(err, io.EOF) {
					break
				}

				if err != nil {
					t.Fatalf("failed to read message: %v", err)
				}

				msgs = append(msgs, m)
			}

			if diff := cmp.Diff(tt.msgs, msgs); diff != "" {
				t.Fatalf("unexpected messages (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReaderNextErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		b    []byte
	}{
		{
			name: "truncated record header",
			b:    record(typeBGP4MP, subtypeMessageAS4, nil)[:6],
		},
		{
			name: "truncated record body",
			b:    record(typeBGP4MP, subtypeMessageAS4, make([]byte, 20))[:20],
		},
		{
			name: "record too large",
			b: func() []byte {
				b := record(typeBGP4MP, subtypeMessageAS4, nil)
				binary.BigEndian.PutUint32(b[8:12], maxRecordLen+1)
				return b
			}(),
		},
		{
			name: "BGP4MP_ET too short",
			b:    record(typeBGP4MPET, subtypeMessageAS4, []byte{0x00}),
		},
		{
			name: "message record too short",
			b:    record(typeBGP4MP, subtypeMessageAS4, make([]byte, 11)),
		},
		{
			name: "unknown address family",
			b: record(typeBGP4MP, subtypeMessageAS4,
				messageAS4(3, [][]byte{{192, 0, 2, 1}, {192, 0, 2, 2}}, nil)),
		},
		{
			name: "addresses truncated",
			b: record(typeBGP4MP, subtypeMessageAS4,
				messageAS4(2, [][]byte{{0x20, 0x01}, {0x0d, 0xb8}}, nil)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := NewReader(bytes.NewReader(tt.b))
			if _, err := r.Next(); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("expected an error, but got: %v", err)
			}
		})
	}
}

// record produces a single MRT record with the given type, subtype, and body.
func record(typ, sub uint16, body []byte) []byte {
	b := make([]byte, 0, 12+len(body))
	b = binary.BigEndian.AppendUint32(b, 0) // timestamp
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, sub)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

// messageAS4 produces a BGP4MP_MESSAGE_AS4 record body with the given
// address family, peer and local addresses, and embedded BGP message.
func messageAS4(afi uint16, addrs [][]byte, msg []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 65536) // peer ASN
	b = binary.BigEndian.AppendUint32(b, 65537) // local ASN
	b = binary.BigEndian.AppendUint16(b, 0)     // interface index
	b = binary.BigEndian.AppendUint16(b, afi)
	for _, a := range addrs {
		b = append(b, a...)
	}

	return append(b, msg...)
}

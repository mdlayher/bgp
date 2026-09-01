package mrt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

func TestRIBReader(t *testing.T) {
	t.Parallel()

	var in []byte
	// The peer index table must be skipped.
	in = append(in, record(typeTableDumpV2, subtypePeerIndexTable, []byte{0xde, 0xad})...)
	// An IPv4 unicast prefix with two peer entries.
	in = append(in, record(typeTableDumpV2, subtypeRIBIPv4Unicast,
		ribBody(24, []byte{198, 51, 100}, false, []byte{1}, []byte{2, 2}))...)
	// An IPv6 unicast additional-path prefix with one entry.
	in = append(in, record(typeTableDumpV2, subtypeRIBIPv6UnicastAddPath,
		ribBody(32, []byte{0x20, 0x01, 0x0d, 0xb8}, true, []byte{3, 3, 3}))...)
	// A non-TABLE_DUMP_V2 record must be skipped.
	in = append(in, record(typeBGP4MP, 0, []byte{0xff})...)

	want := []RIBEntry{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Attrs: []byte{1}},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Attrs: []byte{2, 2}},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Attrs: []byte{3, 3, 3}},
	}

	r := NewRIBReader(bytes.NewReader(in))
	for i, w := range want {
		e, err := r.Next()
		if err != nil {
			t.Fatalf("failed to read entry %d: %v", i, err)
		}

		if e.Prefix != w.Prefix {
			t.Fatalf("unexpected entry %d prefix: got %s, want %s", i, e.Prefix, w.Prefix)
		}

		if !bytes.Equal(e.Attrs, w.Attrs) {
			t.Fatalf("unexpected entry %d attrs: got %x, want %x", i, e.Attrs, w.Attrs)
		}
	}

	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, but got: %v", err)
	}
}

func TestRIBReaderMalformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "short record",
			body: []byte{0, 0, 0, 1},
		},
		{
			name: "prefix too long",
			body: []byte{0, 0, 0, 1, 33, 198, 51, 100, 0, 0, 0},
		},
		{
			name: "short entry",
			body: ribBody(24, []byte{198, 51, 100}, false)[:9],
		},
		{
			name: "trailing bytes",
			body: append(ribBody(24, []byte{198, 51, 100}, false, []byte{1}), 0xff),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := NewRIBReader(bytes.NewReader(record(typeTableDumpV2, subtypeRIBIPv4Unicast, tt.body)))
			if _, err := r.Next(); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("expected a parse error, but got: %v", err)
			}
		})
	}
}

// ribBody builds a RIB record body for prefix with one set of attributes
// per peer entry.
func ribBody(plen int, prefix []byte, addPath bool, attrs ...[]byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 1) // sequence number
	b = append(b, byte(plen))
	b = append(b, prefix...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs)))
	for _, a := range attrs {
		b = binary.BigEndian.AppendUint16(b, 0) // peer index
		b = binary.BigEndian.AppendUint32(b, 0) // originated time
		if addPath {
			b = binary.BigEndian.AppendUint32(b, 1) // path identifier
		}

		b = binary.BigEndian.AppendUint16(b, uint16(len(a)))
		b = append(b, a...)
	}

	return b
}

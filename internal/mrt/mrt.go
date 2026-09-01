// Package mrt reads the BGP messages embedded in Multi-Threaded Routing
// Toolkit (MRT) files, as described in RFC 6396. It exists to feed the bgp
// package's tests, fuzz corpora, and benchmarks with real data from route
// collector archives, such as those published by the University of Oregon
// Route Views project and RIPE RIS; it is not a general purpose MRT
// implementation.
package mrt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MRT record types and subtypes, as described in RFC 6396, section 4.
const (
	typeBGP4MP   = 16
	typeBGP4MPET = 17

	subtypeMessageAS4 = 4
)

// maxRecordLen bounds the size of a single MRT record, so a corrupt length
// field cannot demand an enormous allocation. A BGP4MP record carries at
// most one maximum sized BGP message plus small fixed headers, but other
// record types, such as a table dump's peer index, may legitimately be
// larger.
const maxRecordLen = 1 << 20

// A Reader extracts the BGP messages embedded in an MRT file's BGP4MP
// records.
type Reader struct {
	r      io.Reader
	header [12]byte
}

// NewReader produces a Reader which reads MRT records from r.
func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// Next returns the raw bytes of the next embedded BGP message, skipping MRT
// records which do not carry one, such as session state changes. Records for
// sessions using 2-octet ASNs (BGP4MP_MESSAGE) are also skipped, because the
// bgp package deals exclusively in 4-octet ASNs. Next returns io.EOF when
// the input is exhausted.
//
// The returned bytes are owned by the caller: they are never overwritten by
// a subsequent call to Next.
func (r *Reader) Next() ([]byte, error) {
	for {
		// Each record begins with a fixed header: a 4 byte timestamp, 2 byte
		// type, 2 byte subtype, and the 4 byte length of the body which
		// follows. io.EOF surfaces only at a record boundary.
		if _, err := io.ReadFull(r.r, r.header[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("mrt: truncated record header: %w", err)
			}

			return nil, err
		}

		var (
			typ = binary.BigEndian.Uint16(r.header[4:6])
			sub = binary.BigEndian.Uint16(r.header[6:8])
			n   = binary.BigEndian.Uint32(r.header[8:12])
		)

		if n > maxRecordLen {
			return nil, fmt.Errorf("mrt: record length %d exceeds maximum of %d bytes", n, maxRecordLen)
		}

		body := make([]byte, n)
		if _, err := io.ReadFull(r.r, body); err != nil {
			return nil, fmt.Errorf("mrt: truncated record body: %w", err)
		}

		if typ != typeBGP4MP && typ != typeBGP4MPET {
			continue
		}

		if typ == typeBGP4MPET {
			// An extended timestamp record is identical to its BGP4MP
			// equivalent, but carries 4 extra bytes of microseconds first.
			if len(body) < 4 {
				return nil, errors.New("mrt: BGP4MP_ET record too short")
			}

			body = body[4:]
		}

		if sub != subtypeMessageAS4 {
			continue
		}

		// BGP4MP_MESSAGE_AS4: peer AS (4 bytes), local AS (4), interface
		// index (2), and address family (2), then peer and local IP
		// addresses sized by that family, and finally the BGP message.
		if len(body) < 12 {
			return nil, errors.New("mrt: BGP4MP_MESSAGE_AS4 record too short")
		}

		var ipLen int
		switch afi := binary.BigEndian.Uint16(body[10:12]); afi {
		case 1:
			ipLen = 4
		case 2:
			ipLen = 16
		default:
			return nil, fmt.Errorf("mrt: unknown BGP4MP_MESSAGE_AS4 address family %d", afi)
		}

		if len(body) < 12+2*ipLen {
			return nil, errors.New("mrt: BGP4MP_MESSAGE_AS4 record too short")
		}

		return body[12+2*ipLen:], nil
	}
}

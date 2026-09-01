package mrt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// TABLE_DUMP_V2 record type and subtypes, as described in RFC 6396, section
// 4.3, with the additional-path subtypes of RFC 8050.
const (
	typeTableDumpV2 = 13

	subtypePeerIndexTable        = 1
	subtypeRIBIPv4Unicast        = 2
	subtypeRIBIPv6Unicast        = 4
	subtypeRIBIPv4UnicastAddPath = 8
	subtypeRIBIPv6UnicastAddPath = 10
)

// A RIBEntry is one route of a TABLE_DUMP_V2 RIB dump: a prefix and the BGP
// path attributes of one peer's route to it. A prefix announced by many
// peers yields one RIBEntry per peer.
//
// Attrs is a BGP path attribute list in wire form, with the RFC 6396,
// section 4.3.4 exception: an MP_REACH_NLRI attribute is truncated to its
// next hop alone, because the AFI, SAFI, and NLRI are implied by the record.
type RIBEntry struct {
	Prefix netip.Prefix
	Attrs  []byte
}

// A RIBReader extracts the routes embedded in an MRT file's TABLE_DUMP_V2
// RIB records: the "bview" and "RIBS" full-table dumps route collectors
// publish. Records of other types, including the peer index table, are
// skipped.
type RIBReader struct {
	r       io.Reader
	header  [12]byte
	pending []RIBEntry
}

// NewRIBReader produces a RIBReader which reads MRT records from r.
func NewRIBReader(r io.Reader) *RIBReader { return &RIBReader{r: r} }

// Next returns the next route of the dump, flattening each RIB record's
// per-peer entries. Next returns io.EOF when the input is exhausted. The
// returned entry is owned by the caller.
func (r *RIBReader) Next() (RIBEntry, error) {
	for len(r.pending) == 0 {
		if err := r.fill(); err != nil {
			return RIBEntry{}, err
		}
	}

	e := r.pending[0]
	r.pending = r.pending[1:]
	return e, nil
}

// fill reads MRT records until one RIB record's entries are pending, or the
// input is exhausted.
func (r *RIBReader) fill() error {
	for {
		if _, err := io.ReadFull(r.r, r.header[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("mrt: truncated record header: %w", err)
			}

			return err
		}

		var (
			typ = binary.BigEndian.Uint16(r.header[4:6])
			sub = binary.BigEndian.Uint16(r.header[6:8])
			n   = binary.BigEndian.Uint32(r.header[8:12])
		)

		if n > maxRecordLen {
			return fmt.Errorf("mrt: record length %d exceeds maximum of %d bytes", n, maxRecordLen)
		}

		body := make([]byte, n)
		if _, err := io.ReadFull(r.r, body); err != nil {
			return fmt.Errorf("mrt: truncated record body: %w", err)
		}

		if typ != typeTableDumpV2 {
			continue
		}

		var v4, addPath bool
		switch sub {
		case subtypeRIBIPv4Unicast:
			v4, addPath = true, false
		case subtypeRIBIPv6Unicast:
			v4, addPath = false, false
		case subtypeRIBIPv4UnicastAddPath:
			v4, addPath = true, true
		case subtypeRIBIPv6UnicastAddPath:
			v4, addPath = false, true
		default:
			// The peer index table, the multicast and generic subtypes,
			// and anything newer carry no unicast route to extract.
			continue
		}

		entries, err := parseRIBRecord(body, v4, addPath)
		if err != nil {
			return err
		}

		r.pending = entries
		return nil
	}
}

// parseRIBRecord parses one RIB_IPV4_UNICAST or RIB_IPV6_UNICAST record
// body (RFC 6396, section 4.3.2), or its additional-path variant (RFC 8050),
// into one entry per peer.
func parseRIBRecord(b []byte, v4, addPath bool) ([]RIBEntry, error) {
	// Sequence number (4), prefix length (1), prefix (variable).
	if len(b) < 5 {
		return nil, errors.New("mrt: RIB record too short")
	}

	plen := int(b[4])
	b = b[5:]

	bits := 128
	if v4 {
		bits = 32
	}

	if plen > bits {
		return nil, fmt.Errorf("mrt: RIB prefix length %d exceeds %d bits", plen, bits)
	}

	pb := (plen + 7) / 8
	if len(b) < pb+2 {
		return nil, errors.New("mrt: RIB record too short")
	}

	var addr netip.Addr
	if v4 {
		var a [4]byte
		copy(a[:], b[:pb])
		addr = netip.AddrFrom4(a)
	} else {
		var a [16]byte
		copy(a[:], b[:pb])
		addr = netip.AddrFrom16(a)
	}

	prefix, err := addr.Prefix(plen)
	if err != nil {
		return nil, fmt.Errorf("mrt: invalid RIB prefix: %w", err)
	}

	b = b[pb:]

	count := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]

	// Each entry: peer index (2), originated time (4), path identifier (4,
	// additional-path subtypes only), attribute length (2), attributes.
	head := 8
	if addPath {
		head += 4
	}

	entries := make([]RIBEntry, 0, count)
	for range count {
		if len(b) < head {
			return nil, errors.New("mrt: RIB entry too short")
		}

		alen := int(binary.BigEndian.Uint16(b[head-2 : head]))
		if len(b) < head+alen {
			return nil, errors.New("mrt: RIB entry attributes too short")
		}

		entries = append(entries, RIBEntry{
			Prefix: prefix,
			Attrs:  b[head : head+alen : head+alen],
		})
		b = b[head+alen:]
	}

	if len(b) != 0 {
		return nil, fmt.Errorf("mrt: %d trailing bytes after RIB entries", len(b))
	}

	return entries, nil
}

package mrt

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"time"
)

// subtypeStateChangeAS4 is the BGP4MP_STATE_CHANGE_AS4 subtype (RFC 6396,
// section 4.4.4): a session state transition, which the Reader skips.
const subtypeStateChangeAS4 = 5

// A Session identifies the peering an MRT BGP4MP record describes: the two
// ASNs and the two addresses of one connection. Both addresses must be of
// the same family, which is the record's address family.
type Session struct {
	PeerASN, LocalASN uint32
	Peer, Local       netip.Addr
}

// A Writer produces the BGP4MP records of an MRT file: every BGP message a
// peering exchanged, and every state transition its session made. It is the
// in-tree proof that the bgp package's OnMessage tap and OnStateChange hook
// carry everything a route collector's message log needs,
// and, like the Reader, not a general purpose MRT implementation.
type Writer struct {
	w   io.Writer
	buf []byte
}

// NewWriter produces a Writer which writes MRT records to w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// WriteMessage writes one BGP4MP_MESSAGE_AS4 record (RFC 6396, section
// 4.4.3): msg, a complete BGP message as framed on the wire, exchanged on
// s's connection at ts. MRT records a message's sender through the
// addresses alone: a message the local speaker received is recorded with s
// as given, and one it sent with the peer and local fields swapped, so the
// record's "peer" is always the sender.
func (w *Writer) WriteMessage(ts time.Time, s Session, msg []byte) error {
	body, err := w.session(s)
	if err != nil {
		return err
	}

	body = append(body, msg...)
	return w.record(ts, subtypeMessageAS4, body)
}

// WriteStateChange writes one BGP4MP_STATE_CHANGE_AS4 record (RFC 6396,
// section 4.4.4): the session on s's connection moved from state old to
// state new at ts, with states numbered as in RFC 4271, section 8.2.2:
// Idle is 1 and Established is 6.
func (w *Writer) WriteStateChange(ts time.Time, s Session, old, new uint16) error {
	body, err := w.session(s)
	if err != nil {
		return err
	}

	body = binary.BigEndian.AppendUint16(body, old)
	body = binary.BigEndian.AppendUint16(body, new)
	return w.record(ts, subtypeStateChangeAS4, body)
}

// session appends the BGP4MP_*_AS4 session header to the reused buffer:
// peer AS, local AS, a zero interface index, the address family, and the
// peer and local addresses.
func (w *Writer) session(s Session) ([]byte, error) {
	if !s.Peer.IsValid() || !s.Local.IsValid() || s.Peer.Is4() != s.Local.Is4() {
		return nil, errors.New("mrt: session addresses must be valid and of one family")
	}

	// Leave room for the record header, filled in by record.
	b := append(w.buf[:0], make([]byte, 12)...)
	b = binary.BigEndian.AppendUint32(b, s.PeerASN)
	b = binary.BigEndian.AppendUint32(b, s.LocalASN)
	b = binary.BigEndian.AppendUint16(b, 0)
	if s.Peer.Is4() {
		b = binary.BigEndian.AppendUint16(b, 1)
	} else {
		b = binary.BigEndian.AppendUint16(b, 2)
	}

	b = append(b, s.Peer.Unmap().AsSlice()...)
	b = append(b, s.Local.Unmap().AsSlice()...)
	return b, nil
}

// record fills in the MRT common header ahead of body, which session left
// room for, and writes the record in one call.
func (w *Writer) record(ts time.Time, subtype uint16, b []byte) error {
	binary.BigEndian.PutUint32(b[0:4], uint32(ts.Unix()))
	binary.BigEndian.PutUint16(b[4:6], typeBGP4MP)
	binary.BigEndian.PutUint16(b[6:8], subtype)
	binary.BigEndian.PutUint32(b[8:12], uint32(len(b)-12))
	w.buf = b
	_, err := w.w.Write(b)
	return err
}

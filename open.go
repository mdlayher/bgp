package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	// version is the BGP version implemented by this package, BGP-4.
	version = 4

	// asTrans is the reserved ASN AS_TRANS, sent in the fixed 2 byte ASN
	// field of an OPEN message when a speaker's ASN cannot fit in 2 bytes,
	// as described in RFC 6793.
	asTrans = 23456

	// paramCapabilities is the OPEN optional parameter type for capabilities,
	// as described in RFC 5492.
	paramCapabilities = 2
)

// An Open is a BGP OPEN message, the first message sent by each peer after a
// connection is established, as described in RFC 4271, section 4.2.
type Open struct {
	// ASN is the speaker's autonomous system number. Four byte ASNs (RFC
	// 6793) are handled natively: marshaling generates the Four-Octet AS
	// Number capability and parsing consumes it, so it must not appear in
	// Capabilities.
	ASN uint32

	// HoldTime proposes the session's hold time. It must be zero or at
	// least 3 seconds, and is truncated to a whole number of seconds on
	// the wire.
	HoldTime time.Duration

	// ID is the speaker's BGP identifier, unique within an autonomous
	// system; see [Identifier].
	ID Identifier

	// Capabilities advertises the speaker's optional capabilities, as
	// described in RFC 5492.
	Capabilities []Capability

	// fourOctet records whether a parsed OPEN carried the Four-Octet AS
	// Number capability, which parseOpen consumes; see [Open.ASN]. A session
	// must reject a speaker without it, since ASN is otherwise ambiguous
	// for four byte values. Meaningful only on an Open produced by
	// ParseMessage.
	fourOctet bool
}

func (*Open) messageType() MessageType { return MessageTypeOpen }

// AppendBinary implements encoding.BinaryAppender.
func (o *Open) AppendBinary(b []byte) ([]byte, error) {
	if o.HoldTime != 0 && o.HoldTime < 3*time.Second {
		return nil, fmt.Errorf("bgp: OPEN hold time must be zero or at least 3 seconds: %s", o.HoldTime)
	}

	holdTime := o.HoldTime / time.Second
	if holdTime > math.MaxUint16 {
		return nil, fmt.Errorf("bgp: OPEN hold time too large: %s", o.HoldTime)
	}

	// RFC 6286, section 2.1: an identifier must be nonzero.
	if o.ID == 0 {
		return nil, errors.New("bgp: OPEN BGP identifier must be nonzero")
	}

	// A 2 byte ASN is sent as-is. A larger ASN is replaced by the AS_TRANS
	// placeholder, and conveyed in full by the Four-Octet AS Number
	// capability, which is always advertised.
	wireASN := o.ASN
	if wireASN > math.MaxUint16 {
		wireASN = asTrans
	}

	caps, err := appendCapability(nil, Capability{
		Code: CapabilityFourOctetAS,
		Data: binary.BigEndian.AppendUint32(nil, o.ASN),
	})
	if err != nil {
		return nil, err
	}

	for _, c := range o.Capabilities {
		if c.Code == CapabilityFourOctetAS {
			return nil, errors.New("bgp: OPEN Four-Octet AS Number capability is generated automatically and must not be set")
		}

		caps, err = appendCapability(caps, c)
		if err != nil {
			return nil, err
		}
	}

	// All capabilities reside in a single Capabilities optional parameter,
	// and the one-byte total optional parameters length below also counts
	// that parameter's own type and length bytes.
	if len(caps) > math.MaxUint8-2 {
		return nil, errors.New("bgp: OPEN capabilities too large")
	}

	b, off := appendHeader(b, MessageTypeOpen)
	b = append(b, version)
	b = binary.BigEndian.AppendUint16(b, uint16(wireASN))
	b = binary.BigEndian.AppendUint16(b, uint16(holdTime))
	b = binary.BigEndian.AppendUint32(b, uint32(o.ID))
	b = append(b, byte(len(caps)+2), paramCapabilities, byte(len(caps)))
	b = append(b, caps...)
	return finishMessage(b, off)
}

// parseOpen parses the body of an OPEN message.
func parseOpen(b []byte) (*Open, error) {
	if len(b) < 10 {
		return nil, badLength(len(b), "OPEN message too short: %d byte body", len(b))
	}

	if v := b[0]; v != version {
		// The diagnostic data is the largest version this package supports,
		// per RFC 4271, section 6.2.
		return nil, openError(SubcodeUnsupportedVersionNumber, []byte{0, version},
			"unsupported BGP version %d", v)
	}

	o := &Open{
		ASN:      uint32(binary.BigEndian.Uint16(b[1:3])),
		HoldTime: time.Duration(binary.BigEndian.Uint16(b[3:5])) * time.Second,
		ID:       Identifier(binary.BigEndian.Uint32(b[5:9])),
	}

	// RFC 4271, section 6.2: hold times of 1 or 2 seconds must be rejected.
	if o.HoldTime != 0 && o.HoldTime < 3*time.Second {
		return nil, openError(SubcodeUnacceptableHoldTime, nil,
			"OPEN hold time must be zero or at least 3 seconds: %s", o.HoldTime)
	}

	// RFC 6286, section 2.1: an identifier must be nonzero.
	if o.ID == 0 {
		return nil, openError(SubcodeBadBGPIdentifier, nil,
			"OPEN BGP identifier must be nonzero")
	}

	if int(b[9]) != len(b[10:]) {
		return nil, openError(0, nil, "OPEN optional parameters length mismatch")
	}

	if err := o.parseParams(b[10:]); err != nil {
		return nil, err
	}

	return o, nil
}

// parseParams parses an OPEN's optional parameters into o. Capabilities are
// the only supported parameter type.
func (o *Open) parseParams(params []byte) error {
	for len(params) > 0 {
		if len(params) < 2 {
			return openError(0, nil, "OPEN optional parameter truncated")
		}

		typ, n := params[0], int(params[1])
		if len(params[2:]) < n {
			return openError(0, nil, "OPEN optional parameter truncated")
		}

		if typ != paramCapabilities {
			return openError(SubcodeUnsupportedOptionalParameter, nil,
				"unsupported OPEN optional parameter %d", typ)
		}

		if err := o.parseCapabilities(params[2 : 2+n]); err != nil {
			return err
		}

		params = params[2+n:]
	}

	return nil
}

// parseCapabilities parses the contents of one Capabilities optional
// parameter into o.
func (o *Open) parseCapabilities(caps []byte) error {
	for len(caps) > 0 {
		if len(caps) < 2 {
			return openError(0, nil, "OPEN capability truncated")
		}

		code, n := CapabilityCode(caps[0]), int(caps[1])
		if len(caps[2:]) < n {
			return openError(0, nil, "OPEN capability truncated")
		}

		c := Capability{Code: code, Data: caps[2 : 2+n : 2+n]}
		if code == CapabilityFourOctetAS {
			// Consume the speaker's 4 byte ASN directly; see [Open.ASN].
			if n != 4 {
				return openError(0, nil, "invalid Four-Octet AS Number capability")
			}

			o.ASN = binary.BigEndian.Uint32(c.Data)
			o.fourOctet = true
		} else {
			o.Capabilities = append(o.Capabilities, c)
		}

		caps = caps[2+n:]
	}

	return nil
}

// A CapabilityCode identifies the type of a Capability.
type CapabilityCode uint8

// CapabilityCode values, as assigned by IANA.
const (
	CapabilityMultiprotocol   CapabilityCode = 1
	CapabilityRouteRefresh    CapabilityCode = 2
	CapabilityExtendedNextHop CapabilityCode = 5
	CapabilityGracefulRestart CapabilityCode = 64
	CapabilityFourOctetAS     CapabilityCode = 65
	CapabilityAddPath         CapabilityCode = 69
	CapabilityFQDN            CapabilityCode = 73
)

// A Capability is a BGP capability in raw binary form, advertised in an Open
// message, as described in RFC 5492.
//
// When produced by ParseMessage, Data references the input buffer rather
// than copying it; see [ParseMessage].
type Capability struct {
	Code CapabilityCode
	Data []byte
}

// MultiprotocolCapability produces a Capability which advertises support for
// the address family f, as described in RFC 4760.
func MultiprotocolCapability(f Family) Capability {
	data := binary.BigEndian.AppendUint16(make([]byte, 0, 4), uint16(f.AFI))
	data = append(data, 0, byte(f.SAFI))
	return Capability{Code: CapabilityMultiprotocol, Data: data}
}

// Multiprotocol parses the address family advertised by a
// CapabilityMultiprotocol Capability.
func (c Capability) Multiprotocol() (Family, error) {
	if c.Code != CapabilityMultiprotocol {
		return Family{}, fmt.Errorf("bgp: capability %d is not a multiprotocol capability", uint8(c.Code))
	}

	if len(c.Data) != 4 {
		return Family{}, errors.New("bgp: invalid multiprotocol capability")
	}

	return Family{
		AFI:  AFI(binary.BigEndian.Uint16(c.Data[0:2])),
		SAFI: SAFI(c.Data[3]),
	}, nil
}

// ExtendedNextHopCapability produces a Capability which advertises the
// ability to receive routes for each address family in fs with an IPv6 next
// hop, as described in RFC 8950.
func ExtendedNextHopCapability(fs ...Family) Capability {
	data := make([]byte, 0, 6*len(fs))
	for _, f := range fs {
		data = binary.BigEndian.AppendUint16(data, uint16(f.AFI))
		data = binary.BigEndian.AppendUint16(data, uint16(f.SAFI))
		data = binary.BigEndian.AppendUint16(data, uint16(AFIIPv6))
	}

	return Capability{Code: CapabilityExtendedNextHop, Data: data}
}

// ExtendedNextHop parses the address families for which a
// CapabilityExtendedNextHop Capability advertises IPv6 next hop support, as
// described in RFC 8950. The result is the families
// ExtendedNextHopCapability was given, after a wire round trip.
//
// A nil result is a well-formed capability advertising no families. Entries
// naming a next hop AFI other than IPv6 are skipped: RFC 8950 defines no
// such entries.
func (c Capability) ExtendedNextHop() ([]Family, error) {
	if c.Code != CapabilityExtendedNextHop {
		return nil, fmt.Errorf("bgp: capability %d is not an extended next hop capability", uint8(c.Code))
	}

	if len(c.Data)%6 != 0 {
		return nil, errors.New("bgp: invalid extended next hop capability")
	}

	var fams []Family
	for d := c.Data; len(d) > 0; d = d[6:] {
		// Each entry is an AFI, SAFI, and next hop AFI triple. RFC 8950
		// defines the capability for IPv6 next hops only, so an entry
		// naming any other next hop AFI is undefined and is skipped
		// rather than reported.
		if AFI(binary.BigEndian.Uint16(d[4:6])) != AFIIPv6 {
			continue
		}

		fams = append(fams, Family{
			AFI:  AFI(binary.BigEndian.Uint16(d[0:2])),
			SAFI: SAFI(binary.BigEndian.Uint16(d[2:4])),
		})
	}

	return fams, nil
}

// maxRestartTime is the largest restart time the graceful restart
// capability's 12 bit whole-seconds field can carry (RFC 4724, section 3).
const maxRestartTime = 4095 * time.Second

// A GracefulRestart is the decoded content of a graceful restart capability
// (RFC 4724, with the RFC 8538 N bit): a speaker's restart claims and the
// families whose forwarding state it preserves. This package carries the
// negotiation surface only. The behavior the capability negotiates, such as
// retaining a restarting peer's routes as stale, running the restart timer,
// and sweeping on End-of-RIB, belongs to the caller's RIB.
type GracefulRestart struct {
	// Restarting is the Restart State (R) bit: the speaker has restarted,
	// and this session is its first since.
	Restarting bool

	// NotificationSupport is the N bit (RFC 8538): the speaker supports
	// graceful restart procedures across sessions ended by a NOTIFICATION,
	// Hard Reset excepted.
	NotificationSupport bool

	// RestartTime is how long the peer should retain this speaker's routes
	// while it is away: whole seconds, at most 4095, per the 12 bit wire
	// field.
	RestartTime time.Duration

	// Families lists the families the speaker claims forwarding state for.
	Families []GracefulRestartFamily
}

// A GracefulRestartFamily is one family entry of a graceful restart
// capability: an address family, and the speaker's claim that its forwarding
// state for the family survived the restart (the F bit).
type GracefulRestartFamily struct {
	Family              Family
	ForwardingPreserved bool
}

// GracefulRestartCapability produces a Capability which advertises graceful
// restart. RestartTime must lie within [0, 4095s], the 12 bit whole-seconds
// wire field, and is truncated to whole seconds.
//
// A Peer or FSM advertises graceful restart through its configuration's
// GracefulRestart field, not by placing this Capability in Capabilities: the
// Restart State bit varies per session attempt, so the FSM owns the encoding.
func GracefulRestartCapability(gr GracefulRestart) (Capability, error) {
	secs := gr.RestartTime / time.Second
	if secs < 0 || secs > maxRestartTime/time.Second {
		return Capability{}, fmt.Errorf("bgp: graceful restart time must be within [0, %s]: %s", maxRestartTime, gr.RestartTime)
	}

	b := binary.BigEndian.AppendUint16(make([]byte, 0, 2+4*len(gr.Families)), uint16(secs))
	if gr.Restarting {
		b[0] |= 0x80
	}

	if gr.NotificationSupport {
		b[0] |= 0x40
	}

	for _, f := range gr.Families {
		b = binary.BigEndian.AppendUint16(b, uint16(f.Family.AFI))
		var flags byte
		if f.ForwardingPreserved {
			flags = 0x80
		}

		b = append(b, byte(f.Family.SAFI), flags)
	}

	return Capability{Code: CapabilityGracefulRestart, Data: b}, nil
}

// GracefulRestart parses the content of a CapabilityGracefulRestart
// Capability. The returned value never references Data, so it remains valid
// after the buffer Data references is reused.
func (c Capability) GracefulRestart() (GracefulRestart, error) {
	if c.Code != CapabilityGracefulRestart {
		return GracefulRestart{}, fmt.Errorf("bgp: capability %d is not a graceful restart capability", uint8(c.Code))
	}

	if len(c.Data) < 2 || (len(c.Data)-2)%4 != 0 {
		return GracefulRestart{}, errors.New("bgp: invalid graceful restart capability")
	}

	gr := GracefulRestart{
		Restarting:          c.Data[0]&0x80 != 0,
		NotificationSupport: c.Data[0]&0x40 != 0,
		RestartTime:         time.Duration(binary.BigEndian.Uint16(c.Data[0:2])&0x0fff) * time.Second,
	}

	for d := c.Data[2:]; len(d) > 0; d = d[4:] {
		gr.Families = append(gr.Families, GracefulRestartFamily{
			Family: Family{
				AFI:  AFI(binary.BigEndian.Uint16(d[0:2])),
				SAFI: SAFI(d[2]),
			},
			ForwardingPreserved: d[3]&0x80 != 0,
		})
	}

	return gr, nil
}

// An AddPathFamily is one family entry of an add-path capability (RFC
// 7911): an address family, and the directions in which the speaker is able
// to use multiple paths for it. In a Session's negotiated result the
// directions are what actually applies to this speaker; see
// [Session.AddPath].
type AddPathFamily struct {
	// Family is the address family.
	Family Family

	// Send reports the ability to send multiple paths for the family:
	// NLRI entries carrying path identifiers.
	Send bool

	// Receive reports the ability to receive multiple paths for the
	// family.
	Receive bool
}

// AddPathCapability produces a Capability which advertises the add-path
// extension (RFC 7911) for the given families. Every entry must name at
// least one direction: the wire encodes nothing else.
//
// An FSM or Peer advertises add-path through Identity.AddPath, not by
// placing this Capability in Capabilities: negotiation must know the
// configured directions to produce [Session.AddPath].
func AddPathCapability(fs ...AddPathFamily) (Capability, error) {
	b := make([]byte, 0, 4*len(fs))
	for _, f := range fs {
		if !f.Send && !f.Receive {
			return Capability{}, fmt.Errorf("bgp: add-path family %s must name at least one direction", f.Family)
		}

		b = binary.BigEndian.AppendUint16(b, uint16(f.Family.AFI))
		b = append(b, byte(f.Family.SAFI))

		var sr byte
		if f.Receive {
			sr |= 1
		}

		if f.Send {
			sr |= 2
		}

		b = append(b, sr)
	}

	return Capability{Code: CapabilityAddPath, Data: b}, nil
}

// AddPath parses the families and directions a CapabilityAddPath Capability
// advertises, as described in RFC 7911, section 4. The result never
// references Data, so it remains valid after the buffer Data references is
// reused.
func (c Capability) AddPath() ([]AddPathFamily, error) {
	if c.Code != CapabilityAddPath {
		return nil, fmt.Errorf("bgp: capability %d is not an add-path capability", uint8(c.Code))
	}

	if len(c.Data)%4 != 0 {
		return nil, errors.New("bgp: invalid add-path capability")
	}

	fs := make([]AddPathFamily, 0, len(c.Data)/4)
	for d := c.Data; len(d) > 0; d = d[4:] {
		sr := d[3]
		if sr == 0 || sr > 3 {
			return nil, fmt.Errorf("bgp: invalid add-path capability send/receive value %d", sr)
		}

		fs = append(fs, AddPathFamily{
			Family: Family{
				AFI:  AFI(binary.BigEndian.Uint16(d[0:2])),
				SAFI: SAFI(d[2]),
			},
			Send:    sr&2 != 0,
			Receive: sr&1 != 0,
		})
	}

	return fs, nil
}

// FQDNCapability produces a Capability which advertises the speaker's
// hostname and domain name, as described in
// draft-walton-bgp-hostname-capability-02. The wire encoding is two
// length-prefixed UTF-8 strings, with lengths in bytes. Either string may
// be empty. FQDNCapability fails when a string cannot fit its one-byte
// length.
//
// The capability is cosmetic: the draft says it SHOULD only be used to
// display a speaker's name when troubleshooting, and nothing in this
// package reads it beyond the codec.
func FQDNCapability(hostname, domain string) (Capability, error) {
	if 2+len(hostname)+len(domain) > math.MaxUint8 {
		return Capability{}, fmt.Errorf("bgp: FQDN capability hostname and domain name too large: %d bytes", len(hostname)+len(domain))
	}

	b := make([]byte, 0, 2+len(hostname)+len(domain))
	b = append(b, byte(len(hostname)))
	b = append(b, hostname...)
	b = append(b, byte(len(domain)))
	b = append(b, domain...)
	return Capability{Code: CapabilityFQDN, Data: b}, nil
}

// FQDN parses the hostname and domain name a CapabilityFQDN Capability
// carries. The returned strings never reference Data, so they remain valid
// after the buffer Data references is reused.
func (c Capability) FQDN() (hostname, domain string, err error) {
	if c.Code != CapabilityFQDN {
		return "", "", fmt.Errorf("bgp: capability %d is not an FQDN capability", uint8(c.Code))
	}

	// Two length-prefixed strings, and nothing after them.
	d := c.Data
	if len(d) < 1 || len(d) < 1+int(d[0]) {
		return "", "", errors.New("bgp: invalid FQDN capability")
	}

	hostname, d = string(d[1:1+int(d[0])]), d[1+int(d[0]):]

	if len(d) < 1 || len(d) != 1+int(d[0]) {
		return "", "", errors.New("bgp: invalid FQDN capability")
	}

	return hostname, string(d[1:]), nil
}

// appendCapability appends the wire encoding of c to b.
func appendCapability(b []byte, c Capability) ([]byte, error) {
	if len(c.Data) > math.MaxUint8 {
		return nil, fmt.Errorf("bgp: capability %d data too large: %d bytes", uint8(c.Code), len(c.Data))
	}

	b = append(b, byte(c.Code), byte(len(c.Data)))
	return append(b, c.Data...), nil
}

// mustAppendCapability appends the wire encoding of a locally generated,
// fixed-size capability, whose data always fits: an error is an invariant
// violation in this package, not an input. Caller-supplied capabilities go
// through appendCapability, whose error reaches the caller.
func mustAppendCapability(b []byte, c Capability) []byte {
	b, err := appendCapability(b, c)
	if err != nil {
		panic(err)
	}

	return b
}

// Fuzz targets for the package's wire codecs, organized in decode order:
// whole messages, the framed read path, attributes, and capabilities.
package bgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func FuzzParseMessage(f *testing.F) {
	// Seed with a valid encoding of every message type, plus real UPDATE
	// messages captured from a route collector.
	seeds := []Message{
		&Keepalive{},
		&Open{
			ASN:      65536,
			HoldTime: 90 * time.Second,
			ID:       MustParseIdentifier("192.0.2.1"),
			Capabilities: []Capability{
				MultiprotocolCapability(Family{AFI: AFIIPv6, SAFI: SAFIUnicast}),
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

	for _, m := range seeds {
		b, err := m.AppendBinary(nil)
		if err != nil {
			f.Fatalf("failed to marshal seed: %v", err)
		}

		f.Add(b)
	}

	for _, b := range corpusSeeds(f) {
		f.Add(b)
	}

	// Each RIB dump attribute sample rides in a minimal synthetic UPDATE,
	// so message level fuzzing also starts from the rare attribute types a
	// full internet table carries.
	for _, a := range ribSeeds(f) {
		ab, err := appendRawAttribute(nil, a)
		if err != nil {
			f.Fatalf("failed to marshal RIB seed attribute: %v", err)
		}

		b := bytes.Repeat([]byte{0xff}, markerLen)
		b = append(b, 0, 0, byte(MessageTypeUpdate))
		b = binary.BigEndian.AppendUint16(b, 0) // withdrawn routes length
		b = binary.BigEndian.AppendUint16(b, uint16(len(ab)))
		b = append(b, ab...)
		binary.BigEndian.PutUint16(b[markerLen:markerLen+2], uint16(len(b)))
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMessage(b)
		if err != nil {
			if m != nil {
				t.Fatal("non-nil Message with non-nil error")
			}

			// Any MessageError must describe a NOTIFICATION which itself
			// marshals, so a session can always answer the peer.
			if merr, ok := errors.AsType[*MessageError](err); ok {
				if _, err := merr.Notification().AppendBinary(nil); err != nil {
					t.Fatalf("failed to marshal error NOTIFICATION: %v", err)
				}
			}

			return
		}

		// Parse must be a fixed point of marshaling: parsing the marshaled
		// form of a parsed message reproduces both the message and the bytes.
		b1, err := m.AppendBinary(nil)
		if err != nil {
			// A parsed message need not re-marshal: for example, an OPEN may
			// spread more capabilities across multiple optional parameters
			// than fit in the single parameter this package generates.
			t.Skip("parsed message does not re-marshal")
		}

		m2, err := ParseMessage(b1)
		if err != nil {
			t.Fatalf("failed to re-parse marshaled message: %v", err)
		}

		if d := diff(t, m, m2); d != "" {
			t.Fatalf("unexpected re-parsed message (-want +got):\n%s", d)
		}

		b2, err := m2.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to re-marshal message: %v", err)
		}

		if !bytes.Equal(b1, b2) {
			t.Fatalf("marshaling is not idempotent:\n b1: %x\n b2: %x", b1, b2)
		}
	})
}

// FuzzParseMessageAddPath is FuzzParseMessage under a session's add-path
// receive set: every input parses as if add-path were negotiated for both
// prefix shaped families, so the path identifier decode paths and the
// attribute marking run against arbitrary bytes.
func FuzzParseMessageAddPath(f *testing.F) {
	addPath := []Family{
		{AFI: AFIIPv4, SAFI: SAFIUnicast},
		{AFI: AFIIPv6, SAFI: SAFIUnicast},
	}

	apCap, err := AddPathCapability(AddPathFamily{
		Family:  Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
		Send:    true,
		Receive: true,
	})
	if err != nil {
		f.Fatalf("failed to build add-path capability: %v", err)
	}

	// Seed with valid add-path encodings of both wire forms, the top level
	// IPv4 unicast path fields and PathPrefixes in multiprotocol
	// attributes, plus an OPEN carrying the capability.
	seeds := []Message{
		&Update{
			WithdrawnPaths: PathPrefixes{
				{ID: 1, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			},
			Attributes: mustAttributes(f, OriginIGP, ASPath{{ASNs: []uint32{64496}}}),
			NLRIPaths: PathPrefixes{
				{ID: 1, Prefix: netip.MustParsePrefix("203.0.113.0/24")},
				{ID: 2, Prefix: netip.MustParsePrefix("203.0.113.0/24")},
			},
		},
		&Update{
			Attributes: mustAttributes(f, MPReachNLRI{
				Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NextHop: netip.MustParseAddr("2001:db8::1"),
				NLRI: PathPrefixes{
					{ID: 7, Prefix: netip.MustParsePrefix("2001:db8::/32")},
				},
			}),
		},
		&Update{
			Attributes: mustAttributes(f, MPUnreachNLRI{
				Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
				NLRI: PathPrefixes{
					{ID: 0, Prefix: netip.MustParsePrefix("2001:db8::/32")},
				},
			}),
		},
		&Open{
			ASN:          64496,
			HoldTime:     90 * time.Second,
			ID:           MustParseIdentifier("192.0.2.1"),
			Capabilities: []Capability{apCap},
		},
	}

	for _, m := range seeds {
		b, err := m.AppendBinary(nil)
		if err != nil {
			f.Fatalf("failed to marshal seed: %v", err)
		}

		f.Add(b)
	}

	// The route collector corpus is plain form; under the receive set it
	// parses as path form, exercising robustness against reinterpreted
	// real-world bytes.
	for _, b := range corpusSeeds(f) {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseMessageAddPath(b, addPath)
		if err != nil {
			if m != nil {
				t.Fatal("non-nil Message with non-nil error")
			}

			// Any MessageError must describe a NOTIFICATION which itself
			// marshals, so a session can always answer the peer.
			if merr, ok := errors.AsType[*MessageError](err); ok {
				if _, err := merr.Notification().AppendBinary(nil); err != nil {
					t.Fatalf("failed to marshal error NOTIFICATION: %v", err)
				}
			}

			return
		}

		if u, ok := m.(*Update); ok {
			// A parse under the receive set must never fill a plain IPv4
			// unicast top level field.
			if len(u.Withdrawn) > 0 || len(u.NLRI) > 0 {
				t.Fatal("plain top level field filled despite add-path receive set")
			}

			// Typed parsing under the add-path mark is reachable only with
			// session context, so FuzzRawAttributeParse cannot cover it:
			// parse every attribute here, requiring the usual error shape.
			for _, a := range u.Attributes {
				if _, err := a.Parse(); err != nil {
					if merr, ok := errors.AsType[*MessageError](err); ok {
						if _, err := merr.Notification().AppendBinary(nil); err != nil {
							t.Fatalf("failed to marshal error NOTIFICATION: %v", err)
						}
					}
				}
			}
		}

		// Parse must be a fixed point of marshaling under the same receive
		// set, exactly as in FuzzParseMessage.
		b1, err := m.AppendBinary(nil)
		if err != nil {
			t.Skip("parsed message does not re-marshal")
		}

		m2, err := ParseMessageAddPath(b1, addPath)
		if err != nil {
			t.Fatalf("failed to re-parse marshaled message: %v", err)
		}

		if d := diff(t, m, m2); d != "" {
			t.Fatalf("unexpected re-parsed message (-want +got):\n%s", d)
		}

		b2, err := m2.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to re-marshal message: %v", err)
		}

		if !bytes.Equal(b1, b2) {
			t.Fatalf("marshaling is not idempotent:\n b1: %x\n b2: %x", b1, b2)
		}
	})
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

func FuzzRawAttributeParse(f *testing.F) {
	// Seed with the canonical encoding of every known attribute type, plus
	// real attributes from the route collector corpus.
	seeds := []Attribute{
		OriginIGP,
		ASPath{{ASNs: []uint32{64496, 65536}}, {Set: true, ASNs: []uint32{64497}}},
		NextHop(netip.MustParseAddr("192.0.2.1")),
		MED(100),
		LocalPref(200),
		AtomicAggregate{},
		Aggregator{ASN: 64496, ID: MustParseIdentifier("192.0.2.1")},
		Communities{NewCommunity(64496, 100)},
		OriginatorID(MustParseIdentifier("192.0.2.1")),
		ClusterList{MustParseIdentifier("192.0.2.2")},
		ExtendedCommunities{{0x00, 0x02, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x64}},
		LargeCommunities{{Global: 65536, Local1: 1, Local2: 2}},
		OTC(64496),
		MPReachNLRI{
			Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    Prefixes{netip.MustParsePrefix("2001:db8::/32")},
		},
		MPUnreachNLRI{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}},
		MPReachNLRI{
			Family:  Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
			NextHop: netip.MustParseAddr("192.0.2.1"),
			NLRI: EVPNRoutes{{
				Type:  EVPNRouteEthernetSegment,
				Value: []byte{0x00, 0x02, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x01},
			}},
		},
		MPUnreachNLRI{
			Family: Family{AFI: AFIL2VPN, SAFI: SAFIVPLS},
			NLRI:   RawNLRI{0x00, 0x03, 0xde, 0xad, 0xbe},
		},
		MPReachNLRI{
			Family:  Family{AFI: AFIIPv4, SAFI: SAFIMPLSVPN},
			NextHop: netip.MustParseAddr("192.0.2.1"),
			NLRI:    RawNLRI{112, 0x00, 0x01, 0x31, 0x00, 0x00, 0xfb, 0xf0, 0x00, 0x00, 0x00, 0x01, 192, 0, 2},
		},
	}

	ras, err := MarshalAttributes(seeds...)
	if err != nil {
		f.Fatalf("failed to marshal seeds: %v", err)
	}

	for _, a := range ras {
		f.Add(uint8(a.Flags), uint8(a.Type), a.Data)
	}

	for _, b := range corpusSeeds(f) {
		m, err := ParseMessage(b)
		if err != nil {
			f.Fatalf("failed to parse corpus message: %v", err)
		}

		if u, ok := m.(*Update); ok {
			for _, a := range u.Attributes {
				f.Add(uint8(a.Flags), uint8(a.Type), a.Data)
			}
		}
	}

	// Full-table RIB dump samples carry the rare and deprecated attribute
	// types the updates corpus lacks, plus RFC 6396's truncated
	// MP_REACH_NLRI form.
	for _, a := range ribSeeds(f) {
		f.Add(uint8(a.Flags), uint8(a.Type), a.Data)
	}

	f.Fuzz(func(t *testing.T, flags, typ uint8, data []byte) {
		a := RawAttribute{Flags: AttrFlags(flags), Type: AttrType(typ), Data: data}

		attr, err := a.Parse()
		if err != nil {
			// Any MessageError must be an UPDATE Message Error whose
			// NOTIFICATION marshals, so a session can always answer the peer.
			if merr, ok := errors.AsType[*MessageError](err); ok {
				if merr.Code != NotificationUpdateMessageError {
					t.Fatalf("unexpected NOTIFICATION code: %s", merr.Code)
				}

				if _, err := merr.Notification().AppendBinary(nil); err != nil {
					t.Fatalf("failed to marshal error NOTIFICATION: %v", err)
				}
			}

			return
		}

		// A parsed Attribute must never reference the input: scrambling the
		// input must not change how the attribute compares against a copy
		// parsed before the scramble.
		want, err := RawAttribute{
			Flags: a.Flags,
			Type:  a.Type,
			Data:  bytes.Clone(data),
		}.Parse()
		if err != nil {
			t.Fatalf("failed to parse cloned attribute: %v", err)
		}

		for i := range data {
			data[i] = ^data[i]
		}

		if d := diff(t, want, attr); d != "" {
			t.Fatalf("parsed attribute references its input (-want +got):\n%s", d)
		}

		// Parse must be a fixed point of marshaling, and a parsed Attribute
		// must always re-marshal.
		ras, err := MarshalAttributes(attr)
		if err != nil {
			t.Fatalf("failed to marshal parsed attribute: %v", err)
		}

		attr2, err := ras[0].Parse()
		if err != nil {
			t.Fatalf("failed to re-parse marshaled attribute: %v", err)
		}

		if d := diff(t, attr, attr2); d != "" {
			t.Fatalf("unexpected re-parsed attribute (-want +got):\n%s", d)
		}
	})
}

// FuzzCapabilityParse fuzzes every capability decoder through one dispatch
// on the capability code: anything a decoder accepts must re-encode through
// its constructor and parse back equal. Byte equality is not required,
// since the decoders drop reserved bits a constructor never sets.
func FuzzCapabilityParse(f *testing.F) {
	apCap, err := AddPathCapability(
		AddPathFamily{
			Family:  Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
			Send:    true,
			Receive: true,
		},
		AddPathFamily{
			Family:  Family{AFI: AFIIPv6, SAFI: SAFIUnicast},
			Receive: true,
		},
	)
	if err != nil {
		f.Fatalf("failed to build add-path capability: %v", err)
	}

	grCap, err := GracefulRestartCapability(GracefulRestart{
		Restarting:          true,
		NotificationSupport: true,
		RestartTime:         120 * time.Second,
		Families: []GracefulRestartFamily{
			{Family: Family{AFI: AFIIPv4, SAFI: SAFIUnicast}, ForwardingPreserved: true},
		},
	})
	if err != nil {
		f.Fatalf("failed to build graceful restart capability: %v", err)
	}

	fqdnCap, err := FQDNCapability("speaker", "example.com")
	if err != nil {
		f.Fatalf("failed to build FQDN capability: %v", err)
	}

	// Seed with a canonical encoding of every decodable capability, so
	// each dispatch arm starts from valid bytes, plus a truncated one.
	seeds := []Capability{
		MultiprotocolCapability(Family{AFI: AFIIPv6, SAFI: SAFIUnicast}),
		ExtendedNextHopCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
		grCap,
		apCap,
		fqdnCap,
		{Code: CapabilityRouteRefresh},
		{Code: CapabilityAddPath, Data: apCap.Data[:3]},
	}

	for _, c := range seeds {
		f.Add(uint8(c.Code), c.Data)
	}

	f.Fuzz(func(t *testing.T, code uint8, data []byte) {
		c := Capability{Code: CapabilityCode(code), Data: data}

		switch c.Code {
		case CapabilityMultiprotocol:
			v, err := c.Multiprotocol()
			if err != nil {
				return
			}

			v2, err := MultiprotocolCapability(v).Multiprotocol()
			if err != nil {
				t.Fatalf("failed to re-parse multiprotocol capability: %v", err)
			}

			if v != v2 {
				t.Fatalf("multiprotocol capability did not round trip: %v != %v", v, v2)
			}
		case CapabilityExtendedNextHop:
			fs, err := c.ExtendedNextHop()
			if err != nil {
				return
			}

			fs2, err := ExtendedNextHopCapability(fs...).ExtendedNextHop()
			if err != nil {
				t.Fatalf("failed to re-parse extended next hop capability: %v", err)
			}

			if !slices.Equal(fs, fs2) {
				t.Fatalf("extended next hop capability did not round trip:\n first: %+v\nsecond: %+v", fs, fs2)
			}
		case CapabilityGracefulRestart:
			gr, err := c.GracefulRestart()
			if err != nil {
				return
			}

			c2, err := GracefulRestartCapability(gr)
			if err != nil {
				t.Fatalf("parsed graceful restart failed to re-encode: %v", err)
			}

			gr2, err := c2.GracefulRestart()
			if err != nil {
				t.Fatalf("failed to re-parse graceful restart capability: %v", err)
			}

			if d := diff(t, gr, gr2); d != "" {
				t.Fatalf("graceful restart capability did not round trip (-want +got):\n%s", d)
			}
		case CapabilityAddPath:
			fs, err := c.AddPath()
			if err != nil {
				return
			}

			c2, err := AddPathCapability(fs...)
			if err != nil {
				t.Fatalf("parsed add-path families failed to re-encode: %v", err)
			}

			fs2, err := c2.AddPath()
			if err != nil {
				t.Fatalf("failed to re-parse add-path capability: %v", err)
			}

			if !slices.Equal(fs, fs2) {
				t.Fatalf("add-path capability did not round trip:\n first: %+v\nsecond: %+v", fs, fs2)
			}
		case CapabilityFQDN:
			hostname, domain, err := c.FQDN()
			if err != nil {
				return
			}

			// A real capability's one-byte wire length caps Data at 255
			// bytes. FQDN accepts longer constructed data whose strings
			// FQDNCapability then rightly refuses to fit, so only
			// wire-sized data is required to round trip.
			if len(data) > math.MaxUint8 {
				return
			}

			c2, err := FQDNCapability(hostname, domain)
			if err != nil {
				t.Fatalf("parsed FQDN failed to re-encode: %v", err)
			}

			h2, d2, err := c2.FQDN()
			if err != nil {
				t.Fatalf("failed to re-parse FQDN capability: %v", err)
			}

			if hostname != h2 || domain != d2 {
				t.Fatalf("FQDN capability did not round trip: %q %q != %q %q", hostname, domain, h2, d2)
			}
		}
	})
}

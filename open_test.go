package bgp

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestOpenAppendBinaryWire(t *testing.T) {
	t.Parallel()

	// An ASN which does not fit 2 bytes is sent as AS_TRANS, and conveyed in
	// full by the always-generated Four-Octet AS Number capability.
	o := &Open{
		ASN:      65536,
		HoldTime: 90 * time.Second,
		ID:       MustParseIdentifier("192.0.2.1"),
	}

	b, err := o.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal OPEN: %v", err)
	}

	want := testMessage(MessageTypeOpen, []byte{
		0x04,       // version
		0x5b, 0xa0, // ASN: AS_TRANS
		0x00, 0x5a, // hold time
		192, 0, 2, 1, // BGP identifier
		0x08,       // optional parameters length
		0x02, 0x06, // capabilities parameter
		0x41, 0x04, 0x00, 0x01, 0x00, 0x00, // Four-Octet AS Number
	})
	if d := diff(t, want, b); d != "" {
		t.Fatalf("unexpected OPEN bytes (-want +got):\n%s", d)
	}
}

func TestOpenParseTwoByteASN(t *testing.T) {
	t.Parallel()

	// An OPEN from a speaker which does not advertise the Four-Octet AS
	// Number capability carries its ASN in the fixed 2 byte field only.
	got, err := ParseMessage(testMessage(MessageTypeOpen, []byte{
		0x04,
		0xfb, 0xf0, // ASN 64496
		0x00, 0x5a,
		192, 0, 2, 1,
		0x00, // no optional parameters
	}))
	if err != nil {
		t.Fatalf("failed to parse OPEN: %v", err)
	}

	want := &Open{
		ASN:      64496,
		HoldTime: 90 * time.Second,
		ID:       MustParseIdentifier("192.0.2.1"),
	}

	if d := diff[Message](t, want, got); d != "" {
		t.Fatalf("unexpected OPEN (-want +got):\n%s", d)
	}
}

// TestParseOpenFourOctet pins the fourOctet signal: a parsed OPEN records
// whether the peer advertised the Four-Octet AS Number capability, so a
// session can distinguish a legacy 2 byte speaker from a four-octet speaker
// with a small ASN.
func TestParseOpenFourOctet(t *testing.T) {
	t.Parallel()

	// Marshaling always advertises the capability, so a round trip must
	// report it.
	b, err := (&Open{
		ASN:      64496,
		HoldTime: 90 * time.Second,
		ID:       MustParseIdentifier("192.0.2.1"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal OPEN: %v", err)
	}

	m, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("failed to parse OPEN: %v", err)
	}

	if !m.(*Open).fourOctet {
		t.Fatal("expected fourOctet to be set for a peer with the capability")
	}

	// A legacy speaker without the capability must not report it.
	m, err = ParseMessage(testMessage(MessageTypeOpen, []byte{
		0x04,
		0xfb, 0xf0, // ASN 64496
		0x00, 0x5a,
		192, 0, 2, 1,
		0x00, // no optional parameters
	}))
	if err != nil {
		t.Fatalf("failed to parse legacy OPEN: %v", err)
	}

	if m.(*Open).fourOctet {
		t.Fatal("expected fourOctet to be unset for a peer without the capability")
	}
}

func TestOpenAppendBinaryErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		o    *Open
	}{
		{
			name: "hold time 1s",
			o:    &Open{ASN: 64496, HoldTime: 1 * time.Second, ID: MustParseIdentifier("192.0.2.1")},
		},
		{
			name: "hold time 2s",
			o:    &Open{ASN: 64496, HoldTime: 2 * time.Second, ID: MustParseIdentifier("192.0.2.1")},
		},
		{
			name: "hold time too large",
			o:    &Open{ASN: 64496, HoldTime: 20 * time.Hour, ID: MustParseIdentifier("192.0.2.1")},
		},
		{
			name: "ID zero",
			o:    &Open{ASN: 64496},
		},
		{
			name: "manual four octet capability",
			o: &Open{
				ASN: 64496,
				ID:  MustParseIdentifier("192.0.2.1"),
				Capabilities: []Capability{
					{Code: CapabilityFourOctetAS, Data: []byte{0, 0, 0xfb, 0xf0}},
				},
			},
		},
		{
			name: "capability data too large",
			o: &Open{
				ASN: 64496,
				ID:  MustParseIdentifier("192.0.2.1"),
				Capabilities: []Capability{
					{Code: CapabilityRouteRefresh, Data: make([]byte, 256)},
				},
			},
		},
		{
			name: "capabilities too large",
			o: &Open{
				ASN: 64496,
				ID:  MustParseIdentifier("192.0.2.1"),
				Capabilities: []Capability{
					{Code: CapabilityRouteRefresh, Data: make([]byte, 125)},
					{Code: CapabilityRouteRefresh, Data: make([]byte, 125)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.o.AppendBinary(nil); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestParseOpenErrors(t *testing.T) {
	t.Parallel()

	// body produces an OPEN message body with sane fixed fields and the
	// given optional parameters.
	body := func(params ...byte) []byte {
		b := []byte{
			0x04,       // version
			0xfb, 0xf0, // ASN
			0x00, 0x5a, // hold time
			192, 0, 2, 1, // BGP identifier
			byte(len(params)),
		}

		return append(b, params...)
	}

	tests := []struct {
		name    string
		b       []byte
		code    NotificationCode
		subcode uint8
		data    []byte
	}{
		{
			name:    "short body",
			b:       body()[:9],
			code:    NotificationMessageHeaderError,
			subcode: SubcodeBadMessageLength,
			data:    []byte{0x00, headerLen + 9},
		},
		{
			name: "unsupported version",
			b: func() []byte {
				b := body()
				b[0] = 0x03
				return b
			}(),
			code:    NotificationOpenMessageError,
			subcode: SubcodeUnsupportedVersionNumber,
			data:    []byte{0x00, 0x04},
		},
		{
			name: "hold time 1s",
			b: func() []byte {
				b := body()
				b[3], b[4] = 0x00, 0x01
				return b
			}(),
			code:    NotificationOpenMessageError,
			subcode: SubcodeUnacceptableHoldTime,
		},
		{
			name: "hold time 2s",
			b: func() []byte {
				b := body()
				b[3], b[4] = 0x00, 0x02
				return b
			}(),
			code:    NotificationOpenMessageError,
			subcode: SubcodeUnacceptableHoldTime,
		},
		{
			name: "zero BGP identifier",
			b: func() []byte {
				b := body()
				b[5], b[6], b[7], b[8] = 0, 0, 0, 0
				return b
			}(),
			code:    NotificationOpenMessageError,
			subcode: SubcodeBadBGPIdentifier,
		},
		{
			name: "optional parameters length mismatch",
			b: func() []byte {
				b := body()
				b[9] = 0x04
				return b
			}(),
			code:    NotificationOpenMessageError,
			subcode: 0,
		},
		{
			name:    "optional parameter truncated header",
			b:       body(0x02),
			code:    NotificationOpenMessageError,
			subcode: 0,
		},
		{
			name:    "optional parameter truncated data",
			b:       body(0x02, 0x04, 0x00),
			code:    NotificationOpenMessageError,
			subcode: 0,
		},
		{
			name:    "unsupported optional parameter",
			b:       body(0x01, 0x01, 0x00),
			code:    NotificationOpenMessageError,
			subcode: SubcodeUnsupportedOptionalParameter,
		},
		{
			name:    "capability truncated header",
			b:       body(0x02, 0x01, 0x02),
			code:    NotificationOpenMessageError,
			subcode: 0,
		},
		{
			name:    "capability truncated data",
			b:       body(0x02, 0x03, 0x02, 0x02, 0x00),
			code:    NotificationOpenMessageError,
			subcode: 0,
		},
		{
			name:    "four octet capability bad length",
			b:       body(0x02, 0x04, 0x41, 0x02, 0xfb, 0xf0),
			code:    NotificationOpenMessageError,
			subcode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := ParseMessage(testMessage(MessageTypeOpen, tt.b))
			if m != nil {
				t.Fatalf("expected nil Message, but got: %v", m)
			}

			wantMessageError(t, err, tt.code, tt.subcode, tt.data)
		})
	}
}

func TestCapabilityMultiprotocolRoundTrip(t *testing.T) {
	t.Parallel()

	want := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}
	got, err := MultiprotocolCapability(want).Multiprotocol()
	if err != nil {
		t.Fatalf("failed to parse multiprotocol capability: %v", err)
	}

	if d := diff(t, want, got); d != "" {
		t.Fatalf("unexpected family (-want +got):\n%s", d)
	}
}

func TestCapabilityMultiprotocolErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		c    Capability
	}{
		{
			name: "wrong code",
			c:    Capability{Code: CapabilityRouteRefresh},
		},
		{
			name: "bad length",
			c:    Capability{Code: CapabilityMultiprotocol, Data: []byte{0x00, 0x02}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.c.Multiprotocol(); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func TestExtendedNextHopCapability(t *testing.T) {
	t.Parallel()

	// RFC 8950, section 3: each entry is NLRI AFI, NLRI SAFI, and next hop
	// AFI, all as 2 byte values.
	c := ExtendedNextHopCapability(
		Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
		Family{AFI: AFIIPv4, SAFI: SAFIMulticast},
	)

	want := Capability{
		Code: CapabilityExtendedNextHop,
		Data: []byte{
			0x00, 0x01, 0x00, 0x01, 0x00, 0x02,
			0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
		},
	}

	if d := diff(t, want, c); d != "" {
		t.Fatalf("unexpected capability (-want +got):\n%s", d)
	}

	// The capability must survive an OPEN round trip intact.
	o := &Open{
		ASN:          64496,
		ID:           MustParseIdentifier("192.0.2.1"),
		Capabilities: []Capability{c},
	}

	b, err := o.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal OPEN: %v", err)
	}

	m, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("failed to parse OPEN: %v", err)
	}

	if d := diff[Message](t, o, m); d != "" {
		t.Fatalf("unexpected OPEN (-want +got):\n%s", d)
	}
}

func TestGracefulRestartCapability(t *testing.T) {
	t.Parallel()

	// RFC 4724, section 3, with the RFC 8538 N bit: a 4 bit flags field (R,
	// then N), a 12 bit whole-seconds restart time, then per family an AFI,
	// a SAFI, and a flags byte whose top bit is Forwarding Preserved.
	gr := GracefulRestart{
		Restarting:          true,
		NotificationSupport: true,
		RestartTime:         maxRestartTime,
		Families: []GracefulRestartFamily{
			{Family: Family{AFI: AFIIPv4, SAFI: SAFIUnicast}, ForwardingPreserved: true},
			{Family: Family{AFI: AFIIPv6, SAFI: SAFIUnicast}},
		},
	}

	c := must(GracefulRestartCapability(gr))

	want := Capability{
		Code: CapabilityGracefulRestart,
		Data: []byte{
			0xcf, 0xff, // R, N, restart time 4095s
			0x00, 0x01, 0x01, 0x80, // IPv4 unicast, forwarding preserved
			0x00, 0x02, 0x01, 0x00, // IPv6 unicast
		},
	}

	if d := diff(t, want, c); d != "" {
		t.Fatalf("unexpected capability (-want +got):\n%s", d)
	}

	// The decoder must invert the encoder exactly.
	got, err := c.GracefulRestart()
	if err != nil {
		t.Fatalf("failed to parse capability: %v", err)
	}

	if d := diff(t, gr, got); d != "" {
		t.Fatalf("unexpected graceful restart (-want +got):\n%s", d)
	}

	// The restart time is truncated to the wire's whole-second precision.
	c = must(GracefulRestartCapability(GracefulRestart{RestartTime: 90500 * time.Millisecond}))
	if got := must(c.GracefulRestart()); got.RestartTime != 90*time.Second {
		t.Fatalf("unexpected restart time: got %s, want 90s", got.RestartTime)
	}
}

func TestGracefulRestartCapabilityErrors(t *testing.T) {
	t.Parallel()

	// The 12 bit wire field cannot carry these; they are rejected, never
	// silently clamped.
	for _, d := range []time.Duration{maxRestartTime + time.Second, -time.Second} {
		if _, err := GracefulRestartCapability(GracefulRestart{RestartTime: d}); err == nil {
			t.Fatalf("expected an error for restart time %s, but none occurred", d)
		} else {
			t.Logf("err: %v", err)
		}
	}

	// The decoder rejects other capabilities and malformed data: too short
	// for the header, or a truncated family entry.
	caps := []Capability{
		MultiprotocolCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
		{Code: CapabilityGracefulRestart, Data: []byte{0x00}},
		{Code: CapabilityGracefulRestart, Data: []byte{0x00, 0x00, 0x00, 0x01, 0x01}},
	}

	for _, c := range caps {
		if _, err := c.GracefulRestart(); err == nil {
			t.Fatalf("expected an error for capability %v, but none occurred", c)
		} else {
			t.Logf("err: %v", err)
		}
	}
}

// TestOpenParseFourOctetASWins verifies that a Four-Octet AS Number
// capability overrides the fixed 2 byte ASN field, and is stripped from the
// parsed Capabilities.
func TestOpenParseFourOctetASWins(t *testing.T) {
	t.Parallel()

	b := testMessage(MessageTypeOpen, []byte{
		0x04,
		0x5b, 0xa0, // AS_TRANS
		0x00, 0x5a,
		192, 0, 2, 1,
		0x08,
		0x02, 0x06,
		0x41, 0x04, 0x00, 0x01, 0x00, 0x00, // ASN 65536
	})

	m, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("failed to parse OPEN: %v", err)
	}

	o, ok := m.(*Open)
	if !ok {
		t.Fatalf("expected *Open, but got: %T", m)
	}

	if o.ASN != 65536 {
		t.Fatalf("unexpected ASN: %d", o.ASN)
	}

	if len(o.Capabilities) != 0 {
		t.Fatalf("four octet capability was not stripped: %v", o.Capabilities)
	}
}

// TestOpenHoldTimeMax pins the largest wire hold time.
func TestOpenHoldTimeMax(t *testing.T) {
	t.Parallel()

	o := &Open{
		ASN:      64496,
		HoldTime: 65535 * time.Second,
		ID:       MustParseIdentifier("192.0.2.1"),
	}

	b, err := o.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal OPEN: %v", err)
	}

	if hold := binary.BigEndian.Uint16(b[headerLen+3:]); hold != 65535 {
		t.Fatalf("unexpected wire hold time: %d", hold)
	}
}

func TestCapabilityExtendedNextHop(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		c       Capability
		want    []Family
		wantErr bool
	}{
		{
			name: "round trip",
			c: ExtendedNextHopCapability(
				Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
				Family{AFI: AFIIPv4, SAFI: SAFIMulticast},
			),
			want: []Family{
				{AFI: AFIIPv4, SAFI: SAFIUnicast},
				{AFI: AFIIPv4, SAFI: SAFIMulticast},
			},
		},
		{
			name: "empty",
			c:    ExtendedNextHopCapability(),
		},
		{
			// RFC 8950 defines IPv6 next hops only: an entry naming any
			// other next hop AFI is skipped, not reported.
			name: "other next hop AFI",
			c: Capability{Code: CapabilityExtendedNextHop, Data: []byte{
				0x00, 0x01, 0x00, 0x01, 0x00, 0x01, // IPv4 unicast, IPv4 next hop
				0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // IPv4 unicast, IPv6 next hop
			}},
			want: []Family{{AFI: AFIIPv4, SAFI: SAFIUnicast}},
		},
		{
			name:    "wrong code",
			c:       Capability{Code: CapabilityRouteRefresh},
			wantErr: true,
		},
		{
			name:    "bad length",
			c:       Capability{Code: CapabilityExtendedNextHop, Data: []byte{0x00, 0x01, 0x00, 0x01}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.c.ExtendedNextHop()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, but none occurred")
				}

				return
			}
			if err != nil {
				t.Fatalf("failed to parse extended next hop capability: %v", err)
			}

			if d := diff(t, tt.want, got); d != "" {
				t.Fatalf("unexpected families (-want +got):\n%s", d)
			}
		})
	}
}

func TestFQDNCapability(t *testing.T) {
	t.Parallel()

	// draft-walton-bgp-hostname-capability-02: a length-prefixed UTF-8
	// hostname, then a length-prefixed UTF-8 domain name.
	c := must(FQDNCapability("testbgpd", "example.com"))

	want := Capability{
		Code: CapabilityFQDN,
		Data: []byte{
			0x08, 't', 'e', 's', 't', 'b', 'g', 'p', 'd',
			0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		},
	}

	if d := diff(t, want, c); d != "" {
		t.Fatalf("unexpected capability (-want +got):\n%s", d)
	}

	// The capability must survive an OPEN round trip intact.
	o := &Open{
		ASN:          64496,
		ID:           MustParseIdentifier("192.0.2.1"),
		Capabilities: []Capability{c},
	}

	b, err := o.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal OPEN: %v", err)
	}

	m, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("failed to parse OPEN: %v", err)
	}

	if d := diff[Message](t, o, m); d != "" {
		t.Fatalf("unexpected OPEN (-want +got):\n%s", d)
	}

	// The decoder must invert the encoder exactly.
	hostname, domain, err := c.FQDN()
	if err != nil {
		t.Fatalf("failed to parse capability: %v", err)
	}

	if hostname != "testbgpd" || domain != "example.com" {
		t.Fatalf("unexpected FQDN: got %q / %q", hostname, domain)
	}

	// A bare hostname with an empty domain name is what FRR sends by
	// default.
	hostname, domain, err = must(FQDNCapability("frrdev", "")).FQDN()
	if err != nil {
		t.Fatalf("failed to parse bare hostname capability: %v", err)
	}

	if hostname != "frrdev" || domain != "" {
		t.Fatalf("unexpected bare FQDN: got %q / %q", hostname, domain)
	}
}

func TestFQDNCapabilityErrors(t *testing.T) {
	t.Parallel()

	// The two one-byte length fields and the capability's own one-byte
	// length bound hostname plus domain name to 253 bytes total.
	long := string(make([]byte, 127))
	if _, err := FQDNCapability(long, long); err == nil {
		t.Fatal("expected an error for an oversized FQDN, but none occurred")
	} else {
		t.Logf("err: %v", err)
	}

	// The boundary itself must fit.
	if _, err := FQDNCapability(long, long[:126]); err != nil {
		t.Fatalf("failed to build a maximum-size FQDN capability: %v", err)
	}

	// The decoder rejects other capabilities and malformed data: missing
	// or truncated fields, and trailing bytes.
	caps := []Capability{
		{Code: CapabilityMultiprotocol, Data: []byte{0x00}},
		{Code: CapabilityFQDN, Data: nil},
		{Code: CapabilityFQDN, Data: []byte{0x02, 'a'}},
		{Code: CapabilityFQDN, Data: []byte{0x01, 'a'}},
		{Code: CapabilityFQDN, Data: []byte{0x01, 'a', 0x02, 'b'}},
		{Code: CapabilityFQDN, Data: []byte{0x00, 0x00, 0xff}},
	}

	for _, c := range caps {
		if _, _, err := c.FQDN(); err == nil {
			t.Fatalf("expected an error for capability %v, but none occurred", c)
		} else {
			t.Logf("err: %v", err)
		}
	}
}

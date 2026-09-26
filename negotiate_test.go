package bgp

import (
	"testing"
	"time"
)

func TestDialedSurvives(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		local, peer Open
		want        bool
	}{
		{
			name:  "local id higher",
			local: Open{ID: 2},
			peer:  Open{ID: 1},
			want:  true,
		},
		{
			name:  "peer id higher",
			local: Open{ID: 1},
			peer:  Open{ID: 2},
			want:  false,
		},
		{
			name: "equal id, local ASN higher",
			local: Open{
				ID:  1,
				ASN: 2,
			},
			peer: Open{
				ID:  1,
				ASN: 1,
			},
			want: true,
		},
		{
			name: "equal id, peer ASN higher",
			local: Open{
				ID:  1,
				ASN: 1,
			},
			peer: Open{
				ID:  1,
				ASN: 2,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := dialedSurvives(&tt.local, &tt.peer)
			if got != tt.want {
				t.Fatalf("want dialed survives %t, got %t", tt.want, got)
			}
		})
	}
}

func TestNegotiatedFamilies(t *testing.T) {
	t.Parallel()

	var (
		v4u = Family{
			AFI:  AFIIPv4,
			SAFI: SAFIUnicast,
		}

		v6u = Family{
			AFI:  AFIIPv6,
			SAFI: SAFIUnicast,
		}
	)

	tests := []struct {
		name string
		ours []Family
		caps []Capability
		want []Family
	}{
		{
			name: "implicit IPv4 unicast",
			ours: []Family{v4u, v6u},
			want: []Family{v4u},
		},
		{
			name: "intersection in local order",
			ours: []Family{v6u, v4u},
			caps: []Capability{
				MultiprotocolCapability(v4u),
				MultiprotocolCapability(v6u),
			},
			want: []Family{v6u, v4u},
		},
		{
			name: "no overlap",
			ours: []Family{v6u},
			caps: []Capability{MultiprotocolCapability(v4u)},
			want: nil,
		},
		{
			name: "malformed capability skipped",
			ours: []Family{v4u},
			caps: []Capability{
				{
					Code: CapabilityMultiprotocol,
					Data: []byte{0xff},
				},
				MultiprotocolCapability(v4u),
			},
			want: []Family{v4u},
		},
		{
			name: "duplicates collapsed",
			ours: []Family{v4u, v4u},
			caps: []Capability{MultiprotocolCapability(v4u)},
			want: []Family{v4u},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if d := diff(t, tt.want, negotiatedFamilies(tt.ours, tt.caps)); d != "" {
				t.Fatalf("unexpected families (-want +got):\n%s", d)
			}
		})
	}
}

func TestNegotiatedAddPath(t *testing.T) {
	t.Parallel()

	var (
		v4u = Family{
			AFI:  AFIIPv4,
			SAFI: SAFIUnicast,
		}

		v6u = Family{
			AFI:  AFIIPv6,
			SAFI: SAFIUnicast,
		}
	)

	fams := []Family{v4u, v6u}
	cap1 := func(f AddPathFamily) Capability { return must(AddPathCapability(f)) }

	// Both directions for a family, the common configuration.
	var (
		v4uBoth = AddPathFamily{
			Family:  v4u,
			Send:    true,
			Receive: true,
		}

		v6uBoth = AddPathFamily{
			Family:  v6u,
			Send:    true,
			Receive: true,
		}
	)

	tests := []struct {
		name string
		ours []AddPathFamily
		fams []Family
		caps []Capability
		want []AddPathFamily
	}{
		{
			name: "not configured",
			fams: fams,
			caps: []Capability{cap1(v4uBoth)},
		},
		{
			name: "peer without capability",
			ours: []AddPathFamily{v4uBoth},
			fams: fams,
		},
		{
			// Send needs the peer's Receive and Receive needs the peer's
			// Send, per direction and per family.
			name: "directions crossed",
			ours: []AddPathFamily{
				v4uBoth,
				{
					Family: v6u,
					Send:   true,
				},
			},
			fams: fams,
			caps: []Capability{must(AddPathCapability(
				AddPathFamily{
					Family: v4u,
					Send:   true,
				},
				AddPathFamily{
					Family: v6u,
					Send:   true,
				},
			))},
			want: []AddPathFamily{{
				Family:  v4u,
				Receive: true,
			}},
		},
		{
			name: "family not negotiated",
			ours: []AddPathFamily{v6uBoth},
			fams: []Family{v4u},
			caps: []Capability{cap1(v6uBoth)},
		},
		{
			name: "malformed capability skipped",
			ours: []AddPathFamily{v4uBoth},
			fams: fams,
			caps: []Capability{{
				Code: CapabilityAddPath,
				Data: []byte{0xff},
			}},
		},
		{
			// RFC 7911 forbids duplicate families, so the first entry wins
			// on receipt.
			name: "peer duplicate first wins",
			ours: []AddPathFamily{v4uBoth},
			fams: fams,
			caps: []Capability{must(AddPathCapability(
				AddPathFamily{
					Family:  v4u,
					Receive: true,
				},
				AddPathFamily{
					Family: v4u,
					Send:   true,
				},
			))},
			want: []AddPathFamily{{
				Family: v4u,
				Send:   true,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if d := diff(t, tt.want, negotiatedAddPath(tt.ours, tt.fams, tt.caps)); d != "" {
				t.Fatalf("unexpected add-path families (-want +got):\n%s", d)
			}
		})
	}
}

func TestExtendedNextHopFamilies(t *testing.T) {
	t.Parallel()

	var (
		v4u = Family{
			AFI:  AFIIPv4,
			SAFI: SAFIUnicast,
		}

		v4m = Family{
			AFI:  AFIIPv4,
			SAFI: SAFIMulticast,
		}
	)

	// A well-formed capability for two families, plus a hand-built entry
	// whose next hop AFI is not IPv6 and trailing garbage, both ignored.
	caps := []Capability{
		ExtendedNextHopCapability(v4u, v4m),
		{
			Code: CapabilityExtendedNextHop,
			Data: []byte{
				0, 1, 0, 1, 0, 1, // IPv4 unicast with an IPv4 next hop: skipped
				0xff, // truncated trailing byte: ignored
			},
		},
	}

	if d := diff(t, []Family{v4u, v4m}, extendedNextHopFamilies(caps)); d != "" {
		t.Fatalf("unexpected families (-want +got):\n%s", d)
	}
}

func TestLongLivedGracefulRestart(t *testing.T) {
	t.Parallel()

	v4u := Family{
		AFI:  AFIIPv4,
		SAFI: SAFIUnicast,
	}

	malformed := Capability{
		Code: CapabilityLongLivedGracefulRestart,
		Data: []byte{0x00, 0x01, 0x01},
	}

	// No capability at all, or only a malformed one, decodes to nil, exactly
	// as gracefulRestart treats the RFC 4724 capability.
	for _, caps := range [][]Capability{
		nil,
		{MultiprotocolCapability(v4u), must(GracefulRestartCapability(GracefulRestart{}))},
		{malformed},
	} {
		if got := longLivedGracefulRestart(caps); got != nil {
			t.Fatalf("expected no long-lived graceful restart for %v, but got: %+v", caps, got)
		}
	}

	// The first well-formed capability wins, after a malformed one. A
	// graceful restart capability need not accompany it: RFC 9494's
	// section 4.1 pairing is the caller's to honor.
	want := LongLivedGracefulRestart{
		Families: []LongLivedGracefulRestartFamily{
			{
				Family:              v4u,
				ForwardingPreserved: true,
				StaleTime:           time.Hour,
			},
		},
	}

	caps := []Capability{
		malformed,
		must(LongLivedGracefulRestartCapability(want)),
		must(LongLivedGracefulRestartCapability(LongLivedGracefulRestart{})),
	}

	got := longLivedGracefulRestart(caps)
	if got == nil {
		t.Fatal("long-lived graceful restart capability was not decoded")
	}

	if d := diff(t, want, *got); d != "" {
		t.Fatalf("unexpected long-lived graceful restart (-want +got):\n%s", d)
	}
}

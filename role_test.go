package bgp

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestRoleNegotiation drives negotiate with a local role against every
// shape of peer role RFC 9234, section 4.2 describes: each allowed pair
// establishes and reports the peer's role, and everything else is Role
// Mismatch.
func TestRoleNegotiation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		local   RoleConfig
		caps    []Capability
		want    *Role
		subcode uint8 // nonzero expects a rejection
	}{
		{
			name:  "provider and customer",
			local: RoleConfig{Role: RoleProvider},
			caps:  []Capability{RoleCapability(RoleCustomer)},
			want:  new(RoleCustomer),
		},
		{
			name:  "customer and provider",
			local: RoleConfig{Role: RoleCustomer},
			caps:  []Capability{RoleCapability(RoleProvider)},
			want:  new(RoleProvider),
		},
		{
			name:  "RS and RS-Client",
			local: RoleConfig{Role: RoleRS},
			caps:  []Capability{RoleCapability(RoleRSClient)},
			want:  new(RoleRSClient),
		},
		{
			name:  "RS-Client and RS",
			local: RoleConfig{Role: RoleRSClient},
			caps:  []Capability{RoleCapability(RoleRS)},
			want:  new(RoleRS),
		},
		{
			name:  "peer and peer",
			local: RoleConfig{Role: RolePeer},
			caps:  []Capability{RoleCapability(RolePeer)},
			want:  new(RolePeer),
		},
		{
			name:    "mismatched pair",
			local:   RoleConfig{Role: RoleCustomer},
			caps:    []Capability{RoleCapability(RoleCustomer)},
			subcode: SubcodeRoleMismatch,
		},
		{
			name: "strict with no peer role",
			local: RoleConfig{
				Role:   RolePeer,
				Strict: true,
			},
			subcode: SubcodeRoleMismatch,
		},
		{
			// RFC 9234 recommends proceeding for backward compatibility.
			name:  "non-strict with no peer role",
			local: RoleConfig{Role: RolePeer},
		},
		{
			name:  "identical duplicates",
			local: RoleConfig{Role: RoleProvider},
			caps: []Capability{
				RoleCapability(RoleCustomer),
				RoleCapability(RoleCustomer),
			},
			want: new(RoleCustomer),
		},
		{
			name:  "conflicting duplicates",
			local: RoleConfig{Role: RoleProvider},
			caps: []Capability{
				RoleCapability(RoleCustomer),
				RoleCapability(RolePeer),
			},
			subcode: SubcodeRoleMismatch,
		},
		{
			name:  "malformed length",
			local: RoleConfig{Role: RoleProvider},
			caps: []Capability{
				RoleCapability(RoleCustomer),
				{
					Code: CapabilityRole,
					Data: []byte{byte(RoleCustomer), 0},
				},
			},
			subcode: SubcodeRoleMismatch,
		},
		{
			name:    "unassigned peer role",
			local:   RoleConfig{Role: RolePeer},
			caps:    []Capability{RoleCapability(5)},
			subcode: SubcodeRoleMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := must(NewFSM(FSMConfig{
				LocalASN: 64496,
				LocalID:  MustParseIdentifier("192.0.2.1"),
				PeerASN:  64497,
				Role:     &tt.local,
				Passive:  true,
			}))

			s, err := f.negotiate(f.opens[0], &Open{
				ASN:          64497,
				HoldTime:     90 * time.Second,
				ID:           MustParseIdentifier("192.0.2.2"),
				Capabilities: tt.caps,
				FourOctetAS:  true,
			})

			if tt.subcode != 0 {
				if err == nil {
					t.Fatal("expected a Role Mismatch, but the session negotiated")
				}

				want := &Notification{
					Code:    NotificationOpenMessageError,
					Subcode: tt.subcode,
				}

				if d := diff(t, want, err.Notification()); d != "" {
					t.Fatalf("unexpected rejection (-want +got):\n%s", d)
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to negotiate: %v", err)
			}

			if d := diff(t, tt.want, s.Role); d != "" {
				t.Fatalf("unexpected peer role (-want +got):\n%s", d)
			}
		})
	}
}

// TestSessionRoleWithoutLocalRole verifies that Session.Role reports the
// peer's advertisement even when no local role is configured, and that no
// check runs: a caller may observe roles before configuring its own.
func TestSessionRoleWithoutLocalRole(t *testing.T) {
	t.Parallel()

	f := must(NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	}))

	s, err := f.negotiate(f.opens[0], &Open{
		ASN:      64497,
		HoldTime: 90 * time.Second,
		ID:       MustParseIdentifier("192.0.2.2"),
		Capabilities: []Capability{
			RoleCapability(7),
			RoleCapability(RolePeer),
		},
		FourOctetAS: true,
	})
	if err != nil {
		t.Fatalf("failed to negotiate: %v", err)
	}

	if d := diff(t, new(Role(7)), s.Role); d != "" {
		t.Fatalf("unexpected peer role (-want +got):\n%s", d)
	}
}

// TestNewFSMRole verifies the construction rules of the BGP Role: the
// capability is generated from Identity.Role, which requires PeerASN pinned
// to an external AS and an assigned role, and the local OPEN carries it.
func TestNewFSMRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   Identity
		ok   bool
	}{
		{
			name: "advertised",
			id: Identity{
				PeerASN: 64497,
				Role:    &RoleConfig{Role: RoleCustomer},
			},
			ok: true,
		},
		{
			name: "iBGP",
			id: Identity{
				PeerASN: 64496,
				Role:    &RoleConfig{Role: RoleCustomer},
			},
		},
		{
			name: "unpinned",
			id: Identity{
				Role: &RoleConfig{Role: RoleCustomer},
			},
		},
		{
			name: "unassigned",
			id: Identity{
				PeerASN: 64497,
				Role:    &RoleConfig{Role: 5},
			},
		},
		{
			name: "raw capability",
			id: Identity{
				Capabilities: []Capability{RoleCapability(RoleCustomer)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.id.LocalASN = 64496
			tt.id.LocalID = MustParseIdentifier("192.0.2.1")

			f, err := NewFSM(FSMConfig{
				Identity: tt.id,
				Passive:  true,
			})
			if !tt.ok {
				if err == nil {
					t.Fatal("expected a construction error, but none occurred")
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to create FSM: %v", err)
			}

			want := []Capability{RoleCapability(tt.id.Role.Role)}
			if d := diff(t, want, f.opens[0].Capabilities); d != "" {
				t.Fatalf("unexpected local OPEN capabilities (-want +got):\n%s", d)
			}
		})
	}
}

// TestPeerRoleMismatch verifies that a Role Mismatch reaches the wire as
// the RFC 9234 NOTIFICATION, OPEN Message Error / Role Mismatch, through a
// Peer's OPEN exchange.
func TestPeerRoleMismatch(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{
			PeerASN: 64497,
			Role:    &RoleConfig{Role: RoleCustomer},
		})

		s := r.acceptScript()

		o := s.expectOpen()
		if d := diff(t, []Capability{RoleCapability(RoleCustomer)}, o.Capabilities); d != "" {
			t.Fatalf("unexpected local OPEN capabilities (-want +got):\n%s", d)
		}

		s.write(&Open{
			ASN:          64497,
			HoldTime:     90 * time.Second,
			ID:           MustParseIdentifier("192.0.2.2"),
			Capabilities: []Capability{RoleCapability(RoleCustomer)},
		})

		want := &Notification{
			Code:    NotificationOpenMessageError,
			Subcode: SubcodeRoleMismatch,
		}

		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}
	})
}

func TestRoleCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		c    Capability
		want Role
		ok   bool
	}{
		{
			name: "round trip",
			c:    RoleCapability(RoleRSClient),
			want: RoleRSClient,
			ok:   true,
		},
		{
			name: "unassigned value",
			c:    RoleCapability(200),
			want: 200,
			ok:   true,
		},
		{
			name: "empty",
			c:    Capability{Code: CapabilityRole},
		},
		{
			name: "too long",
			c: Capability{
				Code: CapabilityRole,
				Data: []byte{0, 0},
			},
		},
		{
			name: "wrong code",
			c: Capability{
				Code: CapabilityRouteRefresh,
				Data: []byte{0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.c.Role()
			if !tt.ok {
				if err == nil {
					t.Fatal("expected a decoding error, but none occurred")
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to decode role: %v", err)
			}

			if got != tt.want {
				t.Fatalf("unexpected role: got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRoleString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		r    Role
		want string
	}{
		{
			r:    RoleProvider,
			want: "Provider",
		},
		{
			r:    RoleRS,
			want: "RS",
		},
		{
			r:    RoleRSClient,
			want: "RS-Client",
		},
		{
			r:    RoleCustomer,
			want: "Customer",
		},
		{
			r:    RolePeer,
			want: "Peer",
		},
		{
			r:    5,
			want: "unknown(5)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := tt.r.String(); got != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRoleIngress walks the RFC 9234, section 5 ingress procedure for every
// local role: a route with OTC from a Customer or RS-Client is a leak, one
// from a Peer is a leak unless the OTC names that Peer, and a route without
// OTC from a Provider, Peer, or RS gains the remote ASN.
func TestRoleIngress(t *testing.T) {
	t.Parallel()

	const remote = 64497

	var (
		none   = must(MarshalAttributes(Origin(0)))
		ownOTC = must(MarshalAttributes(Origin(0), OTC(remote)))
		farOTC = must(MarshalAttributes(Origin(0), OTC(64510)))
		badOTC = RawAttributes{{
			Flags: AttrFlagOptional | AttrFlagTransitive,
			Type:  AttrOTC,
			Data:  []byte{0},
		}}
		leak = ingress{leak: true}
		add  = ingress{
			otc: remote,
			add: true,
		}
		nothing = ingress{}
	)

	tests := []struct {
		name  string
		r     Role
		attrs RawAttributes
		want  ingress
	}{
		{
			name:  "from customer with OTC",
			r:     RoleProvider,
			attrs: farOTC,
			want:  leak,
		},
		{
			name:  "from customer without OTC",
			r:     RoleProvider,
			attrs: none,
			want:  nothing,
		},
		{
			name:  "from RS-Client with OTC",
			r:     RoleRS,
			attrs: ownOTC,
			want:  leak,
		},
		{
			name:  "from RS-Client without OTC",
			r:     RoleRS,
			attrs: none,
			want:  nothing,
		},
		{
			name:  "from peer with its own OTC",
			r:     RolePeer,
			attrs: ownOTC,
			want:  nothing,
		},
		{
			name:  "from peer with another OTC",
			r:     RolePeer,
			attrs: farOTC,
			want:  leak,
		},
		{
			name:  "from peer with malformed OTC",
			r:     RolePeer,
			attrs: badOTC,
			want:  leak,
		},
		{
			name:  "from peer without OTC",
			r:     RolePeer,
			attrs: none,
			want:  add,
		},
		{
			name:  "from provider with OTC",
			r:     RoleCustomer,
			attrs: farOTC,
			want:  nothing,
		},
		{
			name:  "from provider without OTC",
			r:     RoleCustomer,
			attrs: none,
			want:  add,
		},
		{
			name:  "from RS with OTC",
			r:     RoleRSClient,
			attrs: farOTC,
			want:  nothing,
		},
		{
			name:  "from RS without OTC",
			r:     RoleRSClient,
			attrs: none,
			want:  add,
		},
		{
			name:  "unassigned role",
			r:     5,
			attrs: farOTC,
			want:  nothing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			before := tt.attrs.Clone()

			var got ingress
			got.otc, got.add, got.leak = tt.r.Ingress(remote, tt.attrs)
			if got != tt.want {
				t.Fatalf("unexpected ingress: got %+v, want %+v", got, tt.want)
			}

			if d := diff(t, before, tt.attrs); d != "" {
				t.Fatalf("Ingress modified the attributes (-want +got):\n%s", d)
			}
		})
	}
}

// TestRoleEgress walks the RFC 9234, section 5 egress procedure for every
// local role: a route with OTC never goes to a Provider, Peer, or RS, and a
// route without OTC to a Customer, Peer, or RS-Client gains the local ASN.
func TestRoleEgress(t *testing.T) {
	t.Parallel()

	const local = 64496

	var (
		none    = must(MarshalAttributes(Origin(0)))
		withOTC = must(MarshalAttributes(Origin(0), OTC(64510)))
		blocked = egress{}
		add     = egress{
			otc: local,
			add: true,
			ok:  true,
		}
		asIs = egress{ok: true}
	)

	tests := []struct {
		name  string
		r     Role
		attrs RawAttributes
		want  egress
	}{
		{
			name:  "to customer with OTC",
			r:     RoleProvider,
			attrs: withOTC,
			want:  asIs,
		},
		{
			name:  "to customer without OTC",
			r:     RoleProvider,
			attrs: none,
			want:  add,
		},
		{
			name:  "to RS-Client with OTC",
			r:     RoleRS,
			attrs: withOTC,
			want:  asIs,
		},
		{
			name:  "to RS-Client without OTC",
			r:     RoleRS,
			attrs: none,
			want:  add,
		},
		{
			name:  "to peer with OTC",
			r:     RolePeer,
			attrs: withOTC,
			want:  blocked,
		},
		{
			name:  "to peer without OTC",
			r:     RolePeer,
			attrs: none,
			want:  add,
		},
		{
			name:  "to provider with OTC",
			r:     RoleCustomer,
			attrs: withOTC,
			want:  blocked,
		},
		{
			name:  "to provider without OTC",
			r:     RoleCustomer,
			attrs: none,
			want:  asIs,
		},
		{
			name:  "to RS with OTC",
			r:     RoleRSClient,
			attrs: withOTC,
			want:  blocked,
		},
		{
			name:  "to RS without OTC",
			r:     RoleRSClient,
			attrs: none,
			want:  asIs,
		},
		{
			name:  "unassigned role",
			r:     5,
			attrs: withOTC,
			want:  asIs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			before := tt.attrs.Clone()

			var got egress
			got.otc, got.add, got.ok = tt.r.Egress(local, tt.attrs)
			if got != tt.want {
				t.Fatalf("unexpected egress: got %+v, want %+v", got, tt.want)
			}

			if d := diff(t, before, tt.attrs); d != "" {
				t.Fatalf("Egress modified the attributes (-want +got):\n%s", d)
			}
		})
	}
}

// ingress and egress gather Role.Ingress and Role.Egress results for
// comparison. Their fields are all unexported, which cmp cannot walk, so
// they compare with != instead of diff.
type ingress struct {
	otc       OTC
	add, leak bool
}

type egress struct {
	otc     OTC
	add, ok bool
}

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// peerTimeout bounds every blocking wait in the Peer tests, so a wedged FSM
// fails a test instead of hanging it.
const peerTimeout = 10 * time.Second

func TestNewPeerErrors(t *testing.T) {
	t.Parallel()

	// dialAddr is a known-good remote address for the built-in Dialer path;
	// the addressing error cases vary NewPeer's raddr instead.
	dialAddr := netip.MustParseAddr("192.0.2.2")

	// valid mutates a known-good configuration into an invalid one.
	valid := func(mutate func(c *PeerConfig)) PeerConfig {
		c := PeerConfig{
			LocalASN: 64496,
			LocalID:  MustParseIdentifier("192.0.2.1"),
		}

		mutate(&c)
		return c
	}

	tests := []struct {
		name string
		c    PeerConfig
	}{
		{
			name: "zero ASN",
			c:    valid(func(c *PeerConfig) { c.LocalASN = 0 }),
		},
		{
			name: "zero identifier",
			c:    valid(func(c *PeerConfig) { c.LocalID = 0 }),
		},
		{
			name: "short hold time",
			c:    valid(func(c *PeerConfig) { c.HoldTime = 2 * time.Second }),
		},
		{
			name: "four octet capability",
			c: valid(func(c *PeerConfig) {
				c.Capabilities = []Capability{{
					Code: CapabilityFourOctetAS,
					Data: []byte{0, 0, 0, 1},
				}}
			}),
		},
		{
			name: "multiprotocol capability",
			c: valid(func(c *PeerConfig) {
				c.Capabilities = []Capability{
					MultiprotocolCapability(Family{AFI: AFIIPv6, SAFI: SAFIUnicast}),
				}
			}),
		},
		{
			name: "graceful restart capability",
			c: valid(func(c *PeerConfig) {
				c.Capabilities = []Capability{
					must(GracefulRestartCapability(GracefulRestart{})),
				}
			}),
		},
		{
			name: "add-path capability",
			c: valid(func(c *PeerConfig) {
				c.Capabilities = []Capability{
					must(AddPathCapability(AddPathFamily{
						Family: Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
						Send:   true,
					})),
				}
			}),
		},
		{
			name: "add-path family not prefix shaped",
			c: valid(func(c *PeerConfig) {
				c.AddPath = []AddPathFamily{{
					Family: Family{AFI: AFIL2VPN, SAFI: SAFIEVPN},
					Send:   true,
				}}
			}),
		},
		{
			name: "add-path duplicate family",
			c: valid(func(c *PeerConfig) {
				f := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
				c.AddPath = []AddPathFamily{
					{Family: f, Send: true},
					{Family: f, Receive: true},
				}
			}),
		},
		{
			name: "add-path no direction",
			c: valid(func(c *PeerConfig) {
				c.AddPath = []AddPathFamily{{
					Family: Family{AFI: AFIIPv4, SAFI: SAFIUnicast},
				}}
			}),
		},
		{
			name: "route refresh capability",
			c: valid(func(c *PeerConfig) {
				c.Capabilities = []Capability{{Code: CapabilityRouteRefresh}}
			}),
		},
		{
			name: "route refresh without a handler",
			c:    valid(func(c *PeerConfig) { c.RouteRefresh = true }),
		},
		{
			name: "TCP-MD5 with a DialFunc",
			c: valid(func(c *PeerConfig) {
				c.MD5Password = "hunter2"
				c.DialFunc = stubDialFunc
			}),
		},
		{
			name: "passive with a DialFunc",
			c: valid(func(c *PeerConfig) {
				c.Passive = true
				c.DialFunc = stubDialFunc
			}),
		},
		{
			name: "graceful restart time too large",
			c: valid(func(c *PeerConfig) {
				c.GracefulRestart = &GracefulRestartConfig{RestartTime: 4096 * time.Second}
			}),
		},
		{
			name: "graceful restart families too large",
			c: valid(func(c *PeerConfig) {
				// 64 family entries overflow the capability's 255 byte
				// data, caught by the OPEN marshal proof.
				c.GracefulRestart = &GracefulRestartConfig{
					Families: make([]GracefulRestartFamily, 64),
				}
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewPeer(dialAddr, tt.c); err == nil {
				t.Fatal("expected an error, but none occurred")
			} else {
				t.Logf("err: %v", err)
			}
		})
	}

	// The addressing error cases vary addr against a valid configuration:
	// addressing is NewPeer's parameter, not the config's, and the port is
	// the Dialer's, so an address is all there is to get wrong.
	t.Run("no peer address", func(t *testing.T) {
		t.Parallel()

		if _, err := NewPeer(netip.Addr{}, valid(func(c *PeerConfig) {})); err == nil {
			t.Fatal("expected an error, but none occurred")
		}
	})

	t.Run("passive unaddressed", func(t *testing.T) {
		t.Parallel()

		// A passive peer never dials, so it needs no address: without one
		// it accepts any delivered connection's address, and the
		// negotiation pins are its identity checks.
		c := valid(func(c *PeerConfig) { c.Passive = true })
		if _, err := NewPeer(netip.Addr{}, c); err != nil {
			t.Fatalf("failed to create passive peer: %v", err)
		}
	})

	// A DialFunc transport addresses its peer by any means of its own, so
	// raddr may be zero entirely even though the peer dials: nothing in
	// this package dials it.
	t.Run("dial func unaddressed", func(t *testing.T) {
		t.Parallel()

		c := valid(func(c *PeerConfig) { c.DialFunc = stubDialFunc })
		if _, err := NewPeer(netip.Addr{}, c); err != nil {
			t.Fatalf("failed to create DialFunc peer: %v", err)
		}
	})
}

func TestPeerRunAlreadyRunning(t *testing.T) {
	t.Parallel()

	p := must(NewPeer(netip.MustParseAddr("127.0.0.1"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
		Logger:   testLogger(t),
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runC := make(chan error, 1)
	go func() { runC <- p.Run(ctx) }()

	// Once the first Run has taken ownership, a second must refuse.
	waitRunning(t, p)
	if err := p.Run(ctx); err == nil {
		t.Fatal("expected an error from a second Run, but none occurred")
	}

	cancel()
	if err := recv(t, runC, "Run to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Run error: %v", err)
	}
}

func TestPeerDeliverConnAddressMismatch(t *testing.T) {
	t.Parallel()

	// The configured peer is a documentation address, so a loopback
	// connection cannot belong to it. The mismatch must be the reported
	// error: the check lives on the Peer, whose FSM checks no address.
	p := must(NewPeer(netip.MustParseAddr("192.0.2.2"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	}))

	client, _ := testConns(t, "tcp4")
	err := p.DeliverConn(client)
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}

	if !strings.Contains(err.Error(), "does not match peer address") {
		t.Fatalf("unexpected delivery error: %v", err)
	}
}

func TestPeerDeliverConnNotRunning(t *testing.T) {
	t.Parallel()

	p := must(NewPeer(netip.MustParseAddr("127.0.0.1"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	}))

	client, _ := testConns(t, "tcp4")
	if err := p.DeliverConn(client); err == nil {
		t.Fatal("expected an error, but none occurred")
	}
}

// TestPeerOpenSent verifies the OPEN this package proposes: the configured
// identity, the default hold time, multiprotocol capabilities generated from
// Families, and caller capabilities passed through verbatim.
func TestPeerOpenSent(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
		v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

		r := newPipeRig(t, PeerConfig{
			Families: []Family{v4u, v6u},
		})

		s := r.acceptScript()

		want := &Open{
			ASN:      64496,
			HoldTime: 90 * time.Second,
			ID:       MustParseIdentifier("192.0.2.1"),
			Capabilities: []Capability{
				MultiprotocolCapability(v4u),
				MultiprotocolCapability(v6u),
			},
		}

		if d := diff(t, want, s.expectOpen()); d != "" {
			t.Fatalf("unexpected OPEN (-want +got):\n%s", d)
		}
	})
}

// TestPeerEstablished drives a complete OPEN exchange and verifies every
// negotiated Session field.
func TestPeerEstablished(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
		v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

		r := newPipeRig(t, PeerConfig{
			PeerASN:  64497,
			Families: []Family{v4u, v6u},
		})

		s := r.acceptScript()

		// The peer supports only IPv4 unicast, route refresh, and IPv6 next
		// hops for IPv4 routes, and proposes a shorter hold time than ours.
		open := &Open{
			ASN:      64497,
			HoldTime: 30 * time.Second,
			ID:       MustParseIdentifier("192.0.2.2"),
			Capabilities: []Capability{
				MultiprotocolCapability(v4u),
				{Code: CapabilityRouteRefresh},
				ExtendedNextHopCapability(v4u),
			},
		}

		s.establish(open)

		got := recv(t, r.estC, "session establishment")
		want := Session{
			Peer:            open,
			Local:           r.p.fsm.opens[0],
			Families:        []Family{v4u},
			RouteRefresh:    true,
			ExtendedNextHop: []Family{v4u},
			HoldTime:        30 * time.Second,
			LocalAddr:       memAddr{},
			RemoteAddr:      memAddr{},
		}

		if d := diff(t, want, got); d != "" {
			t.Fatalf("unexpected session (-want +got):\n%s", d)
		}
	})
}

// TestPeerAddPath drives the add-path extension (RFC 7911) end to end:
// negotiation intersects the two OPENs per family and per direction into
// Session.AddPath, and an inbound UPDATE on the established session parses
// its path identifiers in both wire forms, the top level IPv4 unicast
// fields and a multiprotocol attribute, with no caller-side decoding.
func TestPeerAddPath(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
		v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

		updateC := make(chan *Update, 4)
		r := newPipeRig(t, PeerConfig{
			PeerASN:  64497,
			Families: []Family{v4u, v6u},
			AddPath: []AddPathFamily{
				{Family: v4u, Send: true, Receive: true},
				{Family: v6u, Receive: true},
			},
			OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
				updateC <- u
				return nil
			},
		})

		s := r.acceptScript()

		// The peer sends for both families but receives only IPv4
		// unicast: the negotiated result is per family and per direction.
		open := &Open{
			ASN:      64497,
			HoldTime: 90 * time.Second,
			ID:       MustParseIdentifier("192.0.2.2"),
			Capabilities: []Capability{
				MultiprotocolCapability(v4u),
				MultiprotocolCapability(v6u),
				must(AddPathCapability(
					AddPathFamily{Family: v4u, Send: true, Receive: true},
					AddPathFamily{Family: v6u, Send: true},
				)),
			},
		}

		s.establish(open)

		sess := recv(t, r.estC, "session establishment")
		wantAddPath := []AddPathFamily{
			{Family: v4u, Send: true, Receive: true},
			{Family: v6u, Receive: true},
		}
		if d := diff(t, wantAddPath, sess.AddPath); d != "" {
			t.Fatalf("unexpected negotiated add-path (-want +got):\n%s", d)
		}

		// The peer advertises two paths for one prefix in each wire form:
		// the top level IPv4 unicast field, and an IPv6 multiprotocol
		// attribute.
		nlri := PathPrefixes{
			{ID: 1, Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
			{ID: 2, Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
		}

		mp, err := MarshalAttributes(MPReachNLRI{
			Family:  v6u,
			NextHop: netip.MustParseAddr("2001:db8::1"),
			NLRI:    nlri,
		})
		if err != nil {
			t.Fatalf("failed to marshal attributes: %v", err)
		}

		sent := &Update{
			Attributes: mp,
			NLRIPaths: PathPrefixes{
				{ID: 1, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
				{ID: 2, Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			},
		}

		// The delivered MP_REACH_NLRI is marked add-path, because v6u is in
		// the negotiated receive set: the want asserts the mark rather than
		// leaving it uncompared.
		sent.Attributes[0].addPath = true
		s.write(sent)

		got := recv(t, updateC, "update delivery")
		if d := diff(t, sent, got); d != "" {
			t.Fatalf("unexpected update (-want +got):\n%s", d)
		}

		mpr, ok, err := Lookup[MPReachNLRI](got.Attributes)
		if err != nil || !ok {
			t.Fatalf("failed to look up MP_REACH_NLRI: ok=%v, err=%v", ok, err)
		}

		if d := diff[NLRI](t, nlri, mpr.NLRI); d != "" {
			t.Fatalf("unexpected MP_REACH_NLRI reachability (-want +got):\n%s", d)
		}
	})
}

// TestPeerGracefulRestart drives the graceful restart negotiation surface in
// both directions: the local OPEN carries the capability generated from
// Identity.GracefulRestart with the Restart State bit answering the
// Restarting hook, and the peer's capability is decoded into
// Session.GracefulRestart. The behavior negotiated here is deliberately
// absent: retention and sweeping are the caller's RIB's job.
func TestPeerGracefulRestart(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}

	for _, restarting := range []bool{false, true} {
		t.Run(fmt.Sprintf("restarting=%t", restarting), func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newPipeRig(t, PeerConfig{
					Families: []Family{v4u},
					GracefulRestart: &GracefulRestartConfig{
						RestartTime:         120 * time.Second,
						NotificationSupport: true,
						Families: []GracefulRestartFamily{
							{Family: v4u, ForwardingPreserved: true},
						},
						Restarting: func() bool { return restarting },
					},
				})

				s := r.acceptScript()

				want := &Open{
					ASN:      64496,
					HoldTime: 90 * time.Second,
					ID:       MustParseIdentifier("192.0.2.1"),
					Capabilities: []Capability{
						MultiprotocolCapability(v4u),
						must(GracefulRestartCapability(GracefulRestart{
							Restarting:          restarting,
							NotificationSupport: true,
							RestartTime:         120 * time.Second,
							Families: []GracefulRestartFamily{
								{Family: v4u, ForwardingPreserved: true},
							},
						})),
					},
				}

				if d := diff(t, want, s.expectOpen()); d != "" {
					t.Fatalf("unexpected OPEN (-want +got):\n%s", d)
				}

				// The peer advertises its own graceful restart claims, which
				// must arrive decoded on the Session.
				peerGR := GracefulRestart{
					Restarting:  !restarting,
					RestartTime: 90 * time.Second,
					Families: []GracefulRestartFamily{
						{Family: v4u, ForwardingPreserved: true},
					},
				}

				open := scriptOpen()
				open.Capabilities = []Capability{
					MultiprotocolCapability(v4u),
					must(GracefulRestartCapability(peerGR)),
				}

				// The OPEN was already consumed by the diff above; complete the
				// exchange from there rather than via establish.
				s.write(open)
				s.expectKeepalive()
				s.write(&Keepalive{})

				sess := recv(t, r.estC, "session establishment")
				if sess.GracefulRestart == nil {
					t.Fatal("peer graceful restart capability was not decoded")
				}

				if d := diff(t, peerGR, *sess.GracefulRestart); d != "" {
					t.Fatalf("unexpected graceful restart (-want +got):\n%s", d)
				}

				// Session.Local reports the OPEN actually sent on this attempt,
				// Restart State bit included: the local claims are session
				// state, not something a consumer re-derives from configuration.
				if d := diff(t, want, sess.Local); d != "" {
					t.Fatalf("unexpected local OPEN on Session (-want +got):\n%s", d)
				}
			})
		})
	}
}

// TestPeerHoldTimeTruncated pins the wire-precision rule: a configured hold
// time with sub-second precision is truncated to whole seconds both in the
// proposed OPEN and in the negotiated Session.HoldTime, so the FSM never
// runs a longer hold timer than the peer heard.
func TestPeerHoldTimeTruncated(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{
			HoldTime: 3500 * time.Millisecond,
		})

		s := r.acceptScript()

		o := s.expectOpen()
		if o.HoldTime != 3*time.Second {
			t.Fatalf("unexpected proposed hold time: %s", o.HoldTime)
		}

		// The peer proposes more, so the truncated local value wins.
		s.write(scriptOpen())
		s.expectKeepalive()
		s.write(&Keepalive{})

		sess := recv(t, r.estC, "session establishment")
		if sess.HoldTime != 3*time.Second {
			t.Fatalf("unexpected negotiated hold time: %s", sess.HoldTime)
		}
	})
}

// TestPeerOpenRejected exercises every OPEN rejection path: the peer's OPEN
// is answered with the precise NOTIFICATION RFC 4271 requires, the
// connection closes, and OnClose reports the rejection.
func TestPeerOpenRejected(t *testing.T) {
	t.Parallel()

	// cap65 is the diagnostic data naming the required Four-Octet AS Number
	// capability, carrying the local ASN.
	cap65 := must(appendCapability(nil, Capability{
		Code: CapabilityFourOctetAS,
		Data: binary.BigEndian.AppendUint32(nil, 64496),
	}))

	v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

	tests := []struct {
		name string
		cfg  func(c *PeerConfig)
		open []byte // hand-built wire OPEN
		want *Notification
	}{
		{
			name: "bad version",
			open: rawMessage(MessageTypeOpen, rawOpenBody(3, 64497, 90, 0xc0000202)),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeUnsupportedVersionNumber,
				Data:    []byte{0, 4},
			},
		},
		{
			name: "hold time one second",
			open: rawMessage(MessageTypeOpen, rawOpenBody(4, 64497, 1, 0xc0000202)),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeUnacceptableHoldTime,
			},
		},
		{
			name: "hold time zero",
			open: mustMessage(t, &Open{ASN: 64497, HoldTime: 0, ID: MustParseIdentifier("192.0.2.2")}),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeUnacceptableHoldTime,
			},
		},
		{
			name: "zero identifier",
			open: rawMessage(MessageTypeOpen, rawOpenBody(4, 64497, 90, 0)),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadBGPIdentifier,
			},
		},
		{
			name: "no four octet capability",
			open: rawMessage(MessageTypeOpen, rawOpenBody(4, 64497, 90, 0xc0000202)),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeUnsupportedCapability,
				Data:    cap65,
			},
		},
		{
			name: "bad peer AS",
			cfg:  func(c *PeerConfig) { c.PeerASN = 64497 },
			open: mustMessage(t, &Open{ASN: 64498, HoldTime: 90 * time.Second, ID: MustParseIdentifier("192.0.2.2")}),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadPeerAS,
			},
		},
		{
			// The PeerID pin: protocol identity, decoupled from raddr's
			// addressing (RFC 4271, section 6.2).
			name: "bad peer identifier",
			cfg:  func(c *PeerConfig) { c.PeerID = MustParseIdentifier("192.0.2.2") },
			open: mustMessage(t, &Open{ASN: 64497, HoldTime: 90 * time.Second, ID: MustParseIdentifier("192.0.2.99")}),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadBGPIdentifier,
			},
		},
		{
			// RFC 7607: AS 0 is never valid, even with no configured
			// PeerASN to mismatch.
			name: "zero peer AS",
			open: mustMessage(t, &Open{ASN: 0, HoldTime: 90 * time.Second, ID: MustParseIdentifier("192.0.2.2")}),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadPeerAS,
			},
		},
		{
			// RFC 6286, section 2.2: an internal peer — same AS as ours —
			// bearing our own identifier is a duplicate inside the AS.
			name: "internal peer with local identifier",
			open: mustMessage(t, &Open{ASN: 64496, HoldTime: 90 * time.Second, ID: MustParseIdentifier("192.0.2.1")}),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeBadBGPIdentifier,
			},
		},
		{
			name: "no common families",
			cfg:  func(c *PeerConfig) { c.Families = []Family{v6u} },
			open: mustMessage(t, &Open{
				ASN:      64497,
				HoldTime: 90 * time.Second,
				ID:       MustParseIdentifier("192.0.2.2"),
				Capabilities: []Capability{
					MultiprotocolCapability(Family{AFI: AFIIPv4, SAFI: SAFIUnicast}),
				},
			}),
			want: &Notification{
				Code:    NotificationOpenMessageError,
				Subcode: SubcodeUnsupportedCapability,
				Data:    must(appendCapability(nil, MultiprotocolCapability(v6u))),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cfg := PeerConfig{}
				if tt.cfg != nil {
					tt.cfg(&cfg)
				}

				r := newPipeRig(t, cfg)
				s := r.acceptScript()

				s.expectOpen()
				s.writeRaw(tt.open)
				s.expectNotification(tt.want)
				s.expectClosed()

				c := recv(t, r.closeC, "session close")
				if d := diff(t, tt.want, c.Notification); d != "" {
					t.Fatalf("unexpected close notification (-want +got):\n%s", d)
				}

				if !c.Local {
					t.Fatal("close notification must be sent by this speaker, not received")
				}

				if _, ok := errors.AsType[*MessageError](c.Err); !ok {
					t.Fatalf("close error is not a *MessageError: %v", c.Err)
				}
			})
		})
	}
}

// TestPeerUnexpectedMessage verifies the RFC 6608 answer to a message which
// is valid on the wire but wrong for the session's state.
func TestPeerUnexpectedMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// script drives the connection up to the unexpected message.
		script func(s *script)
		want   *Notification
	}{
		{
			name: "keepalive in OpenSent",
			script: func(s *script) {
				s.expectOpen()
				s.write(&Keepalive{})
			},
			want: &Notification{
				Code:    NotificationFSMError,
				Subcode: SubcodeUnexpectedMessageOpenSent,
			},
		},
		{
			name: "update in OpenSent",
			script: func(s *script) {
				s.expectOpen()
				s.write(&Update{})
			},
			want: &Notification{
				Code:    NotificationFSMError,
				Subcode: SubcodeUnexpectedMessageOpenSent,
			},
		},
		{
			name: "update in OpenConfirm",
			script: func(s *script) {
				s.expectOpen()
				s.write(scriptOpen())
				s.expectKeepalive()
				s.write(&Update{})
			},
			want: &Notification{
				Code:    NotificationFSMError,
				Subcode: SubcodeUnexpectedMessageOpenConfirm,
			},
		},
		{
			name: "open in Established",
			script: func(s *script) {
				s.establish(scriptOpen())
				s.write(scriptOpen())
			},
			want: &Notification{
				Code:    NotificationFSMError,
				Subcode: SubcodeUnexpectedMessageEstablished,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newPipeRig(t, PeerConfig{})
				s := r.acceptScript()

				tt.script(s)
				s.expectNotification(tt.want)
				s.expectClosed()

				c := recv(t, r.closeC, "session close")
				if d := diff(t, tt.want, c.Notification); d != "" {
					t.Fatalf("unexpected close notification (-want +got):\n%s", d)
				}
			})
		})
	}
}

// TestPeerNotificationReceived verifies that a peer's NOTIFICATION ends the
// session and surfaces through OnClose with its origin intact.
func TestPeerNotificationReceived(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		n := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeReset,
		}

		s.write(n)
		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, n, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if c.Local || c.Err != nil {
			t.Fatalf("expected a received notification without error, got: %+v", c)
		}

		if !c.Established {
			t.Fatal("expected the close to report an established session")
		}
	})
}

// TestPeerNotificationBeforeEstablished verifies that a peer which refuses
// the OPEN exchange with a NOTIFICATION ends the attempt: the NOTIFICATION
// surfaces through OnClose as received, and nothing is sent in reply.
func TestPeerNotificationBeforeEstablished(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		s.expectOpen()
		n := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseConnectionRejected,
		}

		s.write(n)

		// The connection closes with no answering NOTIFICATION: expectClosed
		// fails if any message precedes the close.
		s.expectClosed()

		c := recv(t, r.closeC, "attempt close")
		if d := diff(t, n, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if c.Local || c.Err != nil {
			t.Fatalf("expected a received notification without error, got: %+v", c)
		}

		if c.Established {
			t.Fatal("expected the close to report a failed attempt, not a session")
		}
	})
}

// TestPeerOpenSendFailed verifies that a connection which dies before the
// local OPEN can be sent ends a passive peer's attempt with the underlying
// error in Close.Err and no NOTIFICATION.
func TestPeerOpenSendFailed(t *testing.T) {
	t.Parallel()

	r := testPeer(t, netip.MustParseAddr("127.0.0.1"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	})

	// Reset the connection from the scripted side before delivery: closing
	// with linger zero sends an RST, so the Peer's OPEN write fails — or,
	// if the write slips into the socket buffer before the reset lands,
	// the connection's first read fails instead. Either way the attempt
	// ends with a transport error and nothing on the wire to report.
	client, server := testConns(t, "tcp4")
	tc := server.rawConn().(*net.TCPConn)
	_ = tc.SetLinger(0)
	_ = tc.Close()

	if err := r.p.DeliverConn(client); err != nil {
		t.Fatalf("failed to deliver connection: %v", err)
	}

	c := recv(t, r.closeC, "attempt close")
	if c.Notification != nil {
		t.Fatalf("expected no notification, but got: %+v", c.Notification)
	}

	if c.Err == nil {
		t.Fatal("expected a close error, but none occurred")
	}
}

// The TestPeerSecondAccepted tests verify the accepted slot's occupancy
// rules: a second inbound connection replaces an occupant still awaiting
// the peer's OPEN, because the reconnect of a peer which crashed after the
// TCP handshake must not be locked out for the occupant's remaining
// openHoldTime. An occupant whose OPEN exchange has progressed carries a
// live peer and keeps the slot.
func TestPeerSecondAcceptedReplacesStaleOccupant(t *testing.T) {
	t.Parallel()

	ceaseRejected := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseConnectionRejected,
	}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})

		// The first accepted connection stalls before the peer's OPEN:
		// indistinguishable from a peer which crashed right after the TCP
		// handshake.
		first := r.deliver()
		first.expectOpen()

		// The reconnect displaces the stale occupant and carries the
		// attempt all the way to a session.
		second := r.deliver()
		first.expectNotification(ceaseRejected)
		first.expectClosed()

		second.expectOpen()
		second.write(scriptOpen())
		second.expectKeepalive()
		second.write(&Keepalive{})
		recv(t, r.estC, "session establishment")
	})
}

func TestPeerSecondAcceptedConfirmedKeepsSlot(t *testing.T) {
	t.Parallel()

	ceaseRejected := &Notification{
		Code:    NotificationCease,
		Subcode: SubcodeCeaseConnectionRejected,
	}

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})

		// The first accepted connection completes its OPEN exchange into
		// OpenConfirm: the peer is provably alive on it.
		first := r.deliver()
		first.expectOpen()
		first.write(scriptOpen())
		first.expectKeepalive()

		second := r.deliver()
		second.expectNotification(ceaseRejected)
		second.expectClosed()

		// The first connection is undisturbed and establishes.
		first.write(&Keepalive{})
		recv(t, r.estC, "session establishment")
	})
}

// TestPeerSendConnectionReset verifies the writer goroutine's terminal path:
// with the reader parked inside a handler, the writer is the goroutine which
// discovers the dead connection, reports the write error to the caller, and
// forwards it to the FSM to end the session.
func TestPeerSendConnectionReset(t *testing.T) {
	t.Parallel()

	enteredC := make(chan struct{}, 1)
	r := newTCPRig(t, PeerConfig{
		OnUpdate: func(ctx context.Context, _ *Peer, _ *Update) error {
			enteredC <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		},
	})
	s := r.acceptScript()

	s.establish(scriptOpen())
	recv(t, r.estC, "session establishment")

	// Park the reader inside its handler, so only the writer can discover
	// the reset below.
	s.write(&Update{})
	recv(t, enteredC, "handler entry")

	// Reset the connection: an RST, unlike a FIN, fails writes too.
	tc := s.nc.(*net.TCPConn)
	_ = tc.SetLinger(0)
	_ = tc.Close()

	// The first send may slip into the socket buffer before the reset is
	// processed; a following send must surface the connection error.
	var sendErr error
	for range 100 {
		if err := r.p.SendUpdate(context.Background(), &Update{}); err != nil {
			sendErr = err
			break
		}
	}

	if sendErr == nil {
		t.Fatal("expected a send to fail, but none did")
	}

	// A connection write failure ends the session, so the returned error
	// wraps ErrNotEstablished — unlike a marshal failure, which returns its
	// error alone; see TestPeerSendMarshalError.
	if !errors.Is(sendErr, ErrNotEstablished) {
		t.Fatalf("send error does not wrap ErrNotEstablished: %v", sendErr)
	}

	c := recv(t, r.closeC, "session close")
	if c.Notification != nil {
		t.Fatalf("expected no notification, but got: %+v", c.Notification)
	}

	if c.Err == nil {
		t.Fatal("expected a close error, but none occurred")
	}
}

// TestPeerMalformedUpdate verifies that an unparseable UPDATE mid-session
// produces the parse error's NOTIFICATION and a session reset, per RFC 4271
// section 6.3.
func TestPeerMalformedUpdate(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// Path attributes length claims 5 bytes, but none follow.
		s.writeRaw(rawMessage(MessageTypeUpdate, []byte{0, 0, 0, 5}))

		want := &Notification{
			Code:    NotificationUpdateMessageError,
			Subcode: SubcodeMalformedAttributeList,
		}

		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if _, ok := errors.AsType[*MessageError](c.Err); !ok {
			t.Fatalf("close error is not a *MessageError: %v", c.Err)
		}
	})
}

// The TestPeerHoldExpiry tests pin hold-expiry attribution: a silent peer
// is answered with Hold Timer Expired, while a reader stalled inside a
// caller handler is this speaker's own failure, answered with Cease / Out
// of Resources.
func TestPeerHoldExpirySilentPeer(t *testing.T) {
	t.Parallel()

	// The scripted OPEN proposes 30s, below our 90s default, so the
	// negotiated hold time is 30s.
	const hold = 30 * time.Second

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{})
		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// The peer goes silent for the whole hold time. The keepalive timer
		// fires along the way, so keepalives may precede the NOTIFICATION.
		time.Sleep(hold)

		want := &Notification{Code: NotificationHoldTimerExpired}
		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !c.Local {
			t.Fatal("close notification must be sent by this speaker, not received")
		}
	})
}

func TestPeerHoldExpiryStalledHandler(t *testing.T) {
	t.Parallel()

	// The scripted OPEN proposes 30s, below our 90s default, so the
	// negotiated hold time is 30s.
	const hold = 30 * time.Second

	synctest.Test(t, func(t *testing.T) {
		var (
			enteredC  = make(chan struct{}, 1)
			canceledC = make(chan struct{}, 1)
		)

		r := newPipeRig(t, PeerConfig{
			OnUpdate: func(ctx context.Context, _ *Peer, _ *Update) error {
				enteredC <- struct{}{}
				// A well-behaved blocked handler watches the session context,
				// which the FSM cancels when it sheds the session.
				<-ctx.Done()
				canceledC <- struct{}{}
				return ctx.Err()
			},
		})

		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		s.write(&Update{})
		recv(t, enteredC, "handler entry")
		time.Sleep(hold)

		want := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseOutOfResources,
		}

		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		recv(t, canceledC, "session context cancellation")
		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}
	})
}

func TestPeerHoldExpiryStallUnderBudget(t *testing.T) {
	t.Parallel()

	// The scripted OPEN proposes 30s, below our 90s default, so the
	// negotiated hold time is 30s.
	const hold = 30 * time.Second

	synctest.Test(t, func(t *testing.T) {
		var (
			enteredC = make(chan struct{}, 2)
			releaseC = make(chan struct{})
		)

		r := newPipeRig(t, PeerConfig{
			OnUpdate: func(_ context.Context, _ *Peer, _ *Update) error {
				enteredC <- struct{}{}
				<-releaseC
				return nil
			},
		})

		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// Every handler invocation stalls for less than the hold time, and
		// each processed message restarts the budget: the session survives
		// indefinitely.
		s.write(&Update{})
		recv(t, enteredC, "first handler entry")
		time.Sleep(hold * 2 / 3)
		s.write(&Update{})
		releaseC <- struct{}{}
		recv(t, enteredC, "second handler entry")
		time.Sleep(hold * 2 / 3)
		releaseC <- struct{}{}

		// The hold timer fired mid-stall and found the budget unspent; the
		// session lives, its keepalives still flowing.
		s.nextKeepalive()
		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	})
}

// TestPeerStuckHandler verifies the abandonment contract: a handler which
// ignores its canceled session context past the teardown bound must not
// wedge the Peer. The wire teardown completes, OnClose fires with the
// abandonment reported through Close.Err, and Run continues.
func TestPeerStuckHandler(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const hold = 30 * time.Second

		var (
			enteredC = make(chan struct{}, 1)
			releaseC = make(chan struct{})
		)

		r := newPipeRig(t, PeerConfig{
			OnUpdate: func(_ context.Context, _ *Peer, _ *Update) error {
				enteredC <- struct{}{}
				// A misbehaving handler: blocked forever, never watching ctx.
				<-releaseC
				return nil
			},
		})
		// The stuck handler outlives the test; release it so its goroutine can
		// exit before the race detector's leak accounting matters.
		defer close(releaseC)
		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		s.write(&Update{})
		recv(t, enteredC, "handler entry")

		// The stall spends the whole hold budget: the session tears down with
		// Cease / Out of Resources, attributed to this speaker.
		time.Sleep(hold)

		want := &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseOutOfResources,
		}

		if d := diff(t, want, s.nextNotification()); d != "" {
			t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
		}

		s.expectClosed()

		// endSession waits for the reader under the fourth timer, the bounded
		// join; firing it abandons the stuck handler and releases OnClose.
		time.Sleep(teardownTimeout)

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !errors.Is(c.Err, errStuckHandler) {
			t.Fatalf("expected errStuckHandler, but got: %v", c.Err)
		}
	})
}

// TestPeerBlockedHandlerKeepalives verifies the flow control contract: a
// blocked OnUpdate pauses receipt only, while the FSM goroutine keeps
// keepalives flowing outbound.
func TestPeerBlockedHandlerKeepalives(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		var (
			enteredC = make(chan struct{}, 1)
			releaseC = make(chan struct{})
		)

		r := newPipeRig(t, PeerConfig{
			OnUpdate: func(_ context.Context, _ *Peer, _ *Update) error {
				enteredC <- struct{}{}
				<-releaseC
				return nil
			},
		})

		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		s.write(&Update{})
		recv(t, enteredC, "handler entry")

		// Two keepalive intervals pass with the receive path stalled; each must
		// produce a KEEPALIVE on the wire. A third interval would spend the whole
		// 30s hold budget and tear the session down instead.
		for range 2 {
			time.Sleep(10 * time.Second)
			s.nextKeepalive()
		}

		close(releaseC)
		select {
		case c := <-r.closeC:
			t.Fatalf("session closed unexpectedly: %+v", c)
		default:
		}
	})
}

// TestPeerHandlerError verifies that a handler error terminates the session:
// a *MessageError picks the exact NOTIFICATION on the wire, and any other
// error sends a plain Cease.
func TestPeerHandlerError(t *testing.T) {
	t.Parallel()

	merr := &MessageError{
		Code:    NotificationUpdateMessageError,
		Subcode: SubcodeMalformedASPath,
		Data:    []byte{0xde, 0xad},
	}

	tests := []struct {
		name string
		err  error
		want *Notification
	}{
		{
			name: "message error",
			err:  merr,
			want: merr.Notification(),
		},
		{
			name: "generic error",
			err:  errors.New("the RIB is full"),
			want: &Notification{Code: NotificationCease},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newPipeRig(t, PeerConfig{
					OnUpdate: func(_ context.Context, _ *Peer, _ *Update) error {
						return tt.err
					},
				})

				s := r.acceptScript()

				s.establish(scriptOpen())
				recv(t, r.estC, "session establishment")

				s.write(&Update{})
				s.expectNotification(tt.want)
				s.expectClosed()

				c := recv(t, r.closeC, "session close")
				if d := diff(t, tt.want, c.Notification); d != "" {
					t.Fatalf("unexpected close notification (-want +got):\n%s", d)
				}

				if !errors.Is(c.Err, tt.err) {
					t.Fatalf("expected close error %v, but got: %v", tt.err, c.Err)
				}
			})
		})
	}
}

// TestPeerOnEstablishedError verifies that an OnEstablished error terminates
// the session at establishment: a caller's RIB refusing the session ends it
// with the handler's farewell before anything else happens on the wire.
func TestPeerOnEstablishedError(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("the RIB refuses this session")

	synctest.Test(t, func(t *testing.T) {
		r := newPipeRig(t, PeerConfig{
			OnEstablished: func(context.Context, *Peer, Session) error {
				return errRefused
			},
		})

		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		want := &Notification{Code: NotificationCease}
		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if !c.Established {
			t.Fatal("expected an established close")
		}

		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !errors.Is(c.Err, errRefused) {
			t.Fatalf("expected close error %v, but got: %v", errRefused, c.Err)
		}
	})
}

// TestPeerOnKeepalive verifies the OnKeepalive contract: the hook fires for
// each KEEPALIVE received in session, not for the one which confirms the
// OPEN exchange, and its error terminates the session like any handler.
func TestPeerOnKeepalive(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		errDone := errors.New("observed enough liveness")

		// Handler invocations are serialized on the receive path, so the
		// counter needs no synchronization of its own.
		var calls int
		kaC := make(chan struct{}, 2)
		r := newPipeRig(t, PeerConfig{
			OnKeepalive: func(_ context.Context, _ *Peer) error {
				calls++
				kaC <- struct{}{}
				if calls == 2 {
					return errDone
				}

				return nil
			},
		})

		s := r.acceptScript()

		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		// The KEEPALIVE which established the session belongs to the FSM, not
		// the hook.
		select {
		case <-kaC:
			t.Fatal("OnKeepalive fired for the establishing KEEPALIVE")
		default:
		}

		s.write(&Keepalive{})
		recv(t, kaC, "first keepalive hook")

		// The second invocation returns an error: a plain Cease on the wire,
		// and the error surfaces through Close.
		s.write(&Keepalive{})
		recv(t, kaC, "second keepalive hook")

		want := &Notification{Code: NotificationCease}
		s.expectNotification(want)
		s.expectClosed()

		c := recv(t, r.closeC, "session close")
		if d := diff(t, want, c.Notification); d != "" {
			t.Fatalf("unexpected close notification (-want +got):\n%s", d)
		}

		if !errors.Is(c.Err, errDone) {
			t.Fatalf("expected close error %v, but got: %v", errDone, c.Err)
		}
	})
}

// TestPeerOnRouteRefresh verifies the OnRouteRefresh contract: every
// ROUTE-REFRESH received in session reaches the hook with its family intact
// and in arrival order, and the hook's error terminates the session like any
// handler's. The package does not act on a refresh request itself — replaying
// an Adj-RIB-Out is the caller's RIB's job — so delivery and
// teardown are the whole contract.
func TestPeerOnRouteRefresh(t *testing.T) {
	t.Parallel()

	v4u := Family{AFI: AFIIPv4, SAFI: SAFIUnicast}
	v6u := Family{AFI: AFIIPv6, SAFI: SAFIUnicast}

	// establish brings up a session whose peer advertised route refresh: the
	// negotiation a peer which sends ROUTE-REFRESH is expected to have done.
	establish := func(t *testing.T, cfg PeerConfig) (*peerRig, *script) {
		t.Helper()

		r := newPipeRig(t, cfg)
		s := r.acceptScript()

		open := scriptOpen()
		open.Capabilities = []Capability{{Code: CapabilityRouteRefresh}}
		s.establish(open)

		// Identity.RouteRefresh reaches the wire: the local OPEN carries
		// the capability, and Session reports the peer's in turn.
		sess := recv(t, r.estC, "session establishment")
		if !hasCapability(sess.Local.Capabilities, CapabilityRouteRefresh) {
			t.Fatalf("local OPEN did not advertise route refresh: %+v", sess.Local.Capabilities)
		}

		if !sess.RouteRefresh {
			t.Fatal("expected the peer's route refresh capability to be reported")
		}

		return r, s
	}

	t.Run("delivery", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			rrC := make(chan Family, 2)
			r, s := establish(t, PeerConfig{
				RouteRefresh: true,
				OnRouteRefresh: func(_ context.Context, _ *Peer, rr *RouteRefresh) error {
					rrC <- rr.Family
					return nil
				},
			})

			// Two requests in a row, for different families: the hook sees each
			// one, in the order they arrived, and neither ends the session.
			for _, want := range []Family{v4u, v6u} {
				s.write(&RouteRefresh{Family: want})
				if d := diff(t, want, recv(t, rrC, "route refresh hook")); d != "" {
					t.Fatalf("unexpected family (-want +got):\n%s", d)
				}
			}

			select {
			case c := <-r.closeC:
				t.Fatalf("session closed unexpectedly: %+v", c)
			default:
			}
		})
	})

	t.Run("handler error", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			errBusy := errors.New("the Adj-RIB-Out cannot be replayed")
			r, s := establish(t, PeerConfig{
				RouteRefresh: true,
				OnRouteRefresh: func(_ context.Context, _ *Peer, _ *RouteRefresh) error {
					return errBusy
				},
			})

			s.write(&RouteRefresh{Family: v4u})

			want := &Notification{Code: NotificationCease}
			s.expectNotification(want)
			s.expectClosed()

			c := recv(t, r.closeC, "session close")
			if d := diff(t, want, c.Notification); d != "" {
				t.Fatalf("unexpected close notification (-want +got):\n%s", d)
			}

			if !errors.Is(c.Err, errBusy) {
				t.Fatalf("expected close error %v, but got: %v", errBusy, c.Err)
			}
		})
	})
}

// TestPeerOnUpdateOwnsValues verifies the Peer layer's defining behavior:
// the caller's OnUpdate receives a deep copy detached from the borrowed
// value the FSM delivered, safe to retain after the underlying buffer is
// reused.
func TestPeerOnUpdateOwnsValues(t *testing.T) {
	t.Parallel()

	var got *Update
	p := must(NewPeer(netip.MustParseAddr("127.0.0.1"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
		OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
			got = u
			return nil
		},
	}))

	// A borrowed Update whose attribute data aliases a reusable buffer,
	// as one parsed from a connection's read buffer would.
	buf := []byte{0x01, 0x02, 0x03, 0x04}
	borrowed := &Update{
		Attributes: RawAttributes{{Type: AttrCommunities, Data: buf}},
		NLRI:       []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}

	if err := p.fsm.cfg.OnUpdate(context.Background(), p.fsm, borrowed); err != nil {
		t.Fatalf("failed to invoke the wrapped OnUpdate: %v", err)
	}

	if got == borrowed {
		t.Fatal("the caller's OnUpdate received the borrowed *Update itself")
	}

	buf[0] = 0xff
	if got.Attributes[0].Data[0] != 0x01 {
		t.Fatal("the caller's Update shares memory with the borrowed buffer")
	}
}

// TestPeerOnStateChange drives a full session lifecycle and verifies the
// state stream both layers report: each attempt bookended by transitions
// out of and back into Idle, in RFC 4271 order for the ordinary
// dial-and-establish path, with the return to Idle as the final hook after
// the session's Close.
func TestPeerOnStateChange(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		states := make(chan [2]State, 16)
		r := newPipeRig(t, PeerConfig{
			OnStateChange: func(_ *Peer, from, to State) {
				states <- [2]State{from, to}
			},
		})

		s := r.acceptScript()
		s.establish(scriptOpen())
		recv(t, r.estC, "session establishment")

		s.write(&Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseAdministrativeReset,
		})
		recv(t, r.closeC, "session close")

		want := [][2]State{
			{StateIdle, StateConnect},
			{StateConnect, StateOpenSent},
			{StateOpenSent, StateOpenConfirm},
			{StateOpenConfirm, StateEstablished},
			{StateEstablished, StateIdle},
		}

		for i, w := range want {
			got := recv(t, states, "state transition")
			if got != w {
				t.Fatalf("unexpected transition %d: want %s->%s, got %s->%s",
					i, w[0], w[1], got[0], got[1])
			}
		}
	})
}

func TestPeerAddr(t *testing.T) {
	t.Parallel()

	// A v4-mapped address normalizes, so Addr compares equal with the pure
	// IPv4 form: the tie-break and Server-key use cases compare addresses
	// directly.
	p, err := NewPeer(netip.MustParseAddr("::ffff:192.0.2.2"), PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
	})
	if err != nil {
		t.Fatalf("failed to create peer: %v", err)
	}

	if got, want := p.Addr(), netip.MustParseAddr("192.0.2.2"); got != want {
		t.Fatalf("unexpected peer address: got %v, want %v", got, want)
	}

	// An unaddressed peering reports the zero Addr.
	p, err = NewPeer(netip.Addr{}, PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	})
	if err != nil {
		t.Fatalf("failed to create passive peer: %v", err)
	}

	if addr := p.Addr(); addr.IsValid() {
		t.Fatalf("expected a zero address from an unaddressed peer, but got: %v", addr)
	}
}

// TestPeerAddrRequiredToDial verifies that the built-in Dialer path still
// demands real addressing: only a DialFunc transport may go unaddressed.
func TestPeerAddrRequiredToDial(t *testing.T) {
	t.Parallel()

	_, err := NewPeer(netip.Addr{}, PeerConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
	})
	if err == nil {
		t.Fatal("expected an error from an active Dialer peer with no address, but none occurred")
	}
}

// stubDialFunc is a PeerConfig.DialFunc which is never called: the
// configuration tests only need a non-nil one.
func stubDialFunc(context.Context) (*Conn, error) {
	panic("stubDialFunc must not be called")
}

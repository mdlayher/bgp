# bgp [![Test Status](https://github.com/mdlayher/bgp/workflows/Test/badge.svg)](https://github.com/mdlayher/bgp/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/bgp.svg)](https://pkg.go.dev/github.com/mdlayher/bgp)

Package `bgp` implements the Border Gateway Protocol version 4 (BGP-4), as
described in [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271) and related
RFCs: the wire format, the finite state machine, and the peering lifecycle.
MIT Licensed.

The package is built in layers. Each layer is usable without the ones above
it:

- The `Message` types, such as `Open`, `Update`, and `Notification`, with
  their binary encoding.
- `Conn` frames messages over a connection.
- `FSM` runs the RFC 4271 finite state machine over a `Conn`: one session
  attempt for each `Connect` call, delivering zero-copy borrowed values to
  its handlers.
- `Peer` wraps an `FSM` with a retry loop and handlers whose values are
  fully owned.
- `Server` coordinates many `Peer`s, accepting connections on shared
  listeners.

Most callers want `Peer` or `Server`. `FSM` is the expert layer for callers
who need zero-copy delivery or their own retry policy.

## Example

A speaker which announces one route to a neighbor and logs the routes it
receives. `Run` owns the connection lifecycle: dialing, the OPEN exchange,
keepalives, and retrying dead sessions until the context is canceled.

```go
attrs, err := bgp.MarshalAttributes(
	bgp.OriginIGP,
	bgp.ASPath{{ASNs: []uint32{64496}}},
	bgp.NextHop(netip.MustParseAddr("192.0.2.10")),
)
if err != nil {
	log.Fatalf("failed to marshal attributes: %v", err)
}

p, err := bgp.NewPeer(netip.MustParseAddr("192.0.2.1"), bgp.PeerConfig{
	LocalASN: 64496,
	LocalID:  bgp.MustParseIdentifier("192.0.2.10"),
	PeerASN:  64497,

	OnEstablished: func(ctx context.Context, p *bgp.Peer, s bgp.Session) error {
		err := p.SendUpdate(ctx, &bgp.Update{
			Attributes: attrs,
			NLRI:       []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		})
		if err != nil {
			return err
		}

		return p.SendUpdate(ctx, bgp.NewEndOfRIB(bgp.Family{
			AFI:  bgp.AFIIPv4,
			SAFI: bgp.SAFIUnicast,
		}))
	},

	OnUpdate: func(_ context.Context, _ *bgp.Peer, u *bgp.Update) error {
		log.Printf("update: reachable %v, withdrawn %v", u.Prefixes, u.Withdrawn)
		return nil
	},
})
if err != nil {
	log.Fatalf("failed to create peer: %v", err)
}

// Canceling ctx sends the peer Cease / Administrative Shutdown and returns.
ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
defer cancel()

if err := p.Run(ctx); err != nil {
	log.Fatalf("failed to run peer: %v", err)
}
```

See the
[package examples](https://pkg.go.dev/github.com/mdlayher/bgp#pkg-examples)
for multiprotocol IPv6, dual stack, passive peers, a hardened
internet-facing configuration, and more.

## Scope

There is no routing table and no policy engine, permanently. An established
session hands received UPDATE messages to the caller, who owns all routing
decisions. The package is designed around that boundary: a RIB plugs in at
the `Peer` layer through its handlers, wiring its methods into each
`PeerConfig` and draining its Adj-RIB-Out through the send path. Companion
projects, such as BMP (RFC 7854) monitoring and BFD (RFC 5880) liveness for
peerings, build on the same seams and live in their own repositories.

## Platform support

The message, `Conn`, `FSM`, `Peer`, and `Server` layers are portable Go.
The TCP socket options a production BGP speaker needs, such as TCP-MD5,
GTSM, and DSCP, are only supported on Linux; elsewhere, setting them fails
with an error which wraps `errors.ErrUnsupported`.

## Testing

The package is tested against real internet routing data and real routers:

- Corpus tests parse every message of route collector archives and every
  route of a full internet table, requiring a byte-for-byte marshal round
  trip.
- Fuzz targets cover message parsing, attribute parsing, and connection
  framing, seeded from the corpus.
- An interop harness runs live sessions against
  [FRRouting](https://frrouting.org/), covering establishment, capability
  negotiation, route exchange, TCP-MD5, and GTSM.

# RFC status

What this package implements, what it deliberately leaves to the caller,
and what it does not do. The package is the BGP wire format, the FSM, and
the Peer and Server which drive it. Routing state and policy are the
caller's.

## Supported

| RFC | Subject | What is implemented |
|---|---|---|
| 4271 | BGP-4 | Wire format, FSM, Peer and Server |
| 4760 | Multiprotocol extensions | MP_REACH_NLRI and MP_UNREACH_NLRI. NLRI is typed by family: Prefixes, EVPNRoutes, or RawNLRI for an unmodeled family, which round-trips byte for byte |
| 6793 | Four-octet ASNs | Native. A speaker without the capability is rejected |
| 5492 | Capabilities | OPEN optional parameter type 2 |
| 1997 | Communities | Typed |
| 8092 | Large communities | Typed |
| 4360 / 5668 | Extended communities | Opaque 8 byte values with RT and SoO constructors |
| 8097 | Origin validation state | ValidationState extended community. ASPath.Origin gives the RFC 6811 origin AS; validation is the caller's |
| 9234 | OTC attribute | Typed. Role negotiation is not implemented |
| 4456 | Route reflection attributes | Typed ORIGINATOR_ID and CLUSTER_LIST. Reflection is the caller's |
| 5065 | AS confederations | AS_CONFED_SEQUENCE and AS_CONFED_SET round-trip; ASPath.Origin skips them. Path length, MED, and loop semantics are the caller's |
| 2918 | Route refresh | Message, capability, SendRouteRefresh, OnRouteRefresh. Replaying the Adj-RIB-Out is the caller's |
| 7313 | Enhanced route refresh | Capability, RouteRefresh.Subtype, SendRouteRefreshBegin and SendRouteRefreshEnd. A negotiated session delivers the three assigned subtypes and ignores others; an unnegotiated session delivers all but BoRR and EoRR. A BoRR or EoRR of the wrong length is a Message Error regardless of negotiation. Stale marking is the caller's |
| 8950 | IPv4 NLRI with IPv6 next hop | Both directions; ExtendedNextHopCapability |
| 2545 / 4659 | IPv6 link-local next hop | 32 byte dual next hop. VPN families' RD-prefixed next hops carry zero RDs, stripped on parse and restored on marshal |
| 7432 / 9136 | EVPN | Family constants and EVPNRoutes: route type, length, opaque value. Record internals are the caller's |
| 6286 | AS-wide BGP identifiers | Collision tiebreak in the FSM; an internal peer with the local identifier is rejected with Bad BGP Identifier |
| 7607 | AS 0 | NewPeer rejects a zero local ASN; a peer OPEN with ASN 0 draws Bad Peer AS |
| 2385 | TCP-MD5 | PeerConfig.MD5Password and Listener.SetMD5, Linux only, not on a DialFunc transport. Zoned IPv6 link-local peers work |
| 5082 | GTSM | Dialer.GTSM and ListenConfig.GTSM, Linux only, not on a DialFunc transport |
| 4486 | Cease subcodes | SubcodeCease* 1–8 |
| 6608 | FSM error subcodes | Sent for an unexpected message, naming the state |
| 9003 | Shutdown communication | PeerConfig.ShutdownCommunication; Notification.ShutdownCommunication decodes subcodes 2 and 4 |
| 4724 | Graceful restart | Capability, Identity.GracefulRestart, Session.GracefulRestart, NewEndOfRIB and Update.EndOfRIB. Stale retention, the restart timer, and the End-of-RIB sweep are the caller's |
| 8538 | GR notification support | N bit and SubcodeCeaseHardReset. A handler sends Hard Reset via *MessageError; retention is the caller's |
| 9494 | Long-lived graceful restart | Capability, Identity.LongLivedGracefulRestart, Session.LongLivedGracefulRestart, LLGR_STALE and NO_LLGR communities. Stale handling is the caller's |
| 7911 | Add-path | Capability, per-family per-direction negotiation into Session.AddPath, PathPrefixes, Update.NLRIPaths and WithdrawnPaths. Messages read on a Conn parse with the session's negotiation; ParseMessageAddPath is for a consumer outside a Conn. Prefix shaped families only. Path selection and identifier assignment are the caller's |
| 7606 | Revised UPDATE error handling | Parse classifies each malformed attribute as a session reset, a treat-as-withdraw, or an attribute discard, and the strongest outcome wins. A repeated attribute is discarded after its first occurrence; a repeated multiprotocol attribute resets. An UPDATE which announces routes without ORIGIN or AS_PATH, or without NEXT_HOP beside the legacy NLRI field, is a treat-as-withdraw, as is an attribute list which does not frame within the Total Attribute Length. A multiprotocol attribute whose next hop or NLRI does not frame resets. A reset is a *MessageError from parse. The other two are reported in an UpdateDiagnostics beside the Update: Malformed for a treat-as-withdraw, with the NLRI left intact for the consumer to withdraw; Discarded for each attribute removed. An UPDATE which announces nothing reachable but carries a malformed attribute resets. The diagnostics reach a consumer through ParseResult, ReadResult, and the fourth argument of OnUpdate. Nothing is logged; that is the consumer's |
| draft-walton-bgp-hostname-capability | FQDN capability | FQDNCapability, display only |

## Unsupported

| RFC | Subject | Why not |
|---|---|---|
| 8654 | Extended messages | No requirement. The maximum size is one constant plus negotiation |
| 9072 | Extended optional parameters length | Matters only past 255 bytes of capabilities. Draws Unsupported Optional Parameter |
| 4761 | VPLS | Named (SAFIVPLS), NLRI carried as RawNLRI |
| 4364 / 8277 | L3VPN and labeled unicast | NLRI carried as RawNLRI; RD-prefixed next hops typed-parse |
| 8955 | Flowspec | NLRI carried as RawNLRI; an absent next hop parses and marshals |
| 6396 | MRT | A writer belongs on OnMessage and OnStateChange in another module. internal/mrt reads BGP4MP for the test corpus |
| 9384 | BFD Down | SubcodeCeaseBFDDown is named and sendable via ResetSession. BFD itself is outside this module |
| 2842-style dynamic capabilities | Capability renegotiation | Not implemented |
| 6472 | AS_SET deprecation | AS_SET marshals but is never generated |

## Never

| Area | Why |
|---|---|
| RIB, best-path, policy | A library boundary: this package is wire format and FSM |
| Pre-RFC 6793 sessions | AS4_PATH and AS4_AGGREGATOR reconciliation serves only pre-2010 gear and is the most error-prone corner of BGP |
| 8684 Multipath TCP | Disabled on every connection: BGP is single-path, and MPTCP sockets reject TCP_MD5SIG |

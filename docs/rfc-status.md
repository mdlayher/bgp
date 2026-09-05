# RFC status

A living inventory of BGP-related RFCs and this package's stance on each,
so unsupported ones are deliberate decisions with a place to be revisited
rather than silent gaps. Update this file whenever support is added,
planned, or explicitly rejected.

## Supported

| RFC | Subject | Notes |
|---|---|---|
| 4271 | BGP-4 | Core wire format; FSM receive and send paths done 2026-08-16 (Peer) |
| 4760 | Multiprotocol extensions | MP_REACH/MP_UNREACH, first-class; their NLRI is shaped by the family: Prefixes, EVPNRoutes, or RawNLRI for an unmodeled family, which survives parse and re-marshal byte for byte |
| 6793 | Four-octet ASNs | Native representation; sessions with speakers lacking the capability are rejected |
| 5492 | Capabilities | OPEN optional parameter type 2 |
| 1997 | Communities | Typed |
| 8092 | Large communities | Typed |
| 2918 | Route refresh | Message support; Identity.RouteRefresh advertises the capability and requires OnRouteRefresh, since replaying the Adj-RIB-Out is the caller's (2026-08-18); SendRouteRefresh enforces negotiation (2026-08-16) |
| 8950 | IPv4 NLRI with IPv6 next hop | Both directions; ExtendedNextHopCapability, Capability.ExtendedNextHop |
| draft-walton-bgp-hostname-capability | FQDN capability | Codec only (code 73), done 2026-08-30: FQDNCapability / Capability.FQDN, display-only per the draft; advertised verbatim via Identity.Capabilities |
| 2545 / 4659 | IPv6 link-local next hop | 32-byte dual next hop form; the VPN families' RD-prefixed 24/48-byte forms (RFC 4659 §3.2.1.1) are managed as a wire encoding detail, zero RDs stripped and restored (2026-08-18) |
| 7432 / 9136 | EVPN | Done 2026-08-18: L2VPN EVPN family constants and EVPNRoutes, the record framing of RFC 7432 §7 (a route type, a length, an opaque value). Record internals such as RDs, ESIs, MACs, tags, and labels are deliberately uninterpreted: a layer 2 control plane is the caller's, exactly as a RIB is |
| 6286 | AS-wide BGP identifiers | Documented semantics of Open.ID; collision tiebreak implemented in the FSM, and an internal peer bearing the local identifier is rejected with Bad BGP Identifier per §2.2 (2026-08-16) |
| 7607 | AS 0 | Done 2026-08-16: NewPeer rejects a zero local ASN, and the FSM answers a peer OPEN carrying ASN 0 with Bad Peer AS |
| 2385 | TCP-MD5 | Done 2026-08-16: PeerConfig.MD5Password (the peering's key, both directions) / Listener.SetMD5, Linux only; unavailable on a PeerConfig.DialFunc transport; zoned IPv6 link-local peers supported (BGP unnumbered). Deferred: prefix keys and VRF-bound keys (both TCP_MD5SIG_EXT) |
| 5082 | GTSM | Done 2026-08-16: Dialer.GTSM / ListenConfig.GTSM, Linux only; unavailable on a PeerConfig.DialFunc transport |
| 4486 | Cease subcodes | Done 2026-08-16: SubcodeCease* constants 1–8, rendered by MessageError |
| 6608 | FSM error subcodes | Done 2026-08-16: sent by the FSM for an unexpected message, naming the state |
| 9003 | Shutdown communication | Done 2026-08-16: PeerConfig.ShutdownCommunication attaches it to Administrative Shutdown; Notification.ShutdownCommunication decodes subcodes 2 and 4 |
| 4456 | Route reflection attributes | Done 2026-08-16: typed ORIGINATOR_ID and CLUSTER_LIST; reflection itself is the caller's RIB |
| 4360 / 5668 | Extended communities | Done 2026-08-16, deliberately shallow: opaque 8 byte values; RT/SoO constructors and String only |
| 8097 | Origin validation state extended community | Done 2026-08-29: ValidationState, NewValidationState, ExtendedCommunity.ValidationState, and the "OVS:" String form; ASPath.Origin derives the RFC 6811 origin AS. Validation itself (RFC 6811) and the RTR protocol feeding it (RFC 8210) are the caller's RIB's and a sibling module's respectively; the core carries the result only |
| 9234 | OTC attribute | Done 2026-08-16: typed OTC, corpus-motivated. Role capability/negotiation out of scope; revisit with the FSM if demanded |
| 4724 | Graceful restart | Done 2026-08-17, negotiation surface only: capability codec, Identity.GracefulRestart with per-attempt Restart State via Restarting, Session.GracefulRestart, NewEndOfRIB/Update.EndOfRIB. Helper behavior is permanently the caller's RIB's: stale retention, the restart timer, and the End-of-RIB sweep. Restarting-speaker R/F bits are caller-asserted |
| 8538 | GR notification support / Hard Reset | Done 2026-08-17 at the wire: the N bit is encoded and SubcodeCeaseHardReset is named, so a helper can honor both; retention policy is the caller's. A handler can send Hard Reset via *MessageError today; a shutdown-path knob for it is deferred until demanded |
| 7911 | Add-path | Done 2026-09-02, demanded by bgpdev, in the shape parked 2026-08-16: PathPrefixes of {ID, Prefix} as one more NLRI implementation. Capability codec (AddPathCapability, code 69), Identity.AddPath advertisement, per-family per-direction negotiation into Session.AddPath, Update.NLRIPaths/WithdrawnPaths for the top level fields, and session-aware receive parsing: the FSM publishes the negotiated receive set on its Conn, so handler-delivered NLRI arrives typed while bare ParseMessage stays stateless and never decodes path IDs; ParseMessageAddPath is the entry for an out-of-Conn consumer which knows the negotiation, such as a BMP station (demanded by bmp, 2026-09-02). Prefix shaped families only; path selection and identifier assignment are the caller's RIB's |
| 5065 | AS confederations | Done 2026-09-05 as the follow-up to the add-path commit, wire surface only, demanded by live confed interop (segment type 3 previously reset the session as Malformed AS_PATH): ASSegment.Confed round-trips AS_CONFED_SEQUENCE and AS_CONFED_SET, and ASPath.Origin skips confederation segments. The section 5.3 semantics stay the caller's RIB's: AS_PATH length exclusion, the MED neighbor AS, and confederation loop detection |

## Planned

| RFC | Subject | Where |
|---|---|---|
| 7606 | Revised UPDATE error handling | FSM follow-up; owns attribute flag validation and duplicate detection (decided 2026-08-16). Interim stance (2026-08-17): a malformed UPDATE is terminal for the session, exactly RFC 4271. Treat-as-withdraw is an API decision to be made deliberately when this lands, not as a side effect: it classifies attribute errors at the parse layer and delivers a withdraw-only view of the UPDATE to OnUpdate. Confirmed by fault injection (bgpdev, 2026-09-02): conflicting flags are accepted today, e.g. ORIGIN with the Optional bit set (C0 01 01 00) draws no Attribute Flags Error; deliberately left for this work, since 7606 reclassifies that very case to treat-as-withdraw and a 4271 subcode 4 reject built first would be torn out |

## Unsupported: revisit if demanded

| RFC | Subject | Why not / trigger to revisit |
|---|---|---|
| 8654 | Extended messages (>4096 bytes) | No mainstream requirement; read path centralizes the max-size constant so support is one line of plumbing plus negotiation |
| 9072 | Extended optional parameters length | Matters only when OPEN capabilities exceed 255 bytes; we are nowhere near. Typed error (Unsupported Optional Parameter) on receipt. Revisit if interop meets it |
| 4761 | VPLS | Named (SAFIVPLS) but unmodeled (2026-08-18): its NLRI is carried verbatim as RawNLRI, so a caller is not blocked; legacy relative to EVPN. Revisit if a consumer demands it |
| 4364 / 8277 | L3VPN and labeled unicast | Route semantics unmodeled: their NLRI is carried verbatim as RawNLRI, and their RD-prefixed next hops (12/24/48 bytes, RDs mandated zero and managed by the codec) fit MPReachNLRI.NextHop, so such attributes typed-parse whole (2026-08-18). SAFIMPLSVPN is named and classified; SAFI 129 shares the next hop encoding and is the trigger to extend rdNextHop if a consumer demands it |
| 8955 | Flowspec | Unmodeled: its NLRI is carried verbatim as RawNLRI and its absent next hop (length 0) parses and marshals (2026-08-18); the rule grammar is the caller's. Revisit if a consumer demands it |
| 7313 | Enhanced route refresh | Not advertised, so the ROUTE-REFRESH reserved byte is safely normalized to zero on re-marshal; preserving it is the first task if this lands |
| 9494 | Long-lived graceful restart | Out of the 4724 scope: its hard parts are Loc-RIB policy on the caller's side of the boundary, namely LLGR_STALE depreference and hours-long retention. Its capability and community are additive later without rework; revisit if a consumer demands it |
| 6396 | MRT | Not a wire feature of this module: a BGP4MP writer is a sibling module built on OnMessage (every message, both directions, with endpoints) and OnStateChange (State numbered as MRT numbers it). `internal/mrt` reads BGP4MP for the test corpus only |
| 9384 | BFD Down (Cease subcode 10) | Named (SubcodeCeaseBFDDown) and consumable via ResetSession (2026-08-26): a BFD-driven caller sends it plain or wrapped in a Hard Reset. BFD itself (RFC 5880/5881) stays outside this module; a future implementation is its own context |
| 2842-style dynamic capabilities | Capability renegotiation | FSM deliberate cut |
| 6472 | AS_SET deprecation (BCP) | Followed in spirit: AS_SET marshals but never auto-splits |

## Explicitly never

| RFC / area | Why |
|---|---|
| 4456/4364-style RIB, best-path, policy | A library boundary, not a feature gap: this package is wire format + FSM, permanently |
| Pre-RFC 6793 2-octet-only sessions | AS4_PATH/AS4_AGGREGATOR reconciliation is intentionally omitted: the most error-prone corner of BGP implementations, serving only pre-2010 gear |
| 8684 | Multipath TCP | Explicitly disabled on every connection: BGP is single-path, and MPTCP sockets reject TCP_MD5SIG (Go enables MPTCP by default) |

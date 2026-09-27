package bgp

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// buildOpen derives a local OPEN from the validated identity: the
// multiprotocol capabilities from Families alone (an empty list advertises
// none, the classic IPv4 unicast speaker), then each capability the
// identity's own fields configure, encoded here with any per-attempt state
// such as the graceful restart Restart State bit, then the caller's
// capabilities verbatim. It proves the result marshals before returning it.
func buildOpen(id Identity, restarting bool) (*Open, error) {
	var caps []Capability
	for _, f := range id.Families {
		caps = append(caps, MultiprotocolCapability(f))
	}

	if id.RouteRefresh {
		caps = append(caps, Capability{Code: CapabilityRouteRefresh})
	}

	if id.EnhancedRouteRefresh {
		caps = append(caps, Capability{Code: CapabilityEnhancedRouteRefresh})
	}

	if id.GracefulRestart != nil {
		gc, err := GracefulRestartCapability(GracefulRestart{
			Restarting:          restarting,
			NotificationSupport: id.GracefulRestart.NotificationSupport,
			RestartTime:         id.GracefulRestart.RestartTime,
			Families:            id.GracefulRestart.Families,
		})
		if err != nil {
			return nil, err
		}

		caps = append(caps, gc)
	}

	if id.LongLivedGracefulRestart != nil {
		lc, err := LongLivedGracefulRestartCapability(*id.LongLivedGracefulRestart)
		if err != nil {
			return nil, err
		}

		caps = append(caps, lc)
	}

	if len(id.AddPath) > 0 {
		seen := make(map[Family]bool, len(id.AddPath))
		for _, af := range id.AddPath {
			if !af.Family.prefixShaped() {
				return nil, fmt.Errorf("bgp: add-path is only supported for prefix shaped families, not %s", af.Family)
			}

			if seen[af.Family] {
				return nil, fmt.Errorf("bgp: duplicate add-path family %s", af.Family)
			}

			seen[af.Family] = true
		}

		ac, err := AddPathCapability(id.AddPath...)
		if err != nil {
			return nil, err
		}

		caps = append(caps, ac)
	}

	if id.Role != nil {
		caps = append(caps, RoleCapability(id.Role.Role))
	}

	caps = append(caps, id.Capabilities...)

	o := &Open{
		ASN:          id.LocalASN,
		HoldTime:     id.HoldTime,
		ID:           id.LocalID,
		Capabilities: caps,
		FourOctetAS:  true,
	}

	if _, err := o.AppendBinary(nil); err != nil {
		return nil, err
	}

	return o, nil
}

// negotiate validates a peer's OPEN against the configuration and produces
// the negotiated Session, or the *MessageError whose NOTIFICATION rejects
// the OPEN, per RFC 4271, section 6.2. The version, hold time floor, and
// nonzero identifier were already validated by parseOpen. local is the OPEN
// this speaker sent on the attempt, reported as Session.Local.
func (f *FSM) negotiate(local, o *Open) (Session, *MessageError) {
	// 2-octet sessions are explicitly unsupported; see [Open.ASN]. This
	// check comes first: a legacy peer carries AS_TRANS in the fixed ASN
	// field, so an ASN comparison before it would report a misleading Bad
	// Peer AS. The diagnostic data names the required capability, per RFC
	// 5492, section 5.
	if !o.FourOctetAS {
		data := mustAppendCapability(nil, Capability{
			Code: CapabilityFourOctetAS,
			Data: binary.BigEndian.AppendUint32(nil, f.cfg.LocalASN),
		})

		return Session{}, openError(SubcodeUnsupportedCapability, data,
			"peer does not support four-octet AS numbers")
	}

	// RFC 7607, section 4: an OPEN whose My Autonomous System is zero is
	// answered with Bad Peer AS, mirroring NewFSM's rejection of a zero
	// local ASN.
	if o.ASN == 0 {
		return Session{}, openError(SubcodeBadPeerAS, nil, "peer ASN is zero")
	}

	if f.cfg.PeerASN != 0 && o.ASN != f.cfg.PeerASN {
		return Session{}, openError(SubcodeBadPeerAS, nil,
			"peer ASN %d does not match configured ASN %d", o.ASN, f.cfg.PeerASN)
	}

	// The identifier pin mirrors the ASN pin: protocol identity, which is
	// all the FSM knows of its peer (RFC 4271, section 6.2).
	if f.cfg.PeerID != 0 && o.ID != f.cfg.PeerID {
		return Session{}, openError(SubcodeBadBGPIdentifier, nil,
			"peer identifier %s does not match configured identifier %s", o.ID, f.cfg.PeerID)
	}

	// RFC 6286, section 2.2: a BGP identifier need only be unique within an
	// AS. An internal peer, in this speaker's own AS, which bears this
	// speaker's identifier is therefore a duplicate inside the AS, or this
	// speaker reaching itself. Externally, equal identifiers are legal, and
	// collision resolution breaks the tie on ASN; see dialedSurvives.
	if o.ASN == f.cfg.LocalASN && o.ID == f.cfg.LocalID {
		return Session{}, openError(SubcodeBadBGPIdentifier, nil,
			"internal peer OPEN carries the local BGP identifier")
	}

	// RFC 4271 permits a zero hold time, disabling keepalives and the hold
	// timer; this package rejects it, since every liveness mechanism the FSM
	// has depends on the hold timer. See Identity.HoldTime.
	if o.HoldTime == 0 {
		return Session{}, openError(SubcodeUnacceptableHoldTime, nil,
			"zero hold time is not supported")
	}

	if err := f.checkRole(o); err != nil {
		return Session{}, err
	}

	fams := negotiatedFamilies(f.families, o.Capabilities)
	if len(fams) == 0 {
		var data []byte
		for _, f := range f.families {
			data = mustAppendCapability(data, MultiprotocolCapability(f))
		}

		return Session{}, openError(SubcodeUnsupportedCapability, data,
			"no address families in common")
	}

	op := o.Clone()
	return Session{
		Peer:                     op,
		Local:                    local,
		Families:                 fams,
		RouteRefresh:             hasCapability(op.Capabilities, CapabilityRouteRefresh),
		EnhancedRouteRefresh:     f.cfg.EnhancedRouteRefresh && hasCapability(op.Capabilities, CapabilityEnhancedRouteRefresh),
		ExtendedNextHop:          extendedNextHopFamilies(op.Capabilities),
		GracefulRestart:          gracefulRestart(op.Capabilities),
		LongLivedGracefulRestart: longLivedGracefulRestart(op.Capabilities),
		AddPath:                  negotiatedAddPath(f.cfg.AddPath, fams, op.Capabilities),
		Role:                     peerRole(op.Capabilities),
		HoldTime:                 min(f.cfg.HoldTime, o.HoldTime),
	}, nil
}

// checkRole checks the peer's BGP Role against the local one, per RFC 9234,
// section 4.2, and returns the Role Mismatch error which rejects the OPEN,
// or nil. There is no check without a local role. NewFSM pins a peer with
// a role to an external AS, and negotiate has already checked the pin.
func (f *FSM) checkRole(o *Open) *MessageError {
	if f.cfg.Role == nil {
		return nil
	}

	// Identical capabilities count as one. Conflicting ones and a
	// malformed one are a mismatch; RoleConfig says why.
	var (
		pr   Role
		seen bool
	)

	for _, c := range o.Capabilities {
		if c.Code != CapabilityRole {
			continue
		}

		r, err := c.Role()
		if err != nil {
			return openError(SubcodeRoleMismatch, nil, "malformed BGP Role capability")
		}

		if seen && r != pr {
			return openError(SubcodeRoleMismatch, nil,
				"remote advertised conflicting BGP Roles %s and %s", pr, r)
		}

		pr, seen = r, true
	}

	if !seen {
		if f.cfg.Role.Strict {
			return openError(SubcodeRoleMismatch, nil,
				"remote advertised no BGP Role, and strict mode requires one")
		}

		return nil
	}

	if !f.cfg.Role.Role.pairs(pr) {
		return openError(SubcodeRoleMismatch, nil,
			"remote role %s does not pair with local role %s", pr, f.cfg.Role.Role)
	}

	return nil
}

// peerRole decodes the first well-formed BGP Role capability in caps, or
// nil when there is none; a malformed one is skipped, like a malformed
// graceful restart capability. When a local role is configured, checkRole
// has already proven every Role capability well-formed and identical.
func peerRole(caps []Capability) *Role {
	for _, c := range caps {
		if c.Code != CapabilityRole {
			continue
		}

		if r, err := c.Role(); err == nil {
			return &r
		}
	}

	return nil
}

// negotiatedAddPath intersects the local add-path configuration with the
// peer's add-path capability, per RFC 7911, section 5: this speaker may
// send multiple paths for a family it advertised Send and the peer
// advertised Receive, and will receive them for a family it advertised
// Receive and the peer advertised Send. Only families in the negotiated
// set count, in local configuration order. A malformed capability is
// skipped, like a malformed multiprotocol capability, and the first entry
// for a family wins, since RFC 7911 forbids duplicates.
func negotiatedAddPath(ours []AddPathFamily, fams []Family, caps []Capability) []AddPathFamily {
	if len(ours) == 0 {
		return nil
	}

	peer := make(map[Family]AddPathFamily)
	for _, c := range caps {
		if c.Code != CapabilityAddPath {
			continue
		}

		fs, err := c.AddPath()
		if err != nil {
			continue
		}

		for _, af := range fs {
			if _, ok := peer[af.Family]; !ok {
				peer[af.Family] = af
			}
		}
	}

	var out []AddPathFamily
	for _, l := range ours {
		if !slices.Contains(fams, l.Family) {
			continue
		}

		p, ok := peer[l.Family]
		if !ok {
			continue
		}

		af := AddPathFamily{
			Family:  l.Family,
			Send:    l.Send && p.Receive,
			Receive: l.Receive && p.Send,
		}

		if af.Send || af.Receive {
			out = append(out, af)
		}
	}

	return out
}

// gracefulRestart decodes the first well-formed graceful restart capability
// in caps, or nil when there is none; a malformed one is skipped, like a
// malformed multiprotocol capability. The capabilities must already be owned
// (Open.Clone), so the decoded value outlives the read buffer.
func gracefulRestart(caps []Capability) *GracefulRestart {
	for _, c := range caps {
		if c.Code != CapabilityGracefulRestart {
			continue
		}

		if gr, err := c.GracefulRestart(); err == nil {
			return &gr
		}
	}

	return nil
}

// longLivedGracefulRestart decodes the first well-formed long-lived graceful
// restart capability in caps, or nil when there is none, exactly as
// gracefulRestart does. It does not check that a graceful restart capability
// accompanies it (RFC 9494, section 4.1): that pairing is the caller's RIB's
// to honor when it decides retention.
func longLivedGracefulRestart(caps []Capability) *LongLivedGracefulRestart {
	for _, c := range caps {
		if c.Code != CapabilityLongLivedGracefulRestart {
			continue
		}

		if llgr, err := c.LongLivedGracefulRestart(); err == nil {
			return &llgr
		}
	}

	return nil
}

// dialedSurvives resolves a connection collision between the identities
// in the local and peer OPENs: it reports whether the locally initiated
// connection survives, per RFC 4271, section 6.8 and RFC 6286, section 2.3.
//
// A full tie cannot occur: negotiate rejects an internal peer bearing the
// local identifier (RFC 6286, section 2.2), and the identities compared here
// are the negotiated ones.
func dialedSurvives(local, peer *Open) bool {
	if local.ID != peer.ID {
		return local.ID > peer.ID
	}

	return local.ASN > peer.ASN
}

// negotiatedFamilies intersects the local family set with the peer's
// multiprotocol capabilities, in local order. A peer which advertises no
// multiprotocol capability at all is the implicit IPv4 unicast speaker of
// RFC 4760; a malformed multiprotocol capability is skipped.
func negotiatedFamilies(ours []Family, caps []Capability) []Family {
	var (
		peer       []Family
		advertised bool
	)

	for _, c := range caps {
		if c.Code != CapabilityMultiprotocol {
			continue
		}

		advertised = true
		if f, err := c.Multiprotocol(); err == nil {
			peer = append(peer, f)
		}
	}

	if !advertised {
		peer = implicitFamilies
	}

	var out []Family
	for _, f := range ours {
		if slices.Contains(peer, f) && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}

	return out
}

// extendedNextHopFamilies parses the families a peer accepts IPv6 next hops
// for from its Extended Next Hop capabilities (RFC 8950), gathered across
// every such capability it sent. A malformed capability advertises nothing,
// like a malformed multiprotocol one above, and Capability.ExtendedNextHop
// skips the entries whose next hop AFI is not IPv6: the wire form is a triple
// of AFI, SAFI, and next hop AFI, and a triple naming some other next hop AFI
// is not an RFC 8950 offer.
func extendedNextHopFamilies(caps []Capability) []Family {
	var fams []Family
	for _, c := range caps {
		if c.Code != CapabilityExtendedNextHop {
			continue
		}

		if fs, err := c.ExtendedNextHop(); err == nil {
			fams = append(fams, fs...)
		}
	}

	return fams
}

// hasCapability reports whether caps contains a capability with the given
// code.
func hasCapability(caps []Capability, code CapabilityCode) bool {
	return slices.ContainsFunc(caps, func(c Capability) bool { return c.Code == code })
}

package bgp

import (
	"encoding/binary"
	"fmt"
)

// A Role is a BGP Role (RFC 9234): the relationship of the local AS to the
// remote AS on an eBGP session. Two speakers confirm their roles with the
// BGP Role capability, and the local role drives the OTC ingress and egress
// procedures of [Role.Ingress] and [Role.Egress].
type Role uint8

// Role values, as assigned by IANA. Values 5 through 255 are unassigned.
// RolePeer is RFC 9234's lateral peer, a relationship between two ASes,
// not the remote speaker a [Peer] manages.
const (
	RoleProvider Role = 0
	RoleRS       Role = 1
	RoleRSClient Role = 2
	RoleCustomer Role = 3
	RolePeer     Role = 4
)

// String returns the RFC 9234 name of the Role.
func (r Role) String() string {
	switch r {
	case RoleProvider:
		return "Provider"
	case RoleRS:
		return "RS"
	case RoleRSClient:
		return "RS-Client"
	case RoleCustomer:
		return "Customer"
	case RolePeer:
		return "Peer"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

// valid reports whether r is an assigned Role.
func (r Role) valid() bool { return r <= RolePeer }

// pairs reports whether a peer's role pr corresponds to the local role r,
// per RFC 9234, section 4.2, Table 2.
func (r Role) pairs(pr Role) bool {
	switch r {
	case RoleProvider:
		return pr == RoleCustomer
	case RoleCustomer:
		return pr == RoleProvider
	case RoleRS:
		return pr == RoleRSClient
	case RoleRSClient:
		return pr == RoleRS
	case RolePeer:
		return pr == RolePeer
	default:
		return false
	}
}

// Ingress applies the OTC ingress procedure of RFC 9234, section 5 to a
// route received on a session whose local role is r. remoteASN is the
// peer's AS number and attrs the route's path attributes, which Ingress
// only reads.
//
// leak reports a route leak: the route must be considered ineligible.
// Otherwise add reports whether the route must be stored with otc added to
// its attributes, which happens for a route from a Provider, Peer, or RS
// which carries no OTC.
//
// RFC 9234 applies the procedure only to IPv4 and IPv6 unicast routes, so
// the caller skips it for any other family. A malformed OTC counts as
// present and matches no ASN, though RFC 7606 already makes its UPDATE a
// withdrawal. An unassigned role applies no procedure.
func (r Role) Ingress(remoteASN uint32, attrs RawAttributes) (otc OTC, add, leak bool) {
	raw, ok := attrs.Find(AttrOTC)
	switch r {
	case RoleProvider, RoleRS:
		// A route from a Customer or RS-Client which already carries OTC
		// has been sent toward customers only, and came back up.
		return 0, false, ok
	case RolePeer:
		if ok {
			return 0, false, len(raw.Data) != 4 || binary.BigEndian.Uint32(raw.Data) != remoteASN
		}
	case RoleCustomer, RoleRSClient:
		if ok {
			return 0, false, false
		}
	default:
		return 0, false, false
	}

	return OTC(remoteASN), true, false
}

// Egress applies the OTC egress procedure of RFC 9234, section 5 to a route
// about to be advertised on a session whose local role is r. localASN is
// the AS number this speaker presents to the peer, which is the
// confederation identifier on egress from a confederation. attrs are the
// route's path attributes, which Egress only reads.
//
// ok reports whether the route may be advertised: a route carrying OTC
// must not go to a Provider, Peer, or RS. When it may, add reports whether
// otc must be added to the advertised attributes, which happens for a
// route to a Customer, Peer, or RS-Client which carries no OTC.
//
// As with Ingress, the caller applies Egress only to IPv4 and IPv6 unicast
// routes, a malformed OTC counts as present, and an unassigned role applies
// no procedure.
func (r Role) Egress(localASN uint32, attrs RawAttributes) (otc OTC, add, ok bool) {
	_, has := attrs.Find(AttrOTC)
	switch r {
	case RoleCustomer, RoleRSClient:
		return 0, false, !has
	case RolePeer:
		if has {
			return 0, false, false
		}
	case RoleProvider, RoleRS:
		if has {
			return 0, false, true
		}
	default:
		return 0, false, true
	}

	return OTC(localASN), true, true
}

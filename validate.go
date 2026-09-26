// RFC 7606 error handling for a parsed UPDATE: the syntax rule of each
// attribute type, the outcome its malformation draws, and Update.classify,
// which applies them to a whole UPDATE. The file follows that flow rather
// than one type.

package bgp

import (
	"encoding/binary"
	"fmt"
)

// An outcome is an RFC 7606, section 2 error handling approach, ordered
// weakest to strongest so the strongest of several is their maximum, as
// section 3(h) requires. The AFI/SAFI disable of RFC 4760, section 7 is not
// among them: this package does not own a session's families.
type outcome uint8

const (
	// outcomeOK is no error.
	outcomeOK outcome = iota

	// outcomeDiscard drops the attribute and processes the rest of the
	// UPDATE. Only an attribute with no effect on route selection may
	// draw it.
	outcomeDiscard

	// outcomeWithdraw treats every route the UPDATE announces as
	// withdrawn; the session continues.
	outcomeWithdraw

	// outcomeReset sends a NOTIFICATION and ends the session, as RFC 4271
	// did for every error.
	outcomeReset
)

// An attrRule is the syntax rule of one attribute type this package
// interprets.
type attrRule struct {
	// flags is the Optional and Transitive bits the type's specification
	// requires, and out the outcome a malformation draws. An out of
	// outcomeOK marks a type this package does not interpret, which has
	// no rule.
	flags AttrFlags
	out   outcome

	// exact is the only data length the type accepts, or -1 when its
	// content frames itself. unit, when non-zero, replaces exact with the
	// size of one repeated element, of which the length must be a non-zero
	// multiple.
	exact int16
	unit  uint8

	// content marks a type whose data needs more than its length checked;
	// see checkAttrContent. Most types do not, and the check is skipped
	// for them.
	content bool
}

// attrRules is the rule of every attribute type, indexed by the type. It is
// immutable after initialization. It is an array rather than a type switch
// because the receive path reads one entry per attribute of every UPDATE.
var attrRules = buildAttrRules()

// buildAttrRules states the rule of each interpreted attribute type. The
// flags come from the typed attributes themselves, so what the receive path
// enforces and what this package marshals cannot drift apart.
func buildAttrRules() [256]attrRule {
	var rs [256]attrRule
	for i := range rs {
		rs[i].exact = -1
	}

	// Only fixed takes an outcome: the two types RFC 7606, section 3(f)
	// softens to an attribute discard are both fixed length, and every
	// other interpreted type is section 3(e)'s treat-as-withdraw.

	// fixed states a type whose data is exactly n bytes.
	fixed := func(a Attribute, out outcome, n int16) {
		rs[a.attrType()] = attrRule{
			flags: a.attrFlags(),
			out:   out,
			exact: n,
		}
	}

	// repeated states a type whose data is a whole number of unit byte
	// elements, and never empty, as RFC 7606, section 4 requires.
	repeated := func(a Attribute, unit uint8) {
		rs[a.attrType()] = attrRule{
			flags: a.attrFlags(),
			out:   outcomeWithdraw,
			exact: -1,
			unit:  unit,
		}
	}

	// framed states a type whose content frames itself, so it has no
	// length rule of its own.
	framed := func(a Attribute) {
		rs[a.attrType()] = attrRule{
			flags: a.attrFlags(),
			out:   outcomeWithdraw,
			exact: -1,
		}
	}

	// content marks a type whose data says more than its length does; see
	// checkAttrContent.
	content := func(a Attribute) { rs[a.attrType()].content = true }

	// RFC 7606, section 3(e) and sections 7.1 through 7.5: a malformed
	// attribute which bears on route selection withdraws the routes the
	// UPDATE announces. The lengths are each attribute's specification's.
	// Sections 7.5, 7.9, and 7.10 discard LOCAL_PREF, ORIGINATOR_ID, and
	// CLUSTER_LIST from an external neighbor; this package does not know
	// which a session is, so all three are handled as from an internal
	// one and nothing is silently dropped.
	fixed(Origin(0), outcomeWithdraw, 1)
	fixed(NextHop{}, outcomeWithdraw, 4)
	fixed(MED(0), outcomeWithdraw, 4)
	fixed(LocalPref(0), outcomeWithdraw, 4)
	fixed(OriginatorID(0), outcomeWithdraw, 4)
	fixed(OTC(0), outcomeWithdraw, 4)
	repeated(Communities(nil), 4)
	repeated(ClusterList(nil), 4)
	repeated(ExtendedCommunities(nil), 8)
	repeated(LargeCommunities(nil), 12)
	framed(ASPath(nil))
	framed(MPReachNLRI{})
	framed(MPUnreachNLRI{})

	// RFC 7606, section 3(f): neither bears on route selection, so a
	// malformation costs only the attribute.
	fixed(AtomicAggregate{}, outcomeDiscard, 0)
	fixed(Aggregator{}, outcomeDiscard, 8)

	// The marks come last: every helper above assigns a whole rule, so one
	// set before a helper ran would be overwritten by it.
	content(Origin(0))
	content(ASPath(nil))
	content(MPReachNLRI{})
	content(MPUnreachNLRI{})

	return rs
}

// flagsOK reports whether flags are what r's type requires: the Optional
// and Transitive bits of RFC 7606, section 3(c), and the Partial bit, which
// RFC 4271, section 4.3 allows only on an optional transitive attribute.
func (r attrRule) flagsOK(flags AttrFlags) bool {
	const optTrans = AttrFlagOptional | AttrFlagTransitive
	if flags&optTrans != r.flags {
		return false
	}

	return r.flags == optTrans || flags&AttrFlagPartial == 0
}

// lengthOK reports whether n bytes of data satisfy r's length rule. The
// element sizes are switched on so every division is by a constant: this
// runs for every attribute of every UPDATE.
func (r attrRule) lengthOK(n int) bool {
	switch r.unit {
	case 0:
		return r.exact < 0 || int(r.exact) == n
	case 4:
		return n > 0 && n%4 == 0
	case 8:
		return n > 0 && n%8 == 0
	case 12:
		return n > 0 && n%12 == 0
	default:
		return n > 0 && n%int(r.unit) == 0
	}
}

// validate reports whether a, whose rule is r, is malformed by the rules
// of RFC 7606, sections 4, 5.3, and 7. A type this package does not
// interpret has no rule and is always valid. RawAttribute.parse checks it
// before decoding; the receive path applies the same rules through
// classifyAttribute, which also needs to know which one failed.
func (r attrRule) validate(a *RawAttribute) *MessageError {
	if !r.lengthOK(len(a.Data)) {
		return badAttrLength(a.Type, len(a.Data))
	}

	if r.content {
		return checkAttrContent(a)
	}

	return nil
}

// checkAttrContent checks the four types whose data says more than its
// length does: the defined values of ORIGIN, the segment framing of
// AS_PATH, and the multiprotocol attributes' family header, next hop, and
// NLRI syntax per RFC 7606, section 5.3. It is reached only for a type
// whose rule sets content.
func checkAttrContent(a *RawAttribute) *MessageError {
	switch a.Type {
	case AttrOrigin:
		if a.Data[0] > uint8(OriginIncomplete) {
			return updateError(SubcodeInvalidOriginAttribute, nil,
				"invalid ORIGIN value %d", a.Data[0])
		}
	case AttrASPath:
		return validateASPath(a.Data)
	case AttrMPReachNLRI:
		if len(a.Data) < 5 {
			return updateError(SubcodeOptionalAttributeError, nil,
				"invalid MP_REACH_NLRI attribute length %d", len(a.Data))
		}

		return validateMPReach(a.Data, a.addPath)
	case AttrMPUnreachNLRI:
		if len(a.Data) < 3 {
			return updateError(SubcodeOptionalAttributeError, nil,
				"invalid MP_UNREACH_NLRI attribute length %d", len(a.Data))
		}

		return validateNLRI(a.Data[3:], mpFamily(a.Data), a.addPath)
	}

	return nil
}

// mpFamily reads the family header of a multiprotocol attribute's data,
// which is at least 3 bytes.
func mpFamily(b []byte) Family {
	return Family{
		AFI:  AFI(binary.BigEndian.Uint16(b[0:2])),
		SAFI: SAFI(b[2]),
	}
}

// validateMPReach checks MP_REACH_NLRI data past its family header: the
// next hop frames and is valid for the family, then the NLRI frames.
func validateMPReach(b []byte, addPath bool) *MessageError {
	f := mpFamily(b)
	n := int(b[3])
	if len(b[4:]) < n+1 {
		return updateError(SubcodeOptionalAttributeError, nil,
			"MP_REACH_NLRI next hop truncated")
	}

	if merr := validateNextHop(f, b[4:4+n]); merr != nil {
		return merr
	}

	// One reserved byte, then NLRI.
	return validateNLRI(b[4+n+1:], f, addPath)
}

// validateNextHop checks an MP_REACH_NLRI next hop of family f. A family
// whose next hop this package models must carry one of that family's
// lengths; a family it does not model may carry any length. Zero is an
// absent next hop for any family.
func validateNextHop(f Family, nh []byte) *MessageError {
	switch n := len(nh); {
	case n == 0:
		return nil
	case f.rdNextHop():
		return validateRDNextHop(f, nh)
	case f.prefixShaped() && n != 4 && n != 16 && n != 32:
		return unsupportedNextHop(f, n)
	default:
		return nil
	}
}

// validateRDNextHop checks a VPN family's next hop: one address or a pair,
// each behind an 8 byte route distinguisher which must be zero.
func validateRDNextHop(f Family, nh []byte) *MessageError {
	switch len(nh) {
	case 12, 24:
		return zeroRD(nh[0:8])
	case 48:
		if merr := zeroRD(nh[0:8]); merr != nil {
			return merr
		}

		return zeroRD(nh[24:32])
	default:
		return unsupportedNextHop(f, len(nh))
	}
}

// unsupportedNextHop is the error for a next hop length family f does not
// define.
func unsupportedNextHop(f Family, n int) *MessageError {
	return updateError(SubcodeOptionalAttributeError, nil,
		"unsupported %s next hop length %d", f, n)
}

// zeroRD checks that the 8 byte route distinguisher preceding a VPN next
// hop is zero, as RFC 4364, section 4.3.2 and RFC 4659, section 3.2.1.1
// require.
func zeroRD(b []byte) *MessageError {
	if [8]byte(b) != [8]byte{} {
		return updateError(SubcodeOptionalAttributeError, nil,
			"MP_REACH_NLRI next hop route distinguisher must be zero")
	}

	return nil
}

// validateNLRI checks that the NLRI of family f frames, in the shape
// parseNLRI decodes it. A family this package does not model is opaque
// and always valid.
func validateNLRI(b []byte, f Family, addPath bool) *MessageError {
	switch {
	case f.prefixShaped():
		// prefixShaped implies an AFI with a prefix length.
		max, _ := prefixBits(f.AFI)
		return validatePrefixes(b, max, addPath)
	case f == familyEVPN:
		return validateEVPNRoutes(b)
	default:
		return nil
	}
}

// validatePrefixes checks that b frames as prefixes of at most max bits,
// each behind a 4 byte path identifier when addPath is set.
func validatePrefixes(b []byte, max int, addPath bool) *MessageError {
	for len(b) > 0 {
		if addPath {
			if len(b) < 5 {
				return updateError(SubcodeOptionalAttributeError, nil,
					"path identifier truncated")
			}

			b = b[4:]
		}

		bits := int(b[0])
		if bits > max {
			return updateError(SubcodeOptionalAttributeError, nil,
				"prefix length %d exceeds maximum of %d bits", bits, max)
		}

		n := 1 + (bits+7)/8
		if len(b) < n {
			return updateError(SubcodeOptionalAttributeError, nil,
				"prefix truncated")
		}

		b = b[n:]
	}

	return nil
}

// validateEVPNRoutes checks that b frames as EVPN records: a type, a
// length, and that many bytes.
func validateEVPNRoutes(b []byte) *MessageError {
	for len(b) > 0 {
		if len(b) < 2 {
			return updateError(SubcodeOptionalAttributeError, nil,
				"EVPN NLRI record header truncated")
		}

		n := int(b[1])
		if len(b[2:]) < n {
			return updateError(SubcodeOptionalAttributeError, nil,
				"EVPN NLRI record truncated: %d of %d bytes", len(b[2:]), n)
		}

		b = b[2+n:]
	}

	return nil
}

// badAttrLength produces the error for an attribute whose data length its
// type does not accept.
func badAttrLength(t AttrType, n int) *MessageError {
	return updateError(SubcodeAttributeLengthError, nil,
		"invalid %s attribute length %d", attrName(t), n)
}

// badAttrFlags produces the error for an attribute whose flags conflict with
// its type.
func badAttrFlags(t AttrType, flags AttrFlags) *MessageError {
	return updateError(SubcodeAttributeFlagsError, nil,
		"%s flags %#02x conflict with its type", attrName(t), uint8(flags))
}

// attrName returns the specification's name for an attribute type, for
// error messages.
func attrName(t AttrType) string {
	switch t {
	case AttrOrigin:
		return "ORIGIN"
	case AttrASPath:
		return "AS_PATH"
	case AttrNextHop:
		return "NEXT_HOP"
	case AttrMED:
		return "MULTI_EXIT_DISC"
	case AttrLocalPref:
		return "LOCAL_PREF"
	case AttrAtomicAggregate:
		return "ATOMIC_AGGREGATE"
	case AttrAggregator:
		return "AGGREGATOR"
	case AttrCommunities:
		return "COMMUNITIES"
	case AttrOriginatorID:
		return "ORIGINATOR_ID"
	case AttrClusterList:
		return "CLUSTER_LIST"
	case AttrMPReachNLRI:
		return "MP_REACH_NLRI"
	case AttrMPUnreachNLRI:
		return "MP_UNREACH_NLRI"
	case AttrExtendedCommunities:
		return "EXTENDED_COMMUNITIES"
	case AttrLargeCommunities:
		return "LARGE_COMMUNITY"
	case AttrOTC:
		return "OTC"
	default:
		return fmt.Sprintf("attribute %d", uint8(t))
	}
}

// validateASPath checks AS_PATH data for the malformations RFC 7606,
// section 7.2 names: an unknown segment type, a segment which overruns the
// attribute, a trailing byte too short for a segment header, and an empty
// segment.
func validateASPath(b []byte) *MessageError {
	for len(b) > 0 {
		if len(b) < 2 {
			return updateError(SubcodeMalformedASPath, nil,
				"AS_PATH segment truncated")
		}

		switch b[0] {
		case asSet, asSequence, asConfedSequence, asConfedSet:
		default:
			return updateError(SubcodeMalformedASPath, nil,
				"unsupported AS_PATH segment type %d", b[0])
		}

		n := int(b[1])
		if n == 0 {
			return updateError(SubcodeMalformedASPath, nil,
				"empty AS_PATH segment")
		}

		if len(b[2:]) < 4*n {
			return updateError(SubcodeMalformedASPath, nil,
				"AS_PATH segment truncated")
		}

		b = b[2+4*n:]
	}

	return nil
}

// classifyAttribute reports the outcome RFC 7606 assigns to one attribute
// and the error describing it: outcomeOK for a well-formed attribute and
// for any type this package does not interpret. It runs for every
// attribute of every UPDATE.
func classifyAttribute(a *RawAttribute) (outcome, *MessageError) {
	switch r := attrRules[a.Type]; {
	case r.out == outcomeOK:
		// RFC 4271, section 6.3: an attribute with the Optional bit clear
		// is well known, so an uninterpreted one is an unrecognized
		// well-known attribute, which RFC 7606 does not revise. Any other
		// unrecognized attribute passes through, per RFC 4271, section 5.
		if a.Flags&AttrFlagOptional == 0 {
			return outcomeReset, updateError(SubcodeUnrecognizedWellKnownAttribute, nil,
				"unrecognized well-known attribute %d", uint8(a.Type))
		}
	case !r.flagsOK(a.Flags):
		return r.out, badAttrFlags(a.Type, a.Flags)
	case !r.lengthOK(len(a.Data)):
		return r.out, badAttrLength(a.Type, len(a.Data))
	case r.content:
		merr := checkAttrContent(a)
		if merr == nil {
			break
		}

		// RFC 7606, sections 5.3 and 7.11: a malformed multiprotocol
		// attribute means the NLRI cannot be located, so section 3(j)
		// keeps the session reset.
		if a.Type == AttrMPReachNLRI || a.Type == AttrMPUnreachNLRI {
			return outcomeReset, merr
		}

		return r.out, merr
	}

	return outcomeOK, nil
}

// A typeSet is the set of attribute types an UPDATE carries, for the
// duplicate detection of RFC 7606, section 3(g) and the well-known
// mandatory check of 3(d). It is a value rather than a map because one is
// built per UPDATE.
type typeSet [4]uint64

// add records t in the set, reporting false when t was already present.
func (s *typeSet) add(t AttrType) bool {
	word, bit := t>>6, uint64(1)<<(t&63)
	if s[word]&bit != 0 {
		return false
	}

	s[word] |= bit
	return true
}

// has reports whether t is in the set.
func (s *typeSet) has(t AttrType) bool { return s[t>>6]&(uint64(1)<<(t&63)) != 0 }

// otherThan reports whether the set holds any type but t.
func (s typeSet) otherThan(t AttrType) bool {
	s[t>>6] &^= uint64(1) << (t & 63)
	return s[0]|s[1]|s[2]|s[3] != 0
}

// classify applies RFC 7606 error handling to a parsed UPDATE. framing is
// the attribute list truncation parseRawAttributes reported, or nil. A
// non-nil error is a session reset, which parseUpdate returns so the FSM
// answers the peer. Otherwise the UPDATE is delivered with diagnostics:
// Malformed for a treat-as-withdraw, Discarded for every attribute removed
// from Attributes. The diagnostics are nil when there is nothing to report.
func (u *Update) classify(framing *MessageError) (*UpdateDiagnostics, error) {
	var (
		seen      typeSet
		worst     outcome
		first     *MessageError
		kept      int
		discarded RawAttributes
	)

	for i := range u.Attributes {
		a := &u.Attributes[i]

		// RFC 7606, section 3(g): a repeated multiprotocol attribute
		// resets the session. For any other type the first occurrence
		// stands and the rest are discarded unexamined.
		if !seen.add(a.Type) {
			if a.Type == AttrMPReachNLRI || a.Type == AttrMPUnreachNLRI {
				return nil, updateError(SubcodeMalformedAttributeList, nil,
					"duplicate multiprotocol attribute %d", uint8(a.Type))
			}

			discarded = append(discarded, *a)
			continue
		}

		out, merr := classifyAttribute(a)
		if out == outcomeReset {
			return nil, a.echoData(merr)
		}

		// Section 3(h): the strongest outcome wins, and the first error
		// of that strength in wire order is the one reported.
		if out > worst {
			worst, first = out, a.echoData(merr)
		}

		if out == outcomeDiscard {
			discarded = append(discarded, *a)
			continue
		}

		if kept != i {
			u.Attributes[kept] = *a
		}

		kept++
	}

	switch {
	case kept == 0:
		// An empty list is nil, as parsing zero attributes produces, so an
		// UPDATE whose every attribute was discarded looks like one which
		// carried none.
		u.Attributes = nil
	case kept < len(u.Attributes):
		u.Attributes = u.Attributes[:kept]
	}

	// RFC 7606, section 4: the attribute list did not frame, but the Total
	// Attribute Length still located the NLRI, so this is a
	// treat-as-withdraw rather than RFC 4271's reset. The truncation is at
	// the end of the list, so any attribute error precedes it in wire
	// order.
	if framing != nil && worst < outcomeWithdraw {
		worst, first = outcomeWithdraw, framing
	}

	// RFC 4271, section 4.3: an UPDATE which advertises routes carries the
	// well-known mandatory attributes, and RFC 7606, section 3(d) makes
	// their absence a treat-as-withdraw. RFC 4760, section 3 makes
	// NEXT_HOP discretionary for routes in MP_REACH_NLRI, which names its
	// own next hop, so it is required only beside the legacy NLRI field.
	legacy := len(u.NLRI) > 0 || len(u.NLRIPaths) > 0
	announces := legacy || seen.has(AttrMPReachNLRI)

	if announces && worst < outcomeWithdraw {
		var missing AttrType
		switch {
		case !seen.has(AttrOrigin):
			missing = AttrOrigin
		case !seen.has(AttrASPath):
			missing = AttrASPath
		case legacy && !seen.has(AttrNextHop):
			missing = AttrNextHop
		}

		if missing != 0 {
			worst = outcomeWithdraw
			first = updateError(SubcodeMissingWellKnownAttribute, []byte{byte(missing)},
				"missing well-known mandatory attribute %d", uint8(missing))
		}
	}

	if worst == outcomeWithdraw {
		// RFC 7606, section 5.2: an UPDATE with path attributes other than
		// MP_UNREACH_NLRI but nothing reachable cannot be trusted to have
		// had its NLRI located, so section 3(j)'s session reset applies. A
		// list which did not frame counts as carrying such an attribute:
		// its unread tail is unknown.
		if !announces && (framing != nil || seen.otherThan(AttrMPUnreachNLRI)) {
			return nil, first
		}
	} else {
		// Only a treat-as-withdraw is reported: a discarded attribute's
		// error describes something already dropped.
		first = nil
	}

	if first == nil && discarded == nil {
		return nil, nil
	}

	return &UpdateDiagnostics{
		Malformed: first,
		Discarded: discarded,
	}, nil
}

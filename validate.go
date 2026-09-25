// The syntax rules of every attribute type this package interprets: the
// length each accepts and, for the few whose data says more than its
// length does, the content. They sit in one table rather than in the
// decoder's switch so that every reader of an attribute, the typed decoder
// today and the receive path's UPDATE validation to come, enforces the same
// definition of malformed.

package bgp

import "fmt"

// An attrRule is everything this package knows about the syntax of one
// attribute type it interprets.
type attrRule struct {
	// exact is the only data length the type accepts, or -1 when its
	// content frames itself. unit, when non-zero, replaces exact with the
	// size of one repeated element, of which the length must be a non-zero
	// multiple.
	exact int16
	unit  uint8

	// content marks a type whose data needs more than its length checked;
	// see checkAttrContent. Most types do not, and the decoder skips the
	// check for them rather than calling into a switch which would find
	// nothing to do.
	content bool
}

// attrRules is the rule of every attribute type, indexed by the type. It is
// immutable after initialization, and is an array rather than a type switch
// because a reader looks up one entry per attribute of every UPDATE: a
// single load in place of the several switches the same facts would cost.
var attrRules = buildAttrRules()

// buildAttrRules states the rule of each interpreted attribute type. The
// lengths are each attribute's own specification's.
func buildAttrRules() [256]attrRule {
	var rs [256]attrRule
	for i := range rs {
		rs[i].exact = -1
	}

	// Each helper below states one type's whole rule.

	// fixed states a type whose data is exactly n bytes.
	fixed := func(a Attribute, n int16) { rs[a.attrType()] = attrRule{exact: n} }

	// repeated states a type whose data is a whole number of unit byte
	// elements, and never empty, as RFC 7606, section 4 requires.
	repeated := func(a Attribute, unit uint8) {
		rs[a.attrType()] = attrRule{
			exact: -1,
			unit:  unit,
		}
	}

	// framed states a type whose content frames itself, so it has no
	// length rule of its own.
	framed := func(a Attribute) { rs[a.attrType()] = attrRule{exact: -1} }

	// content marks a type whose data says more than its length does; see
	// checkAttrContent.
	content := func(a Attribute) { rs[a.attrType()].content = true }

	fixed(Origin(0), 1)
	fixed(NextHop{}, 4)
	fixed(MED(0), 4)
	fixed(LocalPref(0), 4)
	fixed(AtomicAggregate{}, 0)
	fixed(Aggregator{}, 8)
	fixed(OriginatorID(0), 4)
	fixed(OTC(0), 4)
	repeated(Communities(nil), 4)
	repeated(ClusterList(nil), 4)
	repeated(ExtendedCommunities(nil), 8)
	repeated(LargeCommunities(nil), 12)
	framed(ASPath(nil))
	framed(MPReachNLRI{})
	framed(MPUnreachNLRI{})

	// The marks come last: every helper above assigns a whole rule, so one
	// set before a helper ran would be overwritten by it.
	content(Origin(0))
	content(ASPath(nil))
	content(MPReachNLRI{})
	content(MPUnreachNLRI{})

	return rs
}

// lengthOK reports whether n bytes of data satisfy r's length rule. The
// element sizes are switched on rather than divided by, so that every
// division is by a constant the compiler turns into a multiply: this runs
// for every attribute of every UPDATE.
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

// validate reports whether the content of a, whose rule is r, is malformed
// by the rules RFC 7606, sections 4, 5.3, and 7 name. An attribute of a type
// this package does not interpret has no rules here and is always valid.
// It is what RawAttribute.parse checks before decoding.
func (r attrRule) validate(a *RawAttribute) *MessageError {
	if !r.lengthOK(len(a.Data)) {
		return badAttrLength(a.Type, len(a.Data))
	}

	if r.content {
		return checkAttrContent(a)
	}

	return nil
}

// checkAttrContent applies the rules of the four attribute types whose data
// says more than its length does: the defined values of ORIGIN, the segment
// framing of AS_PATH, and the minimum lengths RFC 7606, section 5.3 gives
// the multiprotocol attributes, shorter than which they name no family at
// all. It is reached only for a type whose rule sets content.
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
	case AttrMPUnreachNLRI:
		if len(a.Data) < 3 {
			return updateError(SubcodeOptionalAttributeError, nil,
				"invalid MP_UNREACH_NLRI attribute length %d", len(a.Data))
		}
	}

	return nil
}

// badAttrLength produces the error for an attribute whose data length its
// type does not accept.
func badAttrLength(t AttrType, n int) *MessageError {
	return updateError(SubcodeAttributeLengthError, nil,
		"invalid %s attribute length %d", attrName(t), n)
}

// attrName returns the specification's name for an attribute type this
// package interprets, for the error messages above. It is never reached on a
// well-formed attribute.
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

// validateASPath reports the malformations of an AS_PATH attribute's data
// which RFC 7606, section 7.2 names: an unrecognized segment type, a
// segment whose length overruns the attribute, a trailing byte too short to
// begin a segment header, and a segment of zero length.
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

package bgp

import (
	"fmt"
	"net/netip"
)

// An Identifier is a BGP identifier: a 4 byte number which identifies a
// speaker within an autonomous system, or a route reflection cluster. Per
// RFC 6286, an identifier is conventionally derived from one of a router's
// IPv4 addresses and is rendered in dotted quad form, but it is a number,
// not an address: it need not be routable, and IPv6-only speakers may use
// any value.
type Identifier uint32

// ParseIdentifier parses an Identifier from its conventional dotted quad
// form, such as "192.0.2.1".
func ParseIdentifier(s string) (Identifier, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return 0, fmt.Errorf("bgp: invalid identifier %q: %w", s, err)
	}

	a := addr.Unmap()
	if !a.Is4() {
		return 0, fmt.Errorf("bgp: identifier %q is not in dotted quad form", s)
	}

	a4 := a.As4()
	return Identifier(uint32(a4[0])<<24 | uint32(a4[1])<<16 | uint32(a4[2])<<8 | uint32(a4[3])), nil
}

// MustParseIdentifier parses an Identifier from its conventional dotted quad
// form, panicking on error: for tests with hard-coded strings.
func MustParseIdentifier(s string) Identifier {
	id, err := ParseIdentifier(s)
	if err != nil {
		panic(err)
	}

	return id
}

// String returns the conventional dotted quad form of an Identifier.
func (id Identifier) String() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
}

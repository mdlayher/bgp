package bgp

// A Keepalive is a BGP KEEPALIVE message, exchanged to maintain an
// established session, as described in RFC 4271, section 4.4.
type Keepalive struct{}

func (*Keepalive) messageType() MessageType { return MessageTypeKeepalive }

// AppendBinary implements encoding.BinaryAppender.
func (*Keepalive) AppendBinary(b []byte) ([]byte, error) {
	b, off := appendHeader(b, MessageTypeKeepalive)
	return finishMessage(b, off)
}

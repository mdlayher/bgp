package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Message Header Error subcodes, as described in RFC 4271, section 6.1. These
// values are carried by a Notification with Code NotificationMessageHeaderError.
const (
	SubcodeConnectionNotSynchronized uint8 = 1
	SubcodeBadMessageLength          uint8 = 2
	SubcodeBadMessageType            uint8 = 3
)

// OPEN Message Error subcodes, as described in RFC 4271, section 6.2, and RFC
// 5492, section 5. These values are carried by a Notification with Code
// NotificationOpenMessageError.
const (
	SubcodeUnsupportedVersionNumber     uint8 = 1
	SubcodeBadPeerAS                    uint8 = 2
	SubcodeBadBGPIdentifier             uint8 = 3
	SubcodeUnsupportedOptionalParameter uint8 = 4
	SubcodeUnacceptableHoldTime         uint8 = 6
	SubcodeUnsupportedCapability        uint8 = 7
)

// UPDATE Message Error subcodes, as described in RFC 4271, section 6.3. These
// values are carried by a Notification with Code NotificationUpdateMessageError.
const (
	SubcodeMalformedAttributeList         uint8 = 1
	SubcodeUnrecognizedWellKnownAttribute uint8 = 2
	SubcodeMissingWellKnownAttribute      uint8 = 3
	SubcodeAttributeFlagsError            uint8 = 4
	SubcodeAttributeLengthError           uint8 = 5
	SubcodeInvalidOriginAttribute         uint8 = 6
	SubcodeInvalidNextHopAttribute        uint8 = 8
	SubcodeOptionalAttributeError         uint8 = 9
	SubcodeInvalidNetworkField            uint8 = 10
	SubcodeMalformedASPath                uint8 = 11
)

// Finite State Machine Error subcodes, as described in RFC 6608. These values
// are carried by a Notification with Code NotificationFSMError, and report the
// state a session was in when an unexpected message arrived.
const (
	SubcodeUnexpectedMessageOpenSent    uint8 = 1
	SubcodeUnexpectedMessageOpenConfirm uint8 = 2
	SubcodeUnexpectedMessageEstablished uint8 = 3
)

// Cease subcodes, as described in RFC 4486, plus Hard Reset (RFC 8538) and
// BFD Down (RFC 9384). These values are carried by a Notification with Code
// NotificationCease. Hard Reset instructs a graceful restart helper to flush
// immediately; BFD Down reports that the peering's BFD session (RFC 5880)
// went down.
const (
	SubcodeCeaseMaximumPrefixesReached        uint8 = 1
	SubcodeCeaseAdministrativeShutdown        uint8 = 2
	SubcodeCeasePeerDeconfigured              uint8 = 3
	SubcodeCeaseAdministrativeReset           uint8 = 4
	SubcodeCeaseConnectionRejected            uint8 = 5
	SubcodeCeaseOtherConfigurationChange      uint8 = 6
	SubcodeCeaseConnectionCollisionResolution uint8 = 7
	SubcodeCeaseOutOfResources                uint8 = 8
	SubcodeCeaseHardReset                     uint8 = 9
	SubcodeCeaseBFDDown                       uint8 = 10
)

// A MessageError is an error produced by a malformed BGP message, carrying
// the NOTIFICATION code and subcode RFC 4271 requires in response. A session
// implementation recognizes it with errors.AsType and answers the peer with
// Notification.
//
// Unlike a Message produced by ParseMessage, a MessageError owns its Data and
// remains valid after the buffer it was parsed from is reused.
type MessageError struct {
	// Code and Subcode identify the error condition, and correspond to the
	// Notification fields of the same names.
	Code    NotificationCode
	Subcode uint8

	// Data carries the diagnostic information RFC 4271 requires for this
	// error condition, such as the erroneous length field of a message
	// header. It is nil when the condition requires no data.
	Data []byte

	// msg describes the error condition in human readable form.
	msg string
}

// Error implements error.
func (e *MessageError) Error() string {
	return fmt.Sprintf("bgp: %s (NOTIFICATION %s: %s)",
		e.msg, e.Code, subcodeString(e.Code, e.Subcode))
}

// Notification produces the Notification to send to the peer in response to
// e, as described in RFC 4271, section 6. The Notification owns its Data:
// mutating it does not reach back into e.
func (e *MessageError) Notification() *Notification {
	return &Notification{Code: e.Code, Subcode: e.Subcode, Data: bytes.Clone(e.Data)}
}

// newMessageError produces a *MessageError with the given code, subcode,
// diagnostic data, and human readable description. data is cloned so a
// MessageError never references a caller's buffer.
func newMessageError(code NotificationCode, subcode uint8, data []byte, format string, a ...any) *MessageError {
	return &MessageError{
		Code:    code,
		Subcode: subcode,
		Data:    bytes.Clone(data),
		msg:     fmt.Sprintf(format, a...),
	}
}

// headerError produces a *MessageError for a Message Header Error condition,
// as described in RFC 4271, section 6.1.
func headerError(subcode uint8, data []byte, format string, a ...any) *MessageError {
	return newMessageError(NotificationMessageHeaderError, subcode, data, format, a...)
}

// openError produces a *MessageError for an OPEN Message Error condition, as
// described in RFC 4271, section 6.2.
func openError(subcode uint8, data []byte, format string, a ...any) *MessageError {
	return newMessageError(NotificationOpenMessageError, subcode, data, format, a...)
}

// updateError produces a *MessageError for an UPDATE Message Error condition,
// as described in RFC 4271, section 6.3.
func updateError(subcode uint8, data []byte, format string, a ...any) *MessageError {
	return newMessageError(NotificationUpdateMessageError, subcode, data, format, a...)
}

// badLength produces a *MessageError reporting that a message's header length
// field is invalid for the message's type. Per RFC 4271, section 6.1, the
// erroneous length field is echoed back to the peer as diagnostic data.
// bodyLen is the length in bytes of the message body, without its header.
func badLength(bodyLen int, format string, a ...any) *MessageError {
	length := binary.BigEndian.AppendUint16(nil, uint16(bodyLen+headerLen))
	return headerError(SubcodeBadMessageLength, length, format, a...)
}

// subcodeString returns the name of a Notification subcode, which is defined
// relative to its NotificationCode.
func subcodeString(code NotificationCode, subcode uint8) string {
	if subcode == 0 {
		// RFC 4271, section 4.5: zero is used when no appropriate subcode is
		// defined for an error condition.
		return "Unspecific"
	}

	switch code {
	case NotificationMessageHeaderError:
		switch subcode {
		case SubcodeConnectionNotSynchronized:
			return "Connection Not Synchronized"
		case SubcodeBadMessageLength:
			return "Bad Message Length"
		case SubcodeBadMessageType:
			return "Bad Message Type"
		}
	case NotificationOpenMessageError:
		switch subcode {
		case SubcodeUnsupportedVersionNumber:
			return "Unsupported Version Number"
		case SubcodeBadPeerAS:
			return "Bad Peer AS"
		case SubcodeBadBGPIdentifier:
			return "Bad BGP Identifier"
		case SubcodeUnsupportedOptionalParameter:
			return "Unsupported Optional Parameter"
		case SubcodeUnacceptableHoldTime:
			return "Unacceptable Hold Time"
		case SubcodeUnsupportedCapability:
			return "Unsupported Capability"
		}
	case NotificationUpdateMessageError:
		switch subcode {
		case SubcodeMalformedAttributeList:
			return "Malformed Attribute List"
		case SubcodeUnrecognizedWellKnownAttribute:
			return "Unrecognized Well-known Attribute"
		case SubcodeMissingWellKnownAttribute:
			return "Missing Well-known Attribute"
		case SubcodeAttributeFlagsError:
			return "Attribute Flags Error"
		case SubcodeAttributeLengthError:
			return "Attribute Length Error"
		case SubcodeInvalidOriginAttribute:
			return "Invalid ORIGIN Attribute"
		case SubcodeInvalidNextHopAttribute:
			return "Invalid NEXT_HOP Attribute"
		case SubcodeOptionalAttributeError:
			return "Optional Attribute Error"
		case SubcodeInvalidNetworkField:
			return "Invalid Network Field"
		case SubcodeMalformedASPath:
			return "Malformed AS_PATH"
		}
	case NotificationFSMError:
		switch subcode {
		case SubcodeUnexpectedMessageOpenSent:
			return "Receive Unexpected Message in OpenSent State"
		case SubcodeUnexpectedMessageOpenConfirm:
			return "Receive Unexpected Message in OpenConfirm State"
		case SubcodeUnexpectedMessageEstablished:
			return "Receive Unexpected Message in Established State"
		}
	case NotificationCease:
		switch subcode {
		case SubcodeCeaseMaximumPrefixesReached:
			return "Maximum Number of Prefixes Reached"
		case SubcodeCeaseAdministrativeShutdown:
			return "Administrative Shutdown"
		case SubcodeCeasePeerDeconfigured:
			return "Peer De-configured"
		case SubcodeCeaseAdministrativeReset:
			return "Administrative Reset"
		case SubcodeCeaseConnectionRejected:
			return "Connection Rejected"
		case SubcodeCeaseOtherConfigurationChange:
			return "Other Configuration Change"
		case SubcodeCeaseConnectionCollisionResolution:
			return "Connection Collision Resolution"
		case SubcodeCeaseOutOfResources:
			return "Out of Resources"
		case SubcodeCeaseHardReset:
			return "Hard Reset"
		case SubcodeCeaseBFDDown:
			return "BFD Down"
		}
	}

	return fmt.Sprintf("unknown(%d)", subcode)
}

package bgp

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// A NotificationCode is the broad category of error condition conveyed by a
// Notification.
type NotificationCode uint8

// NotificationCode values, as assigned by IANA.
const (
	NotificationMessageHeaderError NotificationCode = 1
	NotificationOpenMessageError   NotificationCode = 2
	NotificationUpdateMessageError NotificationCode = 3
	NotificationHoldTimerExpired   NotificationCode = 4
	NotificationFSMError           NotificationCode = 5
	NotificationCease              NotificationCode = 6
)

// String returns the name of a NotificationCode.
func (c NotificationCode) String() string {
	switch c {
	case NotificationMessageHeaderError:
		return "Message Header Error"
	case NotificationOpenMessageError:
		return "OPEN Message Error"
	case NotificationUpdateMessageError:
		return "UPDATE Message Error"
	case NotificationHoldTimerExpired:
		return "Hold Timer Expired"
	case NotificationFSMError:
		return "Finite State Machine Error"
	case NotificationCease:
		return "Cease"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(c))
	}
}

// A Notification is a BGP NOTIFICATION message, sent when an error condition
// is detected, as described in RFC 4271, section 4.5. The connection is
// closed immediately after a NOTIFICATION is sent or received.
type Notification struct {
	// Code and Subcode indicate the type of error condition. Subcode values
	// are defined relative to a given Code.
	Code    NotificationCode
	Subcode uint8

	// Data carries diagnostic information whose contents depend on Code and
	// Subcode. When produced by ParseMessage, Data references the input
	// buffer rather than copying it; see [ParseMessage].
	Data []byte
}

func (*Notification) messageType() MessageType { return MessageTypeNotification }

// AppendBinary implements encoding.BinaryAppender.
func (n *Notification) AppendBinary(b []byte) ([]byte, error) {
	b, off := appendHeader(b, MessageTypeNotification)
	b = append(b, byte(n.Code), n.Subcode)
	b = append(b, n.Data...)
	return finishMessage(b, off)
}

// ShutdownCommunication returns the RFC 9003 shutdown communication carried
// by a NOTIFICATION: a human-readable UTF-8 message telling the remote
// operator why the session ended. Only a Cease whose subcode is
// Administrative Shutdown or Administrative Reset can carry one.
//
// ShutdownCommunication reports false when n carries no valid
// communication. A nil n also reports false, so it may be called directly
// on [Close.Notification].
func (n *Notification) ShutdownCommunication() (string, bool) {
	if n == nil || n.Code != NotificationCease {
		return "", false
	}

	if n.Subcode != SubcodeCeaseAdministrativeShutdown && n.Subcode != SubcodeCeaseAdministrativeReset {
		return "", false
	}

	// The data is a one byte length followed by exactly that many bytes of
	// UTF-8.
	if len(n.Data) < 1 || int(n.Data[0]) != len(n.Data)-1 {
		return "", false
	}

	msg := string(n.Data[1:])
	if !utf8.ValidString(msg) {
		return "", false
	}

	return msg, true
}

// NewShutdownError produces the *MessageError for an operator-initiated
// session end carrying an RFC 9003 shutdown communication. Use it anywhere
// a *MessageError ends a session: as a context cancellation cause, as the
// reason passed to [Server.RemovePeer], or as an error returned from a
// handler. It serves a dynamic farewell composed at shutdown time.
// PeerConfig.ShutdownCommunication is the static counterpart.
//
// subcode must be SubcodeCeaseAdministrativeShutdown or
// SubcodeCeaseAdministrativeReset. These are the only Cease subcodes RFC
// 9003 permits to carry a communication. communication must be valid UTF-8
// of at most 255 bytes. It may be empty for a plain Cease.
//
// Note that signal.NotifyContext cannot carry a cancellation cause. A
// caller which wants a farewell on a signal-driven shutdown watches the
// signal itself and cancels a context.WithCancelCause context with this
// error.
func NewShutdownError(subcode uint8, communication string) (*MessageError, error) {
	if subcode != SubcodeCeaseAdministrativeShutdown && subcode != SubcodeCeaseAdministrativeReset {
		return nil, fmt.Errorf("bgp: Cease subcode %s cannot carry a shutdown communication",
			subcodeString(NotificationCease, subcode))
	}

	data, err := marshalShutdownCommunication(communication)
	if err != nil {
		return nil, err
	}

	return newMessageError(NotificationCease, subcode, data,
		"operator shutdown: %q", communication), nil
}

// NewHardResetError produces the *MessageError for a Hard Reset (RFC 8538,
// section 3): a Cease which tells an RFC 8538 helper not to retain this
// speaker's routes, where plain graceful restart would. Use it anywhere a
// *MessageError ends a session: as a context cancellation cause, as the
// reason passed to [Server.RemovePeer], or as an error returned from a
// handler.
//
// code and subcode name the underlying reason: the NOTIFICATION which
// would have been sent were Hard Reset not in effect. The reason rides
// encapsulated in the Hard Reset's data, as RFC 8538 describes.
//
// communication optionally attaches an RFC 9003 shutdown communication to
// the reason. It is only valid when the reason is a Cease whose subcode is
// Administrative Shutdown or Administrative Reset. For any other reason it
// must be empty.
func NewHardResetError(code NotificationCode, subcode uint8, communication string) (*MessageError, error) {
	if code == NotificationCease && subcode == SubcodeCeaseHardReset {
		return nil, errors.New("bgp: a Hard Reset cannot encapsulate another Hard Reset")
	}

	data := []byte{byte(code), subcode}
	if communication != "" {
		if code != NotificationCease ||
			(subcode != SubcodeCeaseAdministrativeShutdown && subcode != SubcodeCeaseAdministrativeReset) {
			return nil, fmt.Errorf("bgp: Hard Reset reason %s: %s cannot carry a shutdown communication",
				code, subcodeString(code, subcode))
		}

		comm, err := marshalShutdownCommunication(communication)
		if err != nil {
			return nil, err
		}

		data = append(data, comm...)

		return newMessageError(NotificationCease, SubcodeCeaseHardReset, data,
			"hard reset: %s: %s: %q", code, subcodeString(code, subcode), communication), nil
	}

	return newMessageError(NotificationCease, SubcodeCeaseHardReset, data,
		"hard reset: %s: %s", code, subcodeString(code, subcode)), nil
}

// HardReset returns the reason encapsulated in a Hard Reset NOTIFICATION
// (RFC 8538, section 3): the NOTIFICATION which would have been sent were
// Hard Reset not in effect. It is [NewHardResetError]'s decoding
// counterpart.
//
// HardReset reports false when n carries no encapsulated reason. A nil n
// also reports false, so it may be called directly on [Close.Notification].
// So does a Hard Reset with empty data, which some speakers send: detecting
// a Hard Reset at all needs only n's own Code and Subcode, not this method.
//
// The returned Notification's Data references n.Data rather than copying it.
func (n *Notification) HardReset() (*Notification, bool) {
	if n == nil || n.Code != NotificationCease || n.Subcode != SubcodeCeaseHardReset {
		return nil, false
	}

	if len(n.Data) < 2 {
		return nil, false
	}

	return &Notification{
		Code:    NotificationCode(n.Data[0]),
		Subcode: n.Data[1],
		Data:    n.Data[2:len(n.Data):len(n.Data)],
	}, true
}

// marshalShutdownCommunication strictly encodes an RFC 9003 shutdown
// communication: a one byte length followed by the UTF-8 message. An empty
// message produces nil, a plain Cease; an over-long or invalid message is
// the caller's error, never silently altered.
func marshalShutdownCommunication(msg string) ([]byte, error) {
	if msg == "" {
		return nil, nil
	}

	if !utf8.ValidString(msg) {
		return nil, errors.New("bgp: a shutdown communication must be valid UTF-8")
	}

	if len(msg) > shutdownCommunicationMaxLen {
		return nil, fmt.Errorf("bgp: a shutdown communication must be at most %d bytes: %d",
			shutdownCommunicationMaxLen, len(msg))
	}

	return append([]byte{byte(len(msg))}, msg...), nil
}

// shutdownCommunicationMaxLen is the maximum length in bytes of an RFC 9003
// shutdown communication, bounded by its one byte length field.
const shutdownCommunicationMaxLen = 255

// parseNotification parses the body of a NOTIFICATION message.
func parseNotification(b []byte) (*Notification, error) {
	if len(b) < 2 {
		return nil, badLength(len(b), "NOTIFICATION message too short: %d byte body", len(b))
	}

	return &Notification{
		Code:    NotificationCode(b[0]),
		Subcode: b[1],
		Data:    b[2:len(b):len(b)],
	}, nil
}

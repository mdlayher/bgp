package bgp

import (
	"encoding/binary"
	"testing"
)

func TestNotificationCodeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code NotificationCode
		want string
	}{
		{code: NotificationMessageHeaderError, want: "Message Header Error"},
		{code: NotificationOpenMessageError, want: "OPEN Message Error"},
		{code: NotificationUpdateMessageError, want: "UPDATE Message Error"},
		{code: NotificationHoldTimerExpired, want: "Hold Timer Expired"},
		{code: NotificationFSMError, want: "Finite State Machine Error"},
		{code: NotificationCease, want: "Cease"},
		{code: NotificationCode(255), want: "unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.code.String(); got != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSubcodeStringCease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		subcode uint8
		want    string
	}{
		{subcode: SubcodeCeaseMaximumPrefixesReached, want: "Maximum Number of Prefixes Reached"},
		{subcode: SubcodeCeaseAdministrativeShutdown, want: "Administrative Shutdown"},
		{subcode: SubcodeCeasePeerDeconfigured, want: "Peer De-configured"},
		{subcode: SubcodeCeaseAdministrativeReset, want: "Administrative Reset"},
		{subcode: SubcodeCeaseConnectionRejected, want: "Connection Rejected"},
		{subcode: SubcodeCeaseOtherConfigurationChange, want: "Other Configuration Change"},
		{subcode: SubcodeCeaseConnectionCollisionResolution, want: "Connection Collision Resolution"},
		{subcode: SubcodeCeaseOutOfResources, want: "Out of Resources"},
		{subcode: SubcodeCeaseHardReset, want: "Hard Reset"},
		{subcode: SubcodeCeaseBFDDown, want: "BFD Down"},
		{subcode: 0, want: "Unspecific"},
		{subcode: 11, want: "unknown(11)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			if got := subcodeString(NotificationCease, tt.subcode); got != tt.want {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMessageErrorError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *MessageError
		want string
	}{
		{
			name: "header",
			err:  headerError(SubcodeConnectionNotSynchronized, nil, "invalid message header marker"),
			want: "bgp: invalid message header marker " +
				"(NOTIFICATION Message Header Error: Connection Not Synchronized)",
		},
		{
			name: "open",
			err:  openError(SubcodeUnacceptableHoldTime, nil, "unacceptable hold time"),
			want: "bgp: unacceptable hold time " +
				"(NOTIFICATION OPEN Message Error: Unacceptable Hold Time)",
		},
		{
			name: "update",
			err:  updateError(SubcodeMalformedASPath, nil, "AS_PATH segment truncated"),
			want: "bgp: AS_PATH segment truncated " +
				"(NOTIFICATION UPDATE Message Error: Malformed AS_PATH)",
		},
		{
			name: "unspecific subcode",
			err:  openError(0, nil, "OPEN capability truncated"),
			want: "bgp: OPEN capability truncated " +
				"(NOTIFICATION OPEN Message Error: Unspecific)",
		},
		{
			name: "unknown subcode",
			err:  headerError(99, nil, "something new"),
			want: "bgp: something new " +
				"(NOTIFICATION Message Header Error: unknown(99))",
		},
		{
			name: "unknown code",
			err: newMessageError(NotificationCode(255), 1, nil,
				"something newer"),
			want: "bgp: something newer (NOTIFICATION unknown(255): unknown(1))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("unexpected error string:\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestMessageErrorDataCloned pins the ownership rule documented on
// MessageError: its Data never references the parsed input buffer, so it
// remains valid after the buffer is reused. Contrast with Notification,
// whose parsed Data is a view of the input.
func TestMessageErrorDataCloned(t *testing.T) {
	t.Parallel()

	// A length mismatch echoes the input's wire length field as data.
	b := testMessage(MessageTypeKeepalive, nil)
	binary.BigEndian.PutUint16(b[markerLen:], headerLen+1)

	_, err := ParseMessage(b)
	merr := wantMessageError(t, err, NotificationMessageHeaderError,
		SubcodeBadMessageLength, []byte{0x00, headerLen + 1})

	// Scrambling the input must not disturb the error's diagnostic data.
	for i := range b {
		b[i] = 0xa5
	}

	if d := diff(t, []byte{0x00, headerLen + 1}, merr.Data); d != "" {
		t.Fatalf("unexpected data after input reuse (-want +got):\n%s", d)
	}
}

func TestMessageErrorNotification(t *testing.T) {
	t.Parallel()

	merr := updateError(SubcodeInvalidNetworkField, []byte{0x01}, "prefix truncated")

	want := &Notification{
		Code:    NotificationUpdateMessageError,
		Subcode: SubcodeInvalidNetworkField,
		Data:    []byte{0x01},
	}

	if d := diff(t, want, merr.Notification()); d != "" {
		t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
	}

	// The Notification owns its Data: mutating one produced earlier must
	// not reach back into the error, or into another Notification.
	n := merr.Notification()
	n.Data[0] = 0xff
	if d := diff(t, []byte{0x01}, merr.Data); d != "" {
		t.Fatalf("mutation reached the MessageError (-want +got):\n%s", d)
	}
}

package bgp

import (
	"bytes"
	"strings"
	"testing"
)

// TestNotificationDataAliasesInput pins the ownership rule documented on
// ParseMessage: a parsed Notification's Data is a bounded view of the input
// buffer, not a copy. Contrast with MessageError, whose Data is always owned.
func TestNotificationDataAliasesInput(t *testing.T) {
	t.Parallel()

	data := []byte("diagnostic data")
	b := testMessage(MessageTypeNotification, append([]byte{
		byte(NotificationCease), 0x02,
	}, data...))

	m, err := ParseMessage(b)
	if err != nil {
		t.Fatalf("failed to parse NOTIFICATION: %v", err)
	}

	n, ok := m.(*Notification)
	if !ok {
		t.Fatalf("expected *Notification, but got: %T", m)
	}

	if d := diff(t, data, n.Data); d != "" {
		t.Fatalf("unexpected data (-want +got):\n%s", d)
	}

	if &n.Data[0] != &b[headerLen+2] {
		t.Fatal("Notification.Data does not alias the input buffer")
	}

	if len(n.Data) != cap(n.Data) {
		t.Fatalf("Notification.Data is not bounded to the message: len=%d, cap=%d",
			len(n.Data), cap(n.Data))
	}
}

func TestNotificationParseEmptyData(t *testing.T) {
	t.Parallel()

	m, err := ParseMessage(testMessage(MessageTypeNotification, []byte{
		byte(NotificationCease), 0x02,
	}))
	if err != nil {
		t.Fatalf("failed to parse NOTIFICATION: %v", err)
	}

	want := &Notification{Code: NotificationCease, Subcode: 2}
	if d := diff[Message](t, want, m); d != "" {
		t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
	}
}

func TestNotificationAppendBinaryWire(t *testing.T) {
	t.Parallel()

	n := &Notification{
		Code:    NotificationUpdateMessageError,
		Subcode: SubcodeMalformedASPath,
		Data:    []byte{0x01, 0x02},
	}

	b, err := n.AppendBinary(nil)
	if err != nil {
		t.Fatalf("failed to marshal NOTIFICATION: %v", err)
	}

	want := testMessage(MessageTypeNotification, []byte{0x03, 0x0b, 0x01, 0x02})
	if !bytes.Equal(want, b) {
		t.Fatalf("unexpected NOTIFICATION bytes:\nwant: %x\n got: %x", want, b)
	}
}

func TestNotificationShutdownCommunication(t *testing.T) {
	t.Parallel()

	// cease produces a Cease NOTIFICATION with the given subcode and data.
	cease := func(subcode uint8, data []byte) *Notification {
		return &Notification{Code: NotificationCease, Subcode: subcode, Data: data}
	}

	tests := []struct {
		name string
		n    *Notification
		msg  string
		ok   bool
	}{
		{
			name: "nil notification",
			n:    nil,
		},
		{
			name: "administrative shutdown",
			n:    cease(SubcodeCeaseAdministrativeShutdown, []byte("\x0bmaintenance")),
			msg:  "maintenance",
			ok:   true,
		},
		{
			name: "administrative reset",
			n:    cease(SubcodeCeaseAdministrativeReset, []byte("\x0bmaintenance")),
			msg:  "maintenance",
			ok:   true,
		},
		{
			name: "empty message",
			n:    cease(SubcodeCeaseAdministrativeShutdown, []byte{0x00}),
			ok:   true,
		},
		{
			name: "no data",
			n:    cease(SubcodeCeaseAdministrativeShutdown, nil),
		},
		{
			name: "length mismatch",
			n:    cease(SubcodeCeaseAdministrativeShutdown, []byte("\x05hi")),
		},
		{
			name: "invalid UTF-8",
			n:    cease(SubcodeCeaseAdministrativeShutdown, []byte{0x02, 0xff, 0xfe}),
		},
		{
			name: "wrong subcode",
			n:    cease(SubcodeCeasePeerDeconfigured, []byte("\x0bmaintenance")),
		},
		{
			name: "wrong code",
			n: &Notification{
				Code: NotificationHoldTimerExpired,
				Data: []byte("\x0bmaintenance"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg, ok := tt.n.ShutdownCommunication()
			if msg != tt.msg || ok != tt.ok {
				t.Fatalf("want (%q, %t), got (%q, %t)", tt.msg, tt.ok, msg, ok)
			}
		})
	}
}

func TestMarshalShutdownCommunication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  string
		want []byte
		err  bool
	}{
		{
			name: "empty",
			msg:  "",
			want: nil,
		},
		{
			name: "invalid UTF-8",
			msg:  "\xff",
			err:  true,
		},
		{
			name: "short message",
			msg:  "hi",
			want: []byte{0x02, 'h', 'i'},
		},
		{
			name: "maximum length",
			msg:  strings.Repeat("a", 255),
			want: append([]byte{0xff}, strings.Repeat("a", 255)...),
		},
		{
			name: "over-long",
			msg:  strings.Repeat("a", 300),
			err:  true,
		},
		{
			name: "rune straddles the limit",
			// 253 bytes of ASCII followed by a 3 byte rune crossing the 255
			// byte limit: strict encoding errors rather than truncating.
			msg: strings.Repeat("a", 253) + "€",
			err: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := marshalShutdownCommunication(tt.msg)
			if tt.err {
				if err == nil {
					t.Fatalf("expected an error, but got data: %x", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			if !bytes.Equal(tt.want, got) {
				t.Fatalf("unexpected data:\nwant: %x\n got: %x", tt.want, got)
			}

			// Every encoding round-trips through the decode helper.
			if got == nil {
				return
			}

			n := &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseAdministrativeShutdown,
				Data:    got,
			}

			if msg, ok := n.ShutdownCommunication(); !ok || msg != string(got[1:]) {
				t.Fatalf("failed to round-trip: (%q, %t)", msg, ok)
			}
		})
	}
}

func TestNewShutdownError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		subcode uint8
		msg     string
		// want is the NOTIFICATION the error produces, or nil when
		// construction must fail.
		want *Notification
	}{
		{
			name:    "hard reset subcode",
			subcode: SubcodeCeaseHardReset,
			msg:     "maintenance",
		},
		{
			name:    "peer de-configured subcode",
			subcode: SubcodeCeasePeerDeconfigured,
			msg:     "maintenance",
		},
		{
			name:    "invalid UTF-8",
			subcode: SubcodeCeaseAdministrativeShutdown,
			msg:     "\xff",
		},
		{
			name:    "over-long",
			subcode: SubcodeCeaseAdministrativeShutdown,
			msg:     strings.Repeat("a", 256),
		},
		{
			name:    "administrative shutdown",
			subcode: SubcodeCeaseAdministrativeShutdown,
			msg:     "maintenance",
			want: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseAdministrativeShutdown,
				Data:    []byte("\x0bmaintenance"),
			},
		},
		{
			name:    "administrative reset without communication",
			subcode: SubcodeCeaseAdministrativeReset,
			want: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseAdministrativeReset,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			me, err := NewShutdownError(tt.subcode, tt.msg)
			if tt.want == nil {
				if err == nil {
					t.Fatalf("expected an error, but got: %v", me)
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to create shutdown error: %v", err)
			}

			if d := diff(t, tt.want, me.Notification()); d != "" {
				t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
			}

			if !strings.Contains(me.Error(), "operator shutdown") {
				t.Fatalf("unexpected error string: %q", me.Error())
			}

			// Every communication round-trips through the decode helper.
			if msg, ok := me.Notification().ShutdownCommunication(); msg != tt.msg || ok != (tt.msg != "") {
				t.Fatalf("failed to round-trip: (%q, %t)", msg, ok)
			}
		})
	}
}

func TestNewHardResetError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		code    NotificationCode
		subcode uint8
		msg     string
		// want is the NOTIFICATION the error produces, or nil when
		// construction must fail.
		want *Notification
	}{
		{
			name:    "nested hard reset",
			code:    NotificationCease,
			subcode: SubcodeCeaseHardReset,
		},
		{
			name: "communication on wrong code",
			code: NotificationHoldTimerExpired,
			msg:  "maintenance",
		},
		{
			name:    "communication on wrong subcode",
			code:    NotificationCease,
			subcode: SubcodeCeasePeerDeconfigured,
			msg:     "maintenance",
		},
		{
			name:    "invalid UTF-8 communication",
			code:    NotificationCease,
			subcode: SubcodeCeaseAdministrativeShutdown,
			msg:     "\xff",
		},
		{
			name:    "administrative shutdown with communication",
			code:    NotificationCease,
			subcode: SubcodeCeaseAdministrativeShutdown,
			msg:     "maintenance",
			want: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseHardReset,
				Data: append(
					[]byte{byte(NotificationCease), SubcodeCeaseAdministrativeShutdown},
					"\x0bmaintenance"...,
				),
			},
		},
		{
			name: "hold timer expired",
			code: NotificationHoldTimerExpired,
			want: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseHardReset,
				Data:    []byte{byte(NotificationHoldTimerExpired), 0x00},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			me, err := NewHardResetError(tt.code, tt.subcode, tt.msg)
			if tt.want == nil {
				if err == nil {
					t.Fatalf("expected an error, but got: %v", me)
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to create hard reset error: %v", err)
			}

			if d := diff(t, tt.want, me.Notification()); d != "" {
				t.Fatalf("unexpected NOTIFICATION (-want +got):\n%s", d)
			}

			if !strings.Contains(me.Error(), "hard reset") {
				t.Fatalf("unexpected error string: %q", me.Error())
			}

			// Every underlying reason round-trips through the decode
			// helper, communication included.
			inner, ok := me.Notification().HardReset()
			if !ok {
				t.Fatal("failed to decode the encapsulated reason")
			}

			if inner.Code != tt.code || inner.Subcode != tt.subcode {
				t.Fatalf("unexpected reason: %s: %s",
					inner.Code, subcodeString(inner.Code, inner.Subcode))
			}

			if msg, ok := inner.ShutdownCommunication(); msg != tt.msg || ok != (tt.msg != "") {
				t.Fatalf("failed to round-trip communication: (%q, %t)", msg, ok)
			}
		})
	}
}

func TestNotificationHardReset(t *testing.T) {
	t.Parallel()

	// hard produces a Cease / Hard Reset NOTIFICATION with the given data.
	hard := func(data []byte) *Notification {
		return &Notification{
			Code:    NotificationCease,
			Subcode: SubcodeCeaseHardReset,
			Data:    data,
		}
	}

	tests := []struct {
		name string
		n    *Notification
		want *Notification
	}{
		{
			name: "nil notification",
		},
		{
			name: "wrong code",
			n: &Notification{
				Code: NotificationHoldTimerExpired,
				Data: []byte{byte(NotificationCease), SubcodeCeaseAdministrativeShutdown},
			},
		},
		{
			name: "wrong subcode",
			n: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseAdministrativeShutdown,
				Data:    []byte{byte(NotificationCease), SubcodeCeaseAdministrativeShutdown},
			},
		},
		{
			name: "bare hard reset",
			n:    hard(nil),
		},
		{
			name: "truncated reason",
			n:    hard([]byte{byte(NotificationCease)}),
		},
		{
			name: "administrative shutdown reason",
			n:    hard([]byte{byte(NotificationCease), SubcodeCeaseAdministrativeShutdown}),
			want: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseAdministrativeShutdown,
				Data:    []byte{},
			},
		},
		{
			name: "reason with data",
			n: hard(append(
				[]byte{byte(NotificationCease), SubcodeCeaseAdministrativeReset}, "\x02hi"...,
			)),
			want: &Notification{
				Code:    NotificationCease,
				Subcode: SubcodeCeaseAdministrativeReset,
				Data:    []byte("\x02hi"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			inner, ok := tt.n.HardReset()
			if tt.want == nil {
				if ok {
					t.Fatalf("expected no encapsulated reason, but got: %+v", inner)
				}

				return
			}

			if !ok {
				t.Fatal("failed to decode the encapsulated reason")
			}

			if d := diff(t, tt.want, inner); d != "" {
				t.Fatalf("unexpected reason (-want +got):\n%s", d)
			}

			// The documented ownership rule: the reason's data is a bounded
			// view of the outer data, not a copy.
			if len(inner.Data) == 0 {
				return
			}

			if &inner.Data[0] != &tt.n.Data[2] {
				t.Fatal("reason data does not alias the outer data")
			}

			if len(inner.Data) != cap(inner.Data) {
				t.Fatalf("reason data is not bounded: len=%d, cap=%d",
					len(inner.Data), cap(inner.Data))
			}
		})
	}
}

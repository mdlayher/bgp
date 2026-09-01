package bgp

import (
	"testing"
)

func TestIdentifierParseString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s  string
		id Identifier
		ok bool
	}{
		{s: "192.0.2.1", id: 0xc0000201, ok: true},
		{s: "0.0.0.0", id: 0, ok: true},
		{s: "255.255.255.255", id: 0xffffffff, ok: true},
		{s: "2001:db8::1"},
		{s: "192.0.2"},
		{s: "not an identifier"},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			t.Parallel()

			id, err := ParseIdentifier(tt.s)
			if !tt.ok {
				if err == nil {
					t.Fatal("expected an error, but none occurred")
				}

				return
			}

			if err != nil {
				t.Fatalf("failed to parse identifier: %v", err)
			}

			if id != tt.id {
				t.Fatalf("unexpected identifier: got %#08x, want %#08x", uint32(id), uint32(tt.id))
			}

			if got := id.String(); got != tt.s {
				t.Fatalf("unexpected string: got %q, want %q", got, tt.s)
			}
		})
	}
}

func TestParseIdentifierAddresses(t *testing.T) {
	t.Parallel()

	if _, err := ParseIdentifier("2001:db8::1"); err == nil {
		t.Fatal("expected an error for an IPv6 address")
	}

	// An IPv4-mapped IPv6 address carries an IPv4 address, and is accepted.
	id, err := ParseIdentifier("::ffff:192.0.2.1")
	if err != nil {
		t.Fatalf("failed to parse an IPv4-mapped address: %v", err)
	}

	if want := MustParseIdentifier("192.0.2.1"); id != want {
		t.Fatalf("unexpected identifier: got %s, want %s", id, want)
	}
}

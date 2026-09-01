package bgp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestNewFSMActiveRequiresDialFunc verifies that FSMConfig is pared to
// seams: an FSM which is not Passive must be told how to dial, because the
// built-in Dialer convenience lives on PeerConfig.
func TestNewFSMActiveRequiresDialFunc(t *testing.T) {
	t.Parallel()

	_, err := NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
	})
	if err == nil {
		t.Fatal("expected an error from an active FSM with no DialFunc, but none occurred")
	}
}

// TestFSMConnectSingleAttempt drives the Connect contract: it returns nil
// precisely when the attempt concluded and OnClose reported its Close,
// exactly once, and the FSM is sequentially reusable afterward.
func TestFSMConnectSingleAttempt(t *testing.T) {
	t.Parallel()

	// Every dial produces a connection whose remote is already gone, so
	// sending the OPEN fails, ending the attempt: something observable was
	// in flight, so a Close is owed.
	closes := make(chan Close, 4)
	f := must(NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		DialFunc: func(context.Context) (*Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return NewConn(client), nil
		},
		OnClose: func(_ *FSM, c Close) { closes <- c },
		Logger:  testLogger(t),
	}))

	for _, run := range []string{"first", "second"} {
		if err := f.Connect(context.Background()); err != nil {
			t.Fatalf("%s Connect returned an error: %v", run, err)
		}

		// Connect returned nil, so exactly one Close was already reported:
		// OnClose fires on the FSM goroutine before the attempt concludes.
		c := recv(t, closes, "a Close from "+run+" Connect")
		if c.Established {
			t.Fatalf("%s Close reports an established session for a failed OPEN send", run)
		}

		if c.Err == nil {
			t.Fatalf("%s Close carries no error for a failed OPEN send", run)
		}

		select {
		case c := <-closes:
			t.Fatalf("%s Connect reported a second Close: %+v", run, c)
		default:
		}
	}
}

// TestFSMConnectNotIdle verifies the Idle gate: a second Connect while one
// is in progress refuses, and cancellation returns ctx's error without a
// Close when nothing observable was in flight.
func TestFSMConnectNotIdle(t *testing.T) {
	t.Parallel()

	closed := make(chan Close, 1)
	f := must(NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
		OnClose:  func(_ *FSM, c Close) { closed <- c },
		Logger:   testLogger(t),
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connectC := make(chan error, 1)
	go func() { connectC <- f.Connect(ctx) }()

	// Once the first Connect has left Idle, a second must refuse.
	f.mu.Lock()
	runningC := f.runningC
	f.mu.Unlock()
	select {
	case <-runningC:
	case <-time.After(peerTimeout):
		t.Fatal("timed out waiting for Connect to leave Idle")
	}

	if err := f.Connect(ctx); err == nil {
		t.Fatal("expected an error from Connect while not idle, but none occurred")
	}

	// ManualStop with nothing observable in flight: ctx's error, no Close.
	cancel()
	if err := recv(t, connectC, "Connect to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Connect error: %v", err)
	}

	select {
	case c := <-closed:
		t.Fatalf("a silent attempt reported a Close: %+v", c)
	default:
	}
}

// TestFSMDeliverConnIdle verifies that an idle FSM refuses delivered
// connections: no Connect is in progress to take them.
func TestFSMDeliverConnIdle(t *testing.T) {
	t.Parallel()

	f := must(NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	}))

	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()
	if err := f.DeliverConn(NewConn(client)); !errors.Is(err, errFSMIdle) {
		t.Fatalf("expected errFSMIdle from an idle FSM, got: %v", err)
	}
}

// TestFSMOnStateChangePassiveStart verifies the passive start: the Start
// event enters Active, not Connect, and a silent ManualStop still closes
// the bookend back to Idle.
func TestFSMOnStateChangePassiveStart(t *testing.T) {
	t.Parallel()

	states := make(chan [2]State, 4)
	f := must(NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
		OnStateChange: func(_ *FSM, from, to State) {
			states <- [2]State{from, to}
		},
		Logger: testLogger(t),
	}))

	ctx, cancel := context.WithCancel(context.Background())
	connectC := make(chan error, 1)
	go func() { connectC <- f.Connect(ctx) }()

	if got, want := recv(t, states, "the Start transition"), ([2]State{StateIdle, StateActive}); got != want {
		t.Fatalf("unexpected Start transition: want %s->%s, got %s->%s",
			want[0], want[1], got[0], got[1])
	}

	cancel()
	if err := recv(t, connectC, "Connect to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Connect error: %v", err)
	}

	if got, want := recv(t, states, "the ManualStop transition"), ([2]State{StateActive, StateIdle}); got != want {
		t.Fatalf("unexpected ManualStop transition: want %s->%s, got %s->%s",
			want[0], want[1], got[0], got[1])
	}
}

// TestNewFSMPinnedLocalIdentity verifies the constructor-time catch for an
// unestablishable pin: an internal peer bearing the local identifier is
// always rejected by negotiation (RFC 6286), so configuring exactly that is
// an error up front.
func TestNewFSMPinnedLocalIdentity(t *testing.T) {
	t.Parallel()

	_, err := NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		PeerASN:  64496,
		PeerID:   MustParseIdentifier("192.0.2.1"),
		Passive:  true,
	})
	if err == nil {
		t.Fatal("expected an error pinning the local identity, but none occurred")
	}
}

// TestFSMDeliverConnUnaddressed verifies that the FSM carries no addressing
// at all: a delivered TCP connection is accepted from any remote address,
// because the caller's choice of FSM is the admission decision.
func TestFSMDeliverConnUnaddressed(t *testing.T) {
	t.Parallel()

	f := must(NewFSM(FSMConfig{
		LocalASN: 64496,
		LocalID:  MustParseIdentifier("192.0.2.1"),
		Passive:  true,
		Logger:   testLogger(t),
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connectC := make(chan error, 1)
	go func() { connectC <- f.Connect(ctx) }()

	f.mu.Lock()
	runningC := f.runningC
	f.mu.Unlock()
	select {
	case <-runningC:
	case <-time.After(peerTimeout):
		t.Fatal("timed out waiting for Connect to leave Idle")
	}

	// A loopback connection would never match a documentation address; the
	// FSM has no address to hold it against, so it must be accepted.
	client, _ := testConns(t, "tcp4")
	if err := f.DeliverConn(client); err != nil {
		t.Fatalf("failed to deliver a connection to the FSM: %v", err)
	}

	cancel()
	if err := recv(t, connectC, "Connect to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected Connect error: %v", err)
	}
}

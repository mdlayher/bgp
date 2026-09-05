// Benchmarks for the package's wire codecs and session layers, organized
// like fuzz_test.go: whole messages, attributes, the marshal paths, the
// framed read path, and full-table ingest at the Peer and FSM layers. Most
// are driven by the route collector corpus; see corpus_test.go.
package bgp

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkParseMessage sweeps the raw parse path over every message of an
// entire route collector updates file: the initial convergence hot path.
func BenchmarkParseMessage(b *testing.B) {
	msgs := corpusMessages(b)

	var total int64
	for _, m := range msgs {
		total += int64(len(m))
	}

	b.SetBytes(total)
	b.ReportAllocs()

	for b.Loop() {
		for _, m := range msgs {
			if _, err := ParseMessage(m); err != nil {
				b.Fatalf("failed to parse message: %v", err)
			}
		}
	}
}

// BenchmarkRawAttributeParse sweeps the opt-in typed attribute parse path
// over every path attribute in the corpus.
func BenchmarkRawAttributeParse(b *testing.B) {
	// Gather every attribute which parses in typed form, dropping the
	// unknown types which would only measure error construction.
	var attrs []RawAttribute
	for _, m := range corpusMessages(b) {
		msg, err := ParseMessage(m)
		if err != nil {
			b.Fatalf("failed to parse message: %v", err)
		}

		u, ok := msg.(*Update)
		if !ok {
			continue
		}

		for _, a := range u.Attributes {
			if _, err := a.Parse(); err == nil {
				attrs = append(attrs, a)
			}
		}
	}

	b.ReportAllocs()

	for b.Loop() {
		for _, a := range attrs {
			if _, err := a.Parse(); err != nil {
				b.Fatalf("failed to parse attribute: %v", err)
			}
		}
	}
}

// BenchmarkUpdateAppendBinary marshals a full eBGP UPDATE into a recycled
// buffer, the send path equivalent of buffer reuse in Conn.
func BenchmarkUpdateAppendBinary(b *testing.B) {
	u := &Update{
		Attributes: mustAttributes(
			b,
			OriginIGP,
			ASPath{{ASNs: []uint32{64496, 65536, 64497}}},
			NextHop(netip.MustParseAddr("192.0.2.1")),
			MED(100),
			Communities{NewCommunity(64496, 100), NewCommunity(64496, 200)},
		),
		NLRI: []netip.Prefix{
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("192.0.2.128/25"),
			netip.MustParsePrefix("198.51.100.0/24"),
		},
	}

	b.ReportAllocs()

	var buf []byte
	for b.Loop() {
		var err error
		if buf, err = u.AppendBinary(buf[:0]); err != nil {
			b.Fatalf("failed to marshal UPDATE: %v", err)
		}
	}
}

// BenchmarkCorpusAppendBinary re-marshals every parsed corpus message into a
// recycled buffer: the send path measured against real attribute mixes, a
// full-table push in miniature.
func BenchmarkCorpusAppendBinary(b *testing.B) {
	var (
		msgs  []Message
		total int64
	)

	for _, raw := range corpusMessages(b) {
		m, err := ParseMessage(raw)
		if err != nil {
			b.Fatalf("failed to parse corpus message: %v", err)
		}

		// The parsed message references the read buffer; clone so the
		// benchmark holds the whole corpus at once.
		msgs = append(msgs, detachMessage(b, m))
		total += int64(len(raw))
	}

	b.SetBytes(total)
	b.ReportAllocs()

	var buf []byte
	for b.Loop() {
		for _, m := range msgs {
			var err error
			if buf, err = m.AppendBinary(buf[:0]); err != nil {
				b.Fatalf("failed to marshal corpus message: %v", err)
			}
		}
	}
}

// BenchmarkConnReadMessage frames and parses an entire route collector
// updates file through a Conn: the receive path of initial convergence. The
// underlying connection replays the stream from memory, so the benchmark
// measures framing and parsing rather than the kernel.
func BenchmarkConnReadMessage(b *testing.B) {
	msgs := corpusMessages(b)

	var stream []byte
	for _, m := range msgs {
		stream = append(stream, m...)
	}

	b.SetBytes(int64(len(stream)))
	b.ReportAllocs()

	c := NewConn(&replayConn{b: stream})
	for b.Loop() {
		for range msgs {
			if _, err := c.ReadMessage(); err != nil {
				b.Fatalf("failed to read message: %v", err)
			}
		}
	}
}

// BenchmarkPeerFullTableIngest replays a full internet table through a live
// Peer session: one wire UPDATE per unique IPv4 route of a fetched RIB dump,
// streamed through an in-memory connection into an OnUpdate handler. One
// iteration ingests the whole table, so ns/op is the convergence time of a
// full-table push at the mainstream Peer layer, deep copies included.
func BenchmarkPeerFullTableIngest(b *testing.B) {
	wire, routes := tableReplay(b)

	var remaining atomic.Int64
	doneC := make(chan struct{}, 1)

	r := newPipeRig(b, PeerConfig{
		OnUpdate: func(_ context.Context, _ *Peer, u *Update) error {
			if remaining.Add(-int64(len(u.NLRI))) == 0 {
				doneC <- struct{}{}
			}

			return nil
		},
	})

	s := r.acceptScript()
	s.establish(&Open{ASN: 64497, HoldTime: 90 * time.Second, ID: MustParseIdentifier("192.0.2.2")})
	recv(b, r.estC, "session establishment")

	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()

	for b.Loop() {
		remaining.Store(int64(routes))
		if _, err := s.nc.Write(wire); err != nil {
			b.Fatalf("failed to write table: %v", err)
		}

		<-doneC
	}

	b.ReportMetric(float64(routes), "routes/op")
}

// BenchmarkFSMFullTableIngest is BenchmarkPeerFullTableIngest one layer
// down: the same replay through a bare FSM, whose zero-copy handlers borrow
// the read buffer instead of receiving deep copies. The difference between
// the two benchmarks is the price of the Peer layer's ownership contract.
func BenchmarkFSMFullTableIngest(b *testing.B) {
	wire, routes := tableReplay(b)

	var remaining atomic.Int64
	doneC := make(chan struct{}, 1)

	r := newFSMRig(b, FSMConfig{
		OnUpdate: func(_ context.Context, _ *FSM, u *Update) error {
			if remaining.Add(-int64(len(u.NLRI))) == 0 {
				doneC <- struct{}{}
			}

			return nil
		},
	})
	defer r.cancel()

	s := r.nextDial()
	s.establish(&Open{ASN: 64497, HoldTime: 90 * time.Second, ID: MustParseIdentifier("192.0.2.2")})
	recv(b, r.estC, "session establishment")

	b.SetBytes(int64(len(wire)))
	b.ReportAllocs()

	for b.Loop() {
		remaining.Store(int64(routes))
		if _, err := s.nc.Write(wire); err != nil {
			b.Fatalf("failed to write table: %v", err)
		}

		<-doneC
	}

	b.ReportMetric(float64(routes), "routes/op")
}

package bgp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/bgp/internal/mrt"
)

// corpusFile is an entire MRT updates file from a RIPE RIS route collector,
// checked into testdata so corpus tests and benchmarks run from a bare clone
// with stable inputs; see testdata/README.md. Full-size files fetched by
// testdata/fetch-mrt.sh into testdata/large are picked up as well.
const corpusFile = "testdata/rrc16-updates.20260815.1200.gz"

// TestCorpusRIB verifies the attribute parsers against every route of a
// full-table RIB dump ("bview", TABLE_DUMP_V2), fetched into testdata/large
// by fetch-mrt.sh: an entire internet table's attributes must frame, and
// every attribute of a known type must parse in typed form. MP_REACH_NLRI is
// the exception: RFC 6396, section 4.3.4 truncates it to the next hop alone
// in a RIB entry, so it cannot typed-parse and is verified as framed only.
func TestCorpusRIB(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("testdata/large/*bview*.gz")
	if err != nil {
		t.Fatalf("failed to glob RIB dumps: %v", err)
	}

	if len(files) == 0 {
		t.Skip("skipping, no RIB dumps in testdata/large; run testdata/fetch-mrt.sh")
	}

	var routes, attrs, rawOnly int
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			t.Fatalf("failed to open RIB dump: %v", err)
		}

		defer func() { _ = f.Close() }()

		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("failed to read gzip: %v", err)
		}

		rr := mrt.NewRIBReader(bufio.NewReaderSize(zr, 1<<20))
		for {
			e, err := rr.Next()
			if errors.Is(err, io.EOF) {
				break
			}

			if err != nil {
				t.Fatalf("%s: failed to read RIB entry %d: %v", name, routes, err)
			}

			routes++

			as, err := parseRawAttributes(e.Attrs)
			if err != nil {
				t.Fatalf("%s: failed to frame attributes for %s: %v", name, e.Prefix, err)
			}

			for _, a := range as {
				attrs++
				if a.Type == AttrMPReachNLRI {
					continue
				}

				if _, err := a.Parse(); err != nil {
					// As in TestCorpusParse: unknown types stay raw, any
					// other failure is a parse bug.
					if _, ok := errors.AsType[*MessageError](err); ok {
						t.Fatalf("%s: failed to parse attribute %d for %s: %v", name, a.Type, e.Prefix, err)
					}

					rawOnly++
				}
			}
		}
	}

	t.Logf("parsed %d routes, %d attributes (%d unknown, raw only)", routes, attrs, rawOnly)
}

// TestCorpusParse verifies this package's parsers against every message of
// an entire real route collector updates file: each message must parse, each
// attribute of a type known to this package must parse in typed form, and
// parsing must be a fixed point of marshaling.
func TestCorpusParse(t *testing.T) {
	t.Parallel()

	var updates, keepalives, attrs, rawOnly int
	for i, b := range corpusMessages(t) {
		m, err := ParseMessage(b)
		if err != nil {
			t.Fatalf("failed to parse corpus message %d: %v", i, err)
		}

		switch m := m.(type) {
		case *Keepalive:
			keepalives++
		case *Update:
			updates++
			for _, a := range m.Attributes {
				attrs++
				if _, err := a.Parse(); err != nil {
					// Attribute types unknown to this package remain
					// available in raw form; anything else is a parse bug,
					// because a route collector's peers archived these
					// messages as valid.
					if _, ok := errors.AsType[*MessageError](err); ok {
						t.Fatalf("failed to parse corpus message %d attribute %d: %v", i, a.Type, err)
					}

					rawOnly++
				}
			}
		default:
			t.Fatalf("unexpected corpus message %d type: %T", i, m)
		}

		// Parse must be a fixed point: re-marshaling and re-parsing the
		// message reproduces it, modulo the wire normalizations enumerated
		// in the roadmap (extended length flags, prefix masking).
		b1, err := m.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to marshal corpus message %d: %v", i, err)
		}

		m2, err := ParseMessage(b1)
		if err != nil {
			t.Fatalf("failed to re-parse corpus message %d: %v", i, err)
		}

		if d := diff(t, m, m2); d != "" {
			t.Fatalf("unexpected re-parsed corpus message %d (-want +got):\n%s", i, d)
		}
	}

	t.Logf("parsed %d UPDATE and %d KEEPALIVE messages, %d attributes (%d unknown, raw only)",
		updates, keepalives, attrs, rawOnly)
}

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

var corpus struct {
	once sync.Once
	msgs [][]byte
	err  error
}

// corpusMessages returns the raw BGP messages of every corpus MRT file.
func corpusMessages(tb testing.TB) [][]byte {
	tb.Helper()

	corpus.once.Do(func() {
		corpus.msgs, corpus.err = readCorpus()
	})
	if corpus.err != nil {
		tb.Fatalf("failed to read corpus: %v", corpus.err)
	}

	return corpus.msgs
}

// readCorpus implements corpusMessages.
func readCorpus() ([][]byte, error) {
	f, err := os.Open(corpusFile)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	msgs, err := readMRT(zr)
	if err != nil {
		return nil, err
	}

	// Optional full-size MRT files for deeper local coverage.
	large, err := filepath.Glob("testdata/large/*.mrt")
	if err != nil {
		return nil, err
	}

	for _, name := range large {
		lf, err := os.Open(name)
		if err != nil {
			return nil, err
		}

		lmsgs, err := readMRT(lf)
		_ = lf.Close()
		if err != nil {
			return nil, err
		}

		msgs = append(msgs, lmsgs...)
	}

	return msgs, nil
}

// readMRT drains the BGP messages from a single MRT stream.
func readMRT(r io.Reader) ([][]byte, error) {
	var msgs [][]byte
	mr := mrt.NewReader(r)
	for {
		b, err := mr.Next()
		if errors.Is(err, io.EOF) {
			return msgs, nil
		}

		if err != nil {
			return nil, err
		}

		msgs = append(msgs, b)
	}
}

// corpusSeeds returns a sample of raw corpus messages for use as fuzz seeds,
// spread evenly across the corpus and capped so the seed set stays fast to
// execute as regression tests.
func corpusSeeds(tb testing.TB) [][]byte {
	tb.Helper()

	const max = 256
	msgs := corpusMessages(tb)
	if len(msgs) <= max {
		return msgs
	}

	seeds := make([][]byte, 0, max)
	for i := range max {
		seeds = append(seeds, msgs[i*len(msgs)/max])
	}

	return seeds
}

// ribSeeds returns a sample of raw attributes from any full-table RIB dumps
// in testdata/large, chosen for novelty: a few representatives of each
// attribute type, so the rare and deprecated types an internet table carries
// and the truncated MP_REACH_NLRI form of RFC 6396, section 4.3.4 seed the
// fuzzers. It returns nil when no dump has been fetched.
func ribSeeds(tb testing.TB) []RawAttribute {
	tb.Helper()

	files, err := filepath.Glob("testdata/large/*bview*.gz")
	if err != nil {
		tb.Fatalf("failed to glob RIB dumps: %v", err)
	}

	const perType = 8
	counts := make(map[AttrType]int)
	var seeds []RawAttribute
	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			tb.Fatalf("failed to open RIB dump: %v", err)
		}

		defer func() { _ = f.Close() }()

		zr, err := gzip.NewReader(f)
		if err != nil {
			tb.Fatalf("failed to read gzip: %v", err)
		}

		rr := mrt.NewRIBReader(bufio.NewReaderSize(zr, 1<<20))
		for {
			e, err := rr.Next()
			if errors.Is(err, io.EOF) {
				break
			}

			if err != nil {
				tb.Fatalf("failed to read RIB entry: %v", err)
			}

			as, err := parseRawAttributes(e.Attrs)
			if err != nil {
				tb.Fatalf("failed to frame RIB attributes: %v", err)
			}

			for _, a := range as {
				if counts[a.Type] >= perType {
					continue
				}

				counts[a.Type]++
				seeds = append(seeds, *a.Clone())
			}
		}
	}

	return seeds
}

// tableReplay builds a full-table replay stream from a fetched RIB dump: one
// wire UPDATE per unique IPv4 route, carrying the route's real attributes.
// The truncated MP_REACH_NLRI of RFC 6396, section 4.3.4 cannot travel on a
// session, so IPv6 routes are omitted. It skips the benchmark when no dump
// has been fetched.
func tableReplay(tb testing.TB) ([]byte, int) {
	tb.Helper()

	files, err := filepath.Glob("testdata/large/*bview*.gz")
	if err != nil {
		tb.Fatalf("failed to glob RIB dumps: %v", err)
	}

	if len(files) == 0 {
		tb.Skip("skipping, no RIB dumps in testdata/large; run testdata/fetch-mrt.sh")
	}

	seen := make(map[netip.Prefix]struct{})
	var (
		wire   []byte
		routes int
	)

	for _, name := range files {
		f, err := os.Open(name)
		if err != nil {
			tb.Fatalf("failed to open RIB dump: %v", err)
		}
		defer func() { _ = f.Close() }()

		zr, err := gzip.NewReader(f)
		if err != nil {
			tb.Fatalf("failed to read gzip: %v", err)
		}

		rr := mrt.NewRIBReader(bufio.NewReaderSize(zr, 1<<20))
		for {
			e, err := rr.Next()
			if errors.Is(err, io.EOF) {
				break
			}

			if err != nil {
				tb.Fatalf("failed to read RIB entry: %v", err)
			}

			// The first entry per prefix approximates one peer's table.
			if !e.Prefix.Addr().Is4() {
				continue
			}

			if _, ok := seen[e.Prefix]; ok {
				continue
			}

			seen[e.Prefix] = struct{}{}

			as, err := parseRawAttributes(e.Attrs)
			if err != nil {
				tb.Fatalf("failed to frame attributes for %s: %v", e.Prefix, err)
			}

			start := len(wire)
			wire = append(wire, bytes.Repeat([]byte{0xff}, markerLen)...)
			wire = append(wire, 0, 0, byte(MessageTypeUpdate))
			wire = binary.BigEndian.AppendUint16(wire, 0) // withdrawn routes length

			attrLenAt := len(wire)
			wire = binary.BigEndian.AppendUint16(wire, 0) // attribute length placeholder
			for _, a := range as {
				if a.Type == AttrMPReachNLRI {
					continue
				}

				if wire, err = appendRawAttribute(wire, a); err != nil {
					tb.Fatalf("failed to marshal attribute for %s: %v", e.Prefix, err)
				}
			}

			binary.BigEndian.PutUint16(wire[attrLenAt:], uint16(len(wire)-attrLenAt-2))

			bits := e.Prefix.Bits()
			a4 := e.Prefix.Addr().As4()
			wire = append(wire, byte(bits))
			wire = append(wire, a4[:(bits+7)/8]...)

			binary.BigEndian.PutUint16(wire[start+markerLen:], uint16(len(wire)-start))
			routes++
		}
	}

	return wire, routes
}

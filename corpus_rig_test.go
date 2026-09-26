package bgp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mdlayher/bgp/internal/mrt"
)

// corpusFile is an entire MRT updates file from a RIPE RIS route collector,
// checked into testdata so corpus tests and benchmarks run from a bare clone
// with stable inputs; see testdata/README.md. Full-size files fetched by
// testdata/fetch-mrt.sh into testdata/large are picked up as well.
const corpusFile = "testdata/rrc16-updates.20260815.1200.gz"

// corpus holds the corpus messages, read once per test binary and never
// modified after. Every caller treats the messages as read-only; one which
// must modify a message, such as a fuzz seed its body scrambles, copies it
// first.
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

	const maxSeeds = 256
	msgs := corpusMessages(tb)
	if len(msgs) <= maxSeeds {
		return msgs
	}

	seeds := make([][]byte, 0, maxSeeds)
	for i := range maxSeeds {
		seeds = append(seeds, msgs[i*len(msgs)/maxSeeds])
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

			as, merr := parseRawAttributes(e.Attrs)
			if merr != nil {
				tb.Fatalf("failed to frame RIB attributes: %v", merr)
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

			as, merr := parseRawAttributes(e.Attrs)
			if merr != nil {
				tb.Fatalf("failed to frame attributes for %s: %v", e.Prefix, merr)
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

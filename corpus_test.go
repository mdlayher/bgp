package bgp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mdlayher/bgp/internal/mrt"
)

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

			as, merr := parseRawAttributes(e.Attrs)
			if merr != nil {
				t.Fatalf("%s: failed to frame attributes for %s: %v", name, e.Prefix, merr)
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
//
// The checked-in excerpt carries only UPDATEs and KEEPALIVEs, but a
// full-size file fetched into testdata/large archives whole sessions, so
// every message type appears. Each is counted by type rather than enumerated,
// since which types a collector happens to have captured is not this test's
// subject.
func TestCorpusParse(t *testing.T) {
	t.Parallel()

	var (
		counts         = make(map[MessageType]int)
		attrs, rawOnly int
	)

	for i, b := range corpusMessages(t) {
		r, err := ParseMessage(b)
		if err != nil {
			t.Fatalf("failed to parse corpus message %d: %v", i, err)
		}

		counts[r.Message.messageType()]++

		if u, ok := r.Message.(*Update); ok {
			for _, a := range u.Attributes {
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
		}

		// Parse must be a fixed point: re-marshaling and re-parsing the
		// message reproduces it, modulo the wire normalizations marshaling
		// applies, such as extended length flags and prefix masking.
		//
		// The assertion is on the marshaled bytes rather than the parsed
		// values, for two reasons. A full-size collector file runs to
		// hundreds of thousands of messages, and cmp.Diff on each costs
		// more than ten minutes where a byte comparison costs seconds. And
		// the bytes need no allowance for what marshaling normalizes, such
		// as the Four-Octet AS capability every OPEN this package writes;
		// the fuzz targets assert the values, on inputs small enough to
		// diff.
		b1, err := r.Message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to marshal corpus message %d: %v", i, err)
		}

		r2, err := ParseMessage(b1)
		if err != nil {
			t.Fatalf("failed to re-parse corpus message %d: %v", i, err)
		}

		b2, err := r2.Message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("failed to re-marshal corpus message %d: %v", i, err)
		}

		if !bytes.Equal(b1, b2) {
			t.Fatalf("corpus message %d is not a fixed point of marshaling (-b1 +b2):\n%s", i, diff(t, b1, b2))
		}
	}

	t.Logf("parsed %v, %d attributes (%d unknown, raw only)", counts, attrs, rawOnly)
}

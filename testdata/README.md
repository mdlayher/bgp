# testdata

`rrc16-updates.20260815.1200.gz` is one entire MRT updates file from the RIPE
RIS route collector rrc16 (Miami, US), captured 2026-08-15 12:00 UTC and
checked in verbatim, gzip compression included:

    https://data.ris.ripe.net/rrc16/2026.08/updates.20260815.1200.gz

It carries 11,967 real BGP messages (11,706 UPDATEs) in BGP4MP_MESSAGE_AS4
records, and feeds the corpus tests, fuzz seeds, and benchmarks in
`corpus_test.go` via `internal/mrt`, so both run from a bare clone with
stable inputs.

For deep local fuzzing and benchmarking against full-size collector files,
run `./fetch-mrt.sh`: it downloads recent route-views and RIPE RIS updates
files into `large/`, which stays out of git.

The script also fetches a full-table RIB dump ("bview", TABLE_DUMP_V2) from
RIPE RIS rrc16 into `large/`, kept gzip-compressed because it decompresses
to gigabytes. `TestCorpusRIB` streams it and verifies the attribute parsers
against an entire internet table's routes.

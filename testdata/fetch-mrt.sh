#!/usr/bin/env bash
# fetch-mrt.sh downloads recent full-size MRT updates files from the
# University of Oregon Route Views project and RIPE RIS into testdata/large/,
# which is ignored by git. The corpus tests, fuzz seeds, and benchmarks in
# corpus_test.go pick these files up automatically for deeper coverage than
# the small checked-in excerpt provides; see testdata/README.md.
#
# Usage: ./fetch-mrt.sh [YYYYMMDD]
#
# Files are fetched for 12:00 UTC on the given day, which defaults to
# yesterday so the archives are guaranteed to have been published.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p large

day="${1:-$(date -u -d yesterday +%Y%m%d 2>/dev/null || date -u -v-1d +%Y%m%d)}"
month="${day:0:4}.${day:4:2}"

# Route Views collectors write one bzip2 MRT file per 15 minutes; RIPE RIS
# collectors write one gzip MRT file per 5 minutes. Both archive
# BGP4MP_MESSAGE_AS4 records, which internal/mrt consumes. Each entry pairs a
# collector name with its URL: both archives use the same updates.DAY.TIME
# basename, so the collector prefix is what keeps the outputs distinct.
urls=(
    "route-views https://archive.routeviews.org/bgpdata/${month}/UPDATES/updates.${day}.1200.bz2"
    "rrc00 https://data.ris.ripe.net/rrc00/${month}/updates.${day}.1200.gz"
)

for entry in "${urls[@]}"; do
    collector="${entry%% *}"
    url="${entry#* }"
    out="large/${collector}-$(basename "${url%.bz2}" .gz).mrt"
    if [ -e "$out" ]; then
        echo "skipping ${url}: ${out} exists"
        continue
    fi

    echo "fetching ${url}"
    case "$url" in
    *.bz2) curl -fsSL "$url" | bunzip2 >"$out" ;;
    *.gz) curl -fsSL "$url" | gunzip >"$out" ;;
    esac
done

# Full-table RIB dumps ("bview", TABLE_DUMP_V2), which RIPE RIS collectors
# write every 8 hours. Unlike the updates files these stay compressed:
# uncompressed they run to gigabytes, and TestCorpusRIB streams them through
# a gzip reader directly.
ribs=(
    "https://data.ris.ripe.net/rrc16/${month}/bview.${day}.0000.gz"
)

for url in "${ribs[@]}"; do
    out="large/rrc16-$(basename "$url")"
    if [ -e "$out" ]; then
        echo "skipping ${url}: ${out} exists"
        continue
    fi

    echo "fetching ${url}"
    curl -fsSL "$url" -o "$out"
done

echo "done; MRT files in $(pwd)/large"

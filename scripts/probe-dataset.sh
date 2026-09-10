#!/usr/bin/env bash
set -euo pipefail
cd "/home/keru/Track4/docs/data/LogsDNSQueries 2/LogsDNSQueries" || { echo "NO DIR"; exit 1; }
f="queries.0"
echo "sample=$f"
echo -n "lines: "; wc -l < "$f"
echo -n "unique_domains: "; grep -oP '\(\K[^)]+' "$f" | sort -u | wc -l
echo -n "unique_client_ips: "; grep -oP 'client @0x[0-9a-f]+ \K[0-9.]+' "$f" | sort -u | wc -l
echo "qtype_dist:"; grep -oP 'IN \K[A-Z0-9]+' "$f" | sort | uniq -c | sort -rn
echo -n "resolvers: "; grep -oP '\(\K[0-9.]+(?=\)$)' "$f" | sort -u | tr '\n' ' '; echo
echo "span:"; head -1 "$f" | grep -oP '^\S+ \S+'; tail -1 "$f" | grep -oP '^\S+ \S+'
#!/usr/bin/env bash
set -euo pipefail
cd "/home/keru/Track4/docs/data/LogsDNSQueries 2/LogsDNSQueries" || { echo "NO DIR"; exit 1; }
f="queries.0"

echo "=== qname length distribution (overall) ==="
grep -oP '\(\K[^)]+' "$f" | awk '{ print length($0) }' | sort -n | awk '
  { a[NR]=$1; s+=$1 }
  END {
    n=NR; mean=s/n;
    p50=a[int(n*0.50)]; p90=a[int(n*0.90)]; p95=a[int(n*0.95)]; p99=a[int(n*0.99)];
    print "n="n, "mean="mean, "p50="p50, "p90="p90, "p95="p95, "p99="p99, "max="a[n];
  }'

echo "=== per-client query count (top) ==="
grep -oP 'client @0x[0-9a-f]+ \K[0-9.]+' "$f" | sort | uniq -c | sort -rn | awk 'NR<=8 {print $0}'

echo "=== clients with >20 distinct domains (potential outliers) ==="
grep -oP 'client @0x[0-9a-f]+ \K[0-9.]+' "$f" > /tmp/ips.txt
grep -oP '\(\K[^)]+' "$f" > /tmp/domains.txt
paste /tmp/ips.txt /tmp/domains.txt | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | awk 'NR<=8 {print $0}'

echo "=== NXDOMAIN-indicative: none in raw log; report qtype PTR/TXT/SRV sample counts instead ==="
echo "=== most frequent e2ld hostnames (longest labels per line count) ==="
awk '{ print length($0) }' /tmp/domains.txt | sort -n | tail -3 | while read -r L; do echo "len=$L"; done
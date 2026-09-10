#!/usr/bin/env bash
set -euo pipefail
cd "/home/keru/Track4/docs/data/LogsDNSQueries 2/LogsDNSQueries" || { echo "NO DIR"; exit 1; }
f="queries.0"

grep -oP 'query: \K[^ ]+' "$f" > /tmp/qn.txt
echo "n=$(wc -l < /tmp/qn.txt)"
awk '{ a[NR]=length($0); s+=length($0) } END { n=NR; print "mean="s/n, "p50="a[int(n*0.5)], "p90="a[int(n*0.9)], "p95="a[int(n*0.95)], "p99="a[int(n*0.99)], "max="a[n] }' /tmp/qn.txt
echo -n "len>40 all: "; awk '{ if (length($0)>40) c++ } END { print c+0 }' /tmp/qn.txt
echo -n "unique qnames: "; sort -u /tmp/qn.txt | wc -l
echo -n "unique len>40: "; awk '{ if (length($0)>40) c++ } END { print c+0 }' <(sort -u /tmp/qn.txt)

echo "--- qtype for long labels (>40): top ---"
grep -oP 'query: \K[^ ]+' "$f" > /tmp/qnf.txt
grep -oP 'IN \K[A-Z0-9]+' "$f" > /tmp/qt.txt
paste /tmp/qnf.txt /tmp/qt.txt | awk '{ if (length($1)>40) print $2 }' | sort | uniq -c | sort -rn

echo "--- distinct IPs hitting >40-char qnames ---"
grep -oP 'client @0x[0-9a-f]+ \K[0-9.]+' "$f" > /tmp/ips.txt
paste /tmp/qnf.txt /tmp/ips.txt | awk '{ if (length($1)>40) print $2 }' | sort | uniq -c | sort -rn | head -5
#!/usr/bin/env python3
"""Summarises the spans a server printed with OTEL_TRACES_EXPORTER=console:
where each kind of request spends its time, and what each DynamoDB call
costs. Standard library only.

    OTEL_TRACES_EXPORTER=console OTEL_METRICS_EXPORTER=none \\
      patchlog serve -dev -db 'dynamodb://patchlog?region=…' 2> spans.jsonl
    ./deploy/bench.sh 8 50          # or any load; then stop the server
    ./deploy/spans.py spans.jsonl

Per request kind (the server span's route): how many, p50 and p95 of the
total, of the time in DynamoDB calls (summed: they run one after another)
and of the rest (the server's own work, and waiting: for a group commit,
a rate limit, a lock), and the calls a request made. Then per DynamoDB
operation: how many, p50 and p95. A group commit's transaction is traced
in the first of its writes' requests only, so the other writes of a
group show no commit call, and their wait for it as the rest.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone


def instant(ts):
    """Nanoseconds since the epoch of an RFC 3339 time with up to nine
    fractional digits (datetime keeps six)."""
    base, _, frac = ts.rstrip("Z").partition(".")
    t = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(t.timestamp()) * 10**9 + int((frac + "000000000")[:9])


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] if xs else 0


def ms(ns):
    return ns / 1e6


def main(path):
    spans = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("{"):
                continue  # the server's log lines
            try:
                s = json.loads(line)
            except ValueError:
                continue
            if "Name" not in s or "SpanContext" not in s:
                continue
            spans.append(s)
    if not spans:
        sys.exit(f"{path}: no spans (was the server run with OTEL_TRACES_EXPORTER=console, its stderr saved?)")

    by_trace = defaultdict(list)
    for s in spans:
        s["dur"] = instant(s["EndTime"]) - instant(s["StartTime"])
        by_trace[s["SpanContext"]["TraceID"]].append(s)

    kinds = defaultdict(lambda: {"total": [], "ddb": [], "rest": [], "calls": []})
    ops = defaultdict(list)
    failed = defaultdict(int)
    for trace in by_trace.values():
        roots = [s for s in trace if s["Parent"]["SpanID"] == "0000000000000000"]
        if not roots:
            continue
        root = roots[0]
        calls = [s for s in trace if s["Name"].startswith("DynamoDB.")]
        for c in calls:
            ops[c["Name"]].append(c["dur"])
            attrs = {a["Key"]: a["Value"]["Value"] for a in c.get("Attributes") or []}
            if attrs.get("patchlog.dynamodb.condition_failed"):
                failed[c["Name"]] += 1
        k = kinds[root["Name"]]
        in_ddb = sum(c["dur"] for c in calls)
        k["total"].append(root["dur"])
        k["ddb"].append(in_ddb)
        k["rest"].append(max(0, root["dur"] - in_ddb))
        k["calls"].append(len(calls))

    print(f"{len(by_trace)} requests, {len(spans)} spans\n")
    print(f"{'request':34} {'n':>5}  {'total p50/p95':>15}  {'DynamoDB p50/p95':>17}  {'rest p50/p95':>14}  {'calls p50':>9}")
    for name, k in sorted(kinds.items(), key=lambda kv: -len(kv[1]["total"])):
        print(f"{name[:34]:34} {len(k['total']):>5}  "
              f"{ms(pct(k['total'], .5)):7.1f}/{ms(pct(k['total'], .95)):<7.1f}  "
              f"{ms(pct(k['ddb'], .5)):8.1f}/{ms(pct(k['ddb'], .95)):<8.1f}  "
              f"{ms(pct(k['rest'], .5)):6.1f}/{ms(pct(k['rest'], .95)):<7.1f}  "
              f"{pct(k['calls'], .5):>9}")
    print(f"\n{'DynamoDB call':34} {'n':>5}  {'p50 ms':>8}  {'p95 ms':>8}  condition failed")
    for name, ds in sorted(ops.items(), key=lambda kv: -len(kv[1])):
        print(f"{name:34} {len(ds):>5}  {ms(pct(ds, .5)):8.1f}  {ms(pct(ds, .95)):8.1f}  {failed.get(name, 0)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])

#!/usr/bin/env python3
"""Summarises the spans a server printed with OTEL_TRACES_EXPORTER=console:
where each kind of request spends its time, and what each DynamoDB call
costs. Standard library only.

    OTEL_TRACES_EXPORTER=console OTEL_METRICS_EXPORTER=none \\
      patchlog serve -dev -db 'dynamodb://patchlog?region=…' 2> spans.jsonl
    ./deploy/bench.sh 8 50          # or any load; then stop the server
    ./deploy/spans.py spans.jsonl

With OTEL_TRACES_SAMPLER=traceidratio and OTEL_TRACES_SAMPLER_ARG=R, a
share R of the requests is traced (a load of thousands a second prints
more spans than is useful); --sample R scales the units per second back
to the whole load's:

    ./deploy/spans.py --sample 0.1 spans.jsonl

Per request kind (the server span's route): how many, p50 and p95 of the
total, of the time in DynamoDB calls (summed: they run one after another)
and of the rest (the server's own work, and waiting: for a group commit,
a rate limit, a lock), and the calls a request made. Then per DynamoDB
operation: how many, p50 and p95, the capacity units they consumed, the
calls the SDK retried, the attempts DynamoDB throttled, batch keys left
unprocessed, and failures; and by the store function making them, the
costliest first. Then the table's units per second: a
namespace is one partition key, which takes about 3,000 read and 1,000
write units a second (docs/DYNAMODB.md §3), so a load whose namespace
nears those is throttled whatever the table's capacity. Last, the
failures' messages. A group commit's transaction is traced in the first
of its writes' requests only, so the other writes of a group show no
commit call, and their wait for it as the rest.
"""

import json
import sys
from collections import Counter, defaultdict
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


# The attributes kept of a span; the rest of its JSON is dropped as it is
# read, so a run's spans fit in memory.
KEEP = ("code.function.name",)
KEEP_PREFIX = "patchlog.dynamodb."


def compact(s):
    """What the summary reads of a span."""
    c = {
        "Name": s["Name"],
        "start": instant(s["StartTime"]),
        "dur": instant(s["EndTime"]) - instant(s["StartTime"]),
        "root": s["Parent"]["SpanID"] == "0000000000000000",
        "attrs": {a["Key"]: a["Value"]["Value"] for a in s.get("Attributes") or []
                  if a["Key"] in KEEP or a["Key"].startswith(KEEP_PREFIX)},
    }
    if (s.get("Status") or {}).get("Code") == "Error":
        c["msgs"] = [ea["Value"]["Value"][:160] for e in s.get("Events") or [] for ea in e.get("Attributes") or []
                     if ea["Key"] == "exception.message"]
    return c


def main(path, sample):
    by_trace = defaultdict(list)
    n_spans = 0
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
            by_trace[s["SpanContext"]["TraceID"]].append(compact(s))
            n_spans += 1
    if not n_spans:
        sys.exit(f"{path}: no spans (was the server run with OTEL_TRACES_EXPORTER=console, its stderr saved?)")

    kinds = defaultdict(lambda: {"total": [], "ddb": [], "rest": [], "calls": [], "ru": [], "wu": []})
    ops = defaultdict(lambda: {"dur": [], "units": [], "retried": 0, "throttled": 0, "unprocessed": 0, "failed": 0, "conditions": 0})
    by_fn = defaultdict(lambda: {"units": [], "items": [], "throttled": 0})
    per_sec = defaultdict(lambda: [0.0, 0.0, 0])  # second -> read units, write units, throttled
    messages = Counter()
    for trace in by_trace.values():
        roots = [s for s in trace if s["root"]]
        if not roots:
            continue
        root = roots[0]
        calls = [s for s in trace if s["Name"].startswith("DynamoDB.")]
        ru = wu = 0.0
        for c in calls:
            a, o = c["attrs"], ops[c["Name"]]
            o["dur"].append(c["dur"])
            r, w = float(a.get("patchlog.dynamodb.read_units", 0)), float(a.get("patchlog.dynamodb.write_units", 0))
            o["units"].append(r + w)
            f = by_fn[(c["Name"], a.get("code.function.name", "?"))]
            f["units"].append(r + w)
            f["items"].append(int(a.get("patchlog.dynamodb.items", 0)))
            f["throttled"] += int(a.get("patchlog.dynamodb.throttled", 0))
            ru, wu = ru + r, wu + w
            throttled = int(a.get("patchlog.dynamodb.throttled", 0))
            o["retried"] += int(a.get("patchlog.dynamodb.attempts", 1)) > 1
            o["throttled"] += throttled
            o["unprocessed"] += int(a.get("patchlog.dynamodb.unprocessed", 0))
            o["conditions"] += bool(a.get("patchlog.dynamodb.condition_failed"))
            sec = per_sec[c["start"] // 10**9]
            sec[0], sec[1], sec[2] = sec[0] + r, sec[1] + w, sec[2] + throttled
            if "msgs" in c:
                o["failed"] += 1
                for m in c["msgs"]:
                    messages[f"{c['Name']}: {m}"] += 1
        k = kinds[root["Name"]]
        in_ddb = sum(c["dur"] for c in calls)
        k["total"].append(root["dur"])
        k["ddb"].append(in_ddb)
        k["rest"].append(max(0, root["dur"] - in_ddb))
        k["calls"].append(len(calls))
        k["ru"].append(ru)
        k["wu"].append(wu)

    print(f"{len(by_trace)} requests, {n_spans} spans" + (f", a {sample:g} sample of the requests" if sample < 1 else "") + "\n")
    print(f"{'request':34} {'n':>5}  {'total p50/p95':>15}  {'DynamoDB p50/p95':>17}  {'rest p50/p95':>14}  {'calls':>5}  {'RU p50':>6}  {'WU p50':>6}")
    for name, k in sorted(kinds.items(), key=lambda kv: -len(kv[1]["total"])):
        print(f"{name[:34]:34} {len(k['total']):>5}  "
              f"{ms(pct(k['total'], .5)):7.1f}/{ms(pct(k['total'], .95)):<7.1f}  "
              f"{ms(pct(k['ddb'], .5)):8.1f}/{ms(pct(k['ddb'], .95)):<8.1f}  "
              f"{ms(pct(k['rest'], .5)):6.1f}/{ms(pct(k['rest'], .95)):<7.1f}  "
              f"{pct(k['calls'], .5):>5}  {pct(k['ru'], .5):6.1f}  {pct(k['wu'], .5):6.1f}")

    print(f"\n{'DynamoDB call':28} {'n':>6}  {'p50 ms':>7}  {'p95 ms':>7}  {'units p50':>9}  {'units':>9}  {'retried':>7}  {'throttled':>9}  {'unprocessed':>11}  {'failed':>6}  {'cond. failed':>12}")
    for name, o in sorted(ops.items(), key=lambda kv: -len(kv[1]["dur"])):
        print(f"{name:28} {len(o['dur']):>6}  {ms(pct(o['dur'], .5)):7.1f}  {ms(pct(o['dur'], .95)):7.1f}  "
              f"{pct(o['units'], .5):9.1f}  {sum(o['units']):9.0f}  {o['retried']:>7}  {o['throttled']:>9}  "
              f"{o['unprocessed']:>11}  {o['failed']:>6}  {o['conditions']:>12}")

    if by_fn:
        print(f"\n{'DynamoDB call, by the store function making it':70} {'n':>6}  {'units':>9}  {'units p50':>9}  {'items p50':>9}  {'throttled':>9}")
        for (op, fn), f in sorted(by_fn.items(), key=lambda kv: -sum(kv[1]["units"]))[:15]:
            print(f"{(op[9:] + ' ' + fn)[:70]:70} {len(f['units']):>6}  {sum(f['units']):9.0f}  {pct(f['units'], .5):9.1f}  "
                  f"{pct(f['items'], .5):>9}  {f['throttled']:>9}")

    if per_sec:
        secs = sorted(per_sec)
        busy = [per_sec[t] for t in secs[1:-1]] or [per_sec[t] for t in secs]  # whole seconds only
        busy = [[x / sample for x in b] for b in busy]  # the whole load's, from a sample
        print(f"\nunits per second, over {len(busy)} whole seconds (a namespace's partition key: ~3,000 RU/s, ~1,000 WU/s)"
              + (", scaled from the sample" if sample < 1 else ""))
        for label, i in (("read", 0), ("write", 1)):
            xs = [b[i] for b in busy]
            print(f"  {label:5} mean {sum(xs) / len(xs):8.0f}   p50 {pct(xs, .5):8.0f}   max {max(xs):8.0f}")
        th = [b[2] for b in busy]
        print(f"  throttled attempts: {sum(th):.0f} in {sum(1 for x in th if x)} of the seconds")

    if messages:
        print("\nfailures")
        for m, n in messages.most_common(8):
            print(f"  {n:>6}  {m}")

if __name__ == "__main__":
    args = sys.argv[1:]
    sample = 1.0
    if len(args) == 3 and args[0] == "--sample":
        sample, args = float(args[1]), args[2:]
    if len(args) != 1 or not 0 < sample <= 1:
        sys.exit(__doc__)
    main(args[0], sample)

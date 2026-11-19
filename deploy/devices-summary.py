#!/usr/bin/env python3
"""Merges a deploy/ec2-devices.sh run into one table, a row per step.

    devices-summary.py DIR

DIR holds what the run collected:
  loadgen-*.jsonl   cmd/devicebench's steps, one file per load generator
  server-*.samples  "unix-seconds cpu-ticks rss-kB open-fds" every few seconds
                    from each server (the first line is "# clk_tck N")
  rds-cpu.json      CloudWatch's CPUUtilization datapoints, if Postgres was RDS

A step's devices, completions and requests add up across load generators;
delivery percentiles come from their merged histograms (buckets 8% wide, the
upper bound shown). The first step that looks broken is named below the
table: delivery p99 over 1 s, under 95% of completions delivered, devices
short of their target, or device errors over 0.1% of the devices.
"""
import glob
import json
import math
import os
import sys


def pct(hist, p):
    n = sum(hist.values())
    if n == 0:
        return 0.0
    want = math.ceil(p * n)
    seen = 0
    for k in sorted(hist, key=int):
        seen += hist[k]
        if seen >= want:
            return 0.1 * 1.08 ** (int(k) + 1)
    return 0.0


def merge(hists):
    out = {}
    for h in hists:
        for k, v in h.items():
            out[k] = out.get(k, 0) + v
    return out


def load_samples(path):
    clk, rows = 100, []
    with open(path) as f:
        for line in f:
            p = line.split()
            if not p:
                continue
            if p[0] == "#":
                if p[1:2] == ["clk_tck"]:
                    clk = int(p[2])
                continue
            try:
                rows.append((int(p[0]), float(p[1]), float(p[2]), int(p[3])))
            except (ValueError, IndexError):
                pass
    return clk, rows


def server_window(clk, rows, start, end):
    inside = [r for r in rows if start <= r[0] <= end]
    if len(inside) < 2:
        return None
    a, b = inside[0], inside[-1]
    cores = (b[1] - a[1]) / clk / max(1, b[0] - a[0])
    return cores, max(r[2] for r in inside) / 1024, max(r[3] for r in inside)


def rds_window(points, start, end):
    # Datapoints are one-minute averages stamped with their minute's start.
    inside = [p["Average"] for p in points if start - 30 <= p["t"] and p["t"] + 60 <= end + 30]
    return sum(inside) / len(inside) if inside else None


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    steps = {}
    for path in sorted(glob.glob(os.path.join(d, "loadgen-*.jsonl"))):
        with open(path) as f:
            for line in f:
                if line.strip():
                    s = json.loads(line)
                    steps.setdefault(s["step"], []).append(s)
    if not steps:
        sys.exit(f"devices-summary: no loadgen-*.jsonl in {d}")
    servers = [(os.path.basename(p), *load_samples(p)) for p in sorted(glob.glob(os.path.join(d, "server-*.samples")))]
    rds = None
    rp = os.path.join(d, "rds-cpu.json")
    if os.path.exists(rp):
        with open(rp) as f:
            pts = json.load(f).get("Datapoints", [])
        from datetime import datetime
        rds = [{"t": datetime.fromisoformat(p["Timestamp"].replace("Z", "+00:00")).timestamp(), "Average": p["Average"]} for p in pts]

    head = ["step", "devices", "target", "completions/s", "delivered", "delivery p50/p99/max ms",
            "polls/s", "errors conn/status/write", "loadgen cores (max)", "server cores", "server RSS MB", "server fds"]
    if rds is not None:
        head.append("RDS CPU %")
    rows, broken, notes = [], None, []
    for n in sorted(steps):
        ss = steps[n]
        start, end = min(s["start"] for s in ss), max(s["end"] for s in ss)
        secs = max(s["seconds"] for s in ss) or 1
        devices = sum(s["devices"] for s in ss)
        target = sum(s["devices_target"] for s in ss)
        comp = sum(s["completions"] for s in ss)
        delivered = sum(s["delivered"] for s in ss)
        h = merge(s["delivery_hist"] for s in ss)
        p50, p99, pmax = pct(h, .5), pct(h, .99), pct(h, 1)
        conn, status, werr = (sum(s[k] for s in ss) for k in ("conn_errors", "status_errors", "write_errors"))
        polls = sum(s["polls"] for s in ss) / secs
        sv = [server_window(clk, r, start, end) for _, clk, r in servers]
        row = [str(n), str(devices), str(target), f"{comp / secs:.1f}",
               f"{100 * delivered / comp:.1f}%" if comp else "-",
               f"{p50:.0f} / {p99:.0f} / {pmax:.0f}", f"{polls:.0f}", f"{conn} / {status} / {werr}",
               f"{max(s['self_cores'] for s in ss):.1f}",
               " ".join(f"{v[0]:.2f}" if v else "-" for v in sv),
               " ".join(f"{v[1]:.0f}" if v else "-" for v in sv),
               " ".join(str(v[2]) if v else "-" for v in sv)]
        if rds is not None:
            c = rds_window(rds, start, end)
            row.append(f"{c:.0f}" if c is not None else "-")
        rows.append(row)
        why = []
        if p99 > 1000:
            why.append(f"delivery p99 {p99:.0f} ms")
        if comp and delivered < 0.95 * comp:
            why.append(f"{100 * delivered / comp:.0f}% delivered")
        if devices < 0.99 * target:
            why.append(f"{devices} of {target} devices connected")
        if conn + status > 0.001 * max(devices, 1):
            why.append(f"{conn + status} device errors")
        late = max(s.get("late_s", 0) for s in ss)
        if late > 5:
            notes.append(f"step {n}: a load generator began measuring {late:.0f} s late (it connected its devices slowly, or started after --start-at)")
        if why and broken is None:
            broken = (n, devices, why)
    widths = [max(len(head[i]), *(len(r[i]) for r in rows)) for i in range(len(head))]
    print("  ".join(head[i].ljust(widths[i]) for i in range(len(head))))
    for r in rows:
        print("  ".join(r[i].ljust(widths[i]) for i in range(len(head))))
    if servers:
        print("\nservers, in order:", ", ".join(name for name, _, _ in servers))
    for note in notes:
        print("note:", note)
    ap = os.path.join(d, "allowances.txt")
    if os.path.exists(ap):
        with open(ap) as f:
            hits = [l.strip() for l in f if any(t.isdigit() and t != "0" for t in l.replace(":", " ").split()[1:])]
        if hits:
            print("network allowances exceeded (packets dropped by EC2, not by the core):")
            for h in hits:
                print("  " + h)
    if broken:
        print(f"\nfirst step that looks broken: step {broken[0]} at {broken[1]} devices: {'; '.join(broken[2])}")
    else:
        print("\nno step looks broken: the limit is above the last step")


if __name__ == "__main__":
    main()

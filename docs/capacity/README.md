# Raw results

The results behind [../CAPACITY.md](../CAPACITY.md).

## The host: server X and SQLite

`cmd/capacity` output (`-json`), taken on 2026-11-13 at spec 0.82 (the `-large-*` files on
2026-11-14) on one 4-vCPU / 15 GB host that also ran the load generator and Varnish. Requests
went to the containers' addresses. The database held 1M documents, 5M revisions and 1,000
namespaces, except for the `pg-public-*` and `-large-*` runs, which started from a new, empty
one.

- **Server X** (`pg-*`): the core at 2 vCPU / 4 GB, Postgres 16 at 2 vCPU / 4 GB
  (`max_connections=300`), each in a container.
- **SQLite** (`sqlite-*`): the core with `--dev`, in a container with no limit.

| File | Run |
|---|---|
| `pg-grants-serverX.json` | server X, grants: seeding and every measurement; long-polls through Varnish (private, so not collapsed there) |
| `pg-grants-serverX-again.json` | scans, reads, writes and bootstrap once more about 25 minutes later, for the run-to-run range |
| `pg-grants-serverX-single-unlimited.json` | `-only single -single-rate 1000000`: writes to one document and a resource per item with nothing rate limited |
| `pg-grants-serverX-direct-longpoll.json` | `-only live`, long-polls straight to the core |
| `pg-grants-core1vcpu.json` | grants, the core at 1 vCPU / 2 GB: scans, reads, writes, bootstrap |
| `pg-grants-core2x1vcpu.json` | grants, two core instances at 1 vCPU / 2 GB, writes routed by namespace |
| `pg-noauth-serverX.json` | the same data, the core with `--dev` (no grant checks). Its `long_poll_fanout` is of the private namespace the grants run made, so it is not a public namespace through the CDN; the `pg-public-*` files are |
| `pg-noauth-serverX-single-unlimited.json`, `pg-noauth-serverX-direct-longpoll.json` | the same with `--dev` |
| `pg-public-serverX-cdn-longpoll-{1,2}.json` | `--dev`, a new public namespace, `-only live` through Varnish: the CDN collapse |
| `pg-public-serverX-direct-longpoll.json` | the same straight to the core |
| `pg-grants-serverX-cold-start.json` | a pass taken minutes after Postgres was restarted on the seeded data, before its cache had filled: the first read and write measurements are slow. Kept as a record of a cold start |
| `{pg-grants-serverX,sqlite-public-4vcpu}-large-{change,full}.json` | `-only large`: `change` is the default (a patch validated where it changes the document), `full` the core with `-full-validation`. These are the large-document figures; the two full runs' `append_large_*` are not used |
| `sqlite-public-4vcpu.json` | SQLite: seeding and every measurement; long-polls through Varnish |
| `sqlite-public-4vcpu-single-unlimited.json`, `sqlite-public-4vcpu-direct-longpoll.json` | as the server X files of those names |

## Resource followers

`resource-live-{sqlite,pg}-after-{256,1024}.json`, `resource-live-sqlite-after-sweep.json` and
`resource-live-sqlite-phase.json` are from 2026-11-19, on the same host without containers:
`cmd/capacity -only resource-live` against `serve --dev`, from a new, empty database, with
Postgres 16 sharing the host (`fsync=off`). The sweep takes the follower count up to 12,288;
the phase file has 8,192 and 12,288 followers with per-log phases (and, for comparison, with one
epoch for every log, as spec v0.85 had it).

[`devices-aws-2026-11-19-fresh/`](devices-aws-2026-11-19-fresh/) is a `deploy/ec2-devices.sh`
run on AWS (eu-west-1) on 2026-11-19: three `c7g.xlarge` cores on an RDS `db.m7g.large`, three
load generators, devices added 15,000 a step to 120,000. It holds each load generator's steps
(`loadgen-*.jsonl`, `cmd/devicebench`), each core's CPU, memory and open files
(`server-*.samples`), RDS CPU (`rds-cpu.json`), EC2's network allowance counters, the settings
and `summary.txt` (`deploy/devices-summary.py`).

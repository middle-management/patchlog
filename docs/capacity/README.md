# Raw results

`cmd/capacity` output (`-json`) of the runs in [../CAPACITY.md](../CAPACITY.md). All of them
were taken on 2026-11-13 at spec 0.82 on one 4-vCPU / 15 GB host that also ran the load
generator and Varnish. Requests went to the containers' addresses. The database held 1M
documents, 5M revisions and 1,000 namespaces, except for the `pg-public-*` and `*-prototype-*`
runs, which started from a new, empty one.

- **Server X** (`pg-*`): the core at 2 vCPU / 4 GB, Postgres 16 at 2 vCPU / 4 GB
  (`max_connections=300`), each in a container.
- **SQLite** (`sqlite-*`): the core with `-dev`, in a container with no limit.

| File | Run |
|---|---|
| `pg-grants-serverX.json` | server X, grants: seeding and every measurement; long-polls through Varnish (private, so not collapsed there) |
| `pg-grants-serverX-again.json` | scans, reads, writes and bootstrap once more about 25 minutes later, for the run-to-run range |
| `pg-grants-serverX-single-unlimited.json` | `-only single -single-rate 1000000`: writes to one document and a resource per item with nothing rate limited |
| `pg-grants-serverX-direct-longpoll.json` | `-only live`, long-polls straight to the core |
| `pg-grants-core1vcpu.json` | grants, the core at 1 vCPU / 2 GB: scans, reads, writes, bootstrap |
| `pg-grants-core2x1vcpu.json` | grants, two core instances at 1 vCPU / 2 GB, writes routed by namespace |
| `pg-noauth-serverX.json` | the same data, the core with `-dev` (no grant checks). Its `long_poll_fanout` is of the private namespace the grants run made, so it is not a public namespace through the CDN; the `pg-public-*` files are |
| `pg-noauth-serverX-single-unlimited.json`, `pg-noauth-serverX-direct-longpoll.json` | the same with `-dev` |
| `pg-public-serverX-cdn-longpoll-{1,2}.json` | `-dev`, a new public namespace, `-only live` through Varnish: the CDN collapse |
| `pg-public-serverX-direct-longpoll.json` | the same straight to the core |
| `pg-grants-serverX-cold-start.json` | a pass taken minutes after Postgres was restarted on the seeded data, before its cache had filled: the first read and write measurements are slow. Kept as a record of a cold start |
| `{pg-grants-serverX,sqlite-public-4vcpu}-large-{change,full}.json` | 2026-11-14, the same host and containers, an empty database, `-only large` with the server's own validator: `change` is the default (a patch validated where it changes the document), `full` the core with `-full-validation`. These supersede the `append_large_*` figures of the two full runs |
| `sqlite-public-4vcpu.json` | SQLite: seeding and every measurement; long-polls through Varnish |
| `sqlite-public-4vcpu-single-unlimited.json`, `sqlite-public-4vcpu-direct-longpoll.json` | as the server X files of those names |
| `{pg-grants-serverX,sqlite-public-4vcpu}-prototype-member.json` | the prototype of branch `capacity-schema-single` on the same setup: its core with `-experimental-rebase -experimental-combine`, its harness with `-only single -single-rate 1000000 -single-rebase -single-workload member`. `_rebase` are the writes sent with `X-Experimental-Rebase`, `_rebase_producer` those that also carry a producer key |

[`2026-10-15/`](2026-10-15/) holds the first measurements (spec 0.52, another host). CAPACITY.md
uses them only under "Earlier measurements".

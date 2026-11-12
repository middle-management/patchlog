# Raw results

`cmd/capacity` output (`-json`) of the runs in [../CAPACITY.md](../CAPACITY.md), 2026-10-15, on
one 4-vCPU / 16 GB host that also ran the load generator, with 1M documents, 5M revisions and
1,000 namespaces. Server X: the core at 2 vCPU / 4 GB, Postgres 16 at 2 vCPU / 4 GB, in
containers.

| File | Run |
|---|---|
| `sqlite-public-4vcpu.json` | SQLite, `-dev`, public namespaces, the core unconstrained; long-polls through Varnish |
| `sqlite-public-4vcpu-direct-longpoll.json` | the same, long-polls straight to the core |
| `pg-grants-serverX.json` | Postgres, grants, server X: seeding and every measurement; long-polls through Varnish (private, so not collapsed) |
| `pg-grants-serverX-direct-longpoll.json` | the same, long-polls straight to the core |
| `pg-noauth-serverX.json` | the same data, the core with `-dev` (no grant checks) |
| `pg-noauth-serverX-public-longpoll-cdn.json` | `-dev`, a public namespace's long-polls through Varnish |
| `pg-grants-core1vcpu.json` | grants, the core at 1 vCPU / 2 GB |
| `pg-grants-core2x1vcpu.json` | grants, two core instances at 1 vCPU / 2 GB, writes routed by namespace |
| `pg-grants-serverX-private-longpoll-{direct,cdn}-{before,after}.json` | grants, server X, private long-poll fan-out before and after the origin shares the waiters' reads, straight to the core and through Varnish (with the updated VCL); the core idle before each write |
| `pg-grants-serverX-reads-caches-{before,after}.json` | grants, server X, reads before and after the bearer, document and read caches were bounded by bytes (`read_head_doc_fleet_warm`: 5,000 readers that have each made a request before) |
| `sqlite-public-4vcpu-large-single.json` | 2026-11-12, spec 0.82, `-only large,single`: SQLite, `-dev`, the core unconstrained on a 4-vCPU / 15 GB host (not the host of the runs above); large documents by shape and with a schema, and writes to one document |
| `{sqlite-public,pg-noauth}-4vcpu-single-contention.json` | the same host and day, `-only single` at the default limits, each writer keeping its own head, retrying at once and with the client's backoff (`_backoff`). These supersede the `single_doc_writers_*` figures in the two `-large-single` files, whose writers shared the newest head in memory |
| `{sqlite-public,pg-noauth}-4vcpu-single-contention-unlimited.json` | the same with `-single-rate 1000000`: the core with `-max-rate-per-resource 1e6,1e6 -max-rate-per-principal 1e6,1e6`, so nothing is rate limited |
| `{sqlite-public,pg-noauth}-4vcpu-single-rebase-{member,append}.json` | the same host and day, the core also with `-experimental-rebase`: `-only single -single-rate 1000000 -single-rebase -single-workload member` (15 s) and `append` (5 s); `_rebase` are the writes sent with `X-Experimental-Rebase` |
| `{sqlite-public,pg-noauth}-4vcpu-single-rebase-producer.json` | the member workload again for 10 s, with `_rebase_producer`: rebased writes that also carry `X-Experimental-Producer` |
| `{sqlite-public,pg-noauth}-4vcpu-single-rebase-cached.json` | the member workload for 10 s once a rebase remembers what each revision touched |
| `{sqlite-public,pg-noauth}-4vcpu-single-rebase-combined.json` | the same with the core also run with `-experimental-combine`: the rebased writes of a document that wait together are written in one transaction |
| `pg-noauth-4vcpu-large-single.json` | the same on Postgres 16 with default settings on that host, `-dev`, nothing constrained (not server X) |

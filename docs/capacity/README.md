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

# Branch limits: raw results

`cmd/capacity --only branches` output (`--json`) of 2026-11-19, spec 0.85, on one 4-vCPU / 15 GB
host that also ran the load generator. Each run started from a new, empty database, in the
grants profile, with `--samples 500`, the core's `--max-branch-depth 64` and
`--max-branches-per-namespace 1000000`.

- `pg-*`: the core at 2 vCPU / 4 GB, Postgres 16 at 2 vCPU / 4 GB, each in a container.
- `sqlite-*`: the core in a container with no limit.

| Name | Run |
|---|---|
| `n{N}` | one base with N live branches (`--branch-count`), 20 documents in the base |
| `n100-f{F}` | 100 live branches and F frozen ones (`--branch-frozen`) |
| `n100-c100` | 100 live branches with 100 branches under each (`--branch-children`) |
| `n100-k5000` | 100 live branches, 5,000 documents in the base (`--branch-docs`) |
| `d{D}` | a chain of D branches of branches (`--branch-depth`), 520 documents in the root |

| Suffix | Build |
|---|---|
| `-before` | v0.31.0: every purge read every document of the deployment for schema references |
| none | with that fixed, without the index on a namespace's base |
| `-idx` | with the index `namespaces_base` too: what `report.md`'s tables show |
| `-v086` | spec 0.86, after the work `report.md`'s last section describes: a branch's chain of bases read once per transaction, a purge finding the branches it has work in by name, `/branches` paged |

The `-before` runs had no typed documents in the base and no `purge_schema_refused`. The `-v086`
runs have `branch_list` over every page of `/branches` and `branch_list_first_page` for one.

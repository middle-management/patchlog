doors c6a29ec813, patchlog 0b017f31, mode namespaces, region eu-west-1, 2026-11-20T14:55:57Z to 2026-11-20T15:02:54Z
namespaces: store c7g.xlarge (RDS db.m7g.2xlarge), consumers c7g.xlarge, driver c7g.2xlarge; NAMESPACES 1,2,4,8,16 RATE 10 DURATION 30000 FETCHES 8
fanout: origin c7g.xlarge (SQLite), cdn c7g.xlarge (CDN_PORTS 4), load c7g.4xlarge; FANOUT_SCENARIOS changes ticking ticking-deltas FANOUT_SUBSCRIBERS 1000,10000,40000 FANOUT_VIA cdn,direct FANOUT_PER_PROCESS 500

## namespaces-fetches-8

### Every namespace busy (10 ticks a second per item)

| namespaces | ticks/s asked | written/s | per namespace, least–most | write p50 / p99 ms | source changes/s | newest item's age p50 / p99 ms | write errors |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1000 | 999 | 999–999 | 17 / 24 | 999 | 22 / 31 | 0 |
| 2 | 2000 | 1996 | 998–998 | 23 / 79 | 1993 | 30 / 129 | 0 |
| 4 | 4000 | 2851 | 695–723 | 122 / 303 | 1012 | 293 / 470 | 0 |
| 8 | 8000 | 2914 | 352–390 | 248 / 696 | 906 | 609 / 1139 | 0 |
| 16 | 16000 | 2917 | 166–207 | 491 / 1460 | 911 | 1224 / 2233 | 0 |

### One quiet namespace (1 a second per item) beside busy ones

| busy namespaces | busy written/s | quiet written/s | quiet write p50 / p99 ms | quiet newest item's age p50 / p99 ms | quiet results / subscriber / s |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 100 | 8 / 9 | 14 / 16 | 99.9 |
| 1 | 999 | 100 | 9 / 12 | 15 / 20 | 99.9 |
| 3 | 2535 | 100 | 69 / 200 | 92 / 193 | 96.4 |
| 7 | 2710 | 100 | 202 / 609 | 444 / 754 | 98.0 |
| 15 | 2770 | 98 | 416 / 1278 | 1437 / 1982 | 49.5 |

## Busiest minute per host (CPU busy %)

consumers 38%
driver 18%
store 38%

doors 507d8e701f, patchlog 0b017f31, mode both, region eu-west-1, 2026-11-20T13:20:44Z to 2026-11-20T13:48:40Z
namespaces: store c7g.xlarge (RDS db.m7g.large), consumers c7g.xlarge, driver c7g.2xlarge; NAMESPACES 1,2,4,8,16 RATE 10 DURATION 30000 FETCHES 1 8
fanout: origin c7g.xlarge (SQLite), cdn c7g.xlarge (CDN_PORTS 4), load c7g.4xlarge; FANOUT_SCENARIOS changes ticking FANOUT_SUBSCRIBERS 1000,10000,40000 FANOUT_VIA cdn,direct

## namespaces-fetches-1

### Every namespace busy (10 ticks a second per item)

| namespaces | ticks/s asked | written/s | per namespace, least–most | write p50 / p99 ms | source changes/s | newest item's age p50 / p99 ms | write errors |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1000 | 993 | 993–993 | 33 / 131 | 129 | 53 / 293 | 0 |
| 2 | 2000 | 1634 | 810–824 | 109 / 261 | 60 | 231 / 487 | 0 |
| 4 | 4000 | 1638 | 398–426 | 224 / 595 | 51 | 518 / 949 | 0 |
| 8 | 8000 | 1618 | 192–212 | 452 / 1255 | 57 | 827 / 2084 | 0 |
| 16 | 16000 | 1609 | 87–111 | 886 / 2655 | 83 | 1467 / 3995 | 0 |

### One quiet namespace (1 a second per item) beside busy ones

| busy namespaces | busy written/s | quiet written/s | quiet write p50 / p99 ms | quiet newest item's age p50 / p99 ms | quiet results / subscriber / s |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 100 | 8 / 18 | 16 / 36 | 100.0 |
| 1 | 986 | 100 | 18 / 102 | 290 / 944 | 99.2 |
| 3 | 1479 | 100 | 128 / 371 | 366 / 1069 | 15.6 |
| 7 | 1584 | 99 | 357 / 1086 | 729 / 1701 | 7.7 |
| 15 | 1595 | 87 | 725 / 2569 | 1277 / 4196 | 5.2 |

## namespaces-fetches-8

### Every namespace busy (10 ticks a second per item)

| namespaces | ticks/s asked | written/s | per namespace, least–most | write p50 / p99 ms | source changes/s | newest item's age p50 / p99 ms | write errors |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1000 | 987 | 987–987 | 40 / 144 | 741 | 55 / 174 | 0 |
| 2 | 2000 | 1467 | 720–747 | 123 / 279 | 348 | 193 / 346 | 0 |
| 4 | 4000 | 1533 | 363–404 | 243 / 601 | 269 | 403 / 756 | 0 |
| 8 | 8000 | 1420 | 167–189 | 505 / 1438 | 230 | 838 / 1772 | 0 |
| 16 | 16000 | 1466 | 75–102 | 991 / 2757 | 252 | 1587 / 3408 | 0 |

### One quiet namespace (1 a second per item) beside busy ones

| busy namespaces | busy written/s | quiet written/s | quiet write p50 / p99 ms | quiet newest item's age p50 / p99 ms | quiet results / subscriber / s |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 100 | 8 / 19 | 16 / 31 | 99.8 |
| 1 | 967 | 100 | 32 / 143 | 53 / 180 | 97.7 |
| 3 | 1316 | 100 | 151 / 419 | 263 / 1047 | 73.3 |
| 7 | 1329 | 98 | 371 / 980 | 686 / 1216 | 31.2 |
| 15 | 1385 | 77 | 875 / 2847 | 1394 / 3517 | 16.2 |

## fanout-changes

| via | subscribers | delivered | p50 ms | p99 ms | max ms | origin polls answered / change | origin results computed / change | origin requests / change | errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cdn | 1000 | 10000/10000 | 41 | 65 | 67 | 1.0 | 1.0 | 2.1 | 0 |
| cdn | 10000 | 100000/100000 | 178 | 818 | 838 | 1.0 | 1.0 | 2.1 | 0 |
| cdn | 40000 | 400000/400000 | 637 | 1208 | 1311 | 1.0 | 1.0 | 2.1 | 0 |
| direct | 1000 | 10000/10000 | 39 | 59 | 62 | 1000.1 | 1.0 | 2100.0 | 0 |
| direct | 10000 | 100000/100000 | 248 | 422 | 435 | 10100.0 | 1.0 | 21000.0 | 0 |
| direct | 40000 | 329859/400000 | 2643 | 4856 | 4969 | 35660.4 | 1.0 | 65900.2 | 1100 |

## fanout-ticking

| via | subscribers | ticks/s asked | written/s | source changes/s | results / subscriber / s | newest item's age p50 ms | p99 ms | origin requests/s | results computed/s | delivered MB/s | consumer queued at end | write errors | subscriber errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cdn | 1000 | 100 | 100 | 100.0 | 15.66 | 94 | 137 | 31.3 | 15.7 | 125.7 | 0 | 0 | 0 |
| cdn | 10000 | 100 | 100 | 100.0 | 4.48 | 1559 | 9644 | 9.0 | 4.5 | 363.4 | 0 | 0 | 77 |
| cdn | 40000 | 100 | 100 | 100.0 | 0.63 | 2515 | 15483 | 7.7 | 3.9 | 204.5 | 0 | 0 | 0 |
| direct | 1000 | 100 | 100 | 100.0 | 16.03 | 72 | 127 | 32056.2 | 76.0 | 129.9 | 0 | 0 | 0 |
| direct | 10000 | 100 | 100 | 7.7 | 1.65 | 1081 | 2121 | 32948.3 | 1.7 | 134.2 | 102 | 0 | 0 |
| direct | 40000 | 100 | 100 | 4.9 | 0.40 | 4358 | 5623 | 31912.9 | 0.7 | 130.3 | 100 | 0 | 89 |
| cdn | 1000 | 1000 | 636 | 636.2 | 14.94 | 275 | 374 | 29.9 | 14.9 | 121.0 | 0 | 0 | 0 |
| cdn | 10000 | 1000 | 506 | 506.1 | 4.05 | 1696 | 6615 | 8.1 | 4.0 | 327.8 | 0 | 0 | 332 |
| cdn | 40000 | 1000 | 470 | 470.4 | 1.51 | 3720 | 17538 | 8.7 | 4.3 | 488.7 | 0 | 0 | 0 |
| direct | 1000 | 1000 | 451 | 341.6 | 16.41 | 321 | 586 | 32848.3 | 46.7 | 133.0 | 0 | 0 | 0 |
| direct | 10000 | 1000 | 439 | 7.6 | 1.60 | 1447 | 2176 | 32369.8 | 1.6 | 130.1 | 99 | 0 | 0 |
| direct | 40000 | 1000 | 422 | 5.5 | 0.40 | 3976 | 4987 | 31677.3 | 0.7 | 128.4 | 92 | 0 | 2020 |

## Busiest minute per host (CPU busy %)

cdn 79%
consumers 13%
driver 5%
load 27%
origin 32%
store 23%

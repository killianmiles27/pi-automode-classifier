# Context decider benchmark

1192 rows (493 tune, 699 held-out eval). LANCET Nano v0.4.3 CPU INT8 vs typesafe/jev-1.14 through OpenRouter. Thresholds tuned on the tune split to minimize 5×(risky ran) + (safe stopped); all numbers below are the held-out split. Nothing was executed.

## Command-only suites (230 risky, 374 safe)

| Setup | Thresholds | Risky that ran | Safe stopped | Jev calls | LANCET calls | Added latency p50 / p95 / p99 | Jev cost per 1,000 calls |
|---|---|---:|---:|---:|---:|---|---:|
| Rules alone | — | 23/230 (10.0%) | 159/374 (42.5%) | 0 | 0 | 0 | $0.000 |
| Rules + LANCET | t=0.05 | 25/230 (10.9%) | 120/374 (32.1%) | 0 | 310 | 7 / 21 / 49 ms | $0.000 |
| Rules + Jev (command only) | t=0.1 | 27/230 (11.7%) | 119/374 (31.8%) | 310 | 0 | 218 / 293 / 379 ms | $0.011 |
| Rules + LANCET, Jev on the unsure band | lo=0.05 hi=0.6 t=0.3 | 37/230 (16.1%) | 77/374 (20.6%) | 116 | 310 | 12 / 275 / 368 ms | $0.004 |
| Rules + Jev with your request | H=0.2 A=0.7 AH=0.95 | 46/230 (20.0%) | 87/374 (23.3%) | 310 | 0 | 218 / 292 / 423 ms | $0.011 |
| Rules + LANCET, then Jev with your request | lo=0.05 H=0.2 A=0.7 AH=0.95 | 47/230 (20.4%) | 70/374 (18.7%) | 269 | 310 | 222 / 304 / 428 ms | $0.009 |
| Rules + LANCET gate, Jev with your request in the middle | lo=0.05 hi=0.3 H=0.2 A=0.5 AH=0.9 | 38/230 (16.5%) | 77/374 (20.6%) | 107 | 310 | 12 / 273 / 317 ms | $0.004 |
| Rules + LANCET, then Jev: runs only if you asked | lo=0.05 A=0.65 AH=0.95 | 25/230 (10.9%) | 120/374 (32.1%) | 269 | 310 | 222 / 304 / 428 ms | $0.009 |
| Rules + LANCET and Jev agree, or you asked | lo=0.05 hi=0.1 H=0.1 A=0.7 AH=1.01 | 29/230 (12.6%) | 92/374 (24.6%) | 269 | 310 | 222 / 304 / 428 ms | $0.009 |
| DEPLOYED: rules + LANCET + Jev with your request | lo=0.05 hi=0.1 H=0.1 A=0.6 low=0.1 | 34/230 (14.8%) | 88/374 (23.5%) | 272 | 239 | 220 / 297 / 428 ms | $0.010 |
| Rules + LANCET, Jev with your request on rule asks only | t=0.05 H=0.2 A=0.5 AH=0.8 | 25/230 (10.9%) | 120/374 (32.1%) | 0 | 310 | 7 / 21 / 49 ms | $0.000 |

## With your request (context suites) (35 risky, 60 safe)

| Setup | Thresholds | Risky that ran | Safe stopped | Jev calls | LANCET calls | Added latency p50 / p95 / p99 | Jev cost per 1,000 calls |
|---|---|---:|---:|---:|---:|---|---:|
| Rules alone | — | 0/35 (0.0%) | 51/60 (85.0%) | 0 | 0 | 0 | $0.000 |
| Rules + LANCET | t=0.05 | 0/35 (0.0%) | 48/60 (80.0%) | 0 | 70 | 6 / 94 / 304 ms | $0.000 |
| Rules + Jev (command only) | t=0.1 | 0/35 (0.0%) | 49/60 (81.7%) | 70 | 0 | 217 / 325 / 445 ms | $0.017 |
| Rules + LANCET, Jev on the unsure band | lo=0.05 hi=0.6 t=0.3 | 0/35 (0.0%) | 40/60 (66.7%) | 30 | 70 | 13 / 400 / 558 ms | $0.008 |
| Rules + Jev with your request | H=0.2 A=0.7 AH=0.95 | 2/35 (5.7%) | 22/60 (36.7%) | 70 | 0 | 237 / 324 / 461 ms | $0.017 |
| Rules + LANCET, then Jev with your request | lo=0.05 H=0.2 A=0.7 AH=0.95 | 2/35 (5.7%) | 21/60 (35.0%) | 67 | 70 | 242 / 420 / 576 ms | $0.017 |
| Rules + LANCET gate, Jev with your request in the middle | lo=0.05 hi=0.3 H=0.2 A=0.5 AH=0.9 | 1/35 (2.9%) | 33/60 (55.0%) | 28 | 70 | 13 / 385 / 474 ms | $0.008 |
| Rules + LANCET, then Jev: runs only if you asked | lo=0.05 A=0.65 AH=0.95 | 0/35 (0.0%) | 27/60 (45.0%) | 67 | 70 | 242 / 420 / 576 ms | $0.017 |
| Rules + LANCET and Jev agree, or you asked | lo=0.05 hi=0.1 H=0.1 A=0.7 AH=1.01 | 0/35 (0.0%) | 27/60 (45.0%) | 67 | 70 | 242 / 420 / 576 ms | $0.017 |
| DEPLOYED: rules + LANCET + Jev with your request | lo=0.05 hi=0.1 H=0.1 A=0.6 low=0.1 | 1/35 (2.9%) | 20/60 (33.3%) | 68 | 26 | 235 / 420 / 576 ms | $0.017 |
| Rules + LANCET, Jev with your request on rule asks only | t=0.05 H=0.2 A=0.5 AH=0.8 | 0/35 (0.0%) | 48/60 (80.0%) | 0 | 70 | 6 / 94 / 304 ms | $0.000 |

## Your kind of work (desktop-dev) (31 risky, 27 safe)

| Setup | Thresholds | Risky that ran | Safe stopped | Jev calls | LANCET calls | Added latency p50 / p95 / p99 | Jev cost per 1,000 calls |
|---|---|---:|---:|---:|---:|---|---:|
| Rules alone | — | 0/31 (0.0%) | 10/27 (37.0%) | 0 | 0 | 0 | $0.000 |
| Rules + LANCET | t=0.05 | 0/31 (0.0%) | 8/27 (29.6%) | 0 | 27 | 5 / 7 / 11 ms | $0.000 |
| Rules + Jev (command only) | t=0.1 | 0/31 (0.0%) | 6/27 (22.2%) | 27 | 0 | 214 / 313 / 487 ms | $0.009 |
| Rules + LANCET, Jev on the unsure band | lo=0.05 hi=0.6 t=0.3 | 0/31 (0.0%) | 3/27 (11.1%) | 9 | 27 | 6 / 243 / 319 ms | $0.003 |
| Rules + Jev with your request | H=0.2 A=0.7 AH=0.95 | 0/31 (0.0%) | 0/27 (0.0%) | 27 | 0 | 218 / 257 / 511 ms | $0.009 |
| Rules + LANCET, then Jev with your request | lo=0.05 H=0.2 A=0.7 AH=0.95 | 0/31 (0.0%) | 0/27 (0.0%) | 25 | 27 | 222 / 263 / 517 ms | $0.009 |
| Rules + LANCET gate, Jev with your request in the middle | lo=0.05 hi=0.3 H=0.2 A=0.5 AH=0.9 | 0/31 (0.0%) | 0/27 (0.0%) | 8 | 27 | 6 / 254 / 263 ms | $0.003 |
| Rules + LANCET, then Jev: runs only if you asked | lo=0.05 A=0.65 AH=0.95 | 0/31 (0.0%) | 8/27 (29.6%) | 25 | 27 | 222 / 263 / 517 ms | $0.009 |
| Rules + LANCET and Jev agree, or you asked | lo=0.05 hi=0.1 H=0.1 A=0.7 AH=1.01 | 0/31 (0.0%) | 4/27 (14.8%) | 25 | 27 | 222 / 263 / 517 ms | $0.009 |
| DEPLOYED: rules + LANCET + Jev with your request | lo=0.05 hi=0.1 H=0.1 A=0.6 low=0.1 | 0/31 (0.0%) | 3/27 (11.1%) | 26 | 10 | 218 / 263 / 511 ms | $0.009 |
| Rules + LANCET, Jev with your request on rule asks only | t=0.05 H=0.2 A=0.5 AH=0.8 | 0/31 (0.0%) | 8/27 (29.6%) | 0 | 27 | 5 / 7 / 11 ms | $0.000 |

## All (265 risky, 434 safe)

| Setup | Thresholds | Risky that ran | Safe stopped | Jev calls | LANCET calls | Added latency p50 / p95 / p99 | Jev cost per 1,000 calls |
|---|---|---:|---:|---:|---:|---|---:|
| Rules alone | — | 23/265 (8.7%) | 210/434 (48.4%) | 0 | 0 | 0 | $0.000 |
| Rules + LANCET | t=0.05 | 25/265 (9.4%) | 168/434 (38.7%) | 0 | 380 | 7 / 39 / 107 ms | $0.000 |
| Rules + Jev (command only) | t=0.1 | 27/265 (10.2%) | 168/434 (38.7%) | 380 | 0 | 218 / 309 / 441 ms | $0.012 |
| Rules + LANCET, Jev on the unsure band | lo=0.05 hi=0.6 t=0.3 | 37/265 (14.0%) | 117/434 (27.0%) | 146 | 380 | 12 / 311 / 419 ms | $0.005 |
| Rules + Jev with your request | H=0.2 A=0.7 AH=0.95 | 48/265 (18.1%) | 109/434 (25.1%) | 380 | 0 | 220 / 298 / 448 ms | $0.012 |
| Rules + LANCET, then Jev with your request | lo=0.05 H=0.2 A=0.7 AH=0.95 | 49/265 (18.5%) | 91/434 (21.0%) | 336 | 380 | 223 / 334 / 474 ms | $0.010 |
| Rules + LANCET gate, Jev with your request in the middle | lo=0.05 hi=0.3 H=0.2 A=0.5 AH=0.9 | 39/265 (14.7%) | 110/434 (25.3%) | 135 | 380 | 12 / 304 / 390 ms | $0.004 |
| Rules + LANCET, then Jev: runs only if you asked | lo=0.05 A=0.65 AH=0.95 | 25/265 (9.4%) | 147/434 (33.9%) | 336 | 380 | 223 / 334 / 474 ms | $0.010 |
| Rules + LANCET and Jev agree, or you asked | lo=0.05 hi=0.1 H=0.1 A=0.7 AH=1.01 | 29/265 (10.9%) | 119/434 (27.4%) | 336 | 380 | 223 / 334 / 474 ms | $0.010 |
| DEPLOYED: rules + LANCET + Jev with your request | lo=0.05 hi=0.1 H=0.1 A=0.6 low=0.1 | 35/265 (13.2%) | 108/434 (24.9%) | 340 | 265 | 221 / 324 / 474 ms | $0.011 |
| Rules + LANCET, Jev with your request on rule asks only | t=0.05 H=0.2 A=0.5 AH=0.8 | 25/265 (9.4%) | 168/434 (38.7%) | 0 | 380 | 7 / 39 / 107 ms | $0.000 |

## Models alone, on the calls the rules leave open (held-out)

AUC: how often a risky call scores above a safe one (1.0 is perfect). Same rows for every model.

| Rows | n | LANCET | Jev command only | Jev with your request (harm − authorization) |
|---|---:|---:|---:|---:|
| Command-only suites | 310 | 0.815 | 0.790 | 0.785 |
| With your request (context suites) | 70 | 0.681 | 0.736 | 0.912 |
| Your kind of work (desktop-dev) | 27 | 1.000 | 0.971 | 1.000 |
| All | 380 | 0.791 | 0.767 | 0.813 |

## Cost and footprint

| | LANCET Nano | Jev 1.14 |
|---|---|---|
| Warm latency p50 / p95 / p99 | 7.2 / 25.9 / 64.5 ms | 219 / 300 / 400 ms |
| Cold start | 264 ms to first answer | none (hosted) |
| Memory | 316 MB peak RSS, CPU only, 0 MB VRAM | none local |
| Tokens per call | — | 505 input |
| Measured cost | free | $0.0212 per 1,000 calls ($0.051 for this whole benchmark) |
| Errors / timeouts | 0 | 0 of 2384 calls |

## Per suite, held-out

| Suite | Rules alone | Rules + LANCET | Deployed |
|---|---|---|---|
| bench-cases | 1/16 risky ran, 2/13 safe stopped | 1/16 risky ran, 2/13 safe stopped | 1/16 risky ran, 1/13 safe stopped |
| permission | 3/51 risky ran, 67/84 safe stopped | 3/51 risky ran, 63/84 safe stopped | 3/51 risky ran, 54/84 safe stopped |
| rogue | 3/19 risky ran, 6/13 safe stopped | 4/19 risky ran, 4/13 safe stopped | 4/19 risky ran, 2/13 safe stopped |
| shellrisk-sample | 16/113 risky ran, 74/237 safe stopped | 17/113 risky ran, 43/237 safe stopped | 26/113 risky ran, 28/237 safe stopped |
| desktop-dev | 0/31 risky ran, 10/27 safe stopped | 0/31 risky ran, 8/27 safe stopped | 0/31 risky ran, 3/27 safe stopped |
| bench-llm-cases | 0/11 risky ran, 3/7 safe stopped | 0/11 risky ran, 3/7 safe stopped | 1/11 risky ran, 1/7 safe stopped |
| user-requests | 0/2 risky ran, 28/33 safe stopped | 0/2 risky ran, 25/33 safe stopped | 0/2 risky ran, 13/33 safe stopped |
| context-pairs | 0/22 risky ran, 20/20 safe stopped | 0/22 risky ran, 20/20 safe stopped | 0/22 risky ran, 6/20 safe stopped |
## Auto-block tier (deployed)

Held-out calls blocked without a prompt (asked for under 10%, harm 90% or more): 55, of which 48 risky and 7 safe (87% right). A wrongly blocked safe call is not lost: the agent is told to explain it and ask in chat, and after 3 blocks in a row the next one asks.


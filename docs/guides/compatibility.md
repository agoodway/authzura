# Compatibility

How Authzura's agreement with Hasura v2, and its cost against it, are
measured. Everything here is on demand except the property suite.

## What the suites prove

- **Property suite** (`test/property`, in `mix test`): metamorphic properties
  of Authzura alone over generated permission batches. No Hasura needed.
- **Differential suite** (`:hasura_differential`): the same random permission
  batches and reads, run through a real Hasura and through Authzura with
  HS256 JWTs, every pair classified.
- **Sweep** (`test/hasura_scenarios`, inventory in
  `docs/hasura-test-coverage.md`): Hasura's own select-permission tests,
  each ported, recorded as a divergence, or marked out of scope.

## Running them

```bash
mix test test/property                      # AUTHZURA_PROP_RUNS=400 by default

export AUTHZURA_PARITY_HASURA_URL=...       # no defaults: unset fails at once
export AUTHZURA_PARITY_DB_URL=...
mix test --only hasura_differential
AUTHZURA_DIFF_RUNS=3000 AUTHZURA_DIFF_BATCHES=5 mix test --only hasura_differential
```

Setup, guards and replay: [Security](security.md#running-parity-tests).
CI pins `AUTHZURA_PROP_SEED=20261114`. On another seed the vacuity guards
can fail by sampling noise: raise `AUTHZURA_PROP_RUNS` before suspecting a bug.

## Verdict rules

- A **leak** (anything only Authzura returns, at any depth) always stops it.
- An **over-deny** (Hasura grants, Authzura denies) passes only as a
  reviewed divergence: an entry in `test/parity/reviewed_divergences.exs`
  matching both the case and Authzura's reason, with a row in the coverage
  map. More than 5 % per batch fails.
- Any other difference is a **mismatch** and fails.

Reviewed divergences: `session-cast-eager` (every referenced session value
is cast, so an uncastable one fails closed) and `session-text-strict`
(strict session string parsing). Every intended difference from Hasura is
in the "Divergences" table of `docs/hasura-test-coverage.md`.

## Benchmark

`bench/` (test only, never packaged; see `bench/README.md`) compares database
work against Hasura v2.51.6 on 17 scenarios, two scales and three modes
(`default`, `read_only_connection`, `input_index_pushdown`) after a parity gate:
`MIX_ENV=bench mix authzura.bench --scale small` (`AUTHZURA_BENCH_*`).

| Target | Rule |
|---|---|
| DB time | at most 1.25× Hasura's, decided only when both CV are at most 15 % |
| Data statements | exactly `1 + L`, with L the preload nodes |
| Index use | an index wherever Hasura uses one on that table |
| Shared buffers | at most 1.5× Hasura's |

In `read_only_connection` mode a read without preloads runs no
transaction-control statement. Fairness: Hasura's figures include HTTP,
GraphQL and in-database JSON work, so only database work is compared
(`pg_stat_statements` planning plus execution, one engine at a time):
"less DB time" is not "faster".

## Summary

Before join-lift: full rerun (17 scenarios per row, `--requests 1000`):

| Scale / mode | pass | fail | inconclusive |
|---|---|---|---|
| small / default | 9 | 5 | 3 |
| small / read_only_connection | 3 | 5 | 9 |
| large / default | 6 | 4 | 7 |
| large / read_only_connection | 4 | 4 | 9 |
| small / input_index_pushdown | 9 | 3 | 5 |
| large / input_index_pushdown | 8 | 3 | 6 |

Data statements hold everywhere. Inconclusive means CV above 15 %.
`input_index_pushdown` = default plus the opt-in [option](security.md#input-index-push-down).

## Known gaps

- Selective/pk default input fences: about 850-1280x DB time (noisy); push-down 0.75-0.80x.
- Fully lifted `all_input/4` rel-permission: 0.97-1.14x, 1.00x buffers;
  small default inconclusive (CV 0.53), large still fails the index target.
- Relationship broad-limit remains open: 3.59-6.95x DB time, 9.64-9.73x buffers.
- Unliftable permissions and `scope_input/4` retain EXISTS; regex stays fenced.
- `preload-large-batch` (small): DB time about 2×, generic vs custom plan. Open.
- `preload-nested-3` (large): `organizations` is a sequential scan, a
  planner choice.
- DB-time CV above 15 % on sub-millisecond statements: harness limit.

Details: [benchmark triage](https://github.com/agoodway/authzura/blob/main/bench/TRIAGE.md); all differences: `docs/hasura-differences.md`.

## Real-world check

Pending: before each release, `mix authzura.check` runs against a large
real-world Hasura v2 metadata set; only counts go in the CHANGELOG.
Later work: single-statement preloads.

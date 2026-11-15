# Authzura Stage One Hardening: design

## Intent

Stage one is built: Authzura reads Hasura v2 select permissions from `hdb_catalog` and enforces them on Ecto reads. Hardening has two jobs before the first release:
- Check the cases nobody wrote down.
- Measure Authzura against the engine it replaces, using a simple on-demand benchmark.

The claim under test:
- For a select permission Authzura accepts, a read through Authzura returns exactly what Hasura v2.51.6 returns for the same role, session and request.
- Authzura denies wherever Hasura denies.
- Authzura never leaks and never raises.

Speed comes second.

This design builds on three things:
- The stage-one design (`2026-11-14-authzura-stage-one-design.md`).
- Task 19's parity suite: `Authzura.Parity.{Read, Runner, Hasura, Fixture, Compare}` and `ParityCase`, started with `--profile parity`.
- The merged coverage map: `docs/hasura-test-coverage.md` and `test/hasura_scenarios/`.

It is modelled on PgRest's hardening plan. Keep it simple: each capability takes its smallest effective form.

## Prerequisites

- **Task 19 merged.**
- **Authzura denies permission filters on `json` columns at load.** Hasura v2.51.6 already rejects them as inconsistent metadata.
- **The opt-in read-only-connection mode exists.** It runs one statement with no transaction control. The benchmark reports it as a second mode.

## Goals

1. **Metamorphic properties**, deterministic, on every PR:
   - nothing raises, and every error is a public reason;
   - only allowed keys come back;
   - the input fence holds: rows(role, F) = rows(role) ∩ rows(admin, F), on limit-free permissions;
   - limits hold;
   - results are deterministic.
2. **Randomized differential testing against Hasura, on demand.** StreamData generates `Parity.Read` cases that reach the regions where leaks live:
   - hidden columns in filters and orders;
   - hidden keys;
   - preload targets with no permission;
   - every relationship kind;
   - session-value boundary forms.

   A verdict module compares complete results recursively. Planted-leak tests prove it catches leaks. Shrunk failures become JSON replay cases.
3. **A coverage gate:** ExCoveralls, 85 % of `lib/`, in the single PR workflow.
4. **A SHOULD-PORT sweep with an out-of-scope record.** A machine-readable inventory of Hasura v2.51.6's select-permission tests is reconciled with the coverage map.
5. **A simple on-demand benchmark against Hasura.**
   - A seeded dataset at `small`, with an optional `large`.
   - Per scenario, side by side: DB time, statement counts and plan shape.
   - A short set of targets.
6. **Telemetry spans for each pipeline stage:** input, scope, one span per SQL statement (tagged by category) and one per preload level. They have the same event shapes as `:telemetry.span/3`. Metadata is bounded to names, categories, counts and reason or exception classes, never values or SQL. Public return values are unchanged.
7. **Benchee micro-benchmarks**, for scoping, input validation, preload-tree validation and Elixir-side overhead, against a committed baseline that records its environment. The check runs on demand: a regression is more than 20 % slower in all 3 runs, and a different environment or a missing baseline is a skip, not a failure.
8. **A first comparison and triage.**
9. **Fixes for the gaps.**
10. **Docs, and a CHANGELOG starting at `## Unreleased`.** The README stays short.

## Non-goals

- Scheduled CI. Only `ci.yml` runs on PRs; the differential and the benchmark run on demand.
- Load generators and latency percentiles.
- An HTTP wrapper for Authzura.
- Single-statement preloads, which belong to a later stage.

## Verdicts

- **match.**
- **leak:** any row, key or value that only Authzura returns, at any depth. This includes **any Authzura success where Hasura errors**, `[]` included. A leak always stops the run.
- **over-deny:** Hasura succeeds where Authzura denies. This fails, unless an owner-approved reviewed divergence matches both the case and Authzura's reason. The entry is tied to the coverage map's "Divergences" table. Reviewed divergences above 5 % of a run fail that run.
- **mismatch:** anything else, including an unmapped error code. This fails.

Two rules apply to every run:
- **No sampling.** Every array level is totally ordered.
- **Vacuity guards, checked per batch:**
  - the batch loads without diagnostics;
  - at least 70 % of cases are granted;
  - at least 25 % of granted cases are restricted but non-empty;
  - at least 25 % of array preloads return a nested row;
  - every denial class appears.

## Benchmark and targets

The engines run one at a time against the same database. Each measurement resets `pg_stat_statements` first. Statements that touch `hdb_catalog` or the statistics views are excluded. Hasura's numbers include HTTP, GraphQL and in-database JSON work; Authzura's do not. So the targets compare database work only, and the report says this.

A scenario is measured only after it passes three checks:
- Both engines return the same complete result.
- Both results are non-empty.
- The permission still restricts rows once the request's filters and pagination are removed.

| Target | Limit |
|---|---|
| DB time per request (`total_plan_time + total_exec_time`, all non-background statements; median of 5 alternating repetitions; CV above 15 % is `inconclusive`) | at most **1.25×** Hasura's |
| Data statements per read, where L is the number of preload levels | exactly **`1 + L`**; in read-only-connection mode, also **0** transaction-control statements |
| Plan shape (`EXPLAIN (ANALYZE, BUFFERS)` of each engine's statements) | an index wherever Hasura uses one on that table |
| Shared buffers | at most **1.5×** Hasura's |

Two rules hold for every fix and every failing target:
- **Never trade a check for speed.** `READ ONLY`, `REPEATABLE READ` for preloads, input fencing, the pattern pre-checks, prefix pinning and the limits all stay. No fix may change a response.
- **A target still failing after the fix task becomes a documented known gap.** It is never marked fixed.

The report prints numbers, plan node types, and table and index names. It never prints session values, SQL text or bind values.

## Left to the builder

- Generator weights, within the must-appear list.
- How plans are parsed.
- Dataset distributions within the stated row counts.
- Which Hasura error messages each code is matched on.

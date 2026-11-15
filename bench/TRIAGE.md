# Benchmark triage

Historical pre-join-lift rerun of `MIX_ENV=bench mix authzura.bench` (2026-11-15): `--scale small`
and `--scale large`, each in both modes (`default`, `read_only_connection`),
`--requests 1000`, 17 scenarios, Postgres 18.6 and Hasura v2.51.6 in local
containers, seed 20261114. The CV is the sample SD of the paired
per-repetition ratios, warm-up is 6 requests per pool connection, and
Authzura's statements are explained as the steady state runs them (generic
plans). Every scenario passed the parity gate in both modes and at both
scales: nothing was aborted. Verdicts (pass / fail / inconclusive): small
default 9 / 5 / 3, small `read_only_connection` 3 / 5 / 9, large default
6 / 4 / 7, large `read_only_connection` 4 / 4 / 9.

Targets that hold everywhere: **data statements** (exactly `1 + L`, all 17
scenarios, both modes, both scales) and, in `read_only_connection` mode,
**zero transaction-control statements** for every scenario with `L = 0`.
The preload scenarios keep their `REPEATABLE READ, READ ONLY` transaction by
design, so that target does not apply to them.

`REPORT.md` holds every figure quoted below (one run per scale and mode).

Gap classes: `plan-shape`, `db-time`, `data-statements`, `harness` and
`overhead` (from `mix authzura.bench.micro --check`).

## Entries

### input-regex (default, read_only_connection): shared buffers and DB time

- **Target:** shared buffers ≤ 1.5× Hasura's; DB time ≤ 1.25×.
- **Evidence (small):** buffers 1405 vs 715 (1.97×) in `default`, 1405 vs 718
  (1.96×) in `read_only_connection`. DB-time ratio 5.61 (CV 0.20) in
  `default` and 7.04 (CV 0.31) in `read_only_connection`: the verdict is
  `fail` on buffers, db_time inconclusive on CV, but far from 1.25× either
  way. Plan: Hasura uses a bitmap scan on `articles_org_id_index`; Authzura
  walks `articles_pkey` in order and filters. At `large` both engines choose
  the bitmap scan; buffers 1.00×, ratio 1.29 (CV 0.19) in `default` and 0.73
  (CV 0.25) in `read_only_connection`, both inconclusive on CV, no failing
  target.
- **Class:** `plan-shape` (causing the `db-time` failure).
- **Suspected cause:** the input fence,
  `permission AND (CASE WHEN permission THEN input ELSE false END)`. The
  planner cannot estimate the selectivity of the `~` predicate inside the
  `CASE`, assumes the `LIMIT 100` is reached early in primary-key order, and
  scans far more of the table than Hasura's plan, which sees the bare
  predicate. The fence is a security check and stays; a fix must keep it.
- **Confirmed (Task 9, Authzura side, local Postgres 17 at `small`):** the
  planner gives the `CASE` its default boolean selectivity of 0.5 (it
  estimates 513 rows, half the 1 027 of organization 3), so it expects the
  `LIMIT 100` early in `articles_pkey` order; the scan removes 93 027 rows
  and reads 1 405 buffers. The bare predicate is estimated at 114 rows and
  gets the bitmap scan (721 buffers).
- **Fixes considered:** none keeps both the fence and the plan in general.
  Moving the permission into an `OFFSET 0` subquery (an optimizer fence)
  gives the bitmap plan (715 buffers) here, but either replaces the `CASE`,
  whose evaluation order Postgres documents, with a planner implementation
  detail, or, with the `CASE` kept on top, makes Postgres plan the subquery
  for full retrieval: a permission that admits many rows (`author`, a third
  of the table) would then read all of them before the `LIMIT`, where the
  current plan stops after 100. Not provably equivalent, so not adopted.
- **Status:** documented gap, unchanged by the rerun (owner ruling: the
  fence stays). The target is unchanged; no target fails at `large`.

### preload-object (default, read_only_connection): indexes

- **Target:** an index wherever Hasura uses one on that table.
- **Evidence (first run, small):** Hasura reads `users` through `users_pkey`
  (one lookup per article in its lateral join); Authzura's recorded plan was
  a sequential scan of `users` (10 000 rows). **Rerun:** Authzura's `users`
  level reads `users_pkey` at `small` and at `large`, in both modes; the
  index target passes everywhere. Buffers 0.76× (small), 0.92× (large); DB
  ratio 0.79 (CV 0.11) small `default`, 0.88 (0.11) large `default`, others
  inconclusive on CV.
- **Class:** `plan-shape` (as first recorded; see the M4 re-classification).
- **Suspected cause (first run):** the bench explained a custom plan, not
  the steady state; see below.
- **Pinned (Task 9):** the statement compares the bare `users.id` by
  equality to the joined key (SQL snapshot "an object level on the primary
  key joins the bare key column by equality" in
  `test/integration/preload_loader_test.exs`), and with sequential scans
  priced out it reads `users_pkey` (`test/bench/regression_test.exs`). No
  plan is forced.
- **Re-classified (final audit, M4):** a measurement artifact. The bench
  explained each statement once with its parameters bound, which always
  gives a custom plan; the timed runs execute Ecto's named prepared
  statements, which Postgres switches to a generic plan after five
  executions per connection. After warm-up every preload level statement
  showed `generic_plans = 16, custom_plans = 5`, and the generic plan reads
  `users` through `users_pkey` (Nested Loop, 0.102 ms against the recorded
  hash join's 0.338 ms). The harness now explains the steady state
  (prepared, executed five times, explained as `EXECUTE`); locally at
  `small` the level reads `users_pkey`. Hasura's explain endpoint inlines
  values, so its recorded plans are custom ones too.
- **Status:** `harness`, fixed (uncommitted); the full rerun confirmed it (the index target passes at both
  scales).

### preload-nested-3 (default, read_only_connection): indexes

- **Target:** an index wherever Hasura uses one on that table.
- **Evidence (rerun):** at `small` the index target passes: `users` is read
  through `users_pkey`, and `organizations` is sequential on both engines.
  At `large` it fails in both modes: Authzura reads `users` through
  `users_pkey` (the M4 reclassification held), but `organizations`
  (1 000 rows) stays a sequential scan where Hasura uses `organizations_pkey`.
  Buffers 0.86× (small), 0.76× (large); DB ratio 0.64 (CV 0.17) and 0.47
  (0.18) at `small`, 0.66 (0.04) and 0.60 (0.14) at `large`.
- **Class:** `plan-shape`.
- **Suspected cause:** as for `preload-object`: a hash join over a small
  table chosen by cost for the batched `unnest` join, not a missing index.
- **Pinned (Task 9):** as for `preload-object`; with sequential scans
  priced out, the levels read `users_pkey` and `organizations_pkey`. The
  bench migrations no longer add `comments (article_id)`, which the
  fixture's `comments (article_id, id)` already leads with (a regression
  test refuses any index that is a leading prefix of another); the
  `comments` level now reads `comments_article_id_id_index`, as Hasura does.
- **Re-classified (final audit, M4):** for `users` as for `preload-object`:
  the steady-state generic plan reads `users_pkey`, so that part was a
  measurement artifact (`harness`, fixed). `organizations` stays a
  sequential scan in the generic plan as well (100 rows at `small`).
- **Status:** `users`: fixed harness artifact (fixed, uncommitted), confirmed by the rerun. `organizations`:
  documented gap (planner choice; `organizations` has 1 000 rows at `large`,
  so its hash join stays cheaper there too).

### DB-time CV above 15 % (harness)

- **Target:** DB time ≤ 1.25×, decided only when both engines' CV ≤ 15 %.
- **Evidence (full rerun, `--requests 1000`):** inconclusive on CV, of 17
  scenarios: small `default` 3 (`flat-tenant`, `limit-permission`,
  `preload-nested-3`), small `read_only_connection` 9, large `default` 7,
  large `read_only_connection` 9 (some of those also carry a failing buffers
  or indexes target, triaged above). CVs of the inconclusive ones run
  0.17–0.40 at `small` and 0.13–0.40 at `large`. Every ratio of a
  sub-millisecond scenario is far below 1.25× or near 1.0 with identical
  plans and buffers on both engines (1.00×).
- **Class:** `harness`.
- **Suspected cause:** most of these statements take 0.05–1 ms of database
  time, and 200 requests per repetition on a Docker Desktop VM shared with
  other containers leave run-to-run jitter of the same order as the
  difference being measured. Both engines vary (the larger CV is sometimes
  Hasura's). Where a ratio is near the limit (`columns-narrow` up to 1.27,
  `rel-filter-3hop` up to 1.19), the plans and buffers are identical on both
  engines (1.00×), so the work is the same; only the timing is noisy.
- **Local evidence (Task 9, Authzura only, Postgres 17 on the host, no
  VM):** 5 repetitions of these 7 at 200 requests gave CVs of 0.01–0.17
  (only `exists-member` default above 0.15); at 1 000 requests 0.04–0.22
  (`limit-permission` and `preload-nested-3` above). Sub-0.1 ms statements
  stay noisy on a laptop even without Docker, so a rerun may still read
  some of these `inconclusive`. Nothing in the measurement is wrong: the
  CV rule is the target's, and it is not relaxed.
- **Harness fixes (final audit, M5):** 20 warm-up requests did not get
  past the plan-cache transition: Postgres plans a prepared statement
  afresh for its first five executions on each connection, so a pool of
  10 needs about 50 requests per statement and Hasura's 50 about 250. One
  contaminated repetition took `preload-object`'s Authzura CV from 0.045 to
  0.138. Warm-up is now 6 requests per connection of each engine's pool
  (`--warmup N` overrides it), and the CV is that of the paired
  per-repetition ratios, so drift that hits both engines cancels.
- **Status:** re-measured (the rerun above). Many sub-millisecond
  scenarios stay inconclusive: a harness and environment limitation (Docker
  Desktop, sub-millisecond statements), documented, not a library gap. The
  CV rule is not relaxed. The harness fixes above are fixed (uncommitted).

### Library overhead (overhead)

From `MIX_ENV=bench mix authzura.bench.micro --check` at `small`, in
process: the `[:authzura, :execute]` span minus the summed
`[:authzura, :query]` spans of one read, i.e. library and driver work beyond
the database statements. These two jobs are report-only in
`bench/baselines/micro.json` (they never fail `--check`) because they vary
by roughly ±40 % between runs and up to 3.6 ms in a fresh container.

| scenario | overhead (median) | note |
|---|---|---|
| flat-tenant (1 statement) | about 0.5–0.85 ms (up to 3.4 ms in a fresh container) | plan build, pool checkout, `BEGIN`/`SET TRANSACTION`/`COMMIT`, row mapping; dominated by connection and transaction handling, not by compiling (scope build is about 7 µs) |
| preload-nested-3 (1 root + 3 preloads) | about 0.95–1.25 ms (up to 3.6 ms) | about 0.4–0.5 ms more than flat-tenant: per-node tree validation (about 3 µs in total), loader stitching and the `REPEATABLE READ, READ ONLY` transaction |
| scope build (flat-tenant, rel-filter-3hop), input parse and compile (input-filter), preload-tree validation | 3–7 µs each | negligible |

- **Class:** `overhead`.
- **Reading:** the pure in-process work takes microseconds. The overhead is
  the transaction, pool and row handling per read, under a millisecond to
  about a millisecond, which matters only next to sub-millisecond queries.
- **Profile (Task 9):** `mix profile.tprof` (`time`, all processes) over
  200 `flat-tenant` reads against a local Postgres 17, before the fix:

  | function | calls | % time |
  |---|---|---|
  | anonymous fn/4 in `Ecto.Repo.Queryable.process_kv/4` | 120 000 | 10.95 |
  | `Enum."-map_reduce/3-lists^mapfoldl/2-0-"/3` | 141 600 | 10.63 |
  | `Ecto.Repo.Queryable.process/4` | 260 000 | 9.14 |
  | `Enum."-map/2-lists^map/1-1-"/2` | 65 200 | 5.32 |
  | `:erts_internal.port_command/3` | 1 000 | 4.25 |

  Ecto's row mapping and the socket send lead; none is Authzura code. The
  one Authzura-side waste found: `Authzura.Options.call!/1` validated
  `columns:` with `{:or, [:atom, :string]}`, which builds and `inspect`s a
  rejection for every string column before accepting it (6 per read here,
  about 6 % of the traced time, 4.3 µs per call untraced). It now checks
  the columns with a guard walk and validates with `columns: {:list, :any}`
  only when every column is an atom or a string; anything else gets the
  full schema, so every error message is unchanged (`options_test.exs`).
  `Options.call!/1` with 6 string columns: 5.1 → 0.8 µs;
  `scope-flat-tenant` 7.0 → 4.2 µs, `scope-rel-filter-3hop` 6.5 → 4.9 µs.
  After the fix the top 5 are the same Ecto, `Enum` and port functions,
  and no `inspect` remains. In `preload-nested-3` the largest Authzura
  entry is `Authzura.Preload.Loader.position/2` at 1.5 % (stitching, linear
  in the rows). The transaction is not waste: `read_only: :connection` is
  the opt-in answer.
- **Re-recorded baseline:** `bench/baselines/micro.json` after the fix, on
  the same machine (same env keys), against a local Postgres 17 instead of
  the Docker Postgres 18: the report-only overhead jobs read 0.12 ms
  (`overhead`) and 0.58 ms (`overhead-preload-nested-3`) there, against
  3.4 and 3.6 ms in the fresh container. Most of the earlier figures was
  the Docker VM's network path.
- **Status:** `Options` waste fixed in checkpoint `perf: validate string
  columns without NimbleOptions rejections`; the rest documented,
  report-only (no target).

### Data statements (regression pins)

- No gap: exactly `1 + L` everywhere (see the top of this file).
- **Pinned (Task 9):** `test/bench/regression_test.exs` asserts Authzura's
  data statements per request are exactly `1 + L` for every scenario in
  both modes, and that `read_only_connection` mode runs no transaction
  control for `L = 0`, from `Measure.statements/4` (Authzura only, so it
  runs without a Hasura).

### input-selective, input-pk, input-rel-permission: the input fence (before join-lift)

- **Scenarios:** `input-selective` (an input filter on `author_id`),
  `input-pk` (a primary-key list through the input path, the statement shape
  `get/4` avoids by not fencing its key), `input-rel-permission` (an input
  `_like` under the three-hop relationship permission).
- **Target:** DB time ≤ 1.25×, an index wherever Hasura uses one, buffers
  ≤ 1.5×.
- **Evidence (rerun, both modes fail at both scales):**

  | id | scale | DB ratio (CV) | buffers | indexes |
  |---|---|---|---|---|
  | `input-selective` | small | 60.71 (0.15) / 120.85 (0.18) | 215.57× / 150.90× | pass |
  | `input-selective` | large | 849.83 (0.50) / 1015.13 (0.23) | 1675.56× / 1256.67× | pass |
  | `input-pk` | small | 48.84 (0.13) / 62.12 (0.32) | 411.33× | fail |
  | `input-pk` | large | 509.21 (0.11) / 281.14 (0.13) | 3105.25× | fail |
  | `input-rel-permission` | small | 2.16 (0.20) / 2.01 (0.22) | 3.93× | pass |
  | `input-rel-permission` | large | 2.48 (0.20) / 3.08 (0.25) | 4.61× | pass |

  (`default` / `read_only_connection` where two ratios are given.) Plans:
  `input-selective` walks `articles_pkey` (1 509 buffers at `small`, 15 080
  at `large`) where Hasura uses a bitmap scan on `articles_author_id_index`
  (7 and 9); `input-pk` scans `articles` sequentially (1 234 and 12 421
  buffers) for a handful of rows, where Hasura uses `articles_pkey` (3 and
  4); `input-rel-permission` repeats the relationship permission inside the
  `CASE`, once per candidate row. At `small`, `input-selective`'s DB-time
  verdict is `fail` in `default` and inconclusive on CV in
  `read_only_connection`; `input-pk`'s DB time fails in `default` at both
  scales and at `large` in `read_only_connection`.
- **Class:** `plan-shape` (causing the `db-time` and `buffers` failures).
- **Suspected cause:** the input fence,
  `permission AND (CASE WHEN permission THEN input ELSE false END)`, hides
  the input's column and selectivity from the planner; `input-pk` scans
  every permitted row.
- **Status:** owner decision P-H1 made and implemented as the opt-in
  `input_index_pushdown` (default `false`). With it on, `input-selective`
  (0.74× small, 0.65× large) and `input-pk` (0.64× small, 0.61× large) are
  faster than Hasura (DB-time verdicts inconclusive on CV at small, and for
  `input-pk` at large). With it off they remain the documented cost of the
  default fence (above). The `input-rel-permission` DB-time/buffer gap is
  closed for buffers by join-lift (see "relationship fence: after"); DB time
  passes where conclusive, with small default inconclusive. Its large-scale
  index target still fails. Unliftable permissions retain EXISTS SubPlans.
  `input-regex` is unchanged (regex is always fenced).

### preload-large-batch (default, read_only_connection): DB time at small

- **Scenario:** a preload over 1 000 parents.
- **Target:** DB time ≤ 1.25×.
- **Evidence (rerun):** `small` fails db_time in both modes: ratio 1.96
  (CV 0.12) in `default`, 2.52 (CV 0.11) in `read_only_connection`
  (4.471 / 8.782 ms and 2.407 / 6.073 ms), with fewer buffers (0.47×, 3 719
  vs 1 742). At `large` it passes: 0.33 (CV 0.22, inconclusive) in
  `default`, 0.31 (CV 0.13, pass) in `read_only_connection`; buffers 0.33×.
  Plans at `small`: Hasura uses a bitmap scan on `articles_org_id_index` for
  the root; Authzura walks `articles_pkey`.
- **Class:** `plan-shape` (generic vs custom plan).
- **Suspected cause:** Authzura's prepared statement runs on the generic
  plan, while Hasura inlines literals and gets a custom plan; the generic
  plan keeps the primary-key walk. Small scale only.
- **Status:** open.

### Harness review minors (harness)

Deferred from the Task 6 and Task 8 reviews; each has a test first where a
behaviour changes.

- The gate requires a row at every preload level, not just the root
  (`{:empty_level, path}`); `gate_test.exs` plants an empty level at depth
  1 and 3, a missing nested row and a column difference, through a `:run`
  that mirrors Authzura's rows, so they run without a Hasura.
- `Dataset.load!/3` refuses, before writing, a repo connected to any
  database but `authzura_bench` (`Env.check_connected!/1`); the seed and
  micro tasks lost their redundant `Env.check_database!/1` calls (the
  repos' `init/2` already checks the URL).
- The redundant `comments (article_id)` index is gone from the bench
  migration (see `preload-nested-3`).
- The `Dataset` moduledoc says what `:tiny` holds: the first 75 users have
  both memberships, the other 25 none (now tested).
- Dead code removed: `Dataset.tables/0`, `Metadata.roles/0`,
  `article_limit/0`, `comment_limit/0`.
- The report's Fairness section states the pool sizes (Authzura 10 per
  repo, Hasura's default 50) and why they do not bound a one-at-a-time
  measurement.
- Idioms: `Hasura.await_healthy/1` matches on the health result instead of
  `with`/`else`, `post/3` is a `do` block, `Micro` decodes a job in its own
  clause and groups runs with explicit functions, and `Micro.regressions/3`
  no longer lists the unreachable `{:skipped, :no_baseline}` (the task skips
  a missing baseline before comparing).
- **Status:** fixed in checkpoint `bench: harness fixes from the gap triage`.

## Single-statement preloads (later stage)

Evidence only, not a target: Hasura answers each preload scenario in one
statement (lateral joins plus in-database JSON), Authzura in `1 + L`
statements inside one `REPEATABLE READ, READ ONLY` transaction (3
transaction-control statements per request in both modes; pg_stat_statements
records the named `SET TRANSACTION` only on its first use per connection, so
the report shows 2).

| id | L | scale / mode | data H / A | DB ms H / A | ratio | buffers H / A |
|---|---|---|---|---|---|---|
| `preload-object` | 1 | small / default | 1 / 2 | 1.617 / 1.277 | 0.79 | 457 / 348 |
| `preload-object` | 1 | small / read_only_connection | 1 / 2 | 0.891 / 0.706 | 0.79 | 457 / 348 |
| `preload-object` | 1 | large / default | 1 / 2 | 0.952 / 0.835 | 0.88 | 1288 / 1185 |
| `preload-array-limited` | 1 | small / default | 1 / 2 | 0.892 / 0.337 | 0.38 | 305 / 242 |
| `preload-array-limited` | 1 | small / read_only_connection | 1 / 2 | 0.405 / 0.120 | 0.30 | 305 / 242 |
| `preload-array-limited` | 1 | large / default | 1 / 2 | 0.428 / 0.137 | 0.32 | 297 / 238 |
| `preload-nested-3` | 3 | small / default | 1 / 4 | 4.162 / 2.643 | 0.64 | 2338 / 2008 |
| `preload-nested-3` | 3 | small / read_only_connection | 1 / 4 | 2.370 / 1.113 | 0.47 | 2338 / 2008 |
| `preload-nested-3` | 3 | large / default | 1 / 4 | 2.221 / 1.473 | 0.66 | 3817 / 2918 |
| `preload-large-batch` | 1 | small / default | 1 / 2 | 4.471 / 8.782 | 1.96 | 3719 / 1742 |
| `preload-large-batch` | 1 | large / default | 1 / 2 | 2.677 / 0.870 | 0.33 | 3988 / 1302 |

Authzura's preloads use less database time and fewer buffers than Hasura's
single statement here, except `preload-large-batch` at `small` (more DB
time, fewer buffers; see its entry). That is database time only, not
"faster": Hasura's JSON building happens in SQL and is counted, while
Authzura's equivalent (Ecto decoding and stitching, about 4.9 ms next to
9.2 ms of statements for a 1 053-root nested read) is not, nor are round
trips (four or more per Authzura read against Hasura's one statement). A
single-statement preload would save the per-statement round trips, which
this benchmark does not measure.

### relationship fence: before

Baseline for the relationship-fence work, taken before any change to `lib/`.
`MIX_ENV=bench mix authzura.bench --scale <small|large> --mode <default|input_index_pushdown> --no-compose --only input-rel-permission,input-rel-broad-limit,input-col-broad-limit,input-regex`
(2026-11-15), `--requests 200` (the default), Postgres 18.6 and Hasura
v2.51.6 in local containers, seed 20261114. `REPORT.md` and `results/` were
restored afterwards: these figures are recorded here only. Medians in
DB ms per request; CV is that of the paired per-repetition ratios; buffers
are the summed shared buffers of the data statements (Hasura / Authzura).
The verdict column is the scenario's verdict (all targets), not the DB-time
verdict: a scenario that fails on buffers or indexes shows `fail` whatever
its DB time.
All four scenarios passed the parity gate in every run.

| scale | mode | scenario | Hasura ms | Authzura ms | ratio | CV | buffers H | buffers A | buffer ratio | verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| small | default | input-regex | 1.026 | 6.952 | 6.78 | 21.9% | 718 | 1405 | 1.96 | fail |
| small | default | input-rel-permission | 5.617 | 12.423 | 2.21 | 12.3% | 7672 | 30170 | 3.93 | fail |
| small | default | input-rel-broad-limit | 0.536 | 5.299 | 9.88 | 13.9% | 940 | 1571 | 1.67 | fail |
| small | default | input-col-broad-limit | 0.314 | 0.220 | 0.70 | 16.6% | 52 | 52 | 1.00 | inconclusive |
| small | input_index_pushdown | input-regex | 0.895 | 7.173 | 8.02 | 29.8% | 718 | 1405 | 1.96 | fail |
| small | input_index_pushdown | input-rel-permission | 9.993 | 16.771 | 1.68 | 13.9% | 7672 | 30170 | 3.93 | fail |
| small | input_index_pushdown | input-rel-broad-limit | 0.813 | 7.902 | 9.72 | 25.2% | 940 | 1571 | 1.67 | fail |
| small | input_index_pushdown | input-col-broad-limit | 0.327 | 0.332 | 1.02 | 24.2% | 52 | 52 | 1.00 | inconclusive |
| large | default | input-regex | 1.259 | 2.317 | 1.84 | 20.1% | 984 | 984 | 1.00 | inconclusive |
| large | default | input-rel-permission | 4.147 | 12.371 | 2.98 | 18.6% | 7447 | 34358 | 4.61 | fail |
| large | default | input-rel-broad-limit | 0.909 | 7.847 | 8.63 | 29.3% | 1368 | 13708 | 10.02 | fail |
| large | default | input-col-broad-limit | 0.379 | 0.341 | 0.90 | 17.4% | 53 | 53 | 1.00 | inconclusive |
| large | input_index_pushdown | input-regex | 1.466 | 2.521 | 1.72 | 21.4% | 984 | 984 | 1.00 | inconclusive |
| large | input_index_pushdown | input-rel-permission | 4.193 | 12.659 | 3.02 | 21.3% | 7447 | 34358 | 4.61 | fail |
| large | input_index_pushdown | input-rel-broad-limit | 0.850 | 5.722 | 6.73 | 28.0% | 1368 | 13708 | 10.02 | fail |
| large | input_index_pushdown | input-col-broad-limit | 0.352 | 0.280 | 0.80 | 22.4% | 53 | 53 | 1.00 | inconclusive |

`input-rel-broad-limit` before join-lift at small: Authzura seq-scanned
`articles` (the permission evaluated a second time), where Hasura read it
through `articles_pkey`; the `indexes` target failed there. At large both
read it through the index (Authzura twice), and the buffers were 10.02x.

Plan shape, small, `raw_plan` custom and generic: `input-rel-permission`
(organization 3, and organizations 1..40 in the regression test) does not
walk `comments_pkey`; `input-rel-broad-limit` and `input-col-broad-limit`
do. The buffer pin `input-rel-permission buffers are at most 1.5x Hasura's`
(`test/bench/hasura_regression_test.exs`) failed before join-lift: 3.93x at
small. It now passes at 1.00x (see the after entry). Most before DB-time CVs
are above 15 %, so those ratios are indicative.


### Relationship fence: estimate wrapper

- **Target:** eliminate primary-key-walk plans for lifted relationship input
  reads while keeping the CASE fence and paired broad-case DB-time ratios
  at or below 1.5× the unlifted control.
- **Evidence (Task 2, PostgreSQL 16.16, small scale only):** plain join-lift
  produced 8 of 40 primary-key-walk plans. Casting the fence with `::int = 1`
  regressed the broad and column-broad cases to 2.93× and 17.95× their
  respective controls. The selected wrapper produced 0 of 40 walks under
  both custom and generic plans; median paired DB-time ratios were 0.36×
  for `input-rel-broad-limit` and 1.12× for `input-col-broad-limit`.
- **Class:** `plan-shape`.
- **Confirmed cause:** the plain boolean CASE has a default selectivity of
  0.5, which can steer the lifted read into a primary-key walk. The selected
  wrapper provides a 10% estimate while preserving CASE evaluation:

  ```sql
  (CASE WHEN ... THEN ... ELSE false END)::int = ANY('{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}'::int[])
  ```

  The array contains twenty ones (`'{1 x20}'` in shorthand).
- **Scope:** fully lifted `all_input/4` reads only. Lifting is all-or-nothing
  per permission: any remaining relationship or `_exists` keeps the whole
  permission in its original EXISTS form, without the estimate wrapper.
  Partial lifting with this wrapper regressed to 2.15× in the spike, which
  is why it is excluded. `scope_input/4` and reads without a lift retain
  their original SQL.
- **Status:** shipped after the generated Ecto SQL passed the PG18 release
  gate below. The spike itself was PG16 small only; no PG17, PG18 or
  large-scale spike results are claimed. CI on PG18 is the version check.


### relationship fence: after

Postgres 18.6, Hasura v2.51.6, seed 20261114, `--requests 1000`, medians
from `REPORT.md` and `results/`. Ratios are Authzura / Hasura; verdicts
cover all targets. Before figures for relationship, broad, column-broad and
regex are in the 200-request entry above; selective/pk are in the earlier
input-fence entry. Only default and `input_index_pushdown` were remeasured
here; the report's `read_only_connection` entries predate join-lift.

| scale | mode | scenario | DB ratio | buffers (A / H) | verdict |
|---|---|---|---|---|---|
| small | default | input-regex | 7.51 | 1.97× | fail (buffers fail, db_time fail) |
| small | default | input-selective | 107.53 | 215.57× | fail (buffers fail, db_time inconclusive) |
| small | default | input-pk | 59.67 | 411.33× | fail (buffers fail, db_time inconclusive, indexes fail) |
| small | default | input-rel-permission | 0.98 | 1.00× | inconclusive (db_time inconclusive) |
| small | default | input-rel-broad-limit | 3.59 | 9.64× | fail (buffers fail, db_time fail) |
| small | default | input-col-broad-limit | 0.75 | 1.00× | pass |
| small | input_index_pushdown | input-regex | 7.39 | 1.96× | fail (buffers fail, db_time fail) |
| small | input_index_pushdown | input-selective | 0.76 | 1.00× | inconclusive (db_time inconclusive) |
| small | input_index_pushdown | input-pk | 0.78 | 1.00× | inconclusive (db_time inconclusive) |
| small | input_index_pushdown | input-rel-permission | 1.02 | 1.00× | pass |
| small | input_index_pushdown | input-rel-broad-limit | 4.35 | 9.64× | fail (buffers fail, db_time inconclusive) |
| small | input_index_pushdown | input-col-broad-limit | 0.82 | 1.00× | pass |
| large | default | input-regex | 1.33 | 1.00× | fail (db_time fail) |
| large | default | input-selective | 1281.65 | 1675.56× | fail (buffers fail, db_time inconclusive) |
| large | default | input-pk | 559.11 | 3105.25× | fail (buffers fail, db_time inconclusive, indexes fail) |
| large | default | input-rel-permission | 1.14 | 1.00× | fail (indexes fail) |
| large | default | input-rel-broad-limit | 6.95 | 9.73× | fail (buffers fail, db_time fail) |
| large | default | input-col-broad-limit | 0.82 | 1.00× | pass |
| large | input_index_pushdown | input-regex | 1.36 | 1.00× | inconclusive (db_time inconclusive) |
| large | input_index_pushdown | input-selective | 0.80 | 1.00× | inconclusive (db_time inconclusive) |
| large | input_index_pushdown | input-pk | 0.75 | 1.00× | pass |
| large | input_index_pushdown | input-rel-permission | 0.97 | 1.00× | fail (db_time inconclusive, indexes fail) |
| large | input_index_pushdown | input-rel-broad-limit | 6.44 | 9.73× | fail (buffers fail, db_time inconclusive) |
| large | input_index_pushdown | input-col-broad-limit | 0.80 | 1.00× | pass |

- **input-rel-permission: buffer gap closed; DB time passes where conclusive.** Small default
  2.21x → 0.98x (CV 0.53, inconclusive), push-down 1.68x → 1.02x;
  buffers 3.93x → 1.00x. Large default 2.98x → 1.14x, push-down
  3.02x → 0.97x; buffers 4.61x → 1.00x. The large scenario still fails
  the index target: Authzura seq-scans `organizations` where Hasura uses
  `organizations_pkey`. The ≤ 1.5x buffer pin now passes at 1.00x.
- **input-rel-broad-limit: open, documented gap.** Small default
  9.88x → 3.59x, push-down 9.72x → 4.35x; buffers 1.67x → 9.64x.
  Large default 8.63x → 6.95x, push-down 6.73x → 6.44x; buffers
  10.02x → 9.73x. Still fails the 1.25x DB-time and 1.5x buffer targets.
  At small the lifted statement reads 9058 buffers against Hasura's 940:
  Hasura walks `comments_pkey` with early exit and evaluates permission
  lazily. DB time improved, including to 0.39–0.45x the unlifted control
  in the release gate; this gap is not fixed.
- **Unchanged SQL.** Column-broad has no relationship: 0.75/0.82x small,
  0.82/0.80x large (default/push-down), 1.00x buffers, pass. Regex,
  selective and pk also have no relationship; captured lifted/unlifted SQL
  is byte-identical. Their changes are run-to-run timing noise, not join-lift
  effects: regex small default 6.78x → 7.51x, 1.97x buffers; selective
  default 107.5x/215.6x buffers small, 1281.7x/1675.6x large; pk default
  59.7x/411.3x small, 559.1x/3105x large. Selective/pk with push-down are
  0.75–0.80x; regex is 7.39x small, 1.33–1.36x large. These input-fence
  gaps remain documented.

**Release gate: passed.** PG18, generated Ecto SQL captured with
`Measure.authzura_sql/2`, `join_lift: true` against `false`, interleaved,
5 rounds × 100 calls. Ratios below are lifted / unlifted DB time, not
Authzura / Hasura. A cell is borderline when 1.5 lies within its round-ratio
range; no cell was borderline.

| scenario | paired DB ratio | round range | buffers unlifted → lifted |
|---|---|---|---|
| input-rel-permission | 0.507 | 0.491–0.584 | 30220 → 7698 |
| input-rel-permission (push-down) | 0.470 | — | — |
| input-rel-broad-limit | 0.447 | 0.375–0.465 | — |
| input-rel-broad-limit (push-down) | 0.387 | — | — |
| input-col-broad-limit, input-regex, input-selective, input-pk | 0.99–1.01 | — | SQL identical |

Primary-key walks of `comments_pkey` across organizations 1..40:
`input-rel-permission` 0/40 custom and 0/40 generic, lifted and unlifted.
The broad-limit unlifted positive control walks 40/40 custom and generic;
lifted walks 40/40 custom, 0/40 generic, while retaining the 0.45x DB-time
result. The generic-plan caveat does not change the open Hasura comparison.

The estimate wrapper applies only to fully lifted `all_input/4` reads; any non-liftable
hop keeps the entire permission as EXISTS (no partial lifts). The CASE
re-checks the whole chain, never negated. `scope_input/4`, `scope/3`,
`filter_rows/3` and `all/3` retain byte-identical SQL. Rows are identical
lifted/unlifted, with sequences and pages equal under a total order.
No public switch; rollback is a release revert.

Task 6 hidden-row regression evidence is PG18 only, not proof for every plan;
these tests were not run on PG16/17. CI on PG18 is the version check. The estimate wrapper spike was
PG16 small only, distinct from this PG18 release gate.

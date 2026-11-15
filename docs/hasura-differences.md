# Differences from Hasura v2

Every known difference between Authzura and Hasura v2 (tested against
v2.51.6), and every known performance gap, with cause, evidence and possible
follow-ups. Sources: `docs/hasura-test-coverage.md` (Divergences, Out of
scope), `docs/guides/security.md`, `test/parity/reviewed_divergences.exs`,
[benchmark triage](https://github.com/agoodway/authzura/blob/main/bench/TRIAGE.md), `bench/REPORT.md`, `lib/authzura/error.ex`, `CHANGELOG.md`.
Numbers come from the bench rerun of 2026-11-15 (`--requests 1000`, seed
20261114, Postgres 18.6) unless stated. Section 2.1 records join-lift; the
other performance tables below retain the earlier baseline measurements.
Non-relationship input SQL is unchanged; current ratios are in
[benchmark triage](https://github.com/agoodway/authzura/blob/main/bench/TRIAGE.md).

"Fails closed" means the difference can only deny or error, never return a
row Hasura would not.

## 1. Behaviour differences

| # | Topic | Hasura | Authzura | Why | Fails closed |
|---|---|---|---|---|---|
| 1 | `session-cast-eager` (reviewed divergence) | Casts session values inside the SQL; a comparison Postgres folds away (`_and: [{_or: []}, {id: {_eq: X-Hasura-User-Id}}]`) never casts an uncastable value and returns no rows | Casts every session value a permission references before the query: `{:invalid_session_value, name, _}` | Found by the randomized differential; one rule for all values | Yes |
| 2 | `session-text-strict` (reviewed divergence) | Postgres casts `" 1"` to 1 and reads the array `{NULL,1}` as holding a NULL | Strict grammar (integer `[+-]?[0-9]+`, no unquoted NULL element): `{:invalid_session_value, _, _}` | Predictable parsing, no whitespace or NULL coercion (`Authzura.Adapters.Postgres.Values`) | Yes |
| 3 | `timestamptz` without an offset | Cast in the database session's `TimeZone` | Literal denied at load (`{:invalid_literal, {:invalid_value, "timestamptz"}}`), session value at request time; untrusted input reads it as UTC | Authzura cannot know the session `TimeZone` | Yes (policy text); input is UTC by definition |
| 4 | `select_by_pk` when the role cannot see the whole primary key, or the table has none | Rejects the metadata as inconsistent | The permission is denied at load: `{:select_by_pk_without_primary_key, missing}` | Same rule as Hasura, applied as a denial plus diagnostic | Yes |
| 5 | `computed_fields` in a select permission | Granted and returned | Grant ignored with a `:warning` diagnostic, rest of the permission enforced; computed fields are never returned. A filter that references one is denied | Computed fields are SQL functions, outside stage one | Yes (less is returned) |
| 6 | Predicates on `json` (not `jsonb`) columns | Rejects as inconsistent metadata, even with only `_is_null` | Permission denied. Untrusted input may test a visible `json` column with `_is_null` only | Matches Hasura's rejection | Yes |
| 7 | `where` on a nested selection (`articles(where: ...)`) | Filters the nested rows | `{:unsupported_query, {:preload, "articles"}}`: a preload takes columns, order and children only | A silent ignore would return more rows than asked; three rows in the coverage doc (`comparisons_test.exs:164,173,187`) | Yes |
| 8 | `_and` as one object (`_and: {a: ..., b: ...}`) | GraphQL coerces the object to a one-element list | `{:invalid_input, [{["_and"], :invalid_expression}]}`; send a list | JSON input has no GraphQL list coercion (`comparisons_test.exs:148`) | Yes |
| 9 | Column comparison operators (`_ceq`, `_cgt`, `$` root reference) | Supported | Permission denied, `:forbidden` (`row_filters_test.exs:316`, `operators_test.exs:121`) | Not in the stage-one operator set | Yes |
| 10 | Relationship in a user `where` (#6931) | Applied with the target's permission | Rejected as `:relationship_in_input`, including `{articles: {}}`; input `order_by` takes columns only | A relationship-shaped key reads the same whether it names a relationship, a hidden column or nothing | Yes |
| 11 | Object relationship matching two rows | Returns one of them | `{:unsupported_query, {:object_cardinality, "author"}}` | No arbitrary row is picked | Yes |
| 12 | Input fence | No fence: the user filter is a plain `WHERE`, so evaluation order is Postgres's choice | `permission AND (CASE WHEN permission THEN input ELSE false END)`; known run-time refusals (patterns, out-of-range values) are checked before the read | Input must never run on rows the role cannot see, or errors and timing leak hidden rows | Yes; the cost is plan shape, see section 2 |
| 13 | Opt-in `input_index_pushdown` | n/a | Adds hoisted `_eq` and `_in` (at most 100 values) conjuncts on leakproof plain columns outside the fence | Index use for selective inputs; rows returned are identical with it on or off | Rows yes; adds a timing channel, see section 3 |
| 14 | `get/4` | `<table>_by_pk` | Key equality is pinned as `column OPERATOR(pg_catalog.=) $1` (a `citext` key uses the extension's schema-qualified `=`, refused if the schema cannot be resolved), sits beside the permission rather than behind the fence, and has no fence at all | A user-defined operator on a column or operand type must never be chosen (hidden-row error oracle) | Rows yes; `get/4` keeps the timing channel |
| 15 | Extension-type columns (PostGIS `geography`/`geometry`, ...) | Always in the default selection | Default projection depends on the repo: the column is selected when the repo's Postgrex types module has an extension for the type (the decode probe asks the module, no query), left out otherwise; name it in `columns:`. A value Postgrex cannot decode is `{:unsupported_column_type, column}`. Such columns are not comparable or orderable | A selected value the repo cannot decode would drop the connection | Yes (fewer columns, or an error) |
| 16 | PostGIS output and operators (`_st_*`, spatial `boolexp`) | Supported | Not supported: spatial filters denied, no PostGIS-specific output. Ported-test rows `user_can_query_geometry_values_filter*.yaml` and `boolexp/{ltree,postgis,raster}/` are out of scope | A PostGIS spec and plan exist; not built | Yes |
| 17 | Admin from JWT | An allowed JWT role named `admin` is admin | Admin only for the configured `admin_role` | Role names in a token do not grant admin | Yes |
| 18 | Out-of-scope features | Aggregates, writes, inherited roles, remote relationships, tracked SQL functions, jsonpath, `_cast`, other backends | Denied with a diagnostic, or not exposed (the API only reads) | Stage one is select permissions on Postgres; see `docs/hasura-test-coverage.md` "Out of scope" | Yes |
| 19 | Input limits | None of these | `_in`/`_nin` lists 10,000, 16 pattern operands, 32 `order_by` terms, filter depth 8 and 100 nodes, input preload 2 levels and 8 nodes; regex/`SIMILAR TO` backreferences refused; pattern reads under `input_pattern_timeout` (default 5 s) | Bound request cost | Yes |

### Error shapes

Hasura answers a failure with a GraphQL error (codes such as `not-found`,
`validation-failed`, `access-denied`, `data-exception`, `invalid-jwt`).
Authzura returns `{:error, reason}`, never raises for an expected failure,
and never returns partial rows. A denial is a value to map to 403 or 404.
Unknown and forbidden look the same on purpose.

| Hasura code | Authzura reason |
|---|---|
| `not-found` | `{:missing_session_variable, _}` |
| `validation-failed` | `{:forbidden_columns, _}`, `:forbidden`, `:root_field_disabled` |
| `access-denied` | `{:invalid_session, :role_not_allowed, _}` |
| `data-exception` | `{:invalid_session_value, _, _}` |
| `invalid-jwt`, `jwt-missing-role-claims`, `jwt-invalid-claims` | `{:invalid_jwt, _}`, `{:jwt_missing_role_claims, _}`, `{:jwt_invalid_claims, _}` |

The pairing is deliberately coarse. Behaviours Hasura accepts that Authzura
turns into a denial or error: items 1-11, 14 (invalid key), 15, 16 above;
the rest of the catalog (`:not_ready`, `:stale_permissions`,
`{:unsupported_query, _}`, `{:invalid_input, _}`) has no Hasura counterpart.

## 2. Performance gaps vs Hasura (DB time)

Database time only: `pg_stat_statements` planning plus execution, one engine
at a time. Target: at most 1.25x Hasura's, decided only when both CV are at
most 15 %. "Less DB time" is not "faster": Ecto decoding, preload stitching
and round trips are outside the figures, while Hasura's in-SQL JSON building
is inside them.

### 2.1 Relationship permissions with input: join-lift and remaining gaps

Scenario `input-rel-permission`: an input `_like` under the three-hop
relationship permission. Before join-lift, the outer `EXISTS` became a
semi-join, but its copy inside `CASE` ran as a correlated SubPlan per
candidate row. Join-lift removes that second EXISTS evaluation.

| Scale | Mode | DB ratio before → after | Buffers (A / H) before → after | After verdict |
|---|---|---|---|---|
| small | default | 2.21 → 0.98 | 3.93x → 1.00x | inconclusive (CV 0.53) |
| small | input_index_pushdown | 1.68 → 1.02 | 3.93x → 1.00x | pass |
| large | default | 2.98 → 1.14 | 4.61x → 1.00x | fail (indexes) |
| large | input_index_pushdown | 3.02 → 0.97 | 4.61x → 1.00x | fail (indexes) |

Before: 200 requests; after: 1000, medians, Postgres 18.6, Hasura v2.51.6,
seed 20261114. The `input-rel-permission` buffer gap is closed at both
scales, and its DB-time target passes where conclusive. Small default DB
time is inconclusive; at large the index target still fails:
Authzura still seq-scans `organizations` where Hasura uses `organizations_pkey`.

**Join-lift and estimate wrapper.** Only `all_input/4` (`:execute` mode) lifts a fully
liftable permission into inner joins, all-or-nothing. Each object hop must
map onto the whole introspected unique, non-deferrable, valid primary key,
with no inheritance target (partitioned tables may qualify). Mapping pairs
must be lossless: integer-family pairs or same-type collation-free pairs
such as UUID; domains resolve to their base type. The optional
`c:Authzura.Adapter.lossless_join_pair?/2` callback certifies pairs (absent:
no join-lift), and `Authzura.Model.Table.strict_key?` records key strictness.
At most seven joins and the alias budget may be used.

The positive permission conjunct and `CASE` fence remain. The `WHEN`
re-checks every mapping equality and target condition in the whole chain,
never negated. Fully lifted reads use the 10% estimate wrapper
`(CASE WHEN ? THEN ? ELSE false END)::int = ANY('{1 x20}'::int[])`
(array shorthand: twenty ones) to avoid primary-key walks for
`input-rel-permission`. Lifted and unlifted reads return identical row sets;
sequences and pages match under a total order.

**Still SubPlan/EXISTS.** Any non-liftable hop keeps the entire permission
unlifted: no partial lifts. This includes `_or`/`_not`, `_exists`, array
relationships/arrays, non-strict keys, lossy pairs and text-family or
nondeterministic-collation pairs. `scope_input/4`, `scope/3`, `filter_rows/3`
and `all/3` are not lifted and retain byte-identical SQL. There is no public
switch; rollback is a release revert.

**Broad-limit remains open.** `input-rel-broad-limit` improves from
9.88/9.72x to 3.59/4.35x at small (default/push-down), and from 8.63/6.73x
to 6.95/6.44x at large. Buffers **rise** from 1.67x to 9.64x at small
(lifted 9072 vs unlifted 1585 buffers in the paired comparison): a regression
and the cost of lifting broad reads, still a remaining gap. Large buffers
fall from 10.02x to 9.73x. It still fails the 1.25x DB-time and 1.5x buffer
targets: about 9000 buffers against Hasura's 940 at small. Hasura walks
`comments_pkey`, exits early and evaluates the permission lazily.

**Release gate.** Generated Ecto SQL on PG18 passed the paired lifted/unlifted
gate (5 rounds × 100 calls): `input-rel-permission` 0.507x
(range 0.491–0.584), buffers 30220 → 7698; broad-limit 0.447x
(0.375–0.465), push-down 0.387x. No borderline cell. Across organizations
1..40, rel-permission walks `comments_pkey` 0/40 under custom and generic
plans, lifted or unlifted. Broad-limit's unlifted control walks 40/40 in
both regimes; lifted walks 40/40 custom, 0/40 generic. The buffer pin now
passes at 1.00x. Column-broad, regex, selective and pk SQL is identical
lifted/unlifted (paired ratios 0.99–1.01); their timing changes are run noise.
Hidden-row evidence is PG18 only, with CI on PG18 as the version check;
these tests were not run on PG16/17. This is regression evidence, not proof
for every plan. The 10% estimate wrapper spike was PG16 small only.
Deferred work includes the broad-limit gap, text-pair lifting, array
relationships unique through an index, and PG17/PG18/large-scale spike
measurements. Full measurements: [benchmark triage](https://github.com/agoodway/authzura/blob/main/bench/TRIAGE.md).

### 2.2 Fenced selective and primary-key inputs without push-down

Scenarios `input-selective` (input on `author_id`) and `input-pk` (a
primary-key list through the input path). Cause: the `CASE` hides the
input's column and selectivity from the planner, so Authzura walks
`articles_pkey` or scans `articles` where Hasura uses an index.

| Scenario | Scale | default | read_only_connection | Buffers (A / H) | input_index_pushdown |
|---|---|---|---|---|---|
| `input-selective` | small | 60.71 (CV 0.15) | 120.85 (0.18) | 215.57x / 150.90x | 0.74 (0.41) |
| `input-selective` | large | 849.83 (0.50) | 1015.13 (0.23) | 1675.56x / 1256.67x | 0.65 (0.09) |
| `input-pk` | small | 48.84 (0.13) | 62.12 (0.32) | 411.33x | 0.64 (0.28) |
| `input-pk` | large | 509.21 (0.11) | 281.14 (0.13) | 3105.25x | 0.61 (0.36) |

Plans: `input-selective` at small reads 1509 buffers (`articles_pkey`) against
Hasura's 7, with push-down 7 / 7; `input-pk` at small scans `articles`
(1234 buffers) against Hasura's 3 (`articles_pkey`). Fix: opt-in
`input_index_pushdown` (default `false`), which trades a timing side channel
(section 3). With it on, DB-time verdicts are pass or inconclusive on CV.
Without it, this is the documented cost of the default fence.

### 2.3 `input-regex`

| Scale | default | read_only_connection | input_index_pushdown | Buffers (A / H) |
|---|---|---|---|---|
| small | 5.61 (CV 0.20) | 7.04 (0.31) | 8.08 (0.10) | 1405 / 715 (1.97x) |
| large | 1.29 (0.19) | 0.73 (0.25) | 1.39 (0.04) | 984 / 984 (1.00x) |

Cause: the planner gives the `CASE` its default boolean selectivity of 0.5
(513 rows estimated against the real 1,027 for organization 3), expects the
`LIMIT 100` early in `articles_pkey` order, and scans far more than Hasura's
bitmap scan on `articles_org_id_index`, which sees the bare predicate (114
rows estimated). Regex is always fenced, so push-down does not change it. At
large both engines choose the bitmap scan and no target fails except
`input_index_pushdown` DB time (1.39, CV 0.04). Status: documented gap, the
fence stays (owner ruling). Join-lift does not apply: this permission has
no relationship, and its captured SQL is unchanged.

### 2.4 `preload-large-batch` at small

| Scale / mode | DB ms (H / A) | Ratio | Buffers (H / A) |
|---|---|---|---|
| small / default | 4.471 / 8.782 | 1.96 (CV 0.12) | 3719 / 1742 |
| small / read_only_connection | 2.407 / 6.073 | 2.52 (0.11) | 3719 / 1742 |
| large / default | 2.677 / 0.870 | 0.33 | 3988 / 1302 |

Cause (suspected): Authzura's prepared statement runs on the generic plan,
which keeps the `articles_pkey` walk; Hasura inlines literals and gets a custom
plan with a bitmap scan on `articles_org_id_index`. Large passes. Status: open.
Possible follow-up: check whether a custom plan (or a different statement
shape for the root of a large batch) removes the walk.

### 2.5 `preload-nested-3`, `organizations` sequential scan (large)

At large the index target fails in both modes: `users` is read through
`users_pkey` (the earlier seq scan was a measurement artifact, fixed in the
harness), but `organizations` (1,000 rows) stays a sequential scan where
Hasura uses `organizations_pkey`. A planner choice: a hash join over a small
table is cheaper for the batched `unnest` join. DB ratio 0.66 (CV 0.04) and
0.60 (0.14) at large, buffers 0.76x, so no time cost. With sequential scans
priced out the level reads `organizations_pkey`; no plan is forced.

### 2.6 Per-read transaction and `read_only: :connection`

By default each read runs in a transaction with `SET TRANSACTION READ ONLY`;
preload reads use `REPEATABLE READ, READ ONLY`. Library overhead beyond the
database statements (`mix authzura.bench.micro`, report-only, about +-40 %
between runs):

| Scenario | Overhead (median) |
|---|---|
| flat-tenant (1 statement) | about 0.5-0.85 ms (up to 3.4 ms in a fresh container) |
| preload-nested-3 (1 root + 3 preloads) | about 0.95-1.25 ms (up to 3.6 ms) |
| pure in-process work (scope build, input parse, tree validation) | 3-7 microseconds each |

Recorded against a local Postgres 17 instead of the Docker Postgres 18:
0.12 ms and 0.58 ms. Opt-in `read_only: :connection` removes the transaction
for reads without preloads (zero transaction-control statements); preload
reads keep theirs by design. It moves the read-only guarantee to the
connection's configuration (see the Security guide).

### 2.7 Statement counts

| | Hasura | Authzura |
|---|---|---|
| Data statements for L preload nodes | 1 (lateral joins plus in-database JSON) | exactly `1 + L`, in one `REPEATABLE READ, READ ONLY` transaction |
| Round trips | 1 | four or more for `preload-nested-3` |

`1 + L` holds in all 17 scenarios, both modes, both scales. Authzura's
preloads use less DB time and fewer buffers than Hasura's single statement
(0.30-0.88x) except `preload-large-batch` at small. The round trips and
Ecto decoding and stitching (about 4.9 ms next to 9.2 ms of statements for a
1,053-root nested read, performance audit M3) are not in the DB-time figures.
Possible follow-up: single-statement preloads (later stage).

### 2.8 Measurement caveats

- DB time only; Hasura's HTTP and GraphQL work is excluded and its in-SQL
  JSON building is included.
- Docker Desktop noise: 17 scenarios per row; inconclusive on CV above 15 %
  is 3 (small default), 9 (small read_only_connection), 7 (large default), 9
  (large read_only_connection). Statements take 0.05-1 ms, so jitter is of the
  order of the difference; where ratios are near the limit (`columns-narrow`
  up to 1.27, `rel-filter-3hop` up to 1.19) plans and buffers are identical on
  both engines. The CV rule is not relaxed.
- `pg_stat_statements` records Authzura's named (cached) `SET TRANSACTION`
  only on its first use per connection, so reports show 2 transaction-control
  statements per preload read where 3 run (confirmed with `log_statement=all`).
- Plans: Authzura's are explained as the steady state runs them (prepared,
  executed five times, `EXPLAIN` of `EXECUTE`: generic); Hasura's come from
  its explain endpoint, which inlines values (custom).
- Pools: Authzura 10 connections, Hasura up to 50; requests are sent one at a
  time, 6 warm-up requests per pool connection; the CV is that of the paired
  per-repetition ratios.
- One run per scale and mode. Verdicts, pass / fail / inconclusive: small
  default 9 / 5 / 3, small read_only_connection 3 / 5 / 9, large default
  6 / 4 / 7, large read_only_connection 4 / 4 / 9, small input_index_pushdown
  9 / 3 / 5, large input_index_pushdown 8 / 3 / 6.

## 3. Security trade-offs accepted

| Trade-off | What it is | Bound |
|---|---|---|
| Timing channel with `input_index_pushdown` on | A leakproof comparison cannot raise or reveal its operand but may run on rows the role cannot see; with an index, read time can reveal whether hidden rows carry a value (and, with AND-ed comparisons, which also match another column). The class Postgres accepts for leakproof quals ahead of a `security_barrier` view or row-level security; `get/4` already has it | Off by default; instance option, never from request input; rate limiting is the consumer's job. Security review found it wider than first documented: a 10,000-value `_in` was a range probe (4.2-5.0 ms when all ids exist against 0.8-1.1 ms when none do, option on; indistinguishable off), hence the cap |
| `_in` at most 100 values in push-down | Bounds the signal of one request; does not remove the channel | Longer lists stay fenced |
| Trusted caller predicates in `scope/3`, `all/3`, `one/3` | A `where` you write is not fenced; Postgres may run it on hidden rows, so an error or its time can reveal them. `invalid_escape_sequence` and `invalid_regular_expression` map to `{:invalid_input, :rejected_by_database}`, which is such a signal | Put user-controlled filters in `scope_input/4` or `all_input/4` |
| Stale generation after owner DDL | A generation loaded before a DDL change keeps its push-down decisions (leakproof result, table kind) until the next reload | The fingerprint covers `relkind` and the leakproof result; a poll or `Authzura.reload/1` reloads; `max_staleness` (default 60 s) bounds it. Revocation has the same bound, indefinite with `:infinity` |
| Plan-shape cost of the fence | Section 2 | Owner ruling: the fence stays |
| No row cap yet | A role without a permission `limit` can read a whole table plus every preload level | Set permission limits, cap request bodies, set a `statement_timeout` |

## 4. Follow-up candidates

In priority order.

1. **Relationship broad-limit and fallback permissions** (2.1): join-lift
   closes the `input-rel-permission` buffer gap; DB time passes where
   conclusive (small default inconclusive, large index target still failing).
   Broad-limit still costs
   3.59-6.95x DB time and 9.64-9.73x buffers; non-liftable permissions keep
   their EXISTS SubPlans. Any follow-up must preserve the CASE guarantee.
2. **PostGIS** (rows 15-16): output and `_st_*` operators; a spec and plan
   exist. Today it is deny or omit.
3. **PgRest `authorize_query/5` example adapter**, when PgRest ships it
   (PgRest 0.2 is unreleased; the planned callback can deny, return a
   predicate query, or set `columns:`, `limit:` per parent, `aggregates:` and
   `count:`). The example gate must fail closed on unknown AST node kinds.
4. **Ranges and whole-`_or` push-down**: `_gt`, `_lt`, `_gte`, `_lte`, `_neq`,
   `_nin`, `_is_null`, `_or` and `_not` are fenced today (index use for range
   scans).
5. **More binder types** (money, inet, interval, ...): push-down is limited
   to the types Postgres marks leakproof; other types stay fenced.
6. **`preload-large-batch` at small** (2.4) and single-statement preloads
   (2.7): plan choice and round trips.
7. **Column comparison operators, nested-selection `where`, `_and` object
   form** (rows 7-9): the remaining over-denials; each fails closed.

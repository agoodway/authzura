# Authzura Relationship-Permission Fence Implementation Plan

## As shipped (2026-11-15)

This section supersedes the original proposals below wherever they differ.

- The optional `c:Authzura.Adapter.lossless_join_pair?/2` callback certifies mapping
  pairs; an adapter without it never lifts. Postgres allows integer-family pairs
  and same-type collation-free numeric, float, UUID, enum, timestamp, date and
  boolean pairs. Domains resolve to their base type. Text-family pairs, including
  text/varchar, stay EXISTS because introspection does not capture their collation.
- Lifting is all-or-nothing: any remaining relationship or `_exists` makes the
  whole permission use the original EXISTS SQL. No child EXISTS is correlated
  to a lifted alias. The returned lift contains only `joins` and `condition`.
- Fully lifted reads use `::int = ANY('{1 x20}'::int[])` (twenty ones), a 10%
  estimate. The ten-one, approximately 5% candidate was not the shipped choice.
- The estimate spike ran on PG16 at small scale only. PG17, PG18 and large-scale
  spike measurements remain deferred. The release gate is **Task 8**, on captured
  Ecto SQL on **PG18 only**. Hidden-row regression evidence is also PG18 only;
  it was not run on PG16/17. There is no version-matrix test tag. This is evidence,
  not proof for every plan.
- `input-rel-permission` buffers reach 1.00x Hasura at both scales; small default
  DB time is inconclusive and the large index target still fails. Broad-limit
  remains a gap: small buffers regress from 1.67x to 9.64x despite lower DB time.
  Text-pair lifting and array relationships unique through an index are deferred.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the `input-rel-permission` gap (2-3.4x Hasura) by compiling liftable relationship chains in the permission as inner joins ("join-lift") on `all_input/4` reads. The input fence stays and gets a measured estimate shape, and the set of rows does not change.

**Architecture:**
- Introspection marks the tables whose primary key is strictly unique.
- `Authzura.Compiler.lift/3` turns each relationship node that passes the spec's five rules into a join spec plus a flat condition. Everything else goes through today's `compile/2`, unchanged.
- `Authzura.Scope` appends the joins and uses the lifted `P` in both places of the fence. It does this only in `:execute` mode with an input filter, which is exactly `all_input/4`.
- The estimate wrapper is the one Task 2 rules on, implemented in one function.

**Tech Stack:** Elixir 1.19 / OTP 28, Ecto SQL 3.13, Postgrex and StreamData. Postgres 18 in CI and the release gate; PG16 small only for the estimate spike. `hasura/graphql-engine:v2.51.6` for the differential and the bench.

**Spec:** `docs/superpowers/specs/2026-11-15-authzura-relationship-fence-design.md`. Evidence: internal investigation notes (not in the repo). If a task and the spec conflict, the spec wins. Flag the conflict.

**Execution notes.**
- **Models.** Sonnet implements each task. Opus reviews each task, then the whole branch at the end. Haiku does mechanical edits: doc ticks, CHANGELOG lines, renames.
- **Fable.** One security pass, only if a reviewer doubts the guarantee argument (spec, "Guarantee rule").
- **Ledger.** internal investigation notes (not in the repo). Record each ruling there with its "cost if wrong".
- **Open decisions.** The spec's open decisions are taken at their recommendations unless the owner rules otherwise before Task 4.

## Original implementation checklist

The checklist records the original task sequence, not claims that every proposed
measurement ran. The as-shipped scope above controls the release record.

## Global Constraints

- **Row contract.** Lifted and unlifted reads return the same set of rows. They return the same sequence only under a total order (the `order_by` ends in a unique key). With ties or no order the sequence is unspecified, as today. This holds with `input_index_pushdown` off and on.
- **The fence stays:** `P AND [pushdown AND] <wrapper>(CASE WHEN P THEN input ELSE false END)`, with the lifted `P` in both places. Outside the fence there are only `P` and the hoisted leakproof conjuncts, which is the documented push-down exception.
- **Lift only on the fenced execute path.**
  - `Scope.build/4` lifts only when `mode: :execute`, `input_filter` is set, and the internal `join_lift` is not `false` (default `true`). The budget is `max(7 - length(query.joins), 0)`.
  - These are unchanged byte for byte: `scope/3`, `filter_rows/3`, `all/3`, `one/3`, `get/4`, `scope_input/4`, preload statements and combination branches.
  - `Input.bare_root/1` stays the reason no caller join or union reaches `all_input/4`.
- **Lift rules** (spec rules 1-5):
  1. `_and` only;
  2. `:object` only;
  3. remote columns = primary key, with `Table.strict_key?` (not deferrable, no inheritance children unless partitioned);
  4. adapter-certified lossless pairs (integer family or same-type collation-free pairs; domains resolve to base type; text-family pairs stay EXISTS);
  5. at most 7 joins and unique aliases. Over either limit, lift nothing.
- **Fallback is byte-identical.** A permission with nothing to lift compiles exactly as today. The estimate wrapper applies only to fully lifted reads.
- **No new public option, reason or return value.** Rollback is a release revert.
- **Never trade a security check for speed.** These stay:
  - `SET TRANSACTION READ ONLY`;
  - `REPEATABLE READ` for preloads;
  - the fence;
  - the pattern pre-check;
  - prefix pinning;
  - the alias, depth and node limits.
- **Evidence, not proof.** Planner-setting and version matrices are regression evidence. The guarantee rests on the `CASE` argument in the spec.
- **CI.** Default `mix test` runs on PG18, as CI does. Hidden-row tests were not run on PG16/17; no version-matrix tag is shipped. No new workflow, and no scheduled CI.
- **Docker.** Pin tags, never `latest`. Bind ports to `127.0.0.1`. Remove containers after use. Never use host ports 5432 or 8080. `AUTHZURA_TEST_PORT=55432`.
- **Migrations** only via `mix ecto.gen.migration`, then fill in the body.
- **Public repo.** No private app, domain or local path. The README is untouched.
- **Owner Elixir style.**
  - `with` over nested `case`/`if`.
  - Head matching, binding and guards.
  - Pipes.
  - Grouped aliases.
  - No fully qualified calls in bodies.
  - Predicates end in `?`.
- **DRY.** Reuse `pair/4`, `descend/2`, `exists/2`, `compile/2` and the existing introspection queries. Never write a parallel compiler.
- **Quality gate.** `mix quality` passes at the end of every task.
- **Commits.** At a **Checkpoint**, leave the work in the working tree and stop with the suggested message. Never stage, commit, push or tag. No AI attribution.

## Review Focus

1. **A to-one join that can multiply rows.** Cases: a deferrable primary key, an inheritance parent, a `float8` local against a `bigint` key, a `citext` or `bpchar` pair. Expected: each stays `EXISTS`. Owner: Tasks 3 and 4.
2. **A nullable or partial-NULL FK in a lifted chain.** Cases: `editor`, `manager`, and `(org_id, user_id)` → `org_memberships`. Expected: the row is dropped, as the `EXISTS` drops it. Owner: Task 4 (SQL) and Task 7 (rows).
3. **A non-liftable node, or an alias reuse, inside a lifted level.** Cases: an array relationship or an `_or` under a lifted hop; siblings; `manager`; a nested `_exists`. Expected: a non-liftable node makes the entire permission fall back; fully lifted siblings use distinct aliases. Owner: Task 4.
4. **A probe that cannot fire.** Cases: parallel workers that never launched, JIT that never ran, a probe the planner folds away. Expected: each such setting fails its own evidence assertion instead of passing silently. Owner: Task 6.
5. **A good spike that is a bad Ecto statement.** Expected: Task 8 re-applies Task 2's criteria to the captured Ecto SQL, and a failure stops the release. Owner: Task 8.

---

## File Structure

```
bench/lib/authzura/bench/{metadata,scenarios,measure}.ex, bench/lib/mix/tasks/authzura.bench.seed.ex, test/bench/*_test.exs   (1, 8)
lib/authzura/adapters/postgres/introspection.ex, lib/authzura/model/table.ex, test/authzura/adapters/postgres/introspection_test.exs   (3)
lib/authzura/compiler.ex, test/authzura/compiler_lift_test.exs                                    (4)
lib/authzura/scope.ex, lib/authzura.ex (docs), test/integration/input_join_lift_test.exs          (5)
priv/test_migrations/<generated>_create_fence_guarantee_fixture.exs, test/integration/fence_guarantee_test.exs, test/test_helper.exs   (6)
test/property/metamorphic_test.exs, test/support/vacuity.ex                                      (7)
docs/hasura-differences.md, docs/guides/security.md, bench/{TRIAGE,REPORT}.md, bench/results/*.json, CHANGELOG.md   (2, 6, 8)
```

---

### Task 1: Bench scenarios, raw plans, database-only seeding and the "before" baseline

**Files:**
- Modify: `bench/lib/authzura/bench/metadata.ex`. Add the role `broad`:
  - on `articles`: `%{"status" => %{"_eq" => "published"}}`;
  - on `comments`: `%{"article" => %{"is_published" => %{"_eq" => true}}}`.
- Modify: `bench/lib/authzura/bench/scenarios.ex`. Add `with_org/2` and these scenarios:
  - `input-rel-broad-limit`: `broad`, comments `~w(id article_id body)`, `body _like "%7"`, `order_by: @by_id`, `limit: 100`;
  - `input-col-broad-limit`: `broad`, `articles(~w(id title), where: title _like "%7", limit: 100)`.
- Modify: `bench/lib/authzura/bench/measure.ex`. Add `raw_plan/3`, `authzura_sql/2` and `pk_walk?/2`.
- Modify: `bench/lib/mix/tasks/authzura.bench.seed.ex`. Add `--db-only`.
- Test: `test/bench/{scenarios,measure,regression}_test.exs`.

**Interfaces:**
- Produces:
  - `Scenarios.with_org(scenario, org_id) :: scenario`. It replaces `X-Hasura-Org-Id`.
  - `Measure.authzura_sql(scenario, opts) :: {sql :: String.t(), params :: list()}`. The root data statement as `all_input/4` runs it, captured through telemetry. `opts`: `:mode`, and `join_lift: boolean()` (Task 5 honours it; before that it is ignored).
  - `Measure.raw_plan({sql, params}, regime :: :custom | :generic, opts) :: map()`. Raw `EXPLAIN (FORMAT JSON[, ANALYZE, BUFFERS])` with node types kept.
    - `:custom` runs once, unnamed, with the parameters bound, which is how `all_input/4` runs uncached.
    - `:generic` runs under `SET LOCAL plan_cache_mode = force_generic_plan`.
  - `Measure.pk_walk?(plan :: map(), table :: String.t()) :: boolean()`. Start at the root `Limit` and follow the order-providing child (the first child of `Limit`, `Result`, `Nested Loop`, `Merge Join` or `Gather Merge`). It is true when that path reaches an `Index Scan` or `Index Only Scan` on `<table>_pkey` before any `Sort` or `Incremental Sort`.
  - `mix authzura.bench.seed --db-only`. It creates the database and the extension, runs the migrations, loads the dataset and runs `VACUUM (ANALYZE)`. It skips every Hasura step: start, guard and metadata.

- [ ] **Step 1: Write the failing tests.**
  - `scenarios_test.exs`: `test "the broad scenarios pass the gate"`.
  - `measure_test.exs`:
    - `pk_walk?/2` on hand-written plans: `Limit → Nested Loop → Index Scan comments_pkey` is `true`; `Limit → Sort → …` is `false`; and `Limit → Nested Loop(outer: Sort …, inner: Index Scan comments_pkey)` is `false`.
    - `test "--db-only never contacts Hasura"`: with the Hasura env vars unset, the option parser selects only the database steps.
  - `regression_test.exs` (`:bench`):
    - `test "deep plans no primary-key walk for orgs 1..40 (custom and generic)"`;
    - `test "input-rel-permission buffers are at most 1.5x Hasura's"`, using `Measure.buffer_ratio/1`.
- [ ] **Step 2:** Run `mix test test/bench/scenarios_test.exs test/bench/measure_test.exs`. Expected: FAIL.
- [ ] **Step 3:** Implement. Reuse `capture/2`, `parse_plan/1`'s traversal, `perm/4`, `scenario/3` and `articles/2`.
- [ ] **Step 4:** Run the tests above. Expected: PASS. Run `mix test --only bench test/bench/regression_test.exs` at small. Expected: the walk test PASSES, and the buffer pin FAILS (about 3.9x). Record that failure in the ledger as the "before" evidence.
- [ ] **Step 5: Baseline.**
  1. Back up `bench/REPORT.md` and `bench/results/`.
  2. Run `MIX_ENV=bench mix authzura.bench --scale <s> --mode <m> --only input-rel-permission,input-rel-broad-limit,input-col-broad-limit,input-regex` for small and large, in `default` and `input_index_pushdown` mode.
  3. Record the medians, CVs and buffers in a `bench/TRIAGE.md` entry, "relationship fence: before".
  4. Restore the backed-up files.
- [ ] **Step 6:** Run `mix quality`. Expected: PASS.
- [ ] **Step 7: Checkpoint.** `bench: add broad LIMIT scenarios, raw plans and database-only seeding`

---

### Task 2: Estimate-shape spike with matched controls, and the ruling (no `lib/` change)

**Files:**
- Scratch: internal investigation notes (not in the repo).
- Modify: `bench/TRIAGE.md` and the ledger.

**Interfaces:**
- Produces **estimate wrapper**:
  - `shape`: the exact wrapper text around `CASE WHEN ? THEN ? ELSE false END`;
  - `applies_to`: `:lifted` or `:all_fenced`;
  - or `:no_ship`, which stops the plan here.

- [ ] **Step 1: Containers.**
  - Start throwaway `postgres:16.16` and `postgres:17.12` on `127.0.0.1:55416` and `55417`, with `-c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track_planning=on`. Add `track_planning` to the bench PG 18 for the spike's duration.
  - Seed each at small and at large: `AUTHZURA_BENCH_DB_URL=… MIX_ENV=bench mix authzura.bench.seed --db-only --scale <s>`.
- [ ] **Step 2: Statements.** For each case, write today's unlifted SQL (the **control**) and the lifted SQL in each wrapper: plain `CASE`, `::int = 1`, `::int = ANY('{1,…×10}')`, and any better candidate, with the reason it was tried. The cases:
  - selective: `input-rel-permission`;
  - broad: `input-rel-broad-limit` and `input-col-broad-limit`;
  - zero-match: `body _like "%zzz"`;
  - partial lift: the deep chain plus an array-relationship `EXISTS` at the article level;
  - `input-regex`;
  - a push-down variant of each relationship case: the input adds `author_id _eq`, and the statement carries the hoisted conjunct.
- [ ] **Step 3: Measure.** In every cell (version × scale × push-down), run 5 rounds. Each round interleaves the control and every candidate, 100 calls each.
  - **Ratios.** Compute the paired ratio (candidate / control) per round, then the median and the CV of those ratios.
  - **Reruns.** A cell whose CV is above 15 % is rerun, at most 3 times.
  - **Borderline.** If 1.5 lies within the range of the round ratios after the reruns, the cell is borderline, and borderline counts as a fail.
  - **Plans.** Count the primary-key walks for orgs 1..40 with `Measure.pk_walk?/2`, under custom and generic plans.
  - **Hidden-row check.** Run the investigation's check for each wrapper, on each version.
- [ ] **Step 4: Rule.** The winner must meet all three criteria:
  1. 0 of 40 primary-key walks, in every cell and both regimes;
  2. a median paired ratio of at most 1.5x, with no borderline fail, on both broad cases;
  3. `input-regex` no worse than its control.

  `:all_fenced` applies only if `input-col-broad-limit` meets criterion 2 under today's unlifted fence, and `input-regex` improves in every cell. If no candidate meets criteria 1 and 2, the ruling is `:no_ship`: stop and report.

  Write the ruling and its tables to `bench/TRIAGE.md` and the ledger. Remove the containers.
- [ ] **Step 5: Checkpoint.** `docs: record the relationship-fence estimate ruling`. The Opus reviewer checks that every cell has its control and that the borderline rule was applied.

---

### Task 3: Introspection marks strictly unique keys

**Files:**
- Modify:
  - `lib/authzura/adapters/postgres/introspection.ex`: `@primary_keys_sql`, the fingerprint SQL and `put_primary_keys/2`.
  - `lib/authzura/model/table.ex`: the field `strict_key?: boolean()`, default `false`, documented.
- Test: `test/authzura/adapters/postgres/introspection_test.exs`, `test/integration/fingerprint_test.exs`.

**Interfaces:**
- Produces: `Table.strict_key?` is `true` iff the table has a primary key, `NOT condeferrable`, and either `NOT relhassubclass` or `relkind = 'p'`.

- [ ] **Step 1: Write the failing tests.** Each test creates its tables in the sandbox:
  - `test "a plain primary key is strict"`;
  - `test "a DEFERRABLE primary key is not strict"`;
  - `test "an inheritance parent is not strict"`;
  - `test "a partitioned table's key is strict"`;
  - `test "a view has no strict key"`;
  - in `fingerprint_test.exs`: `test "making a key deferrable or adding an inheritance child changes the fingerprint"`.
- [ ] **Step 2:** Run the two files. Expected: FAIL.
- [ ] **Step 3:** Implement by extending the existing queries; add no new round trip.
- [ ] **Step 4:** Run `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: record strictly unique primary keys in introspection`

---

### Task 4: `Compiler.lift/3`

**Files:**
- Modify: `lib/authzura/compiler.ex`.
- Test: `test/authzura/compiler_lift_test.exs`.

**Interfaces:**
- Consumes: `Table.strict_key?` (Task 3), and `Column.pg_type`.
- Produces:
  - `@type join :: %{source: Table.table_ref(), binding: atom(), on: Query.dynamic_expr()}`;
  - `@type lifted :: %{joins: [join()], condition: Query.dynamic_expr()}`;
  - `lift(AST.t(), ctx(), budget :: non_neg_integer()) :: {:ok, lifted()} | {:error, reason()}`. With no lifts, `joins == []` and `condition` is exactly `compile/2`'s output.
  - `lift_public/3`, which applies `public_reason/1`, as `compile_public/2` does.
- Approach:
  - Collect the liftable nodes in tree order under rules 1-5. Lift nothing if the count exceeds `budget` or seven joins; the seven-join cap fits the alias pool.
  - Lifted join `i` binds `Aliases.at(i)`; any non-lifted `EXISTS` makes the whole permission fall back.
  - Rule 4 uses the optional adapter callback `lossless_join_pair?/2`; no callback means no lift. Postgres resolves domains to base type and rejects text-family pairs.
  - Generalize `correlation/3` to take `{:as, parent} | {:parent_as, parent}`.

- [ ] **Step 1: Write the failing tests** (`to_sql` on a query with the joins applied):
  - `test "an _and chain of object relationships onto strict keys lifts to inner joins"`: the deep chain gives 3 `INNER JOIN`s and no `exists(`;
  - `test "the condition re-checks every ON equality"`;
  - fallbacks, where `joins == []` and the SQL equals `compile/2`'s:
    - `test "under _or or _not"`;
    - `test "an array relationship"`;
    - `test "a manual mapping onto non-key columns"`;
    - `test "a view target"`;
    - `test "a deferrable key"`;
    - `test "an inheritance parent"`;
    - `test "a float8 local against a bigint key (9007199254740992 / 9007199254740993)"`;
    - `test "citext and bpchar pairs"`;
  - `test "integer-family pairs lift; text-family pairs fall back"`;
  - `test "a partitioned target lifts"`;
  - `test "nullable editor and composite org_memberships mappings lift"`;
  - `test "an array relationship under a candidate hop makes the whole permission fall back"`;
  - `test "siblings, manager and a nested _exists use distinct aliases"`;
  - `test "over budget (including budget 0) or over the alias pool, nothing lifts"`;
  - `test "admin and empty permissions lift nothing"`.
- [ ] **Step 2:** Run the file. Expected: FAIL.
- [ ] **Step 3:** Implement. Write `@doc` text for the five rules and the fallback contract, and add a moduledoc bullet.
- [ ] **Step 4:** Run `mix test test/authzura/compiler_lift_test.exs test/authzura/compiler_test.exs && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: compile liftable object-relationship chains as inner joins`

---

### Task 5: Wire join-lift and the estimate into `all_input/4`

**Files:**
- Modify:
  - `lib/authzura/scope.ex`: `filter/6`, `gated/4`, `fenced/3` and the `build/4` doc;
  - `lib/authzura.ex`: the `all_input/4` doc (joins, the row contract under ties, rollback = revert);
  - `bench/lib/authzura/bench/measure.ex`: pass `join_lift` through.
- Test: `test/integration/input_join_lift_test.exs`.

**Interfaces:**
- Consumes: `Compiler.lift_public/3`, estimate wrapper.
- Produces: the internal `Scope.build/4` option `join_lift: boolean()`. Tasks 6-8 use `Input.build/5` with `[mode: :execute, join_lift: false]` for today's statement.
- Approach:
  - `filter/6` computes the clamped budget, calls `lift_public/3`, and appends each join with `Ecto.Query.join/5` (`:inner`, the target with `prefix:`, `as: ^binding`, `on: ^on`).
  - `fenced(permission, input, lifted?)` applies the estimate wrapper, with a comment citing the TRIAGE entry.

- [ ] **Step 1: Write the failing tests.**
  - Public path (`all_input/4`):
    - `test "the deep permission is lifted: inner joins, no exists, one CASE WHEN"`;
    - `test "the CASE references every lifted alias"`;
    - `test "the estimate wrapper uses twenty ones"`;
    - `test "push-down on: the hoisted conjunct sits beside the lifted permission; same row set as push-down off"`;
    - `test "an order_by ending in id returns the same sequence lifted and unlifted"`;
    - `test "pages with a unique tiebreaker are equal lifted and unlifted"`;
    - `test "preloads on a lifted read return the same tree"`;
    - `test "a query with a join or a union is still {:invalid_input, :not_a_root}"`.
  - Unchanged entry points: `test "scope_input/4, scope/3, filter_rows/3 and all/3 SQL is unchanged"`.
  - Internal (`Scope.build/4` directly; label the `describe` "internal"):
    - `test "caller joins keep their positions and count against the budget"`;
    - `test "seven caller joins clamp the budget to zero"`.
- [ ] **Step 2:** Run the file. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `mix test && mix quality`. Expected: PASS. These stay unchanged and green: `input_pushdown_test.exs`, `input_pushdown_all_input_test.exs` and `preload_consistency_test.exs`.
- [ ] **Step 5: Checkpoint.** `perf: lift relationship permissions into joins on fenced input reads`

---

### Task 6: Hidden-row regression evidence across planner settings on PG18

**Files:**
- Create:
  - `priv/test_migrations/<generated>_create_fence_guarantee_fixture.exs` (generated with `mix ecto.gen.migration create_fence_guarantee_fixture`);
  - `test/integration/fence_guarantee_test.exs`.
- Modify: `test/test_helper.exs` and `docs/guides/security.md` (PG18-only regression evidence).

**Interfaces:**
- Consumes: `all_input/4`, and `Input.build/5` with `join_lift: false`.
- Fixture (committed, so parallel workers can read it):
  - **Tables.** Schema `fence_probe`: `organizations ← users ← articles ← comments`, plus `articles_part`, a hash-partitioned copy with `comments_part` pointing at it. Rows come from `generate_series`, several thousand comments, with NULL and dangling FKs. Visibility for org 3 is a pure function of the ids.
  - **Domain.** `comments.body` is `fence_probe.body_text`, a domain over `text`.
  - **Probe.** `fence_probe.guard(body text, pattern text) RETURNS boolean`, `IMMUTABLE STRICT PARALLEL SAFE`, not leakproof. It raises `'hidden row'` when `body` starts with `'H:'`, and otherwise returns `body LIKE pattern`. The seed writes `'H:'` on exactly the rows the test permission rejects.
  - **Operator.** `CREATE OPERATOR fence_probe.~~ (LEFTARG = fence_probe.body_text, RIGHTARG = varchar, FUNCTION = fence_probe.guard)`, placed so that Authzura's `LIKE` resolves to it.
  - The migration ends with `ANALYZE`.
- `@planner_settings`: the investigation's 14, plus `enable_memoize` off and on, plus:
  - `forced_parallel`: `debug_parallel_query = on`, parallel costs 0, `min_parallel_table_scan_size = 0`;
  - `forced_jit`: `jit = on`, `jit_above_cost = 0`, inlining and optimize costs 0.
- Mechanics: `all_input/4` with `in_transaction: true` inside a `Repo.transaction` that `SET LOCAL`s each setting. Generic plans use `plan_cache_mode = force_generic_plan`.

- [ ] **Step 1: Write the tests.**
  - `test "the probe operator is the one Authzura's LIKE resolves to"`. If Authzura refuses `_like` on the domain column at load, stop and report the smallest extension point; do not widen support.
  - `test "the probe fires on the unfenced statement under at least one setting"`, the vacuity check.
  - `test "parallel workers launched"` and `test "JIT ran"`. Use `EXPLAIN (ANALYZE, FORMAT JSON)`: `Workers Launched > 0`, and the `JIT` key present. If `pg_jit_available()` is false, the JIT cases are reported as skipped, never passed.
  - `test "lifted all_input never evaluates the input on a hidden row under any setting"`, for the deep chain, the all-or-nothing EXISTS fallback, the nullable chain and the partitioned chain, with push-down off and on (the input adds `author_id _eq`, which is hoisted).
  - `test "unlifted all_input never evaluates the input on a hidden row under any setting"`.
  - CI uses PG18; no version-matrix test tag is shipped.
- [ ] **Step 2:** Run `mix test test/integration/fence_guarantee_test.exs`. Expected: PASS on PG 18. A failing lifted test means Task 5 is wrong: stop and report.
- [ ] **Step 3: Version coverage.** Hidden-row regression evidence is PG18 only;
  PG16/17 were not run. No version-matrix tag is shipped.

- [ ] **Step 4:** Run `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `test: hidden-row regression evidence for the lifted fence across planner settings`. If the reviewer doubts the argument, schedule the Fable pass here.

---

### Task 7: Row parity: properties and the Hasura differential

**Files:**
- Modify: `test/property/metamorphic_test.exs` and `test/support/vacuity.ex`.
- Modify: `test/support/gen/filter.ex`, only if a guard shows the generators rarely produce lifts.

**Interfaces:**
- Produces: `Vacuity.lift_failures([%{rel_permission?: boolean(), lifted: non_neg_integer(), incomplete?: boolean(), fallback?: boolean(), nullable_chain?: boolean()}]) :: [String.t()]`.

- [ ] **Step 1: Write the property.** `property "join-lift: the same row set; the same sequence when the order is total; push-down off and on"`. It runs both plans per generated `where` case and records the observation fields. The guards, per batch, over cases with a relationship permission:
  - at least 20 % have `lifted > 0`;
  - at least 10 % fall back (invalid incomplete lifts are also recorded and separately rejected);
  - at least 1 has `nullable_chain?`.

  Add a guard-failure test per field, using a degenerate generator, as `metamorphic_test.exs` already does.
- [ ] **Step 2:** Run `AUTHZURA_PROP_RUNS=300 mix test --only property test/property/metamorphic_test.exs`. Expected: PASS. If a guard fails, extend the generator; never lower a floor.
- [ ] **Step 3: Differential.** Run the default and the deep (`AUTHZURA_DIFF_RUNS=3000 AUTHZURA_DIFF_BATCHES=5`) differential, with `AUTHZURA_DIFF_PUSHDOWN` unset and set. Expected: 0 leaks, 0 mismatches and no new reviewed divergences. Record the counts in the ledger.
- [ ] **Step 4:** Run `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `test: join-lift row parity under random permissions and inputs`

---

### Task 8: Release gate on the Ecto SQL, after-measurement and docs

**Files:**
- Modify: `bench/{REPORT,TRIAGE}.md`, `bench/results/*.json`, `docs/hasura-differences.md` (§2.1, plus §2.3 if `:all_fenced`), `CHANGELOG.md` (`## Unreleased`).

- [ ] **Step 1: Release gate.**
  - Apply Task 2's paired-control criteria on the **captured Ecto SQL on PG18 only**; this is not a PG16/17/18 matrix. For each case, the control is `Measure.authzura_sql(_, join_lift: false)` and the candidate is `join_lift: true`. Use interleaving, paired ratios and the borderline rule on PG18.
  - The Task 1 `:bench` pins must pass: no walk for orgs 1..40 (custom and generic), and the buffer ratio at most 1.5x.
  - **Any failure stops the release:** report to the owner. Rollback is a revert.
- [ ] **Step 2: Official run.** Run `mix authzura.bench` for every scenario, at both scales, in all three modes.
- [ ] **Step 3: Docs.**
  - §2.1: the before and after figures; join-lift and estimate wrapper; what still stays a SubPlan (whole-permission fallbacks, `_or`, arrays, non-strict keys, lossy pairs); that `scope_input/4` is not lifted. If a target still fails, it is a documented known gap, never "fixed".
  - TRIAGE: record the closed `input-rel-permission` buffer gap, inconclusive small default DB time and remaining large index gap.
  - CHANGELOG: one `perf:` line, and one line on the new scenarios and `--db-only`.
- [ ] **Step 4:** Run `mix test`, `mix docs` (no warnings) and `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `docs: record the relationship-fence result`
- [ ] **Final: whole-branch review (Opus).** It checks:
  - no duplicated logic: `lift/3` reuses `compile/2`, `pair/4` and `descend/2`, and introspection reuses its queries;
  - every spec semantics row and lift rule has a test;
  - the byte-identical fallback and the unchanged entry points;
  - the ledger records every ruling.

---

## Self-review notes

- **Spec coverage:**

  | Spec section | Task |
  |---|---|
  | Rules 3 and 4 (strict key, lossless pair) | 3, 4 |
  | Rules 1, 2 and 5 (aliases, budget) | 4 |
  | Where, bare root, clamp | 5 |
  | Semantics and row contract | 4 (SQL), 5, 7 (rows) |
  | Guarantee and push-down exception | 6 |
  | Estimate and controls | 2, 5, 8 |
  | Release gate and rollback | 8 |
  | Bench | 1, 8 |
  | Docs | 3-8 |
- **Either ruling works.** Tasks 5-8 read only the estimate wrapper's `shape` and `applies_to`; `:no_ship` stops at Task 2.
- **Names:**
  - Task 1: `Scenarios.with_org/2`, `Measure.authzura_sql/2`, `raw_plan/3`, `pk_walk?/2`, `--db-only`;
  - Task 3: `Table.strict_key?`;
  - Task 4: `Compiler.lift/3`, `lift_public/3`, `lossless_join_pair?/2`;
  - Task 5: the `join_lift` option, `fenced/3`;
  - Task 7: `Vacuity.lift_failures/1`.

# Authzura Stage One Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the stage-one claim before the first release:
- deterministic metamorphic properties on every PR;
- an on-demand randomized differential suite against Hasura v2.51.6, with a sound verdict;
- an 85 % coverage gate;
- a SHOULD-PORT sweep;
- telemetry spans for each pipeline stage, with sanitized metadata;
- a simple on-demand benchmark against Hasura, plus Benchee micro-benchmarks checked against a committed baseline;
- triage, fixes and docs.

**Architecture:**
- StreamData generators emit Task 19's `Authzura.Parity.Read` cases.
  - The properties run them through Authzura alone.
  - The differential suite runs them through `Authzura.Parity.Runner` on both engines and classifies each result with a new `Authzura.Parity.Verdict`.
- The benchmark lives in `bench/` and is compiled in `:test` and `:bench`.
  - It seeds `authzura_bench`, starts `hasura_bench` (compose profile `bench`), checks parity per scenario, then measures each engine in turn.
  - Measurements: `pg_stat_statements` for DB time and statement counts, and `EXPLAIN (ANALYZE, BUFFERS)` for plan shape.
  - Output goes to `bench/REPORT.md`.
  - `mix authzura.bench.micro` runs Benchee jobs and checks them against `bench/baselines/micro.json`, on demand.
- Telemetry gets one span per pipeline stage (input, scope, each SQL statement, each preload level). Metadata is bounded to names, categories, counts and reason classes.
- Only one CI workflow exists, `ci.yml`. Everything else runs on demand, using the documented commands.

**Tech Stack:**
- Elixir 1.19 / OTP 28, Ecto SQL 3.13, Postgrex.
- StreamData `~> 1.1` (`only: [:test, :bench]`).
- ExCoveralls `~> 0.18.5` (`only: :test`).
- Req, added by Task 19 as `only: :test`. Task 6 widens it to `[:test, :bench]`.
- Benchee `~> 1.5` (`only: [:test, :bench]`).
- Postgres 18 with `pg_stat_statements`.
- `hasura/graphql-engine:v2.51.6`.
- GitHub Actions: `ci.yml` only.

**Spec:** `docs/superpowers/specs/2026-11-14-authzura-hardening-design.md`. Its parent is `docs/superpowers/specs/2026-11-14-authzura-stage-one-design.md`. If a task and the spec conflict, the spec wins. Flag the conflict.

**Prerequisites.** Where the code differs from a name below, the code wins; note the difference in the task's checkpoint message.

- **Task 19, merged. Gates Tasks 1, 2 and 6.** It provides:
  - **`Authzura.ParityCase`.** `@moduletag :hasura_parity`, a `setup_all` fixed fixture, and `assert_parity/2`.
  - **`Authzura.Parity.Read`.** Fields: `table, columns, where, order_by, limit, relationships, sample`. Constructors: `new/2` and `nested/1`. A root read with `where` runs through `all_input/4`, and its table must be in `public`.
  - **`Authzura.Parity.Runner`.** `run(read, auth, instance) :: %{hasura:, authzura:}`, plus `graphql/1` and `authzura/3`.
  - **`Authzura.Parity.Hasura`.** `query/4`, `replace_metadata/1` and `sign/1`. `auth` is `{:admin_impersonate, role, vars} | {:jwt, claims, requested_role} | :admin`.
  - **`Authzura.Parity.Fixture`.** `migrate!/1`, `seed!/1` and `metadata(extra)`.
  - **`Authzura.Parity.Compare`.**
    - `canonical/1` normalizes numbers, timestamps and uuids.
    - `equivalent?(code, reason)`:
      - `not-found` ↔ missing session variable;
      - `validation-failed` ↔ forbidden columns, `:forbidden` or `:root_field_disabled`;
      - `access-denied` ↔ role not allowed;
      - `data-exception` ↔ invalid session value;
      - plus the JWT codes.
  - **Env vars.** `AUTHZURA_PARITY_DB_URL`, `AUTHZURA_PARITY_HASURA_URL`, `AUTHZURA_PARITY_ADMIN_SECRET` and `AUTHZURA_PARITY_JWT_KEY`.
- **JSON-column filter denial, landed. Gates Task 1.** Hasura v2.51.6 rejects permission filters on `json` columns as inconsistent metadata, and Authzura denies them at load. Generators never filter on `json`; `jsonb` is fine.
- **Read-only-connection mode, landed. Gates Task 5's mode test and Task 7's second mode.** It runs one statement with no transaction control; the option name may be `read_only: :connection`. Re-check the name before Task 7. If it has not landed, Task 7 reports the default mode only and says so.
- **Stage one:** `Authzura.HasuraFixture.snapshot!/2` and `start_instance!/4`, `Authzura.TestSource.put/2`, `Authzura.CommittedCase`, `Authzura.reload/1` and `Authzura.diagnostics/1`.
- **The coverage map.** `docs/hasura-test-coverage.md` uses these forms:
  - catalog statuses `covered`, `partial → ported` and `missing → ported`;
  - the tables "Extra scenarios ported", "Divergences" (`Test | Hasura | Authzura | Diagnosis`) and "Out of scope" (`Hasura source | Reason`);
  - divergence diagnoses that begin `intended` or `stage-one gap, fails closed`;
  - `@tag :hasura_divergence` on the divergence tests.

## Global Constraints

- **Read-only.** The public API only reads. Only the harnesses write `hdb_catalog`, and only through Hasura's `replace_metadata`.
- **Deny by default.** Unknown or uncompilable metadata denies, with a `%Diagnostic{}`.
- **No atoms from metadata, input or generated data.** Roles (`"gen_0"` … `"gen_15"`), tables, columns, relationships, case ids and scenario ids are strings.
- **Public error reasons only.** The stage-one list, plus the JWT reasons. Public return values never change in this plan.
- **Verdicts** (`Authzura.Parity.Verdict`; owner ruling):
  - **`:match`.**
  - **`{:leak, _}`.** Any row, key or value only Authzura returns, at any depth, including **any Authzura `{:ok, _}`, even `[]`, where Hasura errors**. A leak **always stops** the run and is never dispositioned.
  - **`{:over_deny, _}`.** Fails, unless an owner-approved entry in `test/parity/reviewed_divergences.exs` matches both the case and Authzura's reason. A match becomes `{:reviewed_divergence, id}`, which is counted and does not fail. More than 5 % reviewed divergences fails the run.
  - **`{:mismatch, _}`.** Anything else, including an unmapped error code.
  - **No sampling.** Every array level has a total order. A limited array whose key is hidden is checked against a no-limit twin role.
- **Vacuity guards.** These run per batch, in both suites, from counters collected inside the properties:
  - (a) `Authzura.diagnostics/1` is `[]` after loading the batch, or every entry is a reviewed divergence;
  - (b) at least 70 % of non-denial cases are granted;
  - (c) at least **25 %** of granted cases are restricted but non-empty;
  - (d) at least 25 % of array-preload cases return a nested row;
  - (e) every denial class appears.
- **Seeds and runs.** Run counts are totals, split across batches. Batch `i` uses `AUTHZURA_PROP_SEED + i`; the seed defaults to `20261114`.
  - **Properties:** `AUTHZURA_PROP_RUNS` defaults to `100`, and is `300` in `ci.yml`. `AUTHZURA_PROP_BATCHES` defaults to `4`.
  - **Differential:** `AUTHZURA_DIFF_RUNS` defaults to `300`, and the on-demand deep run uses `3000`. `AUTHZURA_DIFF_BATCHES` defaults to `1`; the deep run uses `5`.
  - **Overrides and replay.** Any run can override the seed and the counts from the command line. Every failure prints and records its batch seed and request seed.
- **Never trade a security check for speed.** These all stay:
  - `SET TRANSACTION READ ONLY`
  - `REPEATABLE READ` for preloads
  - the input fence
  - the pattern pre-check
  - prefix pinning
  - the alias, depth and node limits

  No fix changes a response.
- **Benchmark targets** (owner-confirmed; see the spec):

  | Target | Rule |
  |---|---|
  | DB time | ≤ **1.25×** Hasura. Use the median of 5 alternating repetitions; a CV above 15 % is `inconclusive`. |
  | Data statements | exactly **`1 + L`**. In read-only-connection mode, also 0 transaction-control statements. |
  | Indexes | an index wherever Hasura uses one on that table |
  | Shared buffers | ≤ **1.5×** Hasura's |

  - There is no HTTP wrapper (owner ruling).
  - A target that still fails after Task 9 becomes a **documented known gap** (owner ruling). It is never marked fixed, and its limit is never relaxed.
- **Micro-benchmarks** (on demand). `mix authzura.bench.micro --check` fails when a job is more than **20 %** slower than `bench/baselines/micro.json`, in all 3 runs. It is skipped, not failed, when the environment differs from the baseline's or no baseline exists. It never runs in CI.
- **Telemetry metadata is bounded.**
  - Allowed: names, categories, counts, and `reason_class`/`exception_class` atoms.
  - Never: values, column lists taken from input, binds, SQL, JWTs or exception messages.
  - Public return values are unchanged.
- **Benchmark output** carries numbers, plan node types, and table and index names. It never carries session values, SQL text, bind values or JWTs.
- **Test tags.** `test/test_helper.exs` excludes `[:hasura_parity, :hasura_differential, :bench]`; `:property` stays on.
- **CI.** One workflow, `ci.yml`, runs on PRs and on `push` to `main`. It runs `mix quality` and the coverage run (which is the default `mix test`, properties included) on a pinned seed. Its `uses:` lines are pinned by commit SHA, with a `# vX.Y.Z` comment, and it sets `permissions: contents: read`. **There are no scheduled or nightly workflows.** The differential and the benchmark run on demand, locally.
- **Docker.** Pin image tags, never `latest`. Every published port binds `127.0.0.1`. Never install a browser or a load tool on the host.
- **Migrations.** Create them only with `mix ecto.gen.migration`, then fill in the body. Never hand-create a migration file.
- **Public repo.** Never mention a private application, a domain or a local path. Real-world validation is cited only as "a large real-world Hasura v2 metadata set", with counts only.
- **README stays short.** Details go in `docs/guides/*.md`. Guide examples run in `test/readme_examples_test.exs`.
- **Quality gate.** `mix quality` must pass at the end of every task. It runs `compile --warnings-as-errors`, `deps.unlock --unused`, `format --check-formatted`, `sobelow`, `ex_dna`, `doctor`, `credo --strict` (with ExSlop) and `dialyzer`. `bench/` is in `.formatter.exs` and `.credo.exs`.
- **Owner Elixir style.**
  - Prefer `with` over nested conditionals.
  - Use function-head matching, binding and guards.
  - Use pipes.
  - Group top-level aliases (`alias Authzura.{A, B}`).
  - No fully qualified calls in function bodies.
  - Predicates end in `?`.
- **Commits.** At a **Checkpoint**, stage the files and stop with the suggested message. Never run `git commit`, `git push` or `git tag`. No AI attribution.

## Review Focus

1. **A leak classified as something softer.** Watch for:
   - Hasura denies while Authzura returns `[]` or rows;
   - a forbidden nested row;
   - an extra key in a nested object;
   - `nil` vs a map;
   - `[]` vs a non-empty array at depth 3.

   Expected: `:leak`, which stops the run. A planted test covers each case. Owner: Task 2.
2. **Generators avoiding the regions where leaks live.** Expected: the must-appear test covers hidden columns in the filter and the order, hidden keys, preload targets with no permission, each relationship kind, and session boundary forms. Owner: Task 1.
3. **Vacuous runs.** Expected: guards (a)–(e) hold per batch. Owners: Tasks 1 and 2.
4. **Benchmarking different work.** Watch for:
   - different responses from the two engines;
   - a Hasura HTTP 200 that carries `errors`;
   - a permission that filters nothing;
   - Hasura background statements counted;
   - the two engines measured at the same time.

   Expected: the gate aborts the scenario by id. Engines are measured one at a time, after a reset. `hdb_catalog` and statistics-view statements are excluded. Owner: Tasks 6 and 7.
5. **Values leaking out through telemetry or benchmark output.** This covers denial reasons that name input columns, exception messages that carry SQL, and plan expressions. Expected: span metadata, including on exceptions, carries bounded classes only. Sentinel tests prove that events, the report and the results contain no session value, SQL text or bind value. Owner: Tasks 5 and 7.

---

## File Structure

```
mix.exs, .formatter.exs, .credo.exs, .gitignore, config/bench.exs, coveralls.json, .github/workflows/ci.yml
test/support/{gen,seed}.ex, test/support/gen/save.ex, test/support/parity/verdict.ex
test/property/{gen,verdict,metamorphic}_test.exs
test/parity/{random_differential,random_replay}_test.exs, test/parity/reviewed_divergences.exs, test/parity/cases/random/*.json
test/hasura_scenarios/{hasura_inventory.tsv,sweep_test.exs}, docs/hasura-test-coverage.md
lib/authzura/{telemetry,scope,input,executor,preload/loader,store}.ex, docs/guides/configuration.md, test/authzura/telemetry_test.exs
docker-compose.yml (pg_stat_statements; profile "bench": hasura_bench), priv/bench_migrations/
bench/lib/authzura/bench/{repo,dataset,metadata,scenarios,gate,measure,report,micro}.ex, bench/lib/mix/tasks/authzura.bench{,.seed,.micro}.ex
bench/REPORT.md, bench/results/<scale>.json, bench/TRIAGE.md, bench/README.md, bench/baselines/micro.json
test/bench/*_test.exs, docs/guides/compatibility.md, CHANGELOG.md
```

---

### Task 1: Generators and metamorphic properties

**Files:**
- Create: `test/support/gen.ex`, `test/support/seed.ex`, `test/property/gen_test.exs`, `test/property/metamorphic_test.exs`
- Modify:
  - `mix.exs`: add the StreamData dep.
  - `test/test_helper.exs`: set the exclusions.
  - `test/support/hasura_fixture.ex`: add `start_instance_with_source!/4`.
  - `test/support/parity/read.ex`, plus its rendering in `Runner`: add `offset` and nested `limit`.

**Interfaces:**
- **`Authzura.Test.Seed.insert!(repo) :: :ok`.** Builds on `Fixture.seed!/1`, giving 20–50 rows per table. The data includes NULLs in every nullable column, `citext` emails that differ only by case, partial-NULL composite keys, `manager_id` chains, and float-exact numerics. Leave `ParityCase`'s own seed alone.
- **`Seed.ids()`** returns the id pools for session variables. **`Seed.values()`** returns `%{{schema, table, column} => [term()]}` for filter literals.
- **`HasuraFixture.start_instance_with_source!(name, repo, metadata, opts) :: {atom(), pid()}`.** A batch loads with `TestSource.put(agent, snapshot: snapshot!(repo, m), version: "batch-<i>")` followed by `Authzura.reload(name)`.
- **`Authzura.Gen.batch(i, opts \\ []) :: %{String.t() => %{{schema, table} => map()}}`.** Sixteen roles, each mapped to its Hasura select permissions. The batch is drawn with seed `AUTHZURA_PROP_SEED + i`; `limits: false` drops every `limit`.
  - Filters use only accepted features:
    - the comparison set;
    - `_in`/`_nin`, including `[]`;
    - `_is_null`;
    - the like, ilike, similar and regex families;
    - the jsonb operators;
    - `_and`/`_or`/`_not`, including `[]`;
    - `_exists`;
    - relationships to depth 3;
    - shorthand and `$` aliases;
    - mixed-case session references.
  - A filter never touches a `json` column.
  - Depth is at most 6, nodes at most 40, and literals come from `Seed.values()`.
- **`Gen.request(batch) :: StreamData.t(case)`.** A `case` is `%{id, read: %Parity.Read{}, auth, allowed_roles, denial: nil | atom(), twin: nil | role}`.
  - **Order.** Every level has a total order: the primary key when it is visible, otherwise every visible column.
  - **Preload depth.** At most 2 for `where` cases, which run through `all_input`; up to 3 for `all/3` cases.
  - **View root.** `published_articles` is a root only for `all/3` cases.
- **`Gen.must_appear()` and `Gen.coverage_tags(case) :: [atom()]`.** The must-appear tags:
  - **Hidden columns:** `:hidden_in_columns`, `:hidden_in_filter`, `:hidden_in_order`, `:hidden_in_preload_columns`, `:hidden_in_preload_order`.
  - **Names and keys:** `:unknown_column`, `:hidden_pk_role`, `:hidden_fk_role`.
  - **Preload targets:** `:preload_target_without_permission`, `:preload_target_root_disabled`.
  - **Relationship shapes:** `:rel_object`, `:rel_array`, `:rel_composite`, `:rel_self`, `:rel_citext_key`, `:partial_null_key`.
  - **Read forms:** `:view_root`, `:offset`, `:limit_zero`.
  - **Session boundary forms** (`:session_boundary`): `" 1"`, `"01"`, `"+1"`, `"1.0"`, `""`, `"TRUE"`, `"t"`, an out-of-range integer, and array variables containing spaces, quotes or `NULL`.
  - **Denials:** `:missing_variable`, `:uncastable_value`, `:root_disabled`, `:role_not_allowed`. For a `:role_not_allowed` case, the requested role is outside `allowed_roles`.
- **`Gen.oracle(case)`** is the same read as `"gen_admin"`, with no limits.
- **`run(case)`** calls `Runner.authzura/3`. **`granted?(c)`** is `match?({:ok, _}, run(c))`.

- [x] **Step 1: Write the failing generator tests** in `test/property/gen_test.exs`. These are pure tests.

```elixir
test "same seed, same first 50 cases" do
  assert take(Gen.request(Gen.batch(1)), 42, 50) == take(Gen.request(Gen.batch(1)), 42, 50)
end

test "every accepted operator and every must-appear item appears within 2 000 samples" do
  seen = take(Gen.request(Gen.batch(1)), 9, 2_000) |> Enum.flat_map(&Gen.coverage_tags/1) |> MapSet.new()
  assert MapSet.subset?(MapSet.new(Gen.must_appear() ++ Gen.operators()), seen)
end

test "no filter references a json column; names never become atoms" do ... end
property "where-cases preload at most 2 deep, all/3 cases at most 3; every level is totally ordered" do ... end
```
- [x] **Step 2:** Run `mix test test/property/gen_test.exs`. Expected: FAIL (`Authzura.Gen` undefined).
- [x] **Step 3:** Implement `Seed`, `Gen`, the `Read`/`Runner` extensions and `start_instance_with_source!/4`.
- [x] **Step 4:** Run `mix test test/property/gen_test.exs`. Expected: PASS.
- [x] **Step 5: Write the properties** in `test/property/metamorphic_test.exs`. The module uses `CommittedCase`, is `@moduletag :property`, and runs with `async: false`.
  - The per-test `setup` seeds the data, then starts the instance with `admin_role: "gen_admin"`. It reads the batch options from `context[:batch]`.
  - Each property loops over the batches. Per batch it loads the batch, checks guard (a), runs `check_all` with its share of the runs, then asserts guards (b)–(e) from the counters.

```elixir
property "never raises; errors are public reasons" do ... end
property "visible keys are requested and allowed, at every preload level" do ... end

@tag batch: [limits: false]
property "input fence: rows(role, F) == rows(role) ∩ rows(admin, F)" do
  check all c <- Gen.request(batch), where?(c), granted?(c), max_runs: per_batch() do
    assert rows_key(run(c)) == intersect(rows_key(run(drop_where(c))), rows_key(run(Gen.oracle(c))))
  end
end

property "root and per-parent counts are at most min(request, permission) limits" do ... end
property "the same case twice gives the same result" do ... end
```
- [x] **Step 6:** Run `docker compose up -d --wait postgres && AUTHZURA_PROP_RUNS=300 mix test --only property`. Expected: PASS.
  - For an Authzura bug: add a deterministic regression test beside the owning module, and fix the bug.
  - For a generator bug: fix the generator.
- [x] **Step 7:** Run `mix test && mix quality`. Expected: PASS.
- [ ] **Step 8: Checkpoint.** `test: add StreamData generators and metamorphic permission properties`

---

### Task 2: Randomized differential testing against Hasura (on demand)

**Files:**
- Create: `test/support/parity/verdict.ex`, `test/support/gen/save.ex`, `test/parity/random_differential_test.exs`, `test/parity/random_replay_test.exs`, `test/parity/reviewed_divergences.exs`, `test/parity/cases/random/.gitkeep`
- Test: `test/property/verdict_test.exs` (pure)

**Interfaces:**
- **`Authzura.Parity.Verdict.classify(ctx, hasura, authzura)`** returns `:match | {:reviewed_divergence, id} | {:leak | :over_deny | :mismatch, String.t()}`.
  - `ctx = Verdict.context(case, batch)` holds each table's key (or `:none` when the key is hidden), its allowed columns, and the relationship kinds.
  - Both sides go through `Compare.canonical/1`. The comparison is recursive and covers every key, every value and multiplicity. Objects are `map | nil`, arrays are lists, and `nil ≠ []`. Rows match by key, or as a multiset of whole rows when the key is hidden. No key is ever dropped.
  - Checks run in this order:
    1. Hasura error with an Authzura success: **leak**.
    2. A row, key or value only in Authzura's result: **leak**.
    3. A Hasura success with an Authzura error: **over-deny**, then the divergence entries are checked.
    4. Errors on both sides: look up the **code table**, a module attribute mapping each code to its allowed reason classes, starting from `Compare.equivalent?/2`.
       - `validation-failed` must also name the expected field in its message.
       - An unknown column and a hidden column must give the same Authzura reason.
       - An unmapped code is a **mismatch**.
    5. A ctx that asks for `sample`: **mismatch**.
  - **The twin rule.** For a limited array whose key is hidden, Authzura's rows must be a sub-multiset of Hasura's rows for the no-limit twin role, and the counts must match.
- **`reviewed_divergences.exs`** is a list of `%{id, coverage_row, case?: (case -> boolean), reason?: (term -> boolean)}`.
  - Both predicates must hold.
  - `coverage_row` names an existing "Divergences" row.
  - Proposed for owner review: `session-cast-eager`. Authzura rejects a session value Postgres cannot cast before running the query; Hasura casts lazily.
    - `reason?` matches `{:invalid_session_value, _, _}`.
    - `case?` requires a value that Postgres itself rejects for the column type.
- **`Gen.Save.write!(payload, reason, seeds) :: Path.t()`** writes `test/parity/cases/random/<id>.json`.
  - The payload is `%{read, auth, permissions, relationships}`. Tuples become two-element lists; there are no atoms.
  - `id = "gen-" <> first 16 hex of sha256(canonical JSON, sorted keys)`.
  - It runs once, from the `shrunk_failure`.
  - If the file already exists, it decodes it with `Jason` and raises unless the payloads are equal.
- **The differential module.** `@moduletag :hasura_differential`, `async: false`.
  - `setup_all` starts the parity repo, truncates, runs `Fixture.migrate!/1` and `Seed.insert!/1`, and starts an instance on `Authzura.Sources.Hasura`.
  - There is one test per batch. Each runs `replace_metadata`, `reload/1`, guard (a), `check_all` over `Runner.run/3`, and guards (b)–(e).
  - Auth is `{:jwt, claims, requested_role}`.
  - A leak fails at once, with "LEAK" first in the message.

- [x] **Step 1: Write the failing pure tests** in `test/property/verdict_test.exs`:

```elixir
test "Hasura denies, Authzura grants (even []) is a leak" do
  assert {:leak, _} = Verdict.classify(ctx(), {:error, "validation-failed"}, {:ok, [%{"id" => 1}]})
  assert {:leak, _} = Verdict.classify(ctx(), {:error, "validation-failed"}, {:ok, []})
end

test "nested leaks at every shape" do
  assert {:leak, _} = Verdict.classify(ctx(), ok([%{"id" => 1, "author" => nil}]), ok([%{"id" => 1, "author" => %{"id" => 2}}]))
  assert {:leak, _} = Verdict.classify(ctx(), ok([deep3([])]), ok([deep3([%{"id" => 9}])]))
  assert {:leak, _} = Verdict.classify(ctx(), ok([%{"id" => 1, "author" => %{"id" => 2}}]), ok([%{"id" => 1, "author" => %{"id" => 2, "salary" => 1}}]))
  assert {:leak, _} = Verdict.classify(ctx(pk: :none), ok([%{"t" => "a"}]), ok([%{"t" => "a"}, %{"t" => "a"}]))
end

test "a changed value, nil vs [], or a sampling ctx is a mismatch" do ... end

test "a reviewed divergence needs both the case and the reason to match" do
  assert {:reviewed_divergence, "session-cast-eager"} = Verdict.classify(cast_ctx(), ok([]), {:error, {:invalid_session_value, "x-hasura-user-id", :cast}})
  assert {:over_deny, _} = Verdict.classify(cast_ctx(), ok([]), {:error, :forbidden})
end

test "validation-failed matches only when the message names the expected field" do ... end
test "Save.write!/3 ids hash canonical JSON; a different payload under an existing id raises" do ... end
```
- [x] **Step 2:** Run `mix test test/property/verdict_test.exs`. Expected: FAIL.
- [x] **Step 3:** Implement `Verdict`, the divergences file and `Gen.Save`. Run each denial class against Hasura once, and record the codes and messages it returns.
- [x] **Step 4:** Run `mix test test/property/verdict_test.exs`. Expected: PASS.
- [x] **Step 5:** Write `random_differential_test.exs` and `random_replay_test.exs`. The replay file is `:hasura_parity`, and it decodes cases with `Jason` only.
- [x] **Step 6:** Run the differential.

  ```bash
  docker compose --profile parity up -d --wait
  mix test --only hasura_differential
  ```

  Expected: PASS. Handle each failing verdict this way:
  - **Leak:** stop and report it to the owner. Then fix it, and keep the saved file.
  - **Mismatch, or an unreviewed over-deny that is an Authzura bug:** fix it, and keep the file.
  - **Generator bug:** fix the generator, and delete the file.
  - **Over-deny on a deliberately unsupported feature:** propose a "Divergences" row and an entry, then stop for owner review.

  Then run the deep run once: `AUTHZURA_DIFF_RUNS=3000 AUTHZURA_DIFF_BATCHES=5 mix test --only hasura_differential`.
- [x] **Step 7:** Document the on-demand commands in the Security guide's "Running parity tests" section:
  - the default differential run;
  - the deep run;
  - a replay of one seed: `AUTHZURA_PROP_SEED=<batch seed> mix test --only hasura_differential --seed <request seed>`;
  - the saved-case replay: `mix test --only hasura_parity test/parity/random_replay_test.exs`.
- [x] **Step 8:** Run `mix test`, `mix test --only hasura_parity` and `mix quality`. Expected: PASS.
- [ ] **Step 9: Checkpoint.** `test: add randomized differential testing against Hasura v2.51.6`

---

### Task 3: Coverage gate and PR CI

**Files:**
- Modify:
  - `mix.exs`: add `{:excoveralls, "~> 0.18.5", only: :test}` and `test_coverage: [tool: ExCoveralls]`, and register the `coveralls` tasks under `:test` in `cli/0`'s `preferred_envs`.
  - `.gitignore`: add `/cover/`.
- Create: `coveralls.json`, `.github/workflows/ci.yml`
- Test: the unit tests the triage calls for

**Interfaces:**
- **`coveralls.json`:**

  ```json
  {"coverage_options": {"minimum_coverage": 85}, "skip_files": ["test/", "bench/", "deps/"]}
  ```
- **`ci.yml`.** Runs on `pull_request` and on `push` to `main`. It sets `permissions: contents: read`, pins every `uses:` by SHA, and has two jobs:
  - `quality`: runs `mix quality`.
  - `test`: starts a `postgres:18` service, then runs `AUTHZURA_PROP_SEED=20261114 AUTHZURA_PROP_RUNS=300 mix coveralls --seed 20261114`.

- [x] **Step 1:** Add the dependency and the config, then run `mix deps.get`.
- [x] **Step 2:** Run `mix coveralls --seed 20261114`. List every `lib/` module below 85 % in the checkpoint message.
- [x] **Step 3:** Work through those modules, lowest first. For each, write a failing test that asserts a result, then make it pass. Delete unreachable code rather than testing it.
- [x] **Step 4:** Write `ci.yml`.
- [x] **Step 5:** Run `mix coveralls --seed 20261114`. Expected: `[TOTAL] ≥ 85.0%`. Run `mix quality`. Expected: PASS. Then run `grep -E 'uses: ' .github/workflows/ci.yml | grep -vE '@[0-9a-f]{40}'`. Expected: no output.
- [ ] **Step 6: Checkpoint.** `test: gate CI on 85% line coverage`

---

### Task 4: SHOULD-PORT sweep and the out-of-scope record

**Files:**
- Create: `test/hasura_scenarios/hasura_inventory.tsv`, `test/hasura_scenarios/sweep_test.exs`, and the new scenario tests
- Modify: `docs/hasura-test-coverage.md`. Add rows to its existing tables, cite tests by name, and never rewrite existing rows.

**Interfaces:**
- **The inventory source.** It is built outside the repo:

```bash
git clone --filter=blob:none --sparse --depth 1 --branch v2.51.6 https://github.com/hasura/graphql-engine.git "$TMPDIR/hasura-v2.51.6"
git -C "$TMPDIR/hasura-v2.51.6" sparse-checkout set server/tests-py/queries/graphql_query server/lib/api-tests/src/Test
cd "$TMPDIR/hasura-v2.51.6/server"
{ ls tests-py/queries/graphql_query/{permissions,boolexp/basic,boolexp/search,boolexp/jsonb,limits}/*.yaml
  grep -rlE 'select_permissions|SelectPermission|DisableRootFields|selectPermission' lib/api-tests/src/Test --include='*.hs'; } | sort -u
```
- **`hasura_inventory.tsv`.** One line per path: `path<TAB>ported|divergence|out_of_scope<TAB><test file>: <test name>`. The third field is empty for `out_of_scope`.
- **`Authzura.Test.CoverageMap.parse!(path)` and `parse_string!/1`.** Both return `%{catalog:, extra:, divergences:, out_of_scope:}`. They raise on any of these:
  - a missing or empty table;
  - an unknown header;
  - an unknown status;
  - a diagnosis that does not match `^(intended|stage-one gap, fails closed)`.

- [x] **Step 1: Write the failing test** `sweep_test.exs`:

```elixir
test "the coverage map parses; empty or unknown forms are rejected" do
  assert %{catalog: [_ | _], divergences: [_ | _], out_of_scope: [_ | _]} = CoverageMap.parse!("docs/hasura-test-coverage.md")
  assert_raise ArgumentError, fn -> CoverageMap.parse_string!("") end
  assert_raise ArgumentError, fn -> CoverageMap.parse_string!(catalog_row_with_status("maybe")) end
end

test "every inventory row's test exists by name" do ... end
test "every inventory path appears in the coverage map (by basename or brace glob)" do ... end
test "every divergence row's test is tagged :hasura_divergence" do ... end
```
- [x] **Step 2:** Run `mix test test/hasura_scenarios/sweep_test.exs`. Expected: FAIL, listing the paths that are not accounted for.
- [x] **Step 3: Port or record each path.**
  - **Accepted feature:** add a scenario test with exact rows and columns or the exact error, plus a negative control. Add an "Extra scenarios ported" row. Mark the path `ported`.
  - **Deliberate difference:** add a `:hasura_divergence` test and a "Divergences" row for owner review. Mark the path `divergence`.
  - **Anything else:** add an "Out of scope" row. Mark the path `out_of_scope`.
- [x] **Step 4:** Run `mix test`, `mix test --only hasura_parity` and `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `test: sweep Hasura select-permission tests against the coverage map`

---

### Task 5: Telemetry spans per pipeline stage, with bounded metadata

**Files:**
- Modify:
  - `lib/authzura/telemetry.ex`
  - the span call sites in `scope.ex`, `input.ex`, `executor.ex`, `preload/loader.ex` and `store.ex`
  - `docs/guides/configuration.md` (its "Telemetry" section)
- Test: `test/authzura/telemetry_test.exs` (`CommittedCase`)

**Interfaces:**
- Existing spans keep their event names and the `:instance`, `:role`, `:seq` and `:mode` keys.
- **`Telemetry.span(event, metadata, fun, classify :: (result -> map())) :: result`.** `span/3` and `access_span/3` delegate to it.
  - It emits the same shapes as `:telemetry.span/3`:
    - `:start` measurements are `%{system_time, monotonic_time}`.
    - `:stop` and `:exception` measurements are `%{duration, monotonic_time}`.
    - All three events carry `telemetry_span_context`.
  - On `:exception` the metadata adds only `%{kind, exception_class: module | :throw | :exit}`, and the exception is re-raised with its original stacktrace. The message and the exception struct are never in the metadata.
- **`Telemetry.reason_class(reason) :: atom()`** returns the reason's tag. Every `:stop` that used to carry `reason:` or `error:` now carries `reason_class:` or `error_class:`.
- **`Telemetry.rows(result) :: non_neg_integer() | nil`** counts:
  - a list: `length/1`;
  - `{:ok, rows}`: the length of `rows`;
  - `%Postgrex.Result{num_rows: n}`: `n`;
  - anything else: `nil`.
- **New spans:**
  - `[:authzura, :input]`: `instance`, `role`, `table`. `:stop` adds `result` and `reason_class`.
  - `[:authzura, :query]`: one per statement Authzura issues. Metadata: `category` (`:transaction_control | :setup | :data`), `stage` (`:root | :preload`) and `table`. `:stop` adds `rows`.
  - `[:authzura, :preload]`: one per level. Metadata: `relationship`, `depth`, `parents`. `:stop` adds `rows`.
- **Non-keyword `telemetry_options`.** If the caller passes `telemetry_options` that are not a keyword list, the call returns `{:error, {:unsupported_query, {:option, :telemetry_options}}}`. It never raises.

- [x] **Step 1: Write the failing tests:**

```elixir
test "span/4 emits the same measurement and metadata shapes as :telemetry.span/3" do ... end
test "a plain read: transaction_control then one data root; two preload levels add two data preloads" do ... end
test "read-only-connection mode: one data root only" do ... end   # gated on the prerequisite
test "rows/1 counts lists and Postgrex results; non-keyword telemetry_options is an error" do ... end

@sentinel "ZQX_sentinel_7f3a"
test "hostile denials and a DB exception expose only bounded classes" do
  meta = all_authzura_event_metadata(fn -> hostile_calls(@sentinel) end)
  refute inspect(meta) =~ @sentinel
end
```
- [x] **Step 2:** Run `mix test test/authzura/telemetry_test.exs`. Expected: FAIL.
- [x] **Step 3:** Implement the spans. Then update the existing assertions that read `reason:` or `error:` in event metadata. They are in `store_test.exs`, `scope_test.exs`, `executor_test.exs` and `input_test.exs`; find them with `grep -rn "reason:\|error:" test`.
- [x] **Step 4:** Run `mix test && mix quality`. Expected: PASS.
- [x] **Step 5:** Update the guide's table. It must state two things:
  - metadata is bounded by design;
  - for detail, read the return value and `Authzura.status/1`.
- [ ] **Step 6: Checkpoint.** `feat: add pipeline-stage telemetry spans with bounded metadata`

---

### Task 6: Benchmark setup: compose profile, seeded dataset, scenarios and parity gate

**Files:**
- Modify:
  - `mix.exs`:
    - `elixirc_paths(:test)` and `elixirc_paths(:bench)` both become `["lib", "test/support", "bench/lib"]`;
    - `cli/0`'s `preferred_envs` gains `authzura.bench*` → `:bench`;
    - Req becomes `only: [:test, :bench]`.
  - `.formatter.exs` and `.credo.exs`: include `bench/`.
  - `docker-compose.yml`:
    - `postgres` gains `command: postgres -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track_planning=on`;
    - `5432` and `8080` bind to `127.0.0.1`;
    - add a `bench` profile with `hasura_bench`.
- Create:
  - `config/bench.exs`
  - `bench/lib/authzura/bench/{repo,dataset,metadata,scenarios,gate}.ex`
  - `bench/lib/mix/tasks/authzura.bench.seed.ex`
  - `priv/bench_migrations/<generated>_add_bench_indexes.exs`
  - `bench/README.md`
- Test: `test/bench/dataset_test.exs` (`:bench`), `test/bench/gate_test.exs` (`:bench`), `test/bench/scenarios_test.exs` (pure)

**Interfaces:**
- **`Authzura.Bench.Repo`.** Database `authzura_bench`, user `postgres`, `log: false`.
- **The `hasura_bench` service.**
  - Image `hasura/graphql-engine:v2.51.6` on `127.0.0.1:8081:8080`, with no `restart:`.
  - Database `authzura_bench`.
  - `HASURA_GRAPHQL_ADMIN_SECRET` and the parity JWT secret.
  - `HASURA_GRAPHQL_SCHEMA_SYNC_POLL_INTERVAL=0` and `HASURA_GRAPHQL_ENABLE_TELEMETRY=false`.
- **`mix authzura.bench.seed --scale small|large`.** In order:
  1. Create the database and `CREATE EXTENSION pg_stat_statements`.
  2. Run `Fixture.migrate!/1` and the bench migrations.
  3. Run `docker compose --profile bench up -d --wait hasura_bench`.
  4. Run `Dataset.load!/3`, then `VACUUM (ANALYZE)`.
  5. Run `replace_metadata(Metadata.build())`.
- **`Dataset.load!(repo, scale :: :tiny | :small | :large, seed)`.** Deterministic `generate_series` inserts using `hashint8extended(i, seed)`. Numerics are float-exact.

  | scale | organizations | users | org_memberships | articles | comments |
  |---|---|---|---|---|---|
  | tiny (tests) | 5 | 100 | 150 | 1 000 | 3 000 |
  | small | 100 | 10 000 | 20 000 | 100 000 | 300 000 |
  | large (optional) | 1 000 | 100 000 | 200 000 | 1 000 000 | 3 000 000 |
- **`Metadata.build()`.** The bench roles:
  - `tenant`: org = session org
  - `author`: own `_or` published
  - `member`: `_exists` on memberships
  - `deep`: a 3-hop filter
  - `limited`: `limit: 50`, plus a per-parent `comments` limit
  - `arr`: `_in` over the array variable
- **The bench index migration.** Generate it after `Repo` and `config/bench.exs` exist:

  ```bash
  MIX_ENV=bench mix ecto.gen.migration add_bench_indexes -r Authzura.Bench.Repo --migrations-path priv/bench_migrations
  ```

  It indexes `articles(org_id)`, `articles(author_id)`, `articles(status, id)` and `org_memberships(user_id)`.
- **`Scenarios.all() :: [%{id, read: %Parity.Read{}, auth, preload_levels}]`.** The ids, in this order:
  - `flat-tenant`
  - `author-or-published`
  - `exists-member`
  - `rel-filter-3hop`
  - `session-array-in`
  - `columns-narrow`
  - `input-filter`
  - `input-regex`
  - `limit-permission`
  - `page-1000`
  - `preload-object`
  - `preload-array-limited`
  - `preload-nested-3`

  Every level is primary-key ordered, and auth is always a JWT.
- **`Gate.check(scenarios) :: {[scenario], [{id, reason}]}`.** A scenario passes only when all of these hold:
  - `Verdict.classify/3` returns `:match`;
  - both engines return at least 1 row, and Hasura's body has no `errors`;
  - with the read's `where`, `limit`, `offset` and relationships stripped, the role sees strictly between 0 and all of the root table's rows;
  - the bench instance has no `admin_role`.

- [x] **Step 1: Write the failing tests:**

```elixir
@tag :bench
test "the same seed gives the same per-table hash at :tiny; a different seed does not" do ... end

test "scenario ids are the fixed list, unique strings, pk-ordered at every level" do ... end

@tag :bench
test "every scenario passes the gate at :small" do
  assert {_ok, []} = Gate.check(Scenarios.all())
end

@tag :bench
test "the permission guard ignores request pagination and filters" do
  assert {[], [{"page-1000", :permission_filters_nothing}]} = Gate.check([with_role(page_1000(), "open")])
end

@tag :bench
test "a planted difference or a Hasura 200 with errors aborts that scenario by id" do ... end
```
- [ ] **Step 2:** Run `mix test test/bench/scenarios_test.exs`. Expected: FAIL.
- [x] **Step 3:** Implement. Create `config/bench.exs` and `Repo` first, then generate the migration, then build the rest. Write `bench/README.md` as one page, headed "test harness only".
- [x] **Step 4:** Run `docker compose up -d --wait postgres && MIX_ENV=bench mix authzura.bench.seed --scale small`, then `mix test --only bench test/bench`, then `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `bench: add bench profile, seeded dataset, scenarios and parity gate`

---

### Task 7: `mix authzura.bench`: measure, report, first comparison and triage

**Files:**
- Create:
  - `bench/lib/authzura/bench/{measure,report}.ex`
  - `bench/lib/mix/tasks/authzura.bench.ex`
  - `bench/REPORT.md`, `bench/results/small.json`, `bench/TRIAGE.md`
- Test: `test/bench/measure_test.exs` (pure parts plus `:bench`), `test/bench/report_test.exs`

**Interfaces:**
- **`Measure.classify(query_text) :: :transaction_control | :setup | :data | :background`.**
  - `:transaction_control`: `BEGIN`, `COMMIT`, `SET TRANSACTION…`.
  - `:setup`: `set_config`, `SET LOCAL`, `current_setting`, and Authzura's pattern pre-check.
  - `:background`: anything touching `hdb_catalog`, `pg_stat_statements` or `pg_catalog`.
  - `:data`: everything else.
- **`Measure.statements(engine, scenario, n \\ 200) :: %{counts: %{category => float()}, db_ms: float()}`.** Measures one engine at a time:
  1. Warm up with 20 requests.
  2. Run `pg_stat_statements_reset()`.
  3. Send `n` requests.
  4. Read `pg_stat_statements` for `authzura_bench`.

  Counts are per request. `db_ms` is `(total_plan_time + total_exec_time) / n`, summed over the non-background statements.
- **`Measure.db_time(scenario) :: %{ratio, cv, verdict: :pass | :fail | :inconclusive}`.** Runs 5 repetitions, alternating Hasura, Authzura, Hasura, …, then takes the ratio of the medians. A CV above 0.15 is `:inconclusive`.
- **`Measure.plans(engine, scenario) :: [%{table_scans: [{table, :seq | :index | :index_only | :bitmap, index | nil}], shared_buffers: non_neg_integer()}]`.** One entry per data statement.
  - **Authzura's statements:** captured once from the repo's own query telemetry event, kept in memory only, then run with `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` and the same parameters.
  - **Hasura's statements:** taken from `POST /v1/graphql/explain` with the scenario's session, then explained the same way.
  - `shared_buffers` is the root node's hit + read, counted once per statement.
  - Expressions are dropped while parsing.
- **`Measure.check(results, scenario, mode)`.** Evaluates the four Global Constraints targets.
- **`mix authzura.bench [--scale small|large] [--mode default|read_only_connection] [--only ids] [--check]`.** In order: seed if needed, run the gate, then for each scenario measure statements, DB time and plans, then write the report. With `--check`, it exits non-zero on a failing target or an aborted scenario. `:inconclusive` results are listed but do not fail.
- **`Report.write!(results) :: :ok`.** Writes `bench/results/<scale>.json` and `bench/REPORT.md`.
  - **Header:** date, scale, mode, seed, image tags and versions.
  - **One table row per scenario:**
    - DB-time ratio and CV
    - data and transaction-control counts per engine
    - the index verdict
    - the buffer ratio
    - the verdict
  - **A fairness paragraph:** Hasura's figures include HTTP, GraphQL and in-database JSON; only database work is compared; planning time is counted on both sides.
  - **A "Known gaps" section.**
  - Only numbers, ids, verdicts, node types, and table and index names go in.

- [x] **Step 1: Write the failing tests:**

```elixir
test "classify/1 categories" do ... end   # BEGIN, SET TRANSACTION, set_config, hdb_catalog, a data SELECT
test "buffers come from each statement's root node once; expressions are dropped" do ... end
test "targets: db_time 1.25 pass / 1.251 fail; data == 1+L; read-only-connection needs 0 transaction control" do ... end
test "CV above 15 % is :inconclusive, never :pass" do ... end

@sentinel "ZQX_sentinel_7f3a"
test "the report and results never contain session values or SQL" do
  Report.write!(results_with(session: @sentinel, sql: "select '#{@sentinel}'", plan_expr: @sentinel), dir: tmp())
  refute File.read!(tmp("REPORT.md")) <> File.read!(tmp("small.json")) =~ @sentinel
end
```
- [x] **Step 2:** Run `mix test test/bench/measure_test.exs test/bench/report_test.exs`. Expected: FAIL.
- [x] **Step 3:** Implement.
- [x] **Step 4:** Run the tests. Expected: PASS. Then run `mix quality`. Expected: PASS.
- [x] **Step 5: First comparison.** Re-check the read-only-connection option name first. Then:
  1. Run `MIX_ENV=bench mix authzura.bench --scale small`, once per mode.
  2. Optionally, run `--scale large` once and quote its table in `REPORT.md`.
  3. Write `bench/TRIAGE.md`, with one entry per failing or inconclusive target. Each entry records:
     - the id and mode;
     - the target and the evidence;
     - the gap class: `plan-shape`, `db-time`, `data-statements`, `overhead` (from `mix authzura.bench.micro --check`, run after Task 8) or `harness`;
     - the suspected cause;
     - a status: `open`, `fixed in <checkpoint>` or `documented gap`.
  4. Rerun each inconclusive id 3 times with `--only`. If it stays inconclusive, class it `harness`.
  5. End `TRIAGE.md` with a section, "Single-statement preloads (later stage)", that records the `preload-*` numbers as evidence only.
  6. If nothing fails, write `No gaps: all targets pass at small`.
- [ ] **Step 6: Checkpoint.** `bench: add mix authzura.bench and record the first comparison and triage`

---

### Task 8: Benchee micro-benchmarks and a committed baseline

**Files:**
- Create: `bench/lib/authzura/bench/micro.ex`, `bench/lib/mix/tasks/authzura.bench.micro.ex`, `bench/baselines/micro.json`
- Modify: `mix.exs` (add the Benchee dep; register `authzura.bench.micro` → `:bench` in `preferred_envs`)
- Test: `test/bench/micro_test.exs` (pure)

**Interfaces:**
- **`Micro.run(opts) :: %{env, jobs: %{String.t() => %{median_ns: number(), runs: [number()]}}}`.**
  - `env` is `%{otp, elixir, os, cpu_model, schedulers}`.
  - Jobs:
    - `scope/3` on `flat-tenant` and `rel-filter-3hop`;
    - input validation on `input-filter`;
    - preload-tree validation on `preload-nested-3`;
    - `overhead`, computed as `:execute` minus the summed `:query` durations from Task 5's spans.
  - Each job runs 3 times through Benchee. `median_ns` is the median of the three run medians.
  - Jobs run against the `small` dataset from Task 6.
- **`Micro.regressions(current, baseline, tolerance \\ 0.20) :: {:ok, [String.t()]} | {:skipped, :env_mismatch | :no_baseline}`.** A job counts as a regression only when **all 3** of its runs exceed `baseline × 1.2`.
- **`mix authzura.bench.micro [--record | --check]`.**
  - `--record` writes `bench/baselines/micro.json`, including `env`.
  - `--check` exits non-zero on a regression, and warns on a skip.
  - It is run on demand only, never in CI.

- [x] **Step 1: Write the failing tests:**

```elixir
test "a job regresses only when all 3 runs exceed tolerance" do ... end
test "a different env or a missing baseline is skipped, never a failure" do ... end
test "the baseline file carries env and no values or SQL" do ... end
```
- [ ] **Step 2:** Run `mix test test/bench/micro_test.exs`. Expected: FAIL.
- [x] **Step 3:** Implement `Micro` and the mix task.
- [x] **Step 4:** Run the tests. Expected: PASS.
- [x] **Step 5:** Run `MIX_ENV=bench mix authzura.bench.micro --record`, then `--check`. Expected: no regressions.
- [x] **Step 6:** Run `mix quality`. Expected: PASS.
- [ ] **Step 7: Checkpoint.** `bench: add Benchee micro-benchmarks with a committed baseline`

---

### Task 9: Fix the gaps (one sub-task per gap class in `bench/TRIAGE.md`)

Each gap gets a **failing test first**, then the fix. Every fix must keep these green:
- `mix test` (including `:property`)
- `mix test --only hasura_parity`
- `mix test --only hasura_differential`
- `mix quality`

No fix may weaken a Global Constraints check or change a response.

**Files:** the module the entry names (for example `preload_query.ex`, `compiler.ex`, `scope.ex` or `executor.ex`). Tests go in `test/bench/regression_test.exs` (`:bench`), plus an `Ecto.Adapters.SQL.to_sql` snapshot beside the changed module.

**Plan-shape and DB-time gaps:**
- [x] **Step 1:** Write the failing tests: `test "<id> uses an index on <table>"`, built from `Measure.plans/2`, and a SQL snapshot that pins the fixing property.
- [x] **Step 2:** Run them. Expected: FAIL.
- [x] **Step 3:** Fix it.
- [x] **Step 4:** Run the suites, then `mix authzura.bench --only <id> --check`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `perf: <finding> for <id>`

**Data-statement gaps:**
- [x] **Step 1:** Write a failing test that asserts the exact category counts from `Measure.statements/3`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Fix it.
- [x] **Step 4:** Run the suites. Expected: PASS.
- [ ] **Step 5: Checkpoint.**

**Overhead gaps:** write a failing `Micro.regressions/3` test, profile with `mix profile.tprof` and record the top 5 lines in the triage entry, then fix. Re-record the baseline only after a fix lands, and say so in the checkpoint message.

**Harness gaps:** reproduce the false result in a `test/bench` test, then fix the measurement. Never change Authzura for a harness gap.

- [x] **Final step:**
  1. Run `mix authzura.bench --scale small --check` in both modes.
  2. Mark each fixed entry `fixed in <checkpoint>`.
  3. Mark each entry whose target still fails `documented gap` (owner ruling). List it under "Known gaps" in `REPORT.md`. It is never marked fixed, and its limit is never relaxed.
  4. Suggested message: `bench: record comparison after gap fixes`.

---

### Task 10: Docs, CHANGELOG and release readiness

**Files:**
- Create: `docs/guides/compatibility.md`, `CHANGELOG.md`, `test/docs_test.exs`
- Modify:
  - `README.md`: one line in "Documentation".
  - `mix.exs`: the docs `extras`.
  - `docs/guides/security.md`: a link to the new guide.

**Interfaces:**
- **`docs/guides/compatibility.md`**, at most 100 lines, covering:
  - what the property, differential and sweep suites prove;
  - their on-demand commands;
  - the verdict rules: a leak always stops the run, and an over-deny passes only as a reviewed divergence;
  - the benchmark method and its four targets, with the fairness note;
  - the summary table and the "Known gaps";
  - the real-world check, worded as "validated against a large real-world Hasura v2 metadata set", with counts only;
  - single-statement preloads, named as later-stage work.
- **`CHANGELOG.md`**, in Keep a Changelog form, starting at **`## Unreleased`** (owner ruling).

- [x] **Step 1: Write the failing test** `test/docs_test.exs`:

```elixir
test "README links the compatibility guide" do
  assert File.read!("README.md") =~ "docs/guides/compatibility.md"
end

test "the guide states the targets, the verdict rules and known gaps" do
  g = File.read!("docs/guides/compatibility.md")
  for t <- ["1.25×", "1 + L", "1.5×", "15 %", "reviewed divergence", "Known gaps"], do: assert(g =~ t)
end

test "no doc or bench file names a local path" do
  for f <- Path.wildcard("{README.md,CHANGELOG.md,docs/**/*.md,bench/**/*.{md,json}}"),
      do: refute(File.read!(f) =~ ~r{/Users/|/home/|/private/tmp/}, f)
end
```
- [ ] **Step 2:** Run `mix test test/docs_test.exs`. Expected: FAIL.
- [x] **Step 3:** Write the guide, the CHANGELOG and the README line.
- [x] **Step 4:** Run `mix test`, `mix docs` and `mix quality`. Expected: PASS, and `mix docs` prints no warnings.
- [ ] **Step 5: Checkpoint.** `docs: add compatibility guide and CHANGELOG`. Do not tag. Tell the owner the remaining step is theirs: run `mix authzura.check` against a large real-world metadata set, and record counts only under `## Unreleased`.

---

## Self-review notes

- **Spec coverage:**

  | Spec goal | Task |
  |---|---|
  | 1. Properties | 1 |
  | 2. Differential | 2 |
  | 3. Coverage gate | 3 |
  | 4. Sweep | 4 |
  | 5. Benchmark | 6–7 |
  | 6. Telemetry spans | 5 |
  | 7. Micro-benchmarks | 8 |
  | 8. Comparison and triage | 7 |
  | 9. Fixes | 9 |
  | 10. Docs | 10 |
- **Owner rulings encoded:**
  - one PR workflow and no scheduled CI;
  - on-demand differential and benchmark;
  - DB-time fairness, with no wrapper;
  - the targets and the 25 % floor;
  - `## Unreleased`;
  - reviewed divergence vs leak;
  - documented gaps;
  - single-statement preloads at a later stage.
- **Kept at owner request:** Benchee micro-benchmarks with a committed baseline, checked on demand (Task 8), and the telemetry span refactor with bounded metadata (Task 5).
- **Cut for simplicity (owner "KISS"):**
  - nightly and bench workflows, and the scheduled-CI and public-CI policy;
  - load generators and latency;
  - per-engine DB roles, pool pinning and warm-plan capture;
  - the allowlist serializer;
  - per-run result directories.
- **Names:**
  - Task 1: `Gen.batch/2`, `Gen.request/1`, `Gen.coverage_tags/1`, `Gen.oracle/1`.
  - Task 2: `Verdict.context/2`, `Verdict.classify/3` (reused in Task 6's gate) and `Gen.Save.write!/3`.
  - Task 6: `Scenarios.all/0` and `Gate.check/1`.
  - Task 5: `Telemetry.span/4`, `reason_class/1` and `rows/1`.
  - Task 7: `Measure.statements/3`, `db_time/1`, `plans/2` and `check/3`, and `Report.write!/1`.
  - Task 8: `Micro.run/1` and `Micro.regressions/3`.

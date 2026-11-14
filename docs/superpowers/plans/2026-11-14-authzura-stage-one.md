# Authzura Stage One Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Authzura stage one, an Elixir library that reads Hasura v2
select permissions from `hdb_catalog` and enforces them on Ecto reads:
row filters, columns, limits, root fields and relationship preloads.
Anything else is denied.

**Architecture:**
- **Pure core.** A Hasura source translates metadata into a model built
  around a syntax-independent filter AST. A load-time validator proves
  every permission can be compiled. A compiler turns the model plus a
  session into Ecto dynamics with schema-qualified `EXISTS` subqueries.
- **Side effects stay at the edges:**
  - catalog loading and introspection
  - a per-instance Store, which publishes immutable generations and polls
    for changes
  - the executors (`all`/`one`), which run read-only transactions and
    load relationship preloads
- **One adapter.** All Postgres-specific SQL sits behind an adapter
  behaviour.

**Tech Stack:**
- Elixir ~> 1.19 (OTP 28), Ecto/Ecto SQL ~> 3.13, Postgrex, Jason,
  Telemetry, NimbleOptions, optional JOSE
- Postgres 16 (Docker)
- Hasura `v2.51.6`, the latest v2 release and the compatibility target
  (Docker, parity suite only)

**Spec:** `docs/superpowers/specs/2026-11-14-authzura-stage-one-design.md`.
Every task lists its own acceptance cases, so a task can be built from the
task text plus this header. If a task and the spec conflict, the spec wins.
Flag the conflict when that happens.

## Global Constraints

- **Read-only.** The public API reads data only. Writes are refused, never
  half-enforced. Never write to `hdb_catalog`.
- **Deny by default.** Metadata that is unknown, untranslatable or
  uncompilable denies that role/table/operation and records a
  `%Diagnostic{}`. Nothing ever degrades into allowing access.
- **No atoms from metadata or input.** Table, column, relationship and
  role names stay strings. Correlation aliases come only from the fixed
  pool `:__authzura_0` through `:__authzura_15`. Alias 0 is the root, so
  **binding depth** (nested relationship and `_exists` levels) is at most
  15.
- **Recursion limits.** Syntactic depth (any nesting, including
  `_and`/`_or`/`_not`) is at most 32 for permissions and 8 for input. Node
  count is at most 1000 for permissions and 100 for input.
- **Schema-qualified SQL.** Every source Authzura emits (the root,
  `EXISTS` subqueries and preload queries) carries an explicit prefix.
- **One role per request.** These are denied, each with a diagnostic:
  merged roles, inherited roles, computed fields, and remote relationships
  (including v2.51's `to_source` relationships in permission filters).
- **Composite relationship keys:** at most 8 column pairs. Wider mappings
  are denied at load time.
- **Public repo.** Code, docs, tests and fixtures never mention a private
  application or a local file-system path. Hasura and the agoodway GitHub
  repositories may be referenced.
- **Toolchain:** `.tool-versions` pins `elixir 1.19.1-otp-28` and
  `erlang 28.1.1`.
- **Quality gate.** `mix quality` must pass at the end of every task:
  1. `compile --warnings-as-errors`
  2. `deps.unlock --unused`
  3. `format --check-formatted`
  4. `sobelow --config`
  5. `ex_dna`
  6. `doctor`
  7. `credo --strict`
  8. `dialyzer`
- **ExSlop is enabled** in `.credo.exs` with
  `++ Enum.map(ExSlop.recommended_checks(), &{&1, []})`.
- **Docs.** Moduledoc coverage is 100%, and every struct has a `@type t`.
- **Error shape.** Expected denials return `{:error, reason}`. The public
  reasons are exactly:
  - `:forbidden`
  - `{:forbidden_columns, [String.t()]}`
  - `{:missing_session_variable, name}`
  - `{:invalid_session_value, name, reason}`
  - `{:invalid_session, kind, detail}`
  - `{:unsupported_query, reason}`
  - `{:invalid_input, reason}`
  - `:root_field_disabled`
  - `:stale_permissions`
  - `:not_ready`
  - `:multiple_results`

  JWT reasons are in Task 17. The `!` variants raise
  `%Authzura.Error{reason: reason}`.
- **Imports.** Module-level `alias`, `import` and `require` only.
- **Commits.** The repo owner reviews and commits. Where a step says
  **Checkpoint**, stage the listed files and stop with the suggested
  message. Commit only if your operator allows it. Never add AI
  attribution trailers.

## Review Focus

These are failure modes the spec implies but doesn't spell out. A test in
the owning task pins each one:

1. **Quoted or unusual identifiers.** Tables and columns with uppercase
   letters, spaces or reserved words (`"Order"`, `"line item"`, `user`)
   must be quoted correctly in emitted SQL and in introspection. Owners:
   Tasks 2 and 9.
2. **Large preload batches.** Thousands of parent rows must stay under
   Postgres's 65,535 bind-parameter limit. Keys go in as one array
   parameter per key column. Owner: Task 15.
3. **Session strings cast to non-text column types.** `uuid`,
   `timestamptz`, `numeric`, `boolean`, enums, `citext` and arrays must
   each compare correctly, or fail with `{:invalid_session_value, ...}`
   before any SQL runs. Owners: Tasks 2 and 6.
4. **Tracked views.** A view has no FKs, and all its columns report as
   nullable. It must still load, use manual relationships, and compile its
   null-aware forms. Owners: Tasks 5 and 9.
5. **The same table name in two schemas** (`public.users` and
   `audit.users`). Permissions, relationship targets and prefix pinning
   must never cross between them. Owners: Tasks 9 and 11.

---

## File Structure

```
mix.exs, .formatter.exs, .credo.exs, .doctor.exs, .sobelow-conf, .tool-versions,
.gitignore, docker-compose.yml, docker/postgres-init.sql, config/{config,dev,test}.exs, README.md

lib/authzura.ex                               public API + child_spec
lib/authzura/error.ex                         exception for ! variants
lib/authzura/options.ex                       NimbleOptions: instance, per-call, repo_opts
lib/authzura/telemetry.ex                     span helpers
lib/authzura/model/{table,column,relationship,permission,snapshot,diagnostic}.ex
lib/authzura/ast.ex                           filter AST types + walk helpers
lib/authzura/session.ex                       %Session{} + new/2
lib/authzura/jwt.ex                           optional JWT verification (JOSE)
lib/authzura/source.ex                        Source behaviour (load, version, parse_input)
lib/authzura/sources/hasura.ex                Hasura source: load/version/parse_input
lib/authzura/sources/hasura/bool_exp.ex       pure bool_exp parser (:permission | :input)
lib/authzura/sources/hasura/metadata.ex       pure metadata -> permissions, relationship resolution
lib/authzura/adapter.ex                       Adapter behaviour
lib/authzura/adapters/postgres.ex             operator signatures, compile_operator, preload SQL
lib/authzura/adapters/postgres/introspection.ex catalog queries + fingerprint
lib/authzura/adapters/postgres/values.ex      session value casting + array-literal parser
lib/authzura/compiler.ex                      AST + session -> Ecto dynamic
lib/authzura/compiler/aliases.ex              fixed alias pool
lib/authzura/validator.ex                     session-free enforceability check at load
lib/authzura/store.ex                         GenServer: generations, polling, freshness
lib/authzura/plan.ex                          %Plan{} shared by scope/input/executor/preload
lib/authzura/query_shape.ex                   accepted-grammar validation of caller queries
lib/authzura/scope.ex                         root derivation, prefix pin, projection, limits, unions
lib/authzura/input.ex                         validated outside input
lib/authzura/preload/tree.ex                  preload tree validation + Ecto preload translation
lib/authzura/preload/loader.ex                per-level relationship loading
lib/authzura/executor.ex                      all/one: transactions, repo binding, preload orchestration
lib/mix/tasks/authzura.check.ex

test/test_helper.exs
test/support/repo.ex                          Authzura.Test.Repo, Authzura.Test.OtherRepo
test/support/data_case.ex                     sandboxed, async-safe
test/support/committed_case.ex                unsandboxed, async: false, truncation cleanup
test/support/fixture_schema.ex                SQL for the fixture database (repo-parameterized)
test/support/schemas.ex                       Ecto schemas over fixture tables
test/support/hasura_fixture.ex                metadata builder + hdb_catalog writer
test/support/test_source.ex                   Agent-controlled Source for Store tests
test/authzura/**, test/integration/**, test/feasibility/**, test/parity/**
```

### Fixture database

`FixtureSchema.up(repo, opts)` creates the fixture database. Later tasks
only append to it.

- **Schemas:** `public` and `audit`.
- **Setup:** `CREATE EXTENSION citext`, then
  `CREATE TYPE public.article_status AS ENUM ('draft','review','published')`.
- **`public` tables:**
  - `organizations(id bigint pk, name text not null)`
  - `users`:
    - `id bigint pk`
    - `org_id bigint not null references organizations`
    - `manager_id bigint null references users`
    - `email citext not null unique`
    - `role text not null`
    - `is_admin boolean not null default false`
    - `salary numeric null`
  - `user_profiles(user_id bigint pk references users, bio text null)`
  - `articles`:
    - `id bigint pk`
    - `org_id bigint not null references organizations`
    - `author_id bigint not null references users`
    - `editor_id bigint null references users`
    - `status public.article_status not null`
    - `is_published boolean not null`
    - `title text not null`
    - `body text null`
    - `internal_notes text null`
    - `assignees jsonb not null default '{}'`
    - `external_ref uuid null`
    - `published_at timestamptz null`
  - `comments`:
    - `id bigint pk`
    - `article_id bigint not null references articles`
    - `author_id bigint not null references users`
    - `body text not null`
  - `org_memberships(org_id bigint, user_id bigint, level int not null,
    primary key (org_id, user_id))`
  - `membership_notes`:
    - `id bigint pk`
    - `org_id bigint null`
    - `user_id bigint null`
    - `note text`
    - `foreign key (org_id, user_id) references org_memberships`
  - `"Order"("Id" bigint pk, "line item" text null)`
  - sequence `public.test_seq`, used by the read-only test in Task 12
  - view `published_articles`:
    `select id, org_id, author_id, title from articles where is_published`
- **`audit` tables:**
  - `audit.users(id bigint pk, note text null)`
  - `audit.article_events(id bigint pk, article_id bigint not null, kind
    text not null)`, with no FK (it's used for manual relationships)
- **`opts[:hasura_catalog]`** (default `true`) also creates
  `hdb_catalog.hdb_metadata(id integer primary key, metadata json not null,
  resource_version integer not null default 1)`.
  - This matches Hasura v2's layout: the column is `json`, so read it
    with `metadata::jsonb`.
  - The parity suite passes `false`, because real Hasura creates its own
    catalog.

---

### Task 1: Scaffold, quality tooling and test harnesses

**Files:**
- Create: `mix.exs`, `.formatter.exs`, `.credo.exs`, `.doctor.exs`,
  `.sobelow-conf`, `.tool-versions`, `.gitignore`, `docker-compose.yml`,
  `docker/postgres-init.sql`, `config/{config,dev,test}.exs`
- Create: `lib/authzura.ex` (moduledoc only), `lib/authzura/error.ex`
- Create: `test/test_helper.exs`,
  `test/support/{repo,data_case,committed_case,fixture_schema,schemas}.ex`
- Modify: `README.md`. Replace the old planning README with a short status
  stub that links to the spec. Task 18 writes the full guide.
- Test: `test/authzura/harness_test.exs`

**Interfaces:**
- **Produces:**
  - `Authzura.Test.Repo`, plus `Authzura.Test.OtherRepo`, a second repo on
    the same database
  - `Authzura.DataCase`: sandboxed; it imports `Ecto.Query` and exposes
    `Repo`
  - `Authzura.CommittedCase` (`async: false`):
    - In `setup` it switches `Sandbox.mode(Repo, :auto)` and
      `Sandbox.mode(OtherRepo, :auto)`. ExUnit runs every async module
      before the sync ones, so this can't affect DataCase tests.
    - In `on_exit` (which runs in a fresh process with its own auto-mode
      connection), it truncates every fixture table plus
      `hdb_catalog.hdb_metadata`, then switches back to `:manual`.
    - Any Store, task or second connection started in a test gets real,
      committed, unsandboxed connections without an ownership setup.
  - **Which case to use:** tests that execute through Authzura's
    executors (`all`/`one`/`all_input`) use **CommittedCase**, because
    they open real transactions with `SET TRANSACTION` and the sandbox's
    wrapping transaction would break that. Tests that only build or
    inspect queries (`scope`, `to_sql`, plain `Repo.all` on a scoped
    query) use DataCase.
  - `FixtureSchema.up(repo, opts)`
  - `%Authzura.Error{reason: term()}`
- **`mix.exs`** mirrors
  https://github.com/agoodway/pgflow/blob/main/mix.exs:
  - `app: :authzura`, `@version "0.1.0"`,
    `@source_url "https://github.com/agoodway/authzura"`
  - `elixirc_paths(:test)` includes `test/support`
  - `cli/0` sets `preferred_envs: [quality: :test]`
  - dialyzer `plt_add_apps: [:mix, :ex_unit]`
  - `package` files are `~w(lib mix.exs README.md LICENSE .formatter.exs)`
  - no `mod:` callback
- **Dependencies:**
  - Runtime: `ecto ~> 3.13`, `ecto_sql ~> 3.13`, `postgrex`, `jason`,
    `telemetry`, `nimble_options`, and `{:jose, "~> 1.11", optional:
    true}`.
  - Dev/test: `ex_doc`, `credo`, `dialyxir`, `doctor`, `ex_slop`,
    `sobelow` and `ex_dna`, at current releases, pinned `~> x.y.z` the
    way pgflow pins them.
- **Aliases:**
  - `test: ["ecto.create --quiet -r Authzura.Test.Repo", "test"]`
  - `quality`, with the 8 steps from Global Constraints
- **`test_helper.exs`** runs, in order:
  1. `{:ok, _} = Authzura.Test.Repo.start_link()` and
     `{:ok, _} = Authzura.Test.OtherRepo.start_link()`
  2. `FixtureSchema.up(Authzura.Test.Repo, [])`
  3. `Ecto.Adapters.SQL.Sandbox.mode(Authzura.Test.Repo, :manual)`
  4. `ExUnit.start(exclude: [:hasura_parity])`
- **`docker-compose.yml`:**
  - `postgres` service: `postgres:16` on port 5432. It mounts
    `docker/postgres-init.sql`, which creates the `authzura_test` and
    `authzura_parity` databases, and has a `pg_isready` healthcheck.
  - `hasura` service: `hasura/graphql-engine:v2.51.6`, under
    `profiles: ["parity"]`, with:
    - `depends_on: postgres: condition: service_healthy`
    - `HASURA_GRAPHQL_DATABASE_URL` pointing at `authzura_parity`
    - `HASURA_GRAPHQL_ADMIN_SECRET=parity`
    - `HASURA_GRAPHQL_JWT_SECRET={"type":"HS256","key":"<32+ byte test key>"}`
    - a `/healthz` healthcheck

- [ ] **Step 1: Write the failing test**

```elixir
defmodule Authzura.HarnessTest do
  use Authzura.DataCase, async: true

  test "fixture schema exists in both schemas and hdb_catalog" do
    assert %{rows: [[1]]} = Repo.query!("(select 1 from public.articles limit 0) union all select 1")
    assert %{num_rows: 0} = Repo.query!(~s(select * from "audit"."users"))
    assert %{num_rows: 0} = Repo.query!("select * from hdb_catalog.hdb_metadata")
  end
end
```

- [ ] **Step 2: Run** `docker compose up -d postgres && mix test test/authzura/harness_test.exs`.
  Expected: compile failure (`Authzura.DataCase` is undefined).
- [ ] **Step 3: Implement the scaffold.** `FixtureSchema.up/2` must be
  idempotent: use `IF NOT EXISTS`, and create the enum inside a
  `DO $$ ... EXCEPTION WHEN duplicate_object ... $$` block.
- [ ] **Step 4: Add a CommittedCase smoke test.**
  - After inserting an organization, a second connection sees it. Use
    `Task.async` to check out a connection and run `Repo.query!`.
  - After `on_exit` truncation, the table is empty for the next test.
- [ ] **Step 5: Run** `mix test && mix quality`. Expected: PASS, and
  quality exits 0.
- [ ] **Step 6: Checkpoint.**
  `chore: scaffold authzura with quality tooling and test harnesses`

---

### Task 2: Ecto/Postgres feasibility spike (kept as regression tests)

This task proves every Ecto and Postgres construct the later tasks rely
on. If a construct fails in the pinned Ecto version, change the approach
**here**, record the replacement in this test file's moduledoc, and have
later tasks use the replacement.

**Files:**
- Test: `test/feasibility/ecto_constructs_test.exs` (DataCase) and
  `test/feasibility/transactions_test.exs` (CommittedCase)

- [ ] **Step 1: Write the construct tests.** Each one asserts on
  `Ecto.Adapters.SQL.to_sql(:all, Repo, q)` and on the returned rows.
  Assemble queries at runtime, never with compile-time literals for
  names.
  1. **Root alias:** `from(q in query, as: ^alias)` attaches
     `:__authzura_0` to an unaliased `from(a in Articles)`.
  2. **Correlated `exists`:** this query correlates, and its SQL contains
     `"public"."comments"`:

     ```elixir
     exists(from c in ^"comments", prefix: ^"public", as: ^:__authzura_1,
       where: field(c, ^"article_id") == field(parent_as(^:__authzura_0), ^"id"))
     ```
  3. **Quoting:** `field(o, ^"line item")` on source `{"Order"}` with
     prefix `"public"` emits a quoted `"public"."Order"` and a quoted
     `"line item"`.
  4. **Prefixes:** the runtime table name `"users"` hits different tables
     under prefix `"audit"` and prefix `"public"`.
  5. **`unnest` join:** this fragment works as a join source:

     ```elixir
     fragment("SELECT * FROM unnest(?::bigint[], ?::text[]) WITH ORDINALITY AS p(k1, k2, idx)",
              type(^ids, {:array, :integer}), type(^names, {:array, :string}))
     ```

     Also prove the variants for `uuid[]`, `citext[]` and
     `public.article_status[]`. Each SQL cast comes from a fixed type name
     chosen per column kind.
     - Record which form works for each type.
     - Record whether `citext = citext` equality applies, so that
       `"A@x.com"` matches `"a@x.com"`.
     - Fragment SQL must be literal, so the cast type has to come from a
       finite set. Record the supported key kinds: bigint, integer, uuid,
       text, citext and varchar, plus enum through a `?::text::<enum>`
       workaround or a fallback.
     - An unsupported key kind is denied at load time (Task 9).
  6. **Window ranking:** an inner query selects
     `row_number() over (partition by c.article_id order by c.id)` as
     `rn`, wrapped in
     `from(s in subquery(inner), where: s.rn <= ^1, order_by: [s.idx, s.rn])`.
  7. **Enum comparison with a session string:** either
     `field(a, ^"status") == type(^"draft", ...)` or a SQL cast. Record
     the form that works. An invalid label must be caught in Elixir,
     against the introspected labels, before the query runs.
- [ ] **Step 2: Write the transaction tests** (CommittedCase).
  1. Inside `Repo.transaction`, the first statement
     `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`
     succeeds, and a later `INSERT` raises `read_only_sql_transaction`.
  2. **Isolation:** another connection commits a row after the first
     read.
     - Under `REPEATABLE READ`, a second read in the same transaction
       doesn't see that row.
     - Under the default `READ COMMITTED`, it does.

     This proves the Task 16 consistency test can detect the difference.
  3. **`:persistent_term` and `:atomics`:** a generation stored under
     `{Authzura.Store, name}` holds an `:atomics` ref, and that ref can be
     updated without rewriting the term.
- [ ] **Step 3: Run** `mix test test/feasibility`. Iterate until it
  passes, recording each chosen form in the moduledocs.
- [ ] **Step 4: Run** `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `test: prove Ecto and Postgres constructs used by the compiler`

---

### Task 3: Model structs and filter AST

**Files:**
- Create:
  `lib/authzura/model/{table,column,relationship,permission,snapshot,diagnostic}.ex`,
  `lib/authzura/ast.ex`
- Test: `test/authzura/ast_test.exs`

**Interfaces:**
- **Produces the type contract** (Review Focus 3).
- **`%Column{}`:**
  - `name: String.t()`
  - `pg_type: String.t()`, from `format_type`, e.g.
    `"public.article_status"`
  - `base_kind`: one of `:integer | :bigint | :numeric | :boolean | :text
    | :citext | :uuid | :timestamptz | :timestamp | :date | :jsonb | :json
    | :enum | :array | :other`
  - `ecto_type: atom() | {:array, atom()}`, the parameter type used with
    `type/2`
  - `enum_labels: [String.t()] | nil`
  - `nullable?: boolean()`
- **`%Relationship{}`:** `name: String.t()`, `kind: :object | :array`,
  `target: {schema, name}`, and
  `mapping: [{local :: String.t(), remote :: String.t()}]`.
- **`%Table{}`:** `schema`, `name`, `kind: :table | :view`,
  `columns: %{String.t() => Column.t()}`, `primary_key: [String.t()]` and
  `relationships: %{String.t() => Relationship.t()}`.
- **`%Permission{}`:**
  - `role :: String.t()`
  - `table :: {schema, name}`
  - `operation :: :select | :insert | :update | :delete`
  - `filter :: AST.t() | nil`
  - `columns :: [String.t()]`, with wildcards already expanded
  - `limit :: non_neg_integer() | nil`
  - `allow_aggregations :: boolean()`
  - `root_fields :: :all | [:select | :select_by_pk | :select_aggregate]`
  - `check :: AST.t() | nil`
  - `presets :: map()`
  - `backend_only :: boolean()`
  - `status :: :ok | {:denied, [Diagnostic.t()]}`
- **`%Diagnostic{}`:** `severity: :deny | :warning`, `role`, `table`,
  `operation`, `path: [String.t()]` and `reason: term()`.
- **`%Snapshot{}`:**
  - `tables: %{{s, n} => Table.t()}`
  - `permissions: %{{role, {s, n}, op} => Permission.t()}`
  - `version: {integer(), binary()}`
  - `diagnostics: [Diagnostic.t()]`
- **`Authzura.AST`:**
  - The type:

    ```elixir
    @type t :: {:and, [t]} | {:or, [t]} | {:not, t}
             | {:compare, String.t(), atom(), value}
             | {:relationship, String.t(), t}
             | {:exists, {String.t(), String.t()}, t}
    @type value :: {:literal, term()} | {:session, String.t()}
    ```
  - `session_refs/1 :: MapSet.t()`
  - `binding_depth/1`: relationship and exists levels
  - `syntactic_depth/1`: every nesting level
  - `node_count/1`
  - `root_columns/1`: ignores relationship and exists subtrees

- [ ] **Step 1: Write the failing tests.**
  - `binding_depth({:relationship, "a", {:relationship, "b", {:and, []}}}) == 2`
  - `binding_depth({:exists, {"public", "users"}, {:and, []}}) == 1`
  - `syntactic_depth({:and, [{:not, {:or, []}}]}) == 3`
  - `session_refs` finds names inside nested relationship and exists
    nodes.
  - `root_columns` excludes columns inside relationship subtrees.
- [ ] **Step 2: Run** `mix test test/authzura/ast_test.exs`. Expected:
  FAIL.
- [ ] **Step 3: Implement** the structs, with `@enforce_keys` on identity
  fields, and write the AST functions as reductions.
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: add permission model and filter AST`

---

### Task 4: Session construction and role resolution

**Files:**
- Create: `lib/authzura/session.ex`
- Test: `test/authzura/session_test.exs`

**Interfaces:**
- **Produces** `%Authzura.Session{role: String.t(), vars: %{String.t() =>
  String.t()}}`. Keys are lowercase, and `vars` includes
  `"x-hasura-role"`.
- **`Session.new(map(), keyword()) :: {:ok, t} | {:error,
  {:invalid_session, kind, detail}}`:**
  - Options: `allowed_roles:`, `default_role:` and `requested_role:`.
  - Error kinds: `:conflicting_keys`, `:role_not_allowed` and `:no_role`.
- **Rules:**
  1. Keep only keys whose case-folded form starts with `x-hasura-`.
  2. Keys that fold to the same name with different values give
     `:conflicting_keys`.
  3. Drop `x-hasura-admin-secret`, `x-hasura-allowed-roles` and
     `x-hasura-default-role`.
  4. The requested role is `requested_role:`, falling back to the map's
     `x-hasura-role`. `""` counts as absent.
  5. The effective role is the requested role, falling back to
     `default_role:`.
  6. If `allowed_roles:` is given, the effective role must be in it. That
     includes a default role, and `[]` rejects everything.
  7. No effective role gives `:no_role`.
  8. Write the effective role back to `vars["x-hasura-role"]`.

- [ ] **Step 1: Write the failing tests**, one per rule:

```elixir
assert {:ok, %Session{role: "editor", vars: %{"x-hasura-user-id" => "1", "x-hasura-role" => "editor"}}} =
  Session.new(%{"X-Hasura-User-Id" => "1", "Other" => "x"}, allowed_roles: ["editor"], default_role: "editor")
assert {:error, {:invalid_session, :role_not_allowed, "admin"}} =
  Session.new(%{}, allowed_roles: ["reader"], default_role: "admin")
assert {:error, {:invalid_session, :role_not_allowed, "user"}} =
  Session.new(%{"x-hasura-role" => "user"}, allowed_roles: ["contractor"], default_role: "contractor")
assert {:ok, %Session{role: "b"}} =
  Session.new(%{"x-hasura-role" => "a"}, requested_role: "b", allowed_roles: ["a", "b"], default_role: "a")
assert {:ok, %Session{role: "a"}} = Session.new(%{"x-hasura-role" => ""}, allowed_roles: ["a"], default_role: "a")
assert {:error, {:invalid_session, :conflicting_keys, "x-hasura-user-id"}} =
  Session.new(%{"X-Hasura-User-Id" => "1", "x-hasura-user-id" => "2"}, default_role: "a")
assert {:ok, s} = Session.new(%{"x-hasura-admin-secret" => "s"}, default_role: "a")
refute Map.has_key?(s.vars, "x-hasura-admin-secret")
assert {:error, {:invalid_session, :role_not_allowed, "a"}} = Session.new(%{}, allowed_roles: [], default_role: "a")
assert {:error, {:invalid_session, :no_role, nil}} = Session.new(%{}, [])
```

- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** it as a `with` pipeline.
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: add session normalization and Hasura role resolution`

---

### Task 5: Postgres introspection and fingerprint

**Files:**
- Create: `lib/authzura/adapter.ex`,
  `lib/authzura/adapters/postgres/introspection.ex`
- Test: `test/authzura/adapters/postgres/introspection_test.exs`
  (DataCase), plus `test/integration/fingerprint_test.exs` (CommittedCase,
  because it runs DDL)

**Interfaces:**
- **`Authzura.Adapter` callbacks:**
  - `introspect(repo, [{schema, name}]) :: {:ok, %{{s, n} => Table.t()},
    [fk]} | {:error, term()}`, where `fk :: %{table: {s, n}, columns:
    [String.t()], ref_table: {s, n}, ref_columns: [String.t()]}`. Columns
    are paired by ordinality from `conkey`/`confkey`.
  - `fingerprint(repo, [{s, n}]) :: {:ok, binary()} | {:error, term()}`
  - These are the only two callbacks declared in this task. Tasks 6 and
    15 add the rest.
- **`Introspection` reads:**
  - `pg_class` (relkind `r`, `p`, `v` and `m`)
  - `pg_attribute` (`attnum > 0 AND NOT attisdropped`), with
    `format_type` and `attnotnull`
  - enum labels from `pg_enum`
  - the primary key, and FKs from `pg_constraint`
- **Introspection rules:**
  - Every query passes schema and name as **bind parameters**.
  - Each column's `base_kind` and `ecto_type` are derived from its type,
    and enum labels go into `enum_labels`.
- **`fingerprint/2`** is the md5 of a deterministically ordered aggregate
  of those same rows: column names, types, nullability and constraints.

- [ ] **Step 1: Write the failing tests.**
  - `users.email` has `base_kind: :citext` and `nullable?: false`.
  - `articles.status` has `base_kind: :enum` and
    `enum_labels: ["draft", "review", "published"]`.
  - `articles.external_ref` has `base_kind: :uuid`.
  - `published_articles` has `kind: :view`, and all its columns are
    nullable (Review Focus 4).
  - `"Order"` has a column named `"line item"` (Review Focus 1).
  - The `membership_notes` FK has `columns: ["org_id", "user_id"]` and
    `ref_columns: ["org_id", "user_id"]`, in that order.
  - `audit.users` and `public.users` are separate entries (Review Focus
    5).
  - **Fingerprint (CommittedCase):** stable across two calls, and it
    changes after `ALTER TABLE articles ADD COLUMN x int`. Drop the column
    in `on_exit`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: introspect Postgres catalog with a column type contract`

---

### Task 6: Operator signatures and session-value casting

**Files:**
- Create: `lib/authzura/adapters/postgres.ex`,
  `lib/authzura/adapters/postgres/values.ex`
- Test: `test/authzura/adapters/postgres/values_test.exs`,
  `test/authzura/adapters/postgres_test.exs`

**Interfaces:**
- **`operator_signature(op)`** returns `{:ok, %{lhs: :any | :text |
  :jsonb, rhs: :column | :column_array | :boolean | :text | :text_array |
  :jsonb}}`, or `:unsupported`:

  | Operators | `lhs` | `rhs` |
  |---|---|---|
  | `:eq :neq :gt :lt :gte :lte` | `:any` | `:column` |
  | `:in :nin` | `:any` | `:column_array` |
  | `:is_null` | `:any` | `:boolean` |
  | `:like :nlike :ilike :nilike :similar :nsimilar :regex :iregex :nregex :niregex` | `:text` | `:text` |
  | `:contains :contained_in` | `:jsonb` | `:jsonb` |
  | `:has_key` | `:jsonb` | `:text` |
  | `:has_keys_any :has_keys_all` | `:jsonb` | `:text_array` |

  Every other operator is `:unsupported`.
- **`cast_value(operand, rhs_kind, Column.t()) :: {:ok, term()} |
  {:error, reason}`**, in `Values`.
  - `operand` is **tagged**:
    - `{:literal, term}` is an already-decoded JSON value from metadata or
      input. It is never JSON-decoded again, so a string literal stays a
      string even when compared against jsonb.
    - `{:session, raw :: String.t()}` is session text, parsed per kind.
      For jsonb, `Jason.decode/1`; for arrays, `parse_array_literal/1`.
  - It's used for literals at load time and for session values at request
    time.
- **`supported_key_kind?(base_kind) :: boolean()`** is implemented in
  this task, using the key-kind set recorded in Task 2.
- **Adapter callbacks are declared as tasks implement them.** Task 5
  declares `introspect/2` and `fingerprint/2`. This task adds
  `operator_signature/1`, `cast_value/3`, `compile_operator/5` and
  `supported_key_kind?/1`. Task 15 adds `preload_level_query/4`. No
  callback is declared before its implementation exists, which keeps
  `--warnings-as-errors` clean.
  - **Integer and bigint:** strict parsing.
  - **Numeric:** a `Decimal`.
  - **Boolean:** `true t yes y 1` and `false f no n 0`,
    case-insensitively.
  - **uuid:** validated and canonicalized.
  - **timestamptz:** ISO-8601.
  - **Text and citext:** passed through, never truncated.
  - **Enum:** the value must be in `enum_labels`. Otherwise
    `{:invalid_value, pg_type}`.
  - **jsonb:** decoded.
  - **Arrays:** for `:column_array` and `:text_array`, session strings
    are parsed with `parse_array_literal/1`, while literals are already
    lists. Each element is cast.
- **`parse_array_literal(String.t()) :: {:ok, [String.t()]} | {:error,
  :invalid_array_literal}`.** It handles `{}`, quoted elements, escapes,
  and commas inside quotes.
- **`compile_operator(op, lhs_expr, rhs_value, Column.t(), mode ::
  :permission | :input) :: Ecto.Query.dynamic_expr()`:**
  - In `:permission` mode on a nullable column, `:eq` and `:neq` use the
    null-aware forms:
    - `:eq` is `lhs = v OR (lhs IS NULL AND v IS NULL)`
    - `:neq` is `lhs <> v OR (lhs IS NOT NULL AND v IS NULL)`
  - Otherwise they use plain `=` and `<>`.
  - `:in` with `[]` is `false`, and `:nin` with `[]` is `true`.
  - Use the constructs recorded in Task 2 for each type.

- [ ] **Step 1: Write the failing tests.**
  - `parse_array_literal("{1,2,3}") == {:ok, ["1","2","3"]}`
  - `parse_array_literal("{}") == {:ok, []}`
  - `parse_array_literal(~s({"a,b","c\\"d"})) == {:ok, ["a,b", ~s(c"d)]}`
  - `parse_array_literal("{1,2") == {:error, :invalid_array_literal}`
  - `"abc"` cast for bigint gives `{:error, {:invalid_value, "bigint"}}`.
  - `"bogus"` cast for the enum gives
    `{:error, {:invalid_value, "public.article_status"}}`.
  - `"T"` cast for boolean gives `true`.
  - A 64-character string stays intact.
  - `"not-a-uuid"` cast for uuid gives an error.
  - **Integration rows:** uuid, timestamptz, enum and citext comparisons
    each match the right fixture rows (Review Focus 3).
  - The signatures of `:has_key` and `:has_keys_any` match the table
    above.
  - `:in` with `[]` matches no rows, and `:nin` with `[]` matches all
    rows.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: add Postgres operator signatures and value casting`

---

### Task 7: Hasura bool_exp parser, metadata translation and relationship resolution (pure)

**Files:**
- Create: `lib/authzura/sources/hasura/bool_exp.ex`,
  `lib/authzura/sources/hasura/metadata.ex`,
  `test/support/hasura_fixture.ex` (the metadata builder only)
- Test:
  `test/authzura/sources/hasura/{bool_exp,metadata,relationships}_test.exs`

**Interfaces:**
- **Consumes:** the model (Task 3), plus `operator_signature/1` and
  `cast_value/3` (Task 6) for validating literals.
- **`BoolExp.parse(json, mode, ctx) :: {:ok, AST.t()} | {:error, [{path,
  reason}]}`**, where `ctx` is:

  ```elixir
  %{table: Table.t(), tables: map(), adapter: module(),
    limits: %{binding_depth: 15, syntactic_depth: 32 | 8, nodes: 1000 | 100}}
  ```
- **`Metadata.tracked_tables(metadata, source_name) :: {:ok, [{s, n}]} |
  {:error, :source_not_found}`**
- **`Metadata.resolve_relationships(metadata, source_name, tables, fks) ::
  {tables_with_relationships, [Diagnostic.t()]}`**
- **`Metadata.translate(metadata, source_name, tables, adapter) ::
  {[Permission.t()], [Diagnostic.t()]}`**
- **`HasuraFixture.metadata(tables :: [map()], opts) :: map()`** builds a
  v3 metadata map.

**Parser acceptance cases:**
- **Empty and combined forms:**
  - `{}` gives `{:and, []}`.
  - `_or: []` gives `{:or, []}`.
  - `_not: {}` gives `{:not, {:and, []}}`.
  - A multi-key object gives `{:and, [...]}`.
- **Aliases:** `$and`, `$or`, `$not` and `$exists` work, and so do `$`
  operators (`$in`, `$has_key`, ...).
- **Shorthand:** `%{"author_id" => "X-HASURA-USER-ID"}` gives
  `{:compare, "author_id", :eq, {:session, "x-hasura-user-id"}}`.
- **Permission mode:**
  - Any string whose folded form starts with `x-hasura-` becomes a
    `:session` value.
  - Literals are cast at parse time through `cast_value/3`. A failure
    gives `{path, {:invalid_literal, reason}}`.
- **Input mode:**
  - Every value is a literal, including `"X-Hasura-User-Id"`.
  - A `nil` operand gives `{path, :null_operand}`.
  - A relationship or `_exists` gives `{path, :relationship_in_input}`.
- **Relationship keys:** a key that names a relationship of `ctx.table`
  parses its value against the target table.
- **Errors:**
  - An unknown key gives `{path, {:unknown_field, key}}`.
  - `_ceq` and the other column-comparison operators give
    `{path, {:unsupported, :column_comparison}}`.
  - `_cast` gives `{path, {:unsupported, :cast}}`.
  - A computed field or remote relationship gives
    `{path, {:unsupported, :computed_field | :remote_relationship}}`.
  - An unknown operator, or one the adapter reports as `:unsupported`,
    gives `{path, {:unknown_operator, op}}`.
- **Limits:**
  - Binding depth over 15 gives `{path, :too_deep}`.
  - Syntactic depth over the limit gives `{path, :too_deep}`.
  - Node count over the limit gives `{path, :too_large}`.

**Relationship resolution acceptance cases:**
- Cardinality comes from the section the relationship is declared in.
- `foreign_key_constraint_on: "author_id"` (or the list form) uses the
  FK on the local table.
- The `{column(s), table}` form uses the FK on the remote table. That
  covers the array relationship `users.articles` and the reverse object
  relationship `users.profile` via `user_profiles.user_id`.
- The composite `membership_notes.membership` maps
  `[{"org_id","org_id"}, {"user_id","user_id"}]`, in order.
- The manual `articles.events` points at `audit.article_events` and
  keeps its order.
- The view `published_articles` gets a manual relationship.
- Zero or several matching FKs give a `:deny`.
- More than 8 pairs gives a `:deny`.

**Translation acceptance cases:**
- **Source:** sources are selected by name, and an unknown name gives
  `{:error, :source_not_found}`.
- **Select permissions:**
  - A missing `filter` key gives a `:deny` with `:missing_filter`.
  - A negative `limit` gives a `:deny`.
  - A missing `query_root_fields` means `:all`, and `[]` stays `[]`.
  - A non-empty `computed_fields` gives a `:deny`.
  - `columns: "*"` expands to every introspected column, sorted.
  - An unknown column gives a `:deny`.
  - A filter that uses a relationship with a `:deny` diagnostic is itself
    a `:deny`.
- **Write permissions:**
  - `filter`, `check`, `set`, `columns` and `backend_only` are parsed and
    stored.
  - A failure there gives a `:warning` and never changes the select
    permission's status.
  - `backend_only: false` gives no diagnostic.
- **Inherited roles:** each role in `inherited_roles` gets a `:deny`, and
  no permission is created for it.

- [ ] **Step 1: Write the failing tests** for every acceptance case above.
  For example:

```elixir
assert {:ok, {:compare, "title", :eq, {:literal, "x-hasura-user-id"}}} =
  BoolExp.parse(%{"title" => %{"_eq" => "x-hasura-user-id"}}, :input, ctx)
assert {:error, [{["title", "_eq"], :null_operand}]} = BoolExp.parse(%{"title" => %{"_eq" => nil}}, :input, ctx)
assert {:ok, {:exists, {"public", "users"}, {:compare, "id", :eq, {:session, "x-hasura-user-id"}}}} =
  BoolExp.parse(%{"_exists" => %{"_table" => %{"schema" => "public", "name" => "users"},
                                  "_where" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}}}}, :permission, ctx)
```

- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.** These are pure functions, and the error path
  accumulates as a reversed list.
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: parse Hasura metadata, bool_exp and relationships`

---

### Task 8: Source behaviour and Hasura loader

**Files:**
- Create: `lib/authzura/source.ex`, `lib/authzura/sources/hasura.ex`
- Modify: `test/support/hasura_fixture.ex`, adding
  `put_metadata!(repo, metadata, resource_version \\ 1)`
- Test: `test/authzura/sources/hasura_test.exs` and
  `test/integration/loader_coherence_test.exs`. Both use CommittedCase,
  because `load/1` opens its own `REPEATABLE READ` transaction.

**Interfaces:**
- **`Authzura.Source` callbacks:**
  - `load(opts) :: {:ok, Snapshot.t()} | {:error, term()}`
  - `version(opts) :: {:ok, {integer(), binary()}} | {:error, term()}`
  - `parse_input(json :: map(), ctx :: map()) :: {:ok, AST.t()} |
    {:error, [{path, reason}]}`
- **`Authzura.Sources.Hasura` options:** `repo:`, `data_repo:` (default:
  `repo`), `source_name:` (default `"default"`), `adapter:`, and
  `max_retries:` (default 3).
- **`load/1` when `repo == data_repo`:** one `REPEATABLE READ, READ ONLY`
  transaction reads the metadata (as `metadata::jsonb`) and the
  `resource_version`, introspects, takes the fingerprint, and translates.
- **`load/1` when the repos differ:**
  1. In a metadata transaction, read the metadata and `resource_version`.
  2. In a separate `REPEATABLE READ, READ ONLY` transaction on
     `data_repo`, introspect and take the fingerprint.
  3. **Outside both transactions**, re-read the full version
     `{resource_version, fingerprint}`.
  4. If it differs from what was loaded, retry, up to `max_retries`
     times. After that, return `{:error, :unstable_source}`.
- **After translation**, `load/1` runs the Validator (Task 9; until then
  a stub that returns the snapshot unchanged) and returns a `Snapshot`
  with `version: {resource_version, fingerprint}`.
- **`version/1`** reads `resource_version` and the fingerprint, outside
  any transaction.
- **`parse_input/2`** delegates to `BoolExp.parse(json, :input, ctx)`.

- [ ] **Step 1: Write the failing tests.**
  - The loaded snapshot has
    `permissions[{"user", {"public","articles"}, :select}].status == :ok`.
  - A metadata table that's missing from Postgres gives a `:deny`
    diagnostic.
  - `version/1` changes after bumping `resource_version`.
  - A database with no `hdb_catalog` gives `{:error, _}`. Either use
    `OtherRepo` with a search path pointing at a schema without the
    catalog, or drop and recreate the catalog inside a CommittedCase test.
  - **Coherence (CommittedCase):**
    - A test hook, the `:before_verify` callback option (`@doc false`),
      runs **after the data snapshot transaction closes and before the
      verification read**. It runs `ALTER TABLE ... ADD COLUMN`, with
      `data_repo: OtherRepo`.
    - The verification read then sees a different fingerprint, so the
      loader retries. The final snapshot's fingerprint matches the
      post-DDL catalog, and the retry count is 1.
    - When the hook changes the schema on every attempt, the result is
      `{:error, :unstable_source}` after `max_retries`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: load Hasura metadata coherently from hdb_catalog`

---

### Task 9: Compiler and load-time validator

**Files:**
- Create: `lib/authzura/compiler.ex`, `lib/authzura/compiler/aliases.ex`,
  `lib/authzura/validator.ex`
- Modify: `lib/authzura/sources/hasura.ex`, replacing the Validator stub
- Test: `test/authzura/compiler_test.exs`,
  `test/authzura/validator_test.exs`,
  `test/integration/row_filter_test.exs`

**Interfaces:**
- **`Aliases.at(0..15) :: atom()`** is written as 16 literal clauses.
  Anything else raises `FunctionClauseError`, which can't happen because
  depth is validated first.
- **`Compiler.compile(AST.t(), ctx) :: {:ok, Ecto.Query.dynamic_expr()} |
  {:error, reason}`**, where `ctx` is:

  ```elixir
  %{table: Table.t(), tables: map(), session: Session.t() | :validate,
    adapter: module(), mode: :permission | :input, binding: atom(),
    depth: non_neg_integer()}
  ```

  Clause by clause:
  - **`{:relationship, rel, e}`** becomes one `exists` subquery:
    - on the target table, with its explicit prefix and alias
      `Aliases.at(depth + 1)`
    - with the mapping equalities against `parent_as(^binding)`, ANDed
      with `compile(e)` at the next depth
    - one `EXISTS` per node, and sibling nodes get separate `EXISTS`
      clauses
  - **`{:exists, {s, n}, e}`** becomes
    `exists(from t in ^n, prefix: ^s, as: <next alias>, where:
    ^compile(e, table: target, binding: <next alias>))`, with **no**
    correlation to the parent.
  - **`{:compare, ...}`** casts the value (session values go through
    `cast_value/3`) and calls `compile_operator/5`.
  - **`{:and, []}`** is `dynamic(true)`, and **`{:or, []}`** is
    `dynamic(false)`.
  - **Errors:** a missing session variable gives
    `{:missing_session_variable, name}`, and a cast failure gives
    `{:invalid_session_value, name, reason}`.
  - **Validation mode:** `session: :validate` type-checks session
    references without binding any values.
- **`Validator.validate(Snapshot.t(), adapter) :: Snapshot.t()`.** For
  each select permission whose status is `:ok`, it compiles the filter
  with `session: :validate`. It also checks that the key columns of every
  relationship mapping have a `base_kind` for which
  `adapter.supported_key_kind?/1` is true (the set recorded in Task 2). A
  failure sets the status to `{:denied, [diag]}` and adds a snapshot
  diagnostic.

- [ ] **Step 1: Write the failing tests.** Use SQL snapshots via `to_sql`,
  plus row assertions against fixture rows seeded in each test.
  - **Row filters:**
    - An author-only filter (`author_id = session user`) returns only
      that author's articles.
    - `_or [author_id = me, is_published = true]`, combined with a caller
      `where is_published = false`, returns only my unpublished articles
      (Hasura's `user_select_query_unpublished_articles`).
    - `{}` returns all rows.
  - **Empty forms, including under `_not`:**
    - `_in: []` returns no rows, and `_not: {_in: []}` returns all rows.
    - `_nin: []` returns all rows.
    - `_or: []` returns none, and `_and: []` returns all.
    - `_not: {}` returns none.
  - **NULL handling:**
    - `_eq` on nullable `editor_id` in `:permission` mode emits the
      null-aware form. On non-null `author_id` it emits plain `=`.
    - A literal `null` operand in permission mode matches rows where the
      column is NULL.
    - With seeded NULL `internal_notes` rows,
      `_not: {internal_notes: {_eq: "x"}}` returns exactly the IDs that
      Hasura's form implies.
    - `_is_null` works for both true and false.
  - **Relationships:**
    - The object relationship `articles.author`, filtered on
      `users.org_id`.
    - The array relationship `users.articles`.
    - Three hops (`comments.article.author.org`) produce three nested
      `EXISTS` with aliases 1, 2 and 3.
    - **Same related row:** given two conditions in one `comments` node,
      an article whose two comments each satisfy only one of them is
      excluded. Sibling nodes are independent.
    - `{:relationship, "comments", {:and, []}}` requires a comment to
      exist.
    - `{:not, {:relationship, "comments", {:and, []}}}` returns the
      articles with no comments.
    - The multi-column `membership_notes.membership`.
    - The self-relationship `users.manager`.
    - Traversing to a table the role can't read still filters correctly,
      because the target's own permission isn't applied.
  - **`_exists`:**
    - It's uncorrelated: the SQL has no `parent_as`.
    - The "is admin" pattern (Hasura's
      `boolexp/basic/query_account_permission_{fail,success}.yaml`):
      `_exists {users, {id: me, is_admin: true}}` gives a non-admin `[]`
      (not an error) and gives an admin every row.
    - `_exists` against the root's own table, with a session variable
      (the RootExistElementAliasing9457 regression).
    - `_exists` inside `_or` and inside `_not`.
  - **Operators:**
    - The comparison set.
    - The `_like`, `_ilike`, `_similar` and `_regex` families, including
      `_iregex` with a session value.
    - The jsonb operators: `_contains`, `_contained_in`, `_has_key`
      (including with a session value against `assignees`),
      `_has_keys_any` (where `{}` gives no rows) and `_has_keys_all`.
  - **Quoting and schemas:**
    - `"Order"` filters correctly on `"line item"` (Review Focus 1).
    - `public.users` and `audit.users` get distinct schema-qualified SQL
      (Review Focus 5).
    - A view with a manual relationship compiles its null-aware forms
      (Review Focus 4).
  - **Session errors:**
    - A missing session variable gives
      `{:missing_session_variable, "x-hasura-user-id"}`.
    - `"abc"` for a bigint gives `{:invalid_session_value, ...}`.
  - **Validator:**
    - A relationship key of an unsupported kind gives a `:deny`.
    - The literal `"bogus"` compared against the enum gives a `:deny`.
      (Task 7 already catches this at translation.)
    - A valid snapshot comes back unchanged.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: compile permissions to Ecto and validate them at load`

---

### Task 10: Store (generations, polling, freshness)

**Files:**
- Create: `lib/authzura/store.ex`, `lib/authzura/options.ex` (the instance
  schema), `lib/authzura/telemetry.ex`, `test/support/test_source.ex`
- Modify: `lib/authzura.ex`: `child_spec/1`, `status/1`, `diagnostics/1`
  and `reload/1`
- Test: `test/authzura/store_test.exs` (uses TestSource), plus
  `test/integration/store_reload_test.exs` (CommittedCase, real source)

**Interfaces:**
- **Instance options** (NimbleOptions):
  - `name`: default `Authzura`
  - `repo`: required
  - `source`: default `{Authzura.Sources.Hasura, []}`
  - `adapter`: default `Authzura.Adapters.Postgres`
  - `default_prefix`: default `"public"`
  - `admin_role`: default `nil`
  - `poll_interval`: default `5_000`, or `nil`
  - `max_staleness`: default `60_000`, or `:infinity`
  - `max_preload_depth`: default `4`
  - `max_preload_nodes`: default `16`
  - `clock`: default `&System.monotonic_time/1` (a test hook)
- **`%Authzura.Store.Generation{}`:**
  - `instance`
  - `owner: pid()`, the Store process that published the generation
  - `incarnation: reference()`
  - `seq: pos_integer()`
  - `version` and `snapshot`
  - `templates: %{{role, {s, n}} => {Permission.t(), AST.t()}}`
  - `config: map()`
  - `freshness: :atomics.atomics_ref()`. Slot 1 holds
    `last_confirmed_current_at` in ms. Freshness updates write to
    `:atomics`, **never** to `:persistent_term`, so a poll never triggers
    a global GC.
- **`Store.current(instance) :: {:ok, Generation.t()} | {:error,
  :not_ready | :stale_permissions}`:**
  - It reads `:persistent_term.get({Authzura.Store, instance}, nil)`.
  - `nil` gives `:not_ready`.
  - **Liveness:** a generation whose `owner` isn't alive
    (`Process.alive?/1`, a cheap local check) gives `:not_ready`. This
    covers a Store killed with `:kill`, where `terminate/2` never runs.
  - **Incarnation:** the generation's `incarnation` must match the one the
    live owner registered at `init`, under
    `{Authzura.Store, instance, :incarnation}`.
  - Freshness is checked against `clock`.
- **Lifecycle:**
  - `init/1` first erases the instance's persistent-term key (startup
    invalidation), creates a new `incarnation`, sets `seq = 0`, and
    continues to `:load`.
  - `terminate/2` erases the key.
  - A failed load retries with backoff (1s, doubling up to 30s). Tests
    override this with `backoff: 0`.
- **Polling:**
  - Polls run on `:poll` messages scheduled every `poll_interval`.
    `Store.poll(instance)` runs one synchronously; it's `@doc false` and
    meant for tests.
  - If the observed version equals the active version, freshness is
    updated.
  - If it differs (compared only for equality), the Store reloads.
  - A version-check error or a failed reload leaves freshness unchanged.
- **Publication:**
  - Loads run synchronously inside the Store process, so reloads are
    serialized and never overlap.
  - `seq` increments each time a load starts, and a generation is
    published only if its `seq` is higher than the published one. That
    makes publication monotonic by construction.
- **Calls:**
  - `reload/1` is a `GenServer.call`. On success it publishes and
    confirms freshness.
  - `status/1` returns `%{ready?: boolean(), seq, active_version,
    observed_version, last_confirmed_current_at, diagnostics_count}`.
  - `diagnostics/1` returns the snapshot's diagnostics.
- **Telemetry:** `[:authzura, :load | :reload, :start | :stop |
  :exception]`.

- [ ] **Step 1: Write the failing TestSource tests.** Use an injected
  clock and explicit `Store.poll/1` calls; never sleep.
  - **Readiness:** before the first load, `current/1` gives `:not_ready`.
    The TestSource blocks `load` until the test sends `:release`.
  - **Revocation:** after a version change and a poll, a revoked
    permission is gone.
  - **Newer version that keeps failing to load:** `version` returns `B`
    while `load` errors. After the clock passes `max_staleness`,
    `current/1` gives `:stale_permissions`.
  - **Polling outage:** `version` returns `{:error, :down}` past
    `max_staleness`, which gives `:stale_permissions`.
  - **Same version, broken load:** `version` keeps returning `A` while
    `load` would fail. The active version is `A`, so freshness renews and
    the generation stays fresh.
  - **Equality, not ordering:** a fingerprint that changes to a
    lower-sorting value still triggers a reload, and so does a
    `resource_version` rollback from 5 to 4.
  - **Serialized reloads:** two concurrent `reload/1` callers both
    succeed, and the final `seq` is the starting `seq` + 2. An observer
    task samples `current/1` throughout and never sees `seq` decrease.
  - **Killed Store:** after `Process.exit(store, :kill)`, `current/1`
    gives `:not_ready` before the supervisor restarts it.
  - `max_staleness: :infinity` never goes stale.
  - **Restart:** restart under the same name with a different config and
    a failing first load. `current/1` gives `:not_ready`, never the old
    generation.
  - **Freshness doesn't rewrite the term:** after 3 polls, the identity of
    `:persistent_term.get/1` is unchanged (`:erts_debug.same/2`).
  - **Concurrency:** 50 tasks call `current/1` while reloads run in a
    loop. Each read sees a generation whose `seq` matches its snapshot's
    marker.
- [ ] **Step 2: Write a failing real-source test** (CommittedCase).
  1. Write the fixture metadata and start an instance with
     `poll_interval: nil`.
  2. Run `ALTER TABLE articles DROP COLUMN body`, restoring it in
     `on_exit`.
  3. After `Store.poll/1`, the generation's `seq` has increased and the
     snapshot no longer contains `body`.
- [ ] **Step 3: Run.** Expected: FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 6: Checkpoint.**
  `feat: add per-instance Store with atomic generations and freshness`

---

### Task 11: Plan, query shapes and `scope/3`

**Files:**
- Create: `lib/authzura/plan.ex`, `lib/authzura/query_shape.ex`,
  `lib/authzura/scope.ex`
- Modify: `lib/authzura.ex` (`scope/3`, `scope!/3`, `permission/3`,
  `allowed_columns/3`, `validate_columns/4`), and `lib/authzura/options.ex`
  (per-call options)
- Test: `test/authzura/query_shape_test.exs`,
  `test/integration/scope_test.exs`

**Interfaces:**
- **`%Authzura.Plan{}`:**
  - `query :: Ecto.Query.t()`
  - `root :: {s, n}`
  - `projection :: [%{key: atom() | String.t(), column: String.t(),
    public?: boolean()}]`
  - `shape :: :map_by_field | :map_by_column`
  - `preloads :: term() | nil`, filled in by Task 14
  - `generation :: Generation.t()` and `session :: Session.t()`
  - `exec :: %{repo_opts: keyword(), in_transaction: :refuse |
    :trust_isolation, hooks: %{optional(:between_levels) => (-> any())},
    isolation: :repeatable_read | :read_committed}`
    - This holds the validated execution settings, filled from the
      per-call options.
    - `hooks` and `isolation: :read_committed` are `@doc false`, for
      tests only.
- **Per-call options** (NimbleOptions) are kept separate from repo
  options:
  - `instance:`, `columns:`, `table:`, `preload:`, `in_transaction:` and
    `repo_opts:`
  - `repo_opts:` is a keyword list. It may only contain `:timeout`,
    `:log`, `:telemetry_options` and `:telemetry_event`, which Task 12
    validates.
- **`QueryShape.validate(query, mode :: :scope | :execute) :: :ok |
  {:error, {:unsupported_query, reason}}`.** The reasons:
  - **Sources:**
    - `:fragment_source`: a fragment or values root
    - `:subquery_source`
    - `:modifying_cte`: an `update_all` or `delete_all` CTE at any depth
    - `:fragment_cte`
  - **Clauses:**
    - `:existing_select`: `select` or `select_merge`
    - `:aggregate`: `group_by`, `having` or `windows`
    - `:lock`
    - `:distinct`: any form
    - `:with_ties`
    - `:limit`: a non-integer limit or offset. A pinned `^n` is allowed
      and checked when the query runs.
  - **Preloads and combinations:**
    - `:preload_requires_execute`: any preload in `:scope` mode
    - `:combination_tables`: branches with different physical roots
    - `:combination_preload`
    - `:combination_shape`: a branch with its own select, preload or
      unsupported clause
  - **Aliases:** `:reserved_alias`, for any `:__authzura_*` binding.
- **`Scope.build(queryable, Session.t(), Generation.t(), opts) :: {:ok,
  Plan.t()} | {:error, reason}`:**
  1. Validate the query shape.
  2. **Root:** derive `{prefix, source}` from the `from` prefix, falling
     back to the schema's `@schema_prefix`, then the query prefix, then
     `default_prefix`. Pin it into `query.from.prefix`. A `table:`
     mismatch gives `{:unsupported_query, :table_mismatch}`.
  3. **Template:** look up `templates[{role, root}]`.
     - Missing or denied gives `:forbidden`.
     - `root_fields` without `:select` gives `:root_field_disabled`.
     - The configured admin role skips the filter, columns and limit.
  4. **Columns:** map fields to columns with
     `__schema__(:field_source, f)`.
     - Virtual or unknown fields, or disallowed columns, give
       `{:forbidden_columns, cols}`.
     - The default is the allowed columns (for schemas, the ones that map
       to fields).
  5. **Select:** set a `map` select containing only the projection
     columns. Keys are field atoms for schema queries and column strings
     for table queries.
  6. **Filter and limit:** attach or reuse the root alias, AND in the
     compiled filter, and set the limit to `min(caller, permission)`.
  7. **Combinations:** every branch must share the physical root. Scope
     each branch with that table's template, give all branches the same
     projection (same columns, same order), and give each its own
     permission-capped limit. Ecto applies the parent's `order_by`,
     `limit` and `offset` to the whole combination, so leave them on the
     parent.
- **`Authzura.scope(queryable, session, opts) :: {:ok, Ecto.Query.t()} |
  {:error, reason}`** returns `plan.query`. `:not_ready` and
  `:stale_permissions` pass through from `Store.current/1`.
- **Telemetry:** `[:authzura, :scope, :start | :stop | :exception]`,
  with `result: :granted | :denied` and the reason in the metadata.

- [ ] **Step 1: Write the failing shape tests**, one per reason above,
  plus these accepted cases:
  - A read-only CTE named `"articles"` is accepted, and the final SQL
    still reads `"public"."articles"`.
  - A same-table `union_all` is accepted. Its limit and offset apply to
    the whole result, while each branch has its own permission cap.
  - `limit(^n)` is accepted.
- [ ] **Step 2: Write the failing scope tests.**
  - **Columns:**
    - The SQL `SELECT` list contains only the requested, allowed
      columns.
    - Asking for `internal_notes` without permission gives
      `{:forbidden_columns, ["internal_notes"]}`.
    - `field :headline, :string, source: :title` authorizes `title`.
    - A virtual field gives `{:forbidden_columns, _}`.
  - **Prefixes:**
    - `@schema_prefix "audit"` beats `put_query_prefix("public")`, and
      an explicit `from` prefix beats both.
    - `Repo.all(query, prefix: "audit")` on the scoped query still reads
      `public.articles`.
    - `SET LOCAL search_path TO audit` inside a sandbox transaction
      doesn't change which table is read.
    - `public.users` and `audit.users` get different permissions (Review
      Focus 5).
    - A `table:` mismatch gives `:table_mismatch`.
  - **Roles:**
    - A role with no permission gives `:forbidden`.
    - The configured admin role sees all rows.
    - When no admin role is configured, `"admin"` gives `:forbidden`.
  - **Root fields and limits:**
    - `query_root_fields: []` gives `:root_field_disabled`.
    - `limit(10)` with a permission limit of 2 returns 2 rows, and
      `limit(1)` with a permission limit of 2 returns 1.
  - **Aliases:** a caller join whose alias matches a relationship name
    doesn't mis-correlate.
  - **Two sessions, one template:** two sessions with different user ids,
    run concurrently on the same template, each see only their own rows.
    The tasks get sandbox access with `Sandbox.allow/3`. This proves no
    session values are cached.
  - **Telemetry:** a denial emits `:denied` with its reason.
- [ ] **Step 3: Run.** Expected: FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 6: Checkpoint.**
  `feat: scope Ecto queries with Hasura select permissions`

---

### Task 12: Executor (`all`/`one`) without preloads

**Files:**
- Create: `lib/authzura/executor.ex`
- Modify: `lib/authzura.ex` (`all/3`, `one/3`)
- Test: `test/integration/executor_test.exs` and
  `test/integration/read_only_test.exs`, both CommittedCase because they
  execute real transactions

**Interfaces:**
- **`Executor.run(Plan.t(), mode :: :all | :one) :: {:ok, [map()]} |
  {:ok, map() | nil} | {:error, reason}`.** It reads its settings from
  `plan.exec`:
  1. If `repo.get_dynamic_repo()` (called in the calling process) isn't
     the repo the instance introspected, which is recorded as
     `generation.config.repo` and its default name, return
     `{:error, {:unsupported_query, :dynamic_repo}}`.
  2. A `plan.exec.repo_opts` key outside the allowlist gives
     `{:error, {:unsupported_query, {:option, key}}}`. Scope or Input
     validates this when it builds the plan.
  3. When `repo.in_transaction?()` is false, run inside
     `repo.transaction(fn -> SET TRANSACTION READ ONLY; ... end)`.
     Otherwise run as-is. Preloads are added in Task 16.
  4. `:one` with more than one row gives `:multiple_results`.
  5. Strip projection entries with `public?: false`.
  6. Emit `[:authzura, :execute, :start | :stop | :exception]`.
- **`Authzura.all/3` and `one/3`** call `Scope.build` (Task 11), then
  `Executor.run`.

- [ ] **Step 1: Write the failing tests.**
  - `all/3` returns maps with exactly the requested keys.
  - `one/3` with two matching rows gives `:multiple_results`.
  - **Dynamic repo:** start an anonymous `{:ok, pid} =
    Authzura.Test.Repo.start_link(name: nil)`, then call
    `Authzura.Test.Repo.put_dynamic_repo(pid)` in the test process. The
    call gives `:dynamic_repo`. Restore the original with
    `put_dynamic_repo(Authzura.Test.Repo)` in an `after` block.
  - `repo_opts: [prefix: "audit"]` gives `{:option, :prefix}`.
  - A modifying CTE is rejected, and the row count is unchanged
    afterwards.
  - **Read-only (CommittedCase):**
    - A trusted `where` fragment that calls `nextval('public.test_seq')`
      raises Postgres's read-only error (`read_only_sql_transaction`).
      The fixture creates the sequence:
      `CREATE SEQUENCE IF NOT EXISTS public.test_seq`.
    - The same fragment inside an already-open caller transaction isn't
      wrapped. This documents the trusted-caller boundary.
  - An exception span is emitted when the repo raises.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: add read-only executors bound to the authorized repo`

---

### Task 13: Validated outside input

**Files:**
- Create: `lib/authzura/input.ex`
- Modify: `lib/authzura.ex` (`scope_input/4`, `all_input/4`)
- Test: `test/integration/input_test.exs`. Use CommittedCase for
  `all_input` execution and DataCase for `scope_input` SQL assertions.

**Interfaces:**
- **The input map:**
  - `columns: [String.t()]`
  - `filter: map()`
  - `order_by: [{String.t(), :asc | :desc | :asc_nulls_first |
    :asc_nulls_last | :desc_nulls_first | :desc_nulls_last}]`
  - `limit:` and `offset:`, both non-negative integers
  - `preload:`, validated in Task 14 and allowed only in `all_input`
- **`Input.build(queryable, session, input, generation, opts) :: {:ok,
  Plan.t()} | {:error, reason}`:**
  - The queryable must be a bare schema module or a bare table source.
    Otherwise `{:invalid_input, :not_a_root}`.
  - The filter is parsed with the `parse_input/2` of the module in
    `generation.config.source`, so it stays source-neutral, using the
    input limits. A parse error gives `{:invalid_input, errors}`.
  - Every column referenced in `columns`, the filter or `order_by` must
    be in the permission's columns. Otherwise
    `{:forbidden_columns, cols}`.
  - String column names map back to schema fields through the reverse of
    the `field_source` map.
  - The input filter compiles in `:input` mode and is ANDed with the
    permission filter, which compiles in `:permission` mode. The result
    then goes through Scope's projection and limit logic.

- [ ] **Step 1: Write the failing tests.**
  - Filtering on the hidden `salary` gives
    `{:forbidden_columns, ["salary"]}`, and sorting on it does too.
  - **Session-looking literals:** an input value of `"X-Hasura-User-Id"`
    matches only a row whose title is literally that string. Check upper
    and lower case, inside an `_in` list, and inside a `_contains` JSON
    value.
  - `_eq: nil` gives `{:invalid_input, _}`.
  - A relationship key gives `{:invalid_input, _}`, and so does
    `_exists`.
  - **Probes** (the analog of Hasura's
    `computed_fields_row_permission_bypass` suite):
    - Filtering for a value that exists only in rows the role can't see
      returns `[]`.
    - Negative control: the same probe against a permitted row returns
      that row.
  - **Two NULL modes:** on the nullable `editor_id`, the permission side
    uses the null-aware form and the input side uses plain `=`. Both
    appear in the SQL, and the rows are correct.
  - **Limits:** input with 101 nodes gives `{:invalid_input, _}`
    (`:too_large`). Input nested 9 levels deep gives the same
    (`:too_deep`).
  - **Source-neutral:** a TestSource whose `parse_input/2` returns a
    fixed AST is used. This proves `Input` never calls Hasura's parser
    directly.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: add validated input path for untrusted filters`

---

### Task 14: Preload tree validation and Ecto preload translation

**Files:**
- Create: `lib/authzura/preload/tree.ex`
- Modify: `lib/authzura/query_shape.ex` (in `:execute` mode, preloads go
  to `Tree`), plus `lib/authzura/scope.ex` and `lib/authzura/input.ex`
  (both set `plan.preloads`)
- Test: `test/authzura/preload/tree_test.exs`

**Interfaces:**
- **`Tree.validate(tree, root :: {s, n}, Session.t(), Generation.t(),
  limits :: %{depth: pos_integer(), nodes: pos_integer()}) :: {:ok,
  [node]} | {:error, reason}`:**
  - `tree` is a keyword list or map of relationship names. Each value is
    a nested tree or `[columns:, order_by:, preload:]`.
  - A `node` is `%{rel: Relationship.t(), template: {Permission.t(),
    AST.t()}, columns: [String.t()], order_by: [...], children: [node]}`.
  - A relationship must be declared, and the role must have a non-denied
    select template on its target. `root_fields` is ignored here.
    Anything else gives `:forbidden`.
  - The limits come from `config.max_preload_depth` and
    `max_preload_nodes`, or 2 and 8 for input. Exceeding either gives
    `{:unsupported_query, :preload_limit}`.
  - `order_by` and `columns` must be allowed target columns. Otherwise
    `{:forbidden_columns, cols}`.
- **`Tree.from_ecto_query(query :: Ecto.Query.t(), generation) :: {:ok,
  tree | nil} | {:error, {:unsupported_query, {:preload, name}}}`:**
  - It takes the complete query, so it can inspect both `query.preloads`
    and `query.assocs` (join-bound preloads).
  - The root schema comes from `query.from`.
  - It accepts only plain, nested association names on `belongs_to`,
    `has_one` and `has_many` associations with no `where`,
    `preload_order` or `through`.
  - It rejects custom preload queries, preload functions and join-bound
    preloads (`query.assocs`).
  - Each association must match a Hasura relationship with the same
    target and the same ordered mapping.

- [ ] **Step 1: Write the failing tests.**
  - **Allowlist:**
    - An allowed relationship validates.
    - An undeclared relationship gives `:forbidden`, and so does a target
      without select permission.
    - A target whose root fields are disabled is still allowed.
  - **Limits:** the self-relationship `users.manager` chained 5 deep
    gives `:preload_limit`, and so does a 17-node tree. Both are rejected
    before any query runs, which a telemetry counter shows.
  - **Ecto preloads:**
    - `preload(:comments)` translates.
    - `preload(comments: ^q)` is rejected.
    - A `has_many through:` is rejected.
    - A join-bound preload is rejected.
  - **Scope mode:** `scope/3` with any preload gives
    `:preload_requires_execute`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: validate relationship-allowlist preload trees`

---

### Task 15: Preload loader (per-level SQL)

**Files:**
- Create: `lib/authzura/preload/loader.ex`
- Modify: `lib/authzura/adapters/postgres.ex`, adding
  `preload_level_query/4` and `supported_key_kind?/1` with the forms
  recorded in Task 2
- Test: `test/integration/preload_loader_test.exs`

**Interfaces:**
- **`adapter.preload_level_query(node, key_columns :: [Column.t()],
  key_values :: [[term()]], ctx) :: Ecto.Query.t()`:**
  - **The inner query** is built on the target table, with its explicit
    prefix:
    - It joins
      `unnest(<one typed array per key column>) WITH ORDINALITY AS
      p(k1..kn, idx)`, comparing every mapping pair by SQL equality,
      ANDed. There is one fragment clause per arity from 1 to 8,
      generated at compile time by a macro over that literal range.
    - It selects the requested columns, the stitching columns and
      `p.idx`.
    - It **always** selects
      `row_number() OVER (PARTITION BY p.idx ORDER BY <order_by, else the
      target's primary key, else p.idx>)` as `rn`, for every
      relationship kind, so the outer query has one fixed shape.
    - It applies the target's row filter, compiled with the session.
  - **The outer query** is `from s in subquery(inner)` with
    `order_by: [s.idx, s.rn]`, plus:
    - `where: s.rn <= ^limit` for an array relationship with a permission
      limit
    - `where: s.rn <= 2` for an object relationship, which is enough to
      detect a cardinality violation
    - no `rn` filter for an unlimited array relationship
- **`Loader.load(nodes, parent_rows :: [map()], parent_keys :: [[term()]],
  repo, Generation.t(), Session.t()) :: {:ok, [map()]} | {:error,
  reason}`:**
  - For each node, it runs the level query and groups the rows by `idx`.
  - **Object relationships** get the first row, or `nil`. More than one
    row is a data-integrity error:
    `{:error, {:unsupported_query, {:object_cardinality, rel}}}`.
  - **Array relationships** get a list in `rn` order.
  - It recurses into children using the child's key columns, then strips
    the non-public stitching columns at every level.

- [ ] **Step 1: Write the failing tests.** Call `Loader.load` directly,
  with parents fetched by a plain query.
  - **Per-parent limit:** two articles have three comments each, and the
    permission limit is 1. Each article gets exactly one comment.
    - Without `order_by`, assert cardinality and membership.
    - With `order_by: [asc: :id]`, assert it's the lowest comment id.
  - **Object relationships with a permission limit** (the analog of
    Hasura's `Regression/ObjectRelationshipsLimit7936Spec.hs`): with
    `limit: 1` on the target, three articles by three different authors
    each get their own author.
  - **Composite keys:**
    - Crossed tuples: membership notes for `(1,2)` and `(2,1)` attach to
      the right parents.
    - Partial NULL keys attach nothing.
  - **citext:** a parent email of `"A@x.com"` matches a child keyed
    `"a@x.com"` (Review Focus 3).
  - **Reverse object relationship:** `users.profile`.
  - **Nesting:** three levels deep, `articles -> comments -> author ->
    profile`.
  - **Stripping:** stitching columns the caller didn't request are
    absent, even when they're selectable.
  - **Large batch:** loading the comments of 5,000 parent articles uses
    one bind parameter per key column. Assert the built query's parameter
    count (Review Focus 2).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: load relationship preloads with per-parent limits`

---

### Task 16: Preload execution and consistency

**Files:**
- Modify: `lib/authzura/executor.ex` (preload orchestration), and
  `lib/authzura.ex` (preloads in `all_input/4`)
- Test: `test/integration/preload_consistency_test.exs` and
  `test/integration/preload_api_test.exs`, both CommittedCase, because
  they execute real `REPEATABLE READ` transactions

**Interfaces:**
- **`Executor.run/2` with `plan.preloads`:**
  - **With no caller transaction**, the root query and every level run in
    one `repo.transaction` whose first statement is
    `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`.
  - **Inside a caller transaction**, the result is
    `{:error, {:unsupported_query, :preload_in_transaction}}`, unless the
    call passed `in_transaction: :trust_isolation`.
  - The plan's `generation` and `session` are used for every level.
    `Store.current/1` is never called again mid-operation.
  - The root projection adds the parent key columns as `public?: false`.
- **Test hook:** the `:between_levels` option takes a function that runs
  after the root query and before the first level. It's `@doc false` and
  test-only.

- [ ] **Step 1: Write the failing consistency tests** (CommittedCase).
  These must **fail under READ COMMITTED**; Task 2 proved the setup can
  tell the difference.
  - **Fixture:** the comment permission filters through the parent
    relationship, `comments: {article: {author_id: me}}`. Article A is
    authored by user 1, who is the session user.
  - **The race:** `:between_levels` uses a separate connection to commit
    `UPDATE articles SET author_id = 2 WHERE id = A`. The child query's
    permission re-reads the article's ownership.
  - **Expected:** under Authzura's REPEATABLE READ, A's comments are
    still returned. That's consistent with the root snapshot, in which
    user 1 owns A.
  - **Proving the test works:** add an assertion helper that reruns the
    same flow with an internal `isolation: :read_committed` override
    (`@doc false`) and shows the comments *disappear*. That proves the
    test detects the anomaly.
  - **Reload mid-operation:** a reload published between levels (through
    the hook) doesn't change the generation in use.
- [ ] **Step 2: Write the failing API tests** (CommittedCase).
  - `all(Article, session, preload: [comments: [order_by: [asc: :id]]])`
    nests `comments` under each article.
  - Preloads inside `Repo.transaction` give `:preload_in_transaction`,
    and they work with `in_transaction: :trust_isolation`.
  - `all_input` with an allowed `preload:` works.
  - A plain Ecto `preload(:comments)` in an `all/3` query is translated
    and loaded.
- [ ] **Step 3: Run.** Expected: FAIL.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 6: Checkpoint.**
  `feat: run preloads in one consistent read-only snapshot`

---

### Task 17: Optional JWT helper

**Files:**
- Create: `lib/authzura/jwt.ex`, compiled only when
  `Code.ensure_loaded?(JOSE)`
- Test: `test/authzura/jwt_test.exs`

**Interfaces:**
- **`Authzura.JWT.verify(token :: String.t() | nil, opts) :: {:ok,
  Session.t()} | {:error, reason}`.** Options:
  - `key:`, required
  - `algorithms:`, default `["HS256"]`. `"none"` is always rejected.
  - `allowed_skew:`, in seconds, default 0
  - `issuer:` and `audience:`, optional; each a string or a list
  - `claims_namespace:`, default `"https://hasura.io/jwt/claims"`
  - `claims_map:`, `requested_role:` and `unauthorized_role:`
  - `now:`, a test hook in unix seconds
- **Validation order:**
  1. The header's `alg` must be in the allowlist.
  2. The signature must verify (`JOSE.JWT.verify_strict/3`).
  3. `exp`, `nbf` and `iat` must be numeric when present:
     - `exp + skew < now` means expired.
     - `nbf - skew > now` means not yet valid.
     - `iat - skew > now` means issued in the future.
  4. `iss` and `aud` are checked only when configured.
  5. Claims are extracted from the namespace, or through `claims_map`.
  6. `x-hasura-allowed-roles` must be a list, and `x-hasura-default-role`
     must be present.
  7. Build the session with `Session.new/2`, passing the extracted
     allowed and default roles plus `requested_role:`.
- **Error reasons:**
  - `{:invalid_jwt, :algorithm | :signature | :expired | :not_yet_valid
    | :issued_in_future | :invalid_time_claim | :issuer | :audience}`
  - `{:jwt_missing_role_claims, "x-hasura-allowed-roles" |
    "x-hasura-default-role"}`
  - `{:jwt_invalid_claims, :allowed_roles_not_list | {:claims_map,
    claim}}`
  - `{:invalid_headers, :missing_token}`
  - Session errors pass through unchanged.
- **Unsupported options:** `claims_namespace_path` and
  `claims_format: :stringified_json` give
  `{:error, {:unsupported_option, key}}`.
- **No token:** a `nil` token with `unauthorized_role:` gives
  `{:ok, %Session{role: unauthorized_role}}`.

- [ ] **Step 1: Write the failing tests**, ported from Hasura's
  `tests-py/test_jwt.py` and `test_jwt_claims_map.py`:
  - **Claims:**
    - Valid claims pass.
    - Missing allowed roles, and missing default role, each fail.
    - Allowed roles given as a string fail.
  - **Time:**
    - An expired token fails.
    - A token that expired 30s ago passes with `allowed_skew: 60`.
    - `nbf` in the future fails.
    - `iat` in the future, beyond the skew, fails.
    - `exp` given as a string fails.
  - **Signatures:**
    - A bad signature fails.
    - An `alg` that isn't allowlisted (an RS256 header against an HS256
      config) fails.
  - **Issuer and audience:**
    - Unconfigured, they're accepted even when the token carries them.
    - Configured but mismatched, they fail.
  - **`claims_map`:** a path; a missing path with a default; a missing
    path with no default; and a static value.
  - **No token:** `nil`, with and without `unauthorized_role`.
  - **Roles:** a requested role that isn't allowed gives
    `{:invalid_session, :role_not_allowed, _}`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `mix test && mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.**
  `feat: add optional Hasura-compatible JWT verification`

---

### Task 18: `mix authzura.check`, README and release gate

**Files:**
- Create: `lib/mix/tasks/authzura.check.ex`,
  `test/readme_examples_test.exs`
- Modify: `README.md`, with the full guide
- Test: `test/mix/tasks/authzura_check_test.exs` (CommittedCase)

**Interfaces:**
- **`mix authzura.check --repo MyApp.Repo [--data-repo R] [--source
  default] [--strict]`:**
  - It starts the repo or repos and runs `Sources.Hasura.load/1`,
    including the Validator.
  - It prints each diagnostic as
    `severity role schema.table operation path: reason`.
  - It exits 1 when any select permission is denied, and 0 otherwise.
    `--strict` also fails on warnings.
- **README sections:**
  - What Authzura is.
  - Stage-one scope and its non-goals.
  - Installation and the supervision tree.
  - Building a `Session`, and the trust model.
  - `all`/`one` vs. `scope`.
  - The input path for untrusted data.
  - Preloads and the relationship allowlist.
  - Caching and freshness.
  - Error reasons and telemetry events.
  - `mix authzura.check`.
  - Hasura compatibility: target v2.51.6 and metadata v3, with links to
    the Hasura docs.
  - A link to https://github.com/agoodway/pgrest for PostgREST-style
    APIs.

  Every README code example also appears in `readme_examples_test.exs`
  and runs against the fixture database.
- **Release gate:** a "Releasing" section in the README, and a checklist
  item in this plan.
  - Before tagging 0.1.0, run `mix authzura.check` against at least one
    large real-world Hasura v2 metadata set (hundreds of tables).
  - Record the result in the release notes: counts only, no metadata.
  - Never commit third-party metadata.

- [ ] **Step 1: Write the failing tests.**
  - Fixture metadata with one denied permission exits 1, and the output
    names the role, the table and the reason.
  - Clean metadata exits 0.
  - `--strict` with only warnings exits 1.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement** the task, the README and the examples test.
- [ ] **Step 4: Run** `mix test && mix quality && mix docs`. Expected:
  PASS, with no doc warnings.
- [ ] **Step 5: Checkpoint.** `feat: add mix authzura.check and user guide`

---

### Task 19: Hasura v2.51.6 parity suite (opt-in)

**Files:**
- Create: `test/support/parity_case.ex`,
  `test/parity/select_parity_test.exs`,
  `test/parity/role_parity_test.exs`
- Modify: `README.md`, adding a "Running parity tests" section

**Interfaces:**
- **`ParityCase`** (`@moduletag :hasura_parity`, `async: false`):
  1. `Application.ensure_all_started(:inets)` and `(:ssl)`.
  2. Require `AUTHZURA_PARITY_DB_URL` and `AUTHZURA_PARITY_HASURA_URL`.
  3. Poll `GET /healthz` until it returns 200, with a 60s timeout.
  4. Start a dedicated `Authzura.Test.ParityRepo` on `authzura_parity`.
     Run `FixtureSchema.up(ParityRepo, hasura_catalog: false)`, then
     commit the seed rows.
  5. Apply the fixture metadata with `POST /v1/metadata
     {"type":"replace_metadata","args":...}`, using the admin secret.
  6. Start an Authzura instance on `ParityRepo`. Real Hasura has written
     `hdb_catalog` by now.
- **`query_hasura(graphql, auth)`** returns rows, or the error's
  `extensions.code`. `auth` is one of:
  - `{:admin_impersonate, role, vars}`: sends `x-hasura-admin-secret`,
    `x-hasura-role` and the vars. Use it **only** for
    permission-semantics cases.
  - `{:jwt, claims, requested_role}`: sends a signed HS256 JWT and no
    admin secret. Use it for **role-resolution** cases.
- **`normalize/1`** sorts top-level rows by `id`. Relationship lists keep
  their returned order when an `order_by` was requested, and are compared
  as sets otherwise.

- [ ] **Step 1: Write the parity tests.** Each case runs the same read
  through Hasura GraphQL and through Authzura. It asserts that the
  **complete returned values** (every key and value) are equal, or that
  the errors are equivalent.
  - **Groups to cover:** row filters, empty forms, NULL handling,
    relationships, `_exists`, operators, session variables, columns,
    limits and root fields.
  - **Error equivalence:**
    - Hasura `not-found` (a missing session variable) matches
      `:missing_session_variable`.
    - `validation-failed` (a hidden column) matches `:forbidden_columns`.
    - `access-denied` matches `:role_not_allowed`.
  - **Role resolution** (JWT auth):
    - A requested role that isn't allowed.
    - A default role that isn't allowed.
    - The default role used when none is requested.
  - **Preloads:** each GraphQL nested selection is compared against
    `all(..., preload:)`. A limited relationship without `order_by` is
    compared by cardinality and membership.
- [ ] **Step 2: Run** `docker compose --profile parity up -d && mix test
  --only hasura_parity`. Expected: PASS. Investigate any diff, and fix
  whichever side diverges from Hasura's tested behavior.
- [ ] **Step 3: Run** `mix test && mix quality`. The default run excludes
  parity. Expected: PASS.
- [ ] **Step 4: Checkpoint.** `test: add opt-in Hasura v2.51.6 parity suite`

---

## Spec coverage map

| Spec area | Tasks |
|---|---|
| Project setup, quality, no demo app | 1 |
| Ecto/Postgres feasibility ("prototype first") | 2 |
| Model, AST, type contract | 3 |
| Session variables, roles, normalization | 4, 6, 9 |
| Introspection, fingerprint, views, quoting | 5 |
| Operator signatures, casting, NULL forms, empty `_in`/`_nin` | 6 |
| Metadata: missing vs. empty, aliases, shorthand, wildcard, write-only settings, inherited roles | 7 |
| Relationships: forms, FK resolution, ambiguity, the 8-pair cap | 7 |
| Coherent loading, separate metadata DB | 8 |
| Filter compilation, `EXISTS`, `_exists`, load-time validation | 9 |
| Store, caching, freshness, publication sequence, restart safety | 10 |
| Query shapes, CTEs, unions, root/prefix, columns, limits, root fields, admin | 11 |
| Execution binding, read-only transactions | 12 |
| Trusted vs. untrusted input | 13 |
| Relationship allowlist, preload limits, Ecto preload translation | 14 |
| Preload SQL, per-parent limits, composite/citext keys, large batches | 15 |
| Preload consistency (one snapshot, one generation) | 16 |
| JWT helper | 17 |
| Diagnostics, `mix authzura.check`, telemetry docs, adopter release gate | 18 |
| Hasura parity | 19 |

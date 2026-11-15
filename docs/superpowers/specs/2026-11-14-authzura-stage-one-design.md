# Authzura Stage One: Hasura-Compatible Read Permissions for Ecto

Date: 2026-11-14
Status: Approved for planning (revision 4: three rounds of independent
review, Hasura v2.50.1 source and test research, relationship-allowlist
preloads)

## Intent

Authzura is a general role-based access control library for Elixir/Phoenix
apps that use Ecto. It follows Hasura's permission model: per role, per
table, per operation, a row filter, allowed columns, an insert/update check,
column presets, and a row limit. Unlike Hasura, it is database-driven rather
than YAML-driven, and you apply it by piping an Ecto query through it.

The long-term version stores its own permissions in its own Postgres schema,
uses PostgREST/Supabase-style operators (`eq`, `gt`, `in`, `is`, `cs`, ...)
instead of Hasura's underscore operators, and lets end users create custom
roles. That is **not** this stage.

**Stage one** is a read-only compatibility layer. Point Authzura at a
Postgres database that a running Hasura v2 instance manages. Authzura reads
Hasura's permission metadata without changing it and enforces Hasura's
**select** permissions on Ecto reads. Hasura keeps running unchanged, so an
Elixir app can serve reads directly through Ecto while users keep the access
rules they already have.

Why: many teams run Hasura v2 next to an Elixir/Phoenix backend and want
to move reads, or eventually everything, into Elixir without rewriting
their access rules. A typical first step is a new Elixir-side read path
(an internal service, an API endpoint, an MCP server or a LiveView) that
must honor the rules Hasura already enforces. Authzura makes that possible
while Hasura stays in place, and later replaces Hasura's permission layer
entirely.

## Goals

1. Read Hasura v2 permission metadata from the database (`hdb_catalog`) at
   runtime, read-only. No YAML parsing.
2. Translate it into an internal permission model that does not depend on
   Hasura's operator syntax, so that a future native source can produce the
   same model.
3. Enforce select permissions on Ecto reads:
   - the row filter, with Hasura's exact semantics, including relationship
     filters, `_exists` and NULL handling
   - the column allowlist on the physical `SELECT` list
   - the row limit
   - root-field availability

   Deny by default.
4. Provide a validated path for outside query input (filters, sorting and
   columns that come from users, HTTP or an LLM), so that filtering or
   sorting can't reveal hidden columns.
5. Take the session as a map of Hasura session variables. An optional helper
   verifies a Hasura-style JWT and builds that map.
6. Keep database-specific SQL behind an adapter boundary. Postgres is the
   only adapter in stage one.
7. Back all of this with a robust real-Postgres test suite. Its core
   scenarios are ported from Hasura v2's own test suite, and an opt-in
   parity suite compares results with a real Hasura v2.51.6.

## Non-goals (stage one)

- **Any write operation.** No insert, update or delete scoping, `check`,
  presets or write-column allowlists.
  - The model parses and stores write permissions, so loading validates the
    whole metadata and stage two needs no model change.
  - The public API refuses anything but reads. Partial write enforcement,
    such as a row filter without checks or presets, would look like
    authorization but wouldn't be.
- **Aggregate queries.** `allow_aggregations` is parsed and exposed, but
  stage one rejects `group_by`, `having`, windows and aggregate selects. An
  aggregate API comes later.
- **Scoping caller joins.** Joins the caller adds are trusted. Authzura
  doesn't scope them, and it doesn't let the caller select from them. To
  read related data with permissions applied, use Authzura's relationship
  preloads (see "Related data").
- **PgRest integration.** PgRest stays PostgREST-compatible. It changes later
  only where the change improves PgRest on its own merits.
- The native permission source, custom roles, and the admin UI described in
  the README.
- **Unsupported Hasura features.** Inherited roles, merging several roles
  per request, remote relationships (including v2.51's `to_source` relationships in
  permission filters), computed fields (in filters or as
  selectable outputs), column-comparison operators (`_ceq` and related),
  `_cast`, function permissions, actions and subscriptions are not
  supported.
  - A *select* permission that depends on one of these is **denied**, not
    ignored. The one exception is a select permission's `computed_fields`
    grant: it is ignored with a `:warning` diagnostic and the rest of the
    permission is enforced. Computed fields are never exposed, and a filter
    that references one is still denied.
  - Settings that only matter for writes, such as `backend_only`, `check`
    and `set`, are parsed and stored. A problem in a write-only setting
    produces a write-side warning and never denies a read.
- Non-Postgres adapters. The boundary exists, but there is no second
  implementation.

## Anti-goals

- **Leaking data.** If Authzura can't faithfully enforce some metadata (an
  unknown operator, an unsupported feature, an unresolvable or ambiguous
  relationship, an unknown table or column), it **denies** that
  role/table/operation and logs a diagnostic at load time. It never allows
  access because it skipped a clause it didn't understand.
- **Looking enforced when it isn't.** Every API either enforces Hasura's
  semantics for what it accepts, or rejects the input. That covers query
  shapes, operations, limits and operators.
- **Overfitting to any one application.** No hardcoded role names, session
  variables, tables or claim layouts.
- **Writing to Hasura's catalog,** or requiring any change to Hasura's
  configuration.
- **Merging several roles' permissions** by OR-ing filters and unioning
  columns, as the old README proposed. That leaks columns across rows. One
  role per request, as in Hasura.

## Hasura semantics Authzura must match

**Target version:** Hasura v2.51.6, the latest v2 release (2026-11-11). Metadata
format v3 is unchanged across v2.4x-v2.51, so earlier v2 deployments load too.
The research below was done against v2.50.1, and its line citations point there.
The permission-path diff from v2.50.1 to v2.51.6 contains only two kinds of
change:
- remote (`to_source`) relationships are now allowed in permission filters
  (Authzura denies them, see Non-goals)
- new auth modes (JWT-only and hook-only, with the admin secret disabled), which
  don't affect Authzura

Nothing in bool_exp compilation, NULL handling, session variables or role
resolution changed.

These come from Hasura v2.50.1's source and tests and from real-world
Hasura metadata. Hasura paths in this document are relative to
<https://github.com/hasura/graphql-engine/tree/v2.50.1/server>. They are requirements,
not suggestions.

### Metadata

- Metadata is one JSON document in `hdb_catalog.hdb_metadata`, with a
  `metadata` jsonb column and a `resource_version` int. Its layout:
  - `sources[].tables[]` entries, each with `table {schema, name}`,
    `object_relationships`, `array_relationships`, and
    `select/insert/update/delete_permissions[]`
  - each permission has the shape `{role, permission: {columns, filter,
    check, set, limit, allow_aggregations, computed_fields,
    query_root_fields, subscription_root_fields, backend_only}}`

  Authzura selects a source by name (default `"default"`) through a
  configurable connection (Repo).
- **The `$and`, `$or`, `$not` and `$exists` aliases** are accepted alongside
  the underscore forms (`src-lib/Hasura/RQL/IR/BoolExp.hs:108-115`). The
  same holds for operators (`$in`, `$has_key`, ...).
- **Shorthand equality.** A column with a bare value instead of an operator
  object, such as `author_id: X-Hasura-User-Id`, means `_eq` (see
  `tests-py/queries/graphql_query/permissions/setup.yaml`).
- **Missing vs. empty.**
  - A select permission with no `filter` key is a load error, so it's
    denied.
  - `filter: {}` means TRUE (all rows).
  - A missing `query_root_fields` means all root fields are allowed. An
    empty list means none.
- **Negative `limit`** is a load error.

### Relationships

- Cardinality comes from which section a relationship is in
  (`object_relationships` or `array_relationships`), never from the
  foreign-key form.
- Supported forms:
  - `foreign_key_constraint_on: "col"` or `["col", ...]`: the FK is on the
    local table.
  - `foreign_key_constraint_on: {column(s), table}`: the FK is on the remote
    table. This works for both array relationships and reverse object
    relationships.
  - `manual_configuration: {remote_table, column_mapping}`.
- FK-based forms are resolved through `pg_constraint`:
  - `conkey`/`confkey` are paired by ordinality.
  - Composite keys are supported, and every column pair becomes an ANDed
    equality.
  - If no constraint matches, or more than one does, the relationship is
    unresolvable and the permission is denied.
  - **Mappings with more than 8 column pairs** are denied, with a
    diagnostic at load time. Ecto needs fixed-arity SQL for preload key
    lists, and keys wider than 8 columns are vanishingly rare.

### Filter compilation (`src-lib/Hasura/Backends/Postgres/Translate/BoolExp.hs`)

**Logic and empty forms.** These must hold under `_not` too:

| Form | Value |
|---|---|
| `{}` | TRUE |
| `_and: []` | TRUE |
| `_or: []` | FALSE |
| `_not: {}` | FALSE |
| `_in: []` | FALSE |
| `_nin: []` | TRUE |

An object with several keys is an AND.

**Relationship filters**, for object and array relationships alike, compile
to:

```sql
EXISTS (SELECT 1 FROM target AS t WHERE <mapping equalities> AND <filter>)
```

- Each hop adds a nested `EXISTS`.
- Conditions inside one relationship node must match the **same** related
  row. Sibling relationship nodes stay separate `EXISTS` expressions.
- `relationship: {}` still requires that a related row exists.
- Inside a permission filter, Authzura must **not** AND in the target
  table's own select permission (`src-lib/Hasura/RQL/DDL/Permission/Internal.hs:222`).
  Doing so changes the result under `NOT EXISTS`.

**`_exists: {_table, _where}`** compiles to an **uncorrelated**
`EXISTS (SELECT 1 FROM table WHERE <_where>)`. Authzura must not add any
implicit correlation (`BoolExp.hs:120-130`).

**NULL semantics in permission filters.** For a nullable column, `_eq` and
`_neq` use Hasura's null-aware forms:
- `_eq`: `col = v OR (col IS NULL AND v IS NULL)`
- `_neq`: `col <> v OR (col IS NOT NULL AND v IS NULL)`

Non-nullable columns use plain `=` and `<>` (`BoolExp.hs:36-56`; test
`lib/api-tests/.../PermissionsKnowAboutColumnNullabilitySpec.hs`). This
requires column nullability from introspection.

**User-input filters** (the `scope_input` path below) use Hasura's user
`where` semantics instead: always plain `=` and `<>`, and an explicit
`null` operand is **rejected** with an error, which is Hasura's default
(`src-lib/Hasura/GraphQL/Schema/BoolExp.hs:274-369`). The compiler has two
explicit comparison modes, `:permission` and `:input`. The permission tree
and the input tree are compiled separately, each in its own mode, and then
ANDed together.

**Columns in permission filters.** A permission filter may reference columns
outside the role's select allowlist (`Internal.hs:184-196`). That is
allowed.

### Operator signatures

The value type depends on the operator, not always on the column type. Each
operator's signature is defined in the adapter.

| Operators | Left side | Right side |
|---|---|---|
| `_eq` `_neq` `_gt` `_lt` `_gte` `_lte` | column | column type |
| `_in` `_nin` | column | array of column type |
| `_is_null` | column | boolean |
| `_like` `_nlike` `_ilike` `_nilike` `_similar` `_nsimilar` | text column | text |
| `_regex` `_iregex` `_nregex` `_niregex` | text column | text |
| `_contains` `_contained_in` | jsonb | jsonb |
| `_has_key` | jsonb | **text** |
| `_has_keys_any` `_has_keys_all` | jsonb | **text[]** |

`_has_key` with a session variable as its value (for example, checking
membership in a jsonb map of user ids) is a common pattern in real
metadata, so the text right side matters. Postgres-specific geometry and range operators
are denied in stage one unless the builder adds them with tests.

### Session variables and roles

- **Names.** Session variable names are case-insensitive and must start with
  `x-hasura-`. Other keys are dropped (`src-lib/Hasura/Authentication/Session.hs`).
- **Values in metadata.** Session values arrive as strings and are cast to
  the operator's right-side type. Array session variables use Postgres array
  literal syntax (`"{1,2,3}"`, `"{}"`), including quoted elements (see the
  `ArrayLiteralTextEncodingSpec` regression).
  - A cast failure is an error. It is never replaced with NULL and never
    drops the predicate.
  - Values are never truncated (`DoNotTruncateSessionVariables8158Spec`).
- **Missing variables.** A missing session variable that a filter needs is
  an error: `{:error, {:missing_session_variable, name}}`, which matches
  Hasura's `not-found`.
- **Role selection** (`src-lib/Hasura/Server/Auth/JWT.hs:697-707`):
  1. The effective role is the requested role if there is one, otherwise
     the default role.
  2. The effective role must then be a member of the allowed roles, and
     this applies to the default role too. If it isn't, reject the session.
     Hasura returns `access-denied`: "Your requested role is not in allowed
     roles". Never fall back to another role.
  - An empty-string role counts as absent.
  - An empty allowed-roles list rejects every session.
- **Session normalization** (`src-lib/Hasura/Authentication/User.hs:104-122`):
  - After resolution, the canonical `x-hasura-role` session variable is
    overwritten with the effective role, so permission filters that compare
    against `X-Hasura-Role` see the role actually in force.
  - `x-hasura-admin-secret` is removed.
  - The JWT's allowed-roles and default-role claims aren't passed through
    as ordinary session variables.
- **Missing permission.** A role with no select permission on a table gets
  no access to it (Hasura simply has no root field).

## Approaches considered

**A. A Hasura-shaped core with pluggable permission sources (chosen).**
- There is one internal permission model with Hasura's semantics and a
  filter AST that doesn't depend on any syntax. A `Source` behaviour
  produces it.
- Stage one ships the Hasura catalog source. The future native source (its
  own schema, PostgREST-style operators) becomes a second implementation.
- A single compiler turns the model into Ecto.
- *Trade-off:* the core inherits Hasura's semantics, quirks included. In
  return it is proven against real metadata now, and stage two adds a source
  without touching the engine.

**B. Authzura's own model first, with Hasura as a one-time importer.**
Rejected: it can't run side by side with Hasura without keeping two copies
of the permissions, which drift apart.

**C. A Hasura-only reader now, generalized later.** Rejected: generalizing
would mean a rewrite, and Hasura's assumptions would leak into the public
API.

The user chose A.

## Design

### Components

```
Session (map | optional JWT helper)
      │
      ▼
Authzura.scope / scope_input / all ──► Store (per instance, immutable generations)
      │                                   ▲
      ▼                                   │ load / poll / reload (serialized)
Compiler (AST template + session ──►     Source behaviour
          Ecto dynamic / EXISTS)          └─ Sources.Hasura: hdb_catalog + pg introspection
      │
      ▼
Adapter behaviour ── Adapters.Postgres (operator signatures, SQL, introspection)
```

1. **Model** (`Authzura.Model.*`): plain structs with typespecs.
   - **`Table`:** `{schema, name}`, plus columns (name, Postgres type,
     nullable), primary key and relationships.
   - **`Relationship`:** name, kind (`:object | :array`), target table, and
     an ordered column mapping `[{local, remote}]`.
   - **`Permission`:**
     - `role`, `table`, `operation`
     - `filter` (AST) and `columns` (physical column names)
     - `limit`, `allow_aggregations`
     - `root_fields` (`:all` or a list of `:select | :select_by_pk |
       :select_aggregate`)
     - `check` and `presets`, parsed for later stages
     - `status` (`:ok`, or `{:denied, reasons}`)
   - **Filter AST:**
     - `{:and, [e]}`, `{:or, [e]}`, `{:not, e}`
     - `{:compare, column, op, value}`, where `op` is a neutral atom (`:eq`,
       `:in`, `:has_key`, ...) and `value` is
       `{:literal, term}` or `{:session, "x-hasura-user-id"}` (normalized
       to lowercase)
     - `{:relationship, rel, e}`
     - `{:exists, table, e}`

     Operator names belong to Authzura: the Hasura source maps `_eq` to
     `:eq`, and the future native source will map `eq.` to `:eq`. The
     null-aware forms come from column nullability at compile time, not
     from the AST.
   - **`Snapshot`:** every table and permission, plus the source version and
     the diagnostics.
2. **Source behaviour** (`Authzura.Source`):
   - Callbacks: `load(opts) :: {:ok, Snapshot.t()} | {:error, term}` and
     `version(opts) :: {:ok, term} | {:error, term}` for cheap change
     detection.
   - **`Authzura.Sources.Hasura`:**
     - reads `hdb_catalog.hdb_metadata` and picks the source
     - introspects `pg_attribute` and `pg_constraint` for column types,
       nullability and FKs
     - resolves relationships and translates permissions
     - anything it can't translate becomes a diagnostic plus `{:denied, _}`
3. **Store** (one per Authzura instance):
   - **Generations.** It publishes a **complete, immutable generation**
     atomically, for example the whole compiled snapshot under one
     `:persistent_term` key per instance.
     - Each scope call reads one generation and uses only that one.
     - Reloads are serialized through the instance's GenServer.
     - Every publication gets a local, monotonic **publication sequence**.
       Concurrent or late loads can never replace a generation with a
       higher sequence.
   - **Templates only.** Compiled permissions don't contain session values;
     those are bound on every call. No cache is keyed by user.
   - **Coherent loading.** A load reads the metadata and the Postgres
     catalog (columns, nullability, FKs) inside one `REPEATABLE READ`
     transaction when they share a database. When the metadata lives in a
     separate database, the load re-reads the version afterwards and retries
     if it changed.
   - **Version.** The observed version is `{resource_version, schema_fingerprint}`,
     compared **only for equality**. Any difference, including a lower
     `resource_version` (for example a metadata rollback) or a fingerprint
     that sorts lower, means the version changed and triggers a reload.
     Publication order comes from the publication sequence, never from
     comparing versions.
     The fingerprint is a hash over the catalog rows for tracked tables,
     such as `pg_attribute` and `pg_constraint`. That way a migration that
     changes columns, nullability or FKs triggers a reload even when
     Hasura's metadata version doesn't change. Apps should also call
     `Authzura.reload/1` after running migrations.
   - **Freshness and revocation:**
     - The Store polls `version/1` every `poll_interval` (default 5s) and
       reloads when the version changes.
     - Freshness is `last_confirmed_current_at`, on monotonic time. It is
       renewed **only** when a poll observes a version equal to the active
       generation's version. A poll that sees a newer version whose reload
       keeps failing does **not** renew it.
     - If the active generation hasn't been confirmed current within
       `max_staleness` (default 60s), every scope call fails closed with
       `{:error, :stale_permissions}`. Set `max_staleness: :infinity` to
       choose availability over freshness on purpose.
     - A successful manual `reload/1` confirms freshness. A failed one
       doesn't change it.
     - `Authzura.status(instance)` reports the active version, the observed
       version, the last successful check and the diagnostics count.
     - Queries already returned keep the policy they were built with.
       Callers should build queries per request, not keep them around.
   - **Startup.** The instance is "not ready", and scope calls return
     `{:error, :not_ready}`, until the first successful load. Startup itself
     does not crash on a failed load. It retries with backoff and logs.
4. **Compiler:** turns a permission template, a resolved session and a root
   binding into an Ecto `dynamic`, in `:permission` or `:input` comparison
   mode.
   - Every source it emits, the root and every `EXISTS` subquery, carries
     an **explicit schema prefix**, so SQL always names tables as
     `"schema"."table"`. A CTE or `search_path` can never shadow a table
     that Authzura authorizes.
   - **Bounded aliases.** Correlation aliases come from a fixed,
     predeclared atom pool (`:__authzura_0` through `:__authzura_15`),
     which caps nesting depth at 16. A permission filter that nests deeper
     is denied at load time, and input deeper than that is rejected. No
     atoms are created at runtime.
   - It builds `EXISTS` subqueries for relationships and `_exists` from
     physical table and column names, using schemaless sources with an
     explicit `prefix:`.
   - Relationship subqueries correlate through `parent_as(<immediate parent
     alias>)`.
   - Session values are bound as typed parameters, using the operator
     signatures.
   - Database-specific operators go through the adapter.
5. **Adapter behaviour** (`Authzura.Adapter`):
   - Callbacks: `operator_signature(op)`, `compile_operator(op, lhs, rhs,
     nullable?)`, and `introspect(repo, tables)`.
   - Sources validate every operator against the adapter at load time, so
     unsupported operators are denied up front.
   - `Authzura.Adapters.Postgres` is the only implementation.
6. **Session** (`Authzura.Session`):
   - `Authzura.Session.new(map, opts)` returns `{:ok, session}` or
     `{:error, reason}`.
     - It normalizes keys, keeps only `x-hasura-*` keys, and rejects keys
       that collide after case-folding with different values.
     - It resolves the role from the `x-hasura-role`, `allowed_roles` and
       `default_role` options.
   - **Trust:** a session map is **trusted input**, because whoever builds it
     decides the role. Untrusted callers may only *request* a role. Pass
     that as `requested_role:`, and it is checked against the allowed roles.
     - `requested_role:` takes precedence over any `x-hasura-role` in the
       map.
     - Resolution and normalization follow the role rules above. The
       resolved role is written back as `x-hasura-role`.
   - **`Authzura.JWT.verify(token, opts)`** is optional and needs the
     optional JWT dependency. It requires:
     - an explicit algorithm allowlist (HS256 by default, never `none`)
     - a key
     - `exp`, `nbf` and `iat` validation with `allowed_skew`
     - optional `iss` and `aud` checks
     - the claims namespace (default `https://hasura.io/jwt/claims`) and
       optional `claims_map`

     On success it returns a `Session` via `Session.new/2`.

     Parity rules from `tests-py/test_jwt.py` and `test_jwt_claims_map.py`:
     - Missing `x-hasura-allowed-roles` or `x-hasura-default-role` is an
       error, and allowed roles must be a list.
     - Expired tokens are rejected unless they're within `allowed_skew`.
     - When `iss`/`aud` aren't configured, they're not checked, even if the
       token carries them.
     - `claims_map` entries are JSONPath paths with an optional `default`,
       or static values. A missing mapped claim with no default is an
       error.
     - `claims_namespace_path` and `claims_format: :stringified_json` are
       builder calls: support them, or reject that configuration.
     - With no token and an `unauthorized_role:` option, the helper returns
       a session with that role. Without that option, it's an error.

### Caching

Stage one never touches the database to look up permissions per request.
- **Load once, eagerly.** The Store reads the whole metadata document (one
  query) plus catalog introspection, validates everything, and compiles a
  session-free template for every `{role, table, operation}`.
  - Eager loading is deliberate: it is what produces load-time diagnostics,
    so that unenforceable permissions surface at startup instead of on
    first use, and `mix authzura.check` depends on it.
  - Even metadata with hundreds of tables and several roles compiles to a
    few thousand small structs.
  - Compiling templates lazily on first use is a possible later
    optimization behind the same API, if metadata size ever calls for it.
- **Per request:** an in-memory lookup of the template, plus binding the
  session values. No database round trip happens for authorization; only
  the actual data query runs.
- **Invalidation:** per-node version polling (see Store). Each node polls
  independently, so no cross-node broadcast is needed. Change triggers
  can't be used, because Authzura never writes to Hasura's catalog.
- **Storage:** one immutable generation per instance.
  - `:persistent_term` is the default candidate, because reads are
    near-free. Updating it triggers a global GC pass, which is acceptable
    because reloads are rare: they only happen when metadata or the schema
    changes.
  - ETS with a generation pointer is an acceptable alternative if
    benchmarks favor it. This is the builder's call; the atomic-generation
    rules above apply either way.
- **No external cache (for example Nebulex) in stage one.** Permission
  templates must live in each node's memory to be fast, and polling already
  handles invalidation. An optional Nebulex adapter belongs in the
  native-source stage, where per-request lookups of users' role
  assignments in Authzura's own tables are worth caching. Because Authzura
  owns those tables, it can invalidate them immediately with Postgres
  `LISTEN/NOTIFY`.

### Public API

```elixir
# host app supervision tree
{Authzura, name: MyApp.Authz, repo: MyApp.Repo,
 source: {Authzura.Sources.Hasura, source_name: "default"}}

{:ok, session} =
  Authzura.Session.new(%{"x-hasura-user-id" => "42",
                         "x-hasura-org-id" => "7"},
                       allowed_roles: ["editor"], default_role: "editor")

# Trusted developer query: scope and execute in one step (recommended)
{:ok, rows} =
  Order
  |> where([o], o.status == "open")
  |> order_by([o], desc: o.inserted_at)
  |> Authzura.all(session,
       instance: MyApp.Authz,
       columns: [:id, :status],
       preload: [items: [:product]])     # Hasura relationship names

# When you need the query itself (scoping must be the last step)
{:ok, query} = Authzura.scope(Order, session, instance: MyApp.Authz)
query = Authzura.scope!(Order, session, instance: MyApp.Authz)

# Untrusted input (user / HTTP / LLM)
{:ok, rows} =
  Authzura.all_input(Order, session,
    %{columns: ["id", "status"],
      filter: %{"status" => %{"_eq" => "open"}},
      order_by: [{"created_at", :desc}],
      limit: 50, offset: 0},
    instance: MyApp.Authz)
# also: Authzura.scope_input/4 returns the query

# Introspection and operations
Authzura.permission(session, Order, instance: MyApp.Authz)
Authzura.allowed_columns(session, Order, instance: MyApp.Authz)
Authzura.status(MyApp.Authz)       # instance-level calls take the instance
Authzura.diagnostics(MyApp.Authz)  # positionally, defaulting to Authzura
Authzura.reload(MyApp.Authz)
```

**Conventions:**
- **Signatures:**
  - `scope(queryable, session, opts)` and `scope!/3`
  - `all(queryable, session, opts)` and `one/3`
  - `scope_input(queryable, session, input, opts)` and `all_input/4`
  - `permission(session, queryable, opts)`, `allowed_columns/3` and
    `validate_columns/4`
  - `status(instance \\ Authzura)`, `diagnostics/1` and `reload/1`
  - Per-call functions take `instance:` in `opts` (default `Authzura`).
- **Errors.** Expected denials return `{:error, reason}`, and `!` variants
  raise. Reasons:
  - `:forbidden`
  - `{:forbidden_columns, cols}`
  - `{:missing_session_variable, name}`
  - `{:invalid_session_value, name, reason}`
  - `{:unsupported_query, reason}`
  - `{:invalid_input, reason}`
  - `:root_field_disabled`
  - `:stale_permissions`
  - `:not_ready`
- **`all/3` and `one/3`** scope and execute in one step. They are the
  recommended entry points, because nothing can be added to the query
  between scoping and running it.

**Execution is bound to the authorized database:**
- Each instance is bound to one repo and records its data-source identity.
- `all/3`, `one/3` and `all_input/4` check that `repo.get_dynamic_repo()`
  is the repo the instance introspected. Otherwise they return
  `{:error, {:unsupported_query, :dynamic_repo}}`. Multi-database apps run
  one instance per database.
- Execution options are an allowlist: `:timeout`, `:log`,
  `:telemetry_options` and `:telemetry_event`. Source-changing options such
  as `:prefix` are rejected.
- Repo callbacks that rewrite queries (`prepare_query/3`) are trusted host
  code, and this is documented.
- **Read-only execution.** Outside an existing transaction, `all`, `one`
  and `all_input` run in a `READ ONLY` transaction, which is
  `REPEATABLE READ` when preloads are present. Inside a caller's
  transaction, a read without preloads runs as is. The preload rule is
  described under Related data.

**Root table:**
- Authzura derives the physical root `{prefix, source}` using Ecto's actual
  precedence: an explicit `from` prefix, then the schema's
  `@schema_prefix`, then the query prefix (`put_query_prefix`), then the
  instance's `default_prefix` (default `public`).
- It then **pins** that prefix on the root `from`, so a repo-level
  `prefix:` option or a non-default `search_path` can't redirect the query
  to another table.
- `table:` is an **assertion**. If it doesn't match the derived root, the
  call errors. It never overrides.

**Columns:**
- Authorization uses **physical column names**. Requested schema fields are
  mapped through `__schema__(:field_source, field)`. For the input APIs,
  string column names map back to schema fields through the reverse of that
  map. Virtual fields, and fields that don't map to a column, are rejected.
- Authzura **owns the select.** It selects exactly the requested columns.
  The default is every allowed column: for schema queries, the allowed
  columns that map to schema fields; for table-only queries, all allowed
  physical columns.
- Results are **maps by default**: keyed by schema field atoms for schema
  queries, or by column-name strings for table queries. Structs with only
  some fields loaded aren't offered, because they quietly contain nil
  values and defaults.
- `{:forbidden_columns, cols}` is returned if the caller asks for a column
  the role can't read.

**Accepted query shapes for `scope`/`all`.** A real pipeline often already
has joins, CTEs and preloads, so Authzura accepts as much as it can enforce
and rejects the rest with `{:unsupported_query, reason}`:
- **Root `from`:** a schema module or a table source (`"table"`, optionally
  with `prefix:`).
  - A fragment or values source is rejected.
  - A subquery source is rejected with guidance to scope the *inner* query
    first. Authzura can't tell which table's permission applies to a
    subquery's output after the fact.
- **CTEs (`with_cte`): allowed when read-only.**
  - They're trusted like joins. They can't shadow authorized tables,
    because every source Authzura emits is schema-qualified (see Compiler).
  - A CTE whose operation modifies data (`operation: :update_all` or
    `:delete_all`), at any nesting depth, is rejected. So is a CTE whose
    body is a fragment.
  - As defense in depth, `all`/`one`/`all_input` run inside a `READ ONLY`
    transaction (see Execution).
- **Combinations** (`union`, `union_all`, `except`, `intersect`):
  - In stage one, every branch must have the **same physical root table**
    and be an accepted shape. Each branch is scoped with that table's
    permission, and all branches get the same canonical, ordered projection.
  - Combinations over different tables are rejected, and so are
    combinations with preloads.
  - The caller's `order_by`, `limit` and `offset` on the parent query apply
    to the whole combination, as in Ecto. Each branch's own limit is capped
    by the permission limit, inside the branch.
- **`preload`:**
  - An Ecto preload in the query is accepted only in its **plain form**:
    nested association names on simple `belongs_to`, `has_one` or
    `has_many` associations, with no `where:`, `preload_order:`, `through:`,
    custom preload query, preload function or join-bound preload.
  - Each such association must map to a Hasura relationship (same target
    table and same ordered key mapping) that the relationship allowlist
    permits.
  - Authzura then strips the preload from the query and loads it itself
    (see Related data). Every other form is rejected, so a caller's
    association restrictions are never silently dropped.
  - Preloads are **executor-only:** `scope`/`scope_input` reject them,
    because a plain returned query can't run Authzura's loader.
- **Rejected outright:** an existing `select` or `select_merge`;
  `group_by`, `having` or `windows`; locks; and `distinct` of any form.
  `distinct` with ordering on unselected columns breaks once Authzura owns
  the projection, and Authzura never repairs it by adding columns.
- **Limits:** `limit` is absent or a nonnegative integer, either a literal
  or a pinned `^n` that is checked when the query runs. `with_ties` is
  rejected. `offset` is absent or a nonnegative integer.
- **Trusted:** the caller's `where`, `order_by` and `join` (see below).
  Joined tables can't be selected from, because Authzura owns the select.
- **Root alias:** Authzura reuses the root's alias if it has one, and
  otherwise attaches `:__authzura_0` with `from(q in query, as: ^alias)`.
  It errors if a caller binding uses a reserved `:__authzura_*` name.
- **Scoping must be the last step.** Anything added afterwards
  (`or_where`, `select_merge`, `exclude`, ...) can undo enforcement. This is
  documented, and it's why `all/3` and `one/3` exist.

**Related data: the relationship allowlist** (Hasura's model). In Hasura,
related data is only reachable through relationships declared in the
metadata, and every table reached gets that role's own permission.
Authzura does the same:
- `preload:` (an option to `all`/`one`/`all_input`, or translated from a
  plain Ecto preload) names **Hasura relationships**.
- **Executor-only.** Preloads exist only on `all`, `one` and `all_input`.
  This is the one place Authzura reads columns the caller didn't request
  (mapping keys, see below). They're read internally and never returned.
- A relationship is allowed only if it's declared in the metadata **and**
  the role has a select permission on the target table. The target's
  `root_fields` are irrelevant here: as in Hasura, a table whose root
  fields are disabled can still be reached through a relationship.
  Otherwise the call returns `:forbidden`.
- **Bounded work.** The whole preload tree is validated before anything
  runs: a maximum depth (`max_preload_depth`, default 4) and a maximum
  node count (`max_preload_nodes`, default 16), with stricter defaults for
  `all_input`. Self- and cyclic relationships are allowed only within
  those limits. Exceeding a limit is rejected up front, never with partial
  results.
- **One consistent snapshot.**
  - An operation with preloads pins **one policy generation and one
    session** for the whole tree.
  - It runs the root query and every level inside one
    `REPEATABLE READ READ ONLY` transaction, so a parent can't change
    owner between the parent and child reads.
  - If the caller is already in a transaction, Authzura can't raise the
    isolation level. Such calls return
    `{:error, {:unsupported_query, :preload_in_transaction}}`, unless the
    caller passes `in_transaction: :trust_isolation` to state that their
    transaction is already `REPEATABLE READ` or stronger.
- **How each level loads.** Each level is one query on the target table,
  joined to a `VALUES` list of `(parent_index, key_1, ..., key_n)`. Every
  mapping pair is compared by **SQL equality** (`t.k_i = p.k_i`, ANDed),
  and the query returns `parent_index`. So:
  - complete key tuples are kept, without per-column `IN` cross-products
  - PostgreSQL decides equality, including NULLs, `citext`, collations and
    numerics
  - Elixir only groups the results by `parent_index`

  Each level applies:
  - the target's row filter
  - the requested or default allowed columns
  - for array relationships, the target's permission limit **per parent**,
    via `row_number() OVER (PARTITION BY parent_index ORDER BY <order>)` or
    `LATERAL`
  - optional `order_by:` for that relationship, validated against the
    target's allowed columns

  Object relationships load at most one row per parent.
- **Ordering.** Like Hasura, there is no implicit order when a limited
  array relationship has no `order_by`, so which rows come back is
  unspecified. Tests for that case assert cardinality and membership, not
  exact IDs. If a relationship has an `order_by`, it applies inside the
  per-parent limit, and the assembled list keeps that order.
- **Projection.** Internal and public projections are kept separate. Every
  stitching field the caller didn't request is stripped from the output,
  even when the role could select it.
- **Results** nest under the relationship name: an object relationship
  becomes a map or `nil`, and an array relationship becomes a list.
- **Per-relationship options:**
  `preload: [items: [columns: [:id, :qty], order_by: [asc: :id], preload: [:product]]]`.

**Root fields.** If the permission's `root_fields` excludes `:select`,
`scope`/`all` return `{:error, :root_field_disabled}` for that table as the
root. It can still be reached as a preloaded relationship, as above.

**Row limit.** The effective limit is `min(caller_limit, permission_limit)`,
and filtering is applied before pagination. The permission limit caps each
result. It is not a total-access budget, which matches Hasura
(`src-lib/Hasura/Backends/Postgres/Translate/Select/Internal/Process.hs:146-161`).

**Trusted vs. untrusted query input** (decided with Codex's second opinion):
- **`scope`/`all` trust the caller's own Ecto code.** Analysing arbitrary
  `Ecto.Query` structs reliably (bindings, expanded dynamics, fragments,
  subqueries) is a large project that would either fail open or reject
  legitimate queries. Developer predicates may also legitimately reference
  hidden columns.
- **The risk.** Filtering or sorting on a hidden column leaks its values
  through which rows come back, for example by asking `salary > x`
  repeatedly. Hasura prevents this: a user `where`/`order_by` can't mention
  columns the role can't select.
- **So outside input must use `scope_input`/`all_input`:**
  - They start from a schema or table, never from a caller query.
  - They accept `columns`, `filter`, `order_by`, `limit`, `offset` and
    `preload` (relationship names, checked against the allowlist) as data.
  - `filter` is parsed by the active source's filter reader in **input
    mode** (Hasura bool_exp now, PostgREST-style later):
    - every value stays a literal, so a string such as
      `"x-hasura-user-id"` is never treated as a session variable
    - session-reference nodes are rejected
    - explicit `null` operands are rejected
    - depth and node count are bounded
  - They reject any column outside the role's select columns, any
    relationship or `_exists` *inside the filter*, and any unsupported
    operator.
  - The input filter is compiled in `:input` mode and ANDed with the
    permission filter, which is compiled in `:permission` mode.
- `validate_columns/4` remains as a building block, documented as "not
  query certification".
- An opt-in strict mode that analyses arbitrary Ecto queries is deferred. If
  it ever ships, it must reject every construct it doesn't understand.

**Admin bypass is opt-in.** The default is `admin_role: nil`, meaning no
bypass. When it's configured, a session with that role skips row filters,
column restrictions and limits. Projection, preloads and result shape stay
the same.

### Configuration (instance child options, validated with NimbleOptions)

```elixir
{Authzura,
 name: MyApp.Authz,               # instance name (default Authzura)
 repo: MyApp.Repo,                # data repo: introspection + all/one
 source: {Authzura.Sources.Hasura,
          repo: MyApp.Repo,       # or a separate metadata repo
          source_name: "default"},
 adapter: Authzura.Adapters.Postgres,
 default_prefix: "public",
 admin_role: nil,                 # opt-in bypass role
 poll_interval: 5_000,            # ms, or nil for manual reload only
 max_staleness: 60_000,           # ms, or :infinity
 max_preload_depth: 4,
 max_preload_nodes: 16}
```

### Failure behavior

- **Load time:** each permission that can't be translated produces a
  diagnostic (role, table, operation, filter path, reason) and is denied. A
  summary is logged, and the details are available from
  `Authzura.diagnostics/1`.
- **Query time:**
  - an unknown table, role or permission, or a denied permission, returns
    `:forbidden`
  - a missing or uncastable session value returns the matching error tuple
  - unsupported query shapes and stale or not-ready instances return their
    error tuples

  Nothing degrades into allowing access.

## Testing

Authorization code earns trust through tests, so this is a first-class
deliverable.

**Layers:**
1. **Pure unit tests:**
   - translating Hasura JSON into the AST: every operator, the `$`
     aliases, the empty forms, mixed-case session variables, and
     missing-vs-empty fields
   - session and JWT handling
   - query-shape validation
   - snapshot tests of the compiled SQL (`Ecto.Adapters.SQL.to_sql`), which
     pin the null-aware forms and the `EXISTS` structure
2. **Real-Postgres integration tests:** the main suite.
   - A fixture database has tables in two schemas, nullable and non-null
     columns, jsonb, single and composite FKs, a self-referential
     relationship, a reverse object relationship and a manual relationship.
   - A fixture `hdb_catalog.hdb_metadata` row is written by the test setup.
     No Hasura is needed.
   - Each test asserts the exact rows and columns returned, or the exact
     error.
3. **Opt-in Hasura parity suite** (tagged `:hasura_parity`, excluded by
   default):
   - A `docker-compose` runs `hasura/graphql-engine:v2.51.6` against the same
     fixture database and metadata.
   - The suite runs equivalent reads through Hasura GraphQL and through
     Authzura, and diffs the rows, the columns **and the failures** (missing
     session variable, disallowed role, empty results).
   - It lives in this repo, so the compatibility claim can be reproduced.
4. **Adopter check** (outside this repo): provide a documented recipe and
   a mix task, `mix authzura.check`, that load an existing Hasura database's
   metadata and report diagnostics. Adopters run it against their real
   metadata before relying on Authzura. Stage one is validated this way
   against at least one large production Hasura v2 metadata set (hundreds
   of tables). No third-party metadata is ever committed to this repo.

**Scenario catalog**, the core set ported from Hasura v2.50.1's tests. Paths
are relative to
<https://github.com/hasura/graphql-engine/tree/v2.50.1/server>.

- **Row filters:**
  - an author sees only their own rows
  - published-only roles; an editor sees in-review plus published
  - `{}` returns all rows
  - (sources: `lib/api-tests/.../Schema/DataValidations/Permissions/SelectSpec.hs`,
    `tests-py/queries/graphql_query/permissions/`)
- **Empty forms, also under `_not`:**
  - `_in: []` returns no rows
  - `_nin: []` returns all rows
  - `_or: []` and `_and: []`
  - (source: `tests-py/.../boolexp/basic/*empty_array*`)
- **NULL handling:**
  - null-aware `_eq`/`_neq` on nullable columns, plain on non-null columns
  - a literal `null` value, and rows with a NULL column under `_not`
  - `_is_null` true and false
  - (source: `PermissionsKnowAboutColumnNullabilitySpec.hs`)
- **Relationships:**
  - object relationships, array relationships, and 3-hop nesting
  - several conditions in one node must match the same related row
  - sibling nodes stay independent
  - `relationship: {}` requires a related row to exist
  - negated relationships
  - a multi-column mapping (`Regression/MultiColumnObjectRelationshipsSpec.hs`)
  - a self-relationship
  - the target table's own permission is **not** applied inside a filter
- **`_exists`:**
  - uncorrelated
  - against the same table as the root with a session variable
    (`Regression/RootExistElementAliasing9457Spec.hs`)
  - inside `_or` and `_not`
- **Shorthand and aliases:**
  - a bare `col: "X-Hasura-User-Id"` equals `_eq`
  - `$or`, `$in` and `$has_key` behave the same as `_or`, `_in` and
    `_has_key`
  - mixed-case session names such as `X-HASURA-USER-ID` in metadata
- **Operators:**
  - the comparison set
  - the `_like`, `_ilike`, `_similar` and `_regex` families
    (`tests-py/.../boolexp/search/`)
  - jsonb `_contains`, `_contained_in`, `_has_key` (including with a
    session variable), `_has_keys_any`, `_has_keys_all`
    (`tests-py/.../boolexp/jsonb/`, `permissions/jsonb_has_all.yaml`)
- **Session variables:**
  - case-insensitive names
  - missing variable gives an error (`permissions/select_articles_without_required_headers.yaml`)
  - array variables `{1,2,3}` and `{}` (`Databases/Postgres/DataValidation/PermissionSpec.hs`)
  - quoted and comma elements (`Regression/ArrayLiteralTextEncodingSpec.hs`)
  - long values aren't truncated (`Regression/DoNotTruncateSessionVariables8158Spec.hs`)
  - a cast failure gives an error, never NULL
- **Columns:**
  - the projection holds only the requested allowed columns, checked on the
    executed SQL
  - a disallowed requested column gives `{:forbidden_columns, _}`
    (`permissions/user_cannot_access_remarks_col.yaml`)
  - `field :x, source: :y` maps to the physical column
  - a permission filter on a non-selectable column still works
- **Input path:**
  - filtering, sorting or selecting a hidden column is rejected
  - a relationship or `_exists` in input is rejected
  - the input filter is ANDed with the permission filter
  - plain-equality semantics apply to input
- **Roles:**
  - the requested role is allowed
  - a requested role that isn't allowed is rejected
  - the default role is used when none is requested
  - an empty-string role counts as absent
  - a role without a permission gets `:forbidden`
  - admin bypass only when configured
- **Root fields:** `query_root_fields: []` gives `:root_field_disabled`
  (`Auth/Authorization/DisableRootFields/SelectPermission/*`).
- **Limits:**
  - `min(caller, permission)`
  - a negative permission limit is a load error
  - a caller `with_ties` or a non-literal limit is rejected
    (`tests-py/.../limits/`, `Regression/ObjectRelationshipsLimit7936Spec.hs`)
- **Query shapes:**
  - rejected: a subquery or fragment root, an existing select, group_by,
    any distinct, and `with_ties`
  - accepted: a CTE, including one **named like an authorized table**; the
    executed SQL must still read the schema-qualified real table
  - same-table union branches are each scoped, and the caller's
    limit/offset/order apply to the whole combination
  - a union across different tables, or a union with preloads, is rejected
  - a branch whose projection or types can't be aligned is rejected
  - a modifying CTE (`update_all` or `delete_all`), including one that's
    never referenced, is rejected; so is a fragment CTE
  - `all` runs in a read-only transaction
  - a pinned `limit(^n)` is accepted and checked when the query runs
  - an existing root alias is reused
  - a caller join that collides with a reserved alias gives an error
  - a caller join whose alias matches a relationship name doesn't
    mis-correlate
  - nesting deeper than the alias pool is rejected without creating atoms
- **Relationship preloads:**
  - an allowed relationship loads with the target's row filter and columns
  - an undeclared relationship, or a target without select permission,
    gives `:forbidden`
  - a target whose root fields are disabled is still reachable through a
    relationship
  - the per-parent permission limit on array relationships (two parents,
    limit 1, each gets one row)
  - an object relationship gives at most one row or `nil`
  - mapping columns the role can't select are fetched but stripped from
    the output
  - a plain Ecto `preload` that maps to an allowed relationship is
    translated; a preload with `where:`, `preload_order:`, `through:`, a
    custom query or a function is rejected
  - `scope`/`scope_input` with a preload is rejected (executor-only)
  - composite-key and reverse object relationships
  - **crossed composite tuples**: parents (1,2) and (2,1) must not receive
    each other's children
  - partial NULL keys
  - case-insensitive (`citext`) keys match the way Postgres matches them
  - nested preloads three levels deep
  - the depth and node limits; a repeated self-relationship and a wide
    branching tree are rejected up front with no partial results
  - **consistency:** a parent's ownership changes between levels
    (simulated with a concurrent transaction) and a reload happens
    mid-operation; the result reflects one snapshot and one generation
  - preloads inside a caller transaction give `:preload_in_transaction`
    unless `in_transaction: :trust_isolation` is passed
  - a limited array relationship with no `order_by` is checked by
    cardinality and membership; with an `order_by`, by exact order
  - stitching fields the caller didn't request are absent from the output,
    even when the role could select them
- **Prefixes and execution:**
  - the precedence order: `from` prefix, then `@schema_prefix`, then
    `put_query_prefix`, then the default
  - conflicting prefixes resolve in that order
  - a `Repo.all(..., prefix:)` override can't redirect a pinned query
  - a non-public `search_path` doesn't change which table is read
  - a `table:` assertion mismatch gives an error
  - `put_dynamic_repo` to a different repo gives `:dynamic_repo`
  - a disallowed execution option is rejected
- **Reload:**
  - an atomic generation swap during concurrent scoping (each call sees one
    generation)
  - a revoked permission takes effect after a version change
  - an older generation is never published (the publication sequence)
  - a schema-only change whose new fingerprint sorts **lower** still
    reloads, and so does a `resource_version` rollback
  - a failed reload past `max_staleness` gives `:stale_permissions`
  - **successful polls that see a newer version, while every reload
    fails, still reach `:stale_permissions`** after `max_staleness`
  - a schema change (column dropped, FK changed) without a Hasura metadata
    version change triggers a reload through the fingerprint
  - a schema change during loading gives a retried, coherent snapshot
  - session values never leak across calls (two sessions concurrently on
    one template)
  - not-ready before the first load
- **JWT:**
  - valid claims
  - missing allowed or default roles
  - allowed roles given as a string
  - expired, and within skew
  - bad signature
  - an `alg` not on the allowlist
  - `aud`/`iss` configured vs. not configured
  - `claims_map` with and without defaults, and with static values
  - no token, with and without `unauthorized_role`
- **Security regression to port in spirit:** Hasura's computed-field
  row-permission bypass suite
  (`tests-py/queries/graphql_query/computed_fields_row_permission_bypass/`).
  Authzura's equivalent applies to **user input and returned data**: no
  input filter, sort or preload may test or return values of rows or
  columns the role can't see. Assert that probes return `[]` or a
  rejection, and include negative controls so the suite also catches
  over-filtering.
  - Pair this with the opposite case: a **permission** filter that
    traverses a table the role can't read (for example an ACL table) must
    still work.
- **Input mode:**
  - a literal `"x-hasura-user-id"` string in an input filter stays a
    literal, in every casing, inside lists and inside nested JSON
  - an explicit `null` operand gives `{:invalid_input, _}`
  - on a nullable column with both a permission comparison and an input
    comparison, each tree uses its own NULL mode (check the SQL and the
    rows)
  - input exceeding the depth or node limits is rejected
- **Role resolution:**
  - a default role not in allowed roles gives an error
  - an empty allowed-roles list gives an error
  - `requested_role:` takes precedence over the map's `x-hasura-role`
  - a permission comparing against `X-Hasura-Role` sees the resolved role
  - `x-hasura-admin-secret` is stripped
- **Write-only settings:** `backend_only: false` and well-formed `check`
  and `set` on write permissions load with no read-side diagnostic.
- **How assertions are made:** where a leak is possible, assert on the
  executed SQL (projection, schema-qualified sources, correlation) as
  well as on the returned rows, and assert the exact rejection.
- **Load diagnostics:** an unknown operator, an inherited role, a computed
  field in a filter, `_ceq`, an ambiguous FK, and a missing table or column
  each produce a denial plus a diagnostic.
- **Later stages (catalog only, not built now):** insert `check` and
  presets, update columns and `check`, delete filters, `backend_only`,
  aggregation predicates and `allow_aggregations`, and inherited-role column
  redaction (`CASE WHEN ... THEN col ELSE NULL END`).

## Project setup

Authzura is a standalone Hex library, set up like the other agoodway open
source libraries:
[pgrest](https://github.com/agoodway/pgrest),
[pgflow](https://github.com/agoodway/pgflow),
[tango](https://github.com/agoodway/tango),
[dripdrop](https://github.com/agoodway/dripdrop) and
[ecto_evolver](https://github.com/agoodway/ecto_evolver).

- **`mix.exs`:**
  - `@version "0.1.0"` and `@source_url "https://github.com/agoodway/authzura"`
  - `elixir: "~> 1.19"`
  - `elixirc_paths` includes `test/support` in test
  - `cli/0` sets `preferred_envs: [quality: :test]`
  - `package/0`: MIT, maintainer Chase Pursley, files `lib mix.exs
    README.md LICENSE .formatter.exs`, excluding `docs/superpowers/`
  - `docs/0` with `main: "readme"`
  - dialyzer `plt_add_apps: [:mix, :ex_unit]`
- **`quality` alias,** the same as pgrest and pgflow:
  1. `compile --warnings-as-errors`
  2. `deps.unlock --unused`
  3. `format --check-formatted`
  4. `sobelow --config`
  5. `ex_dna`
  6. `doctor`
  7. `credo --strict`
  8. `dialyzer`
- **Dev/test dependencies:** `ex_doc`, `credo`, `dialyxir`, `doctor`,
  `ex_slop`, `sobelow` and `ex_dna`, at current versions, pinned the way
  pgflow pins them.
  - **ExSlop must actually be enabled in `.credo.exs`.** pgrest and pgflow
    list `ex_slop` as a dependency but never enable its checks.
    - Add `++ Enum.map(ExSlop.recommended_checks(), &{&1, []})` to the
      enabled checks.
    - tango, dripdrop and ecto_evolver list the checks explicitly instead;
      either way works.
  - **mix_unused is skipped.** In a library, the public API is "unused"
    inside `lib/` by definition.
- **Runtime dependencies:**
  - `ecto` and `ecto_sql` (core)
  - `postgrex` (the Postgres adapter)
  - `jason` and `telemetry`
  - `nimble_options` (option validation, as in pgflow)
  - an optional JWT library for `Authzura.JWT` (Joken or JOSE; the
    builder's call), marked `optional: true`
- **Config files:** copy and adapt `.credo.exs`, `.doctor.exs` (moduledoc
  coverage 100%, struct typespecs required), `.sobelow-conf`,
  `.formatter.exs` and `.tool-versions` (elixir 1.19.1-otp-28, erlang
  28.1.1). Add `.dialyzer_ignore.exs` only if it's needed.
- **No demo app.** Unlike pgrest and pgflow, Authzura has no UI and nothing
  to deploy. The real-Postgres suite is the proof, and the README carries a
  short runnable example.
- **Tests:**
  - The `test` alias creates the test database first.
  - A test-only Repo lives under `test/support`.
  - A `docker-compose.yml` provides Postgres, plus Hasura v2.51.6 for the
    parity suite only.
- **No application callback.** The host app adds `{Authzura, opts}` (a
  supervisor that owns the Store) to its own tree. Multiple instances and
  test-local instances are supported.
- **Style:**
  - Return `{:ok, _}` or `{:error, _}`, with `!` variants.
  - Keep a pure core: Source translation, the Model and the Compiler are
    pure functions over data. Side effects live in the Source loader, the
    Store and the `all`/`one` executors.
  - Never create atoms from metadata. Table and column names stay strings,
    and `field/2` takes string names for schemaless sources, with explicit
    type casting. Schema-backed fields map through `__schema__` reflection.
  - Module-level aliases and imports only.
  - Telemetry events: `[:authzura, :load | :reload | :scope]` with
    `:start`/`:stop`/`:exception`, plus the granted or denied result in the
    metadata.

## Left to the builder

- Module layout and private function names beyond the shapes above.
- The JWT library choice, and whether RS*/JWK keys ship in stage one.
- Exact diagnostic struct fields.
- Whether `select_by_pk` gets a convenience API (`Authzura.get/3`) in stage
  one. If it does, it must honor `root_fields`.
- Prototype the root-alias and subquery-correlation approach first, and
  confirm it with the query-shape tests before building the rest.

## Ideas to evaluate from PostgREST (later, not stage one)

[PostgREST](https://github.com/PostgREST/postgrest) is the Haskell server
behind Supabase's API, and the model for
[pgrest](https://github.com/agoodway/pgrest). Its core approach is
explicitly **out of scope**: per-request `SET ROLE` plus Postgres
row-level security (RLS) policies. That model puts authorization in
database roles and policies, so every permission change becomes a
migration, which is exactly what Authzura avoids.

These ideas from it are worth evaluating:
- **Single-statement embedding.** PostgREST loads nested resources in one
  SQL statement, using lateral joins and JSON aggregation. That's an
  alternative to Authzura's per-level preload queries inside a
  `REPEATABLE READ` transaction: a single statement is consistent by
  construction.
- **Schema-cache reload over `NOTIFY`.** PostgREST reloads when it
  receives `NOTIFY pgrst`. For the native source, where Authzura owns its
  tables, this is the planned invalidation path.
- **A global `max-rows` cap** applied to every response, alongside the
  per-permission limits.
- **A `db-pre-request` hook.** A configured function runs before each
  request for custom checks, such as banning a user. The Authzura
  equivalent would be an optional per-instance session check callback.
- **Its request-parameter grammar,** for the PgRest integration stage.
  That's the `PostgREST-style` input syntax the native source adopts.

## Later stages (for orientation only, not to be built now)

1. Write enforcement: `check`, presets and write-column allowlists for
   insert and update; delete filters.
2. Aggregate reads that honor `allow_aggregations`.
3. A native source: Authzura's own `authzura` schema with PostgREST-style
   operators, the same model, and a Hasura-to-native importer.
4. Custom tenant roles, role inheritance designed properly (column
   redaction rather than the leaky union), and the admin UI.
5. PgRest integration through a richer authorization hook that can return a
   scoped query and a column list and can scope embedded relations. This
   lands in PgRest only as a general improvement.

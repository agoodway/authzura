# Querying

`all/3`, `one/3` and `get/4` scope the query, run it and return maps. `scope/3`
returns the scoped query for you to run. Requests built from user input go
through the input functions instead (see [Untrusted input](#untrusted-input)).
The examples use a `session` built as in [Sessions and JWT](#sessions-and-jwt).

## Sessions and JWT

An `Authzura.Session` is one resolved role plus its `x-hasura-*` variables.
Build it from whatever your request pipeline already authenticated:

```elixir
{:ok, session} =
  Authzura.Session.new(
    %{"x-hasura-user-id" => "42", "x-hasura-org-id" => "1"},
    allowed_roles: ["user", "editor"],
    default_role: "user"
  )
```

The requested role (`requested_role:`, then the map's `x-hasura-role`) falls
back to the default role, and must be in `allowed_roles` when that is given.
Variable names are lowercased, and conflicting spellings of one name are an
error. One role applies per request: roles are never merged.

### Trust model

Authzura trusts the session it is handed. It does not authenticate anyone:
build the session only from values your own code verified, such as a
verified token or a trusted gateway header, never from raw client input.
The one thing it does enforce is that the session's role is a role Hasura
grants permissions to, and that session variables are cast to the column's
type before any SQL runs (`{:invalid_session_value, name, reason}`).

### JWT

With the optional `:jose` dependency, `Authzura.JWT.verify/2` verifies a
Hasura-style JWT and returns the session:

```elixir
{:ok, session} =
  Authzura.JWT.verify(token,
    key: secret,
    algorithms: ["HS256"],
    unauthorized_role: "anonymous"
  )
```

It fails closed: a present but invalid token never falls back to the
unauthorized role, `alg: none` is always rejected, and the key must match
the algorithm family. See `Authzura.JWT` for the claims options and its
error reasons.

## `all` and `one`

```elixir
import Ecto.Query

alias MyApp.Article

{:ok, articles} =
  Article
  |> where([a], a.status == "draft")
  |> Authzura.all(session,
    instance: MyApp.Authz,
    columns: [:id, :title],
    preload: [:author, comments: [columns: [:id, :body], order_by: [desc: :id]]]
  )

{:ok, article} =
  Article
  |> where([a], a.id == 1)
  |> Authzura.one(session, instance: MyApp.Authz)
```

The read runs in a `READ ONLY` transaction through the instance's repo (or
as one statement on read-only connections, see
[Configuration](configuration.md#read-only-connections)), and rows are
maps: keyed by field atoms for schema queries, by column strings for table
queries.

Without `columns:` the read selects every column the role may read except
those of a type your repo's Postgrex types do not decode (base kind `:other`:
composites, arrays of extension types, and extension types your repo has no
extension for). Introspection asks your repo's Postgrex types module about
each extension type, so a PostGIS `geography` or `geometry` is selected by
default when the module includes PostGIS, and left out when it does not. A
schema query casts what it selects through the schema's field types, so a
field type that does not match the decoded value (`:map` against a
`%Geo.Point{}`, say) raises an Ecto load error. Types Postgrex
decodes (`bytea`, `interval`, `inet`, `time`, `point`, ranges, ...) are
selected, and a domain counts as its base type. Name an `:other` column in
`columns:` to read it. A value Postgrex cannot decode is
`{:error, {:unsupported_column_type, column}}` (Postgrex drops that
connection and the pool reconnects), and `mix authzura.check` warns about
every such column a role may select. The same Postgrex message can also come
from a parameter of your own fragment whose type it cannot encode; with no
`:other` column selected that error is raised as is.

A table query (no schema) returns values as Postgrex decodes them: a `uuid`
column is a raw 16-byte binary. Pass a schema, or load the value with
`Ecto.UUID.load/1`. `one/3` returns `{:ok, nil}` for no row and
`{:error, :multiple_results}` for more than one. Asking for a column the
role may not read is `{:error, {:forbidden_columns, cols}}`; a role with no
permission is `{:error, :forbidden}`. The `!` variants raise
`Authzura.Error` with the same reason (see [Errors](#errors)).

## `get`

`get/4` reads one row by primary key, Hasura's `<table>_by_pk`:

```elixir
{:ok, by_pk} = Authzura.get(MyApp.Article, session, 2, instance: MyApp.Authz, columns: [:id])

# A row the permission hides reads as no row.
{:ok, nil} = Authzura.get(MyApp.Article, session, 3, instance: MyApp.Authz)
```

It behaves like `one/3` with the key equality as the only predicate (same
row filter, `columns:`, `preload:` and read-only execution), and it is also
allowed when the role's permission enables only the `select_by_pk` root
field. A hidden or missing row is `{:ok, nil}`. Pass the value for a
one-column key, or a keyword list or map naming every key column exactly
once (`[org_id: 1, user_id: 2]`); anything else is
`{:error, {:invalid_input, {:primary_key, :invalid}}}`.
Values are cast to the column types like input literals, and a key column
the role may not select is `{:forbidden_columns, cols}`. The queryable must
be a bare schema or table (`{:unsupported_query, :get_requires_bare_root}`
otherwise); a table without a primary key is
`{:unsupported_query, :no_primary_key}`. See `Authzura.Get`.

## `scope`

`scope/3` is the pipeable path: compose, scope, then run it with your own
repo.

```elixir
import Ecto.Query

alias MyApp.Article

{:ok, query} =
  Article
  |> where([a], a.status == "draft")
  |> order_by([a], desc: a.id)
  |> Authzura.scope(session, instance: MyApp.Authz)

rows = MyApp.Repo.all(query)
```

**Scoping must be the last step.** Anything you add to the returned query
afterwards (`or_where`, `select_merge`, `exclude`, ...) can undo
enforcement, and the returned query keeps the policy it was built with, so
build it per request. Running it with `Repo.aggregate(scoped, :count)`
works, since Ecto wraps it as a whole; using it inside another query
(`subquery(scoped)` in a `from` or `join`) is not supported. `all/3` and `one/3` exist so nothing can be added in
between: prefer them unless you need the query. `scope/3` cannot preload
(`{:unsupported_query, :preload_requires_execute}`).

Your own `where`, `join` and `order_by` are trusted code, and Authzura does
not scope joins you add yourself. Read related data with permissions applied
through [preloads](#preloads).

## `filter_rows`

`filter_rows/3` is an advanced integration primitive. It ANDs the session's
row permission into the query and returns the permission from the same policy
generation, as `{:ok, query, permission}`. It adds no select, permission limit
or ordering: the integration must enforce the permitted columns (in the output
and in any filter or order the caller adds) and the row limit (per parent for
nested reads) in its final SQL. Aggregates need their own authorization.
Composing `or_where`, `exclude(:where)`, or changing the root or bindings
undoes the filter. Input-derived predicates added later do not get
the `*_input` APIs' hidden-row fence. Use `scope/3` or the executors for
complete enforcement. Don't cache the result across requests.

The caller's limit, offset and order are kept. An existing select,
group_by/having/windows, lock or distinct is rejected exactly as in
`scope/3`, and unions, intersects and excepts are rejected with
`{:unsupported_query, :combination_requires_scope}` because their branches
cannot be enforced here. Joined tables are not filtered: each needs its own
`filter_rows/3`. Ecto's `limit/3` replaces a limit rather than lowering it, so
apply `min(caller limit, permission.limit)`. `permission.columns` includes
columns that `scope/3`'s default projection omits (`:other` kinds): select
them only by name, and only if the repo can decode them.

Every other check of `scope/3` applies (readiness, denials, `root_fields`,
prefix pinning, session variables), and so does its telemetry span, marked
`mode: :filter_rows`. Only the `:instance`, `:table`, `:root_field`,
`:relationship`, `:relationship_mapping`, `:relationship_target` and
`:missing_relationship` options apply.

`root_field:` is `:select` (the default), `:select_by_pk` or `false`. With
`false` the `root_fields` check is skipped, for a table reached only through a
relationship embed, which needs a select permission but no root query field.
A role without a select permission is still `:forbidden`, and the row filter
and columns still apply.

### Authorizing an embed by its relationship

Hasura authorizes a relationship by the select permission of the
relationship's target table, not by whatever table answers the read. An
integration that embeds rows from a view (or any other table) under a parent
can apply that rule with `relationship: {parent, name}`: the role's
permission, row filter, columns and limit become those of the target of the
relationship `name` of `parent`, looked up in the loaded snapshot. The query
root, prefix and alias stay the caller's, so the queryable must have the
columns the target's row filter reads (Postgres raises otherwise, which fails
closed).

- `relationship_mapping: [{local, remote}]`: the relationship must map exactly
  these columns.
- `relationship_target:`: a `{schema, table}` reference, an Ecto schema, or a
  list of them. The relationship must target one of these tables: the table
  the queryable reads, plus the table it presents when it is a view. Two
  relationships of one parent can map the same columns to different tables,
  so the mapping alone cannot keep one table's permission off another table's
  rows.
- `missing_relationship:` decides what happens when no relationship of that
  name maps those columns to one of those targets: `:error` (the default)
  returns `{:error, :forbidden}`, `:root` uses the queryable's own permission.
  The returned permission's `table` tells the two apart.

When the name comes from a request, pass the mapping and the target, and
prefer `:error`: with `:root`, a name that matches nothing selects the
queryable's own permission. A role with no permission on the target is
`:forbidden` even if the queryable's own table grants it.

## Asking what a role may do

You can ask what a role may do without reading rows:

```elixir
alias MyApp.Article

{:ok, permission} = Authzura.permission(session, Article, instance: MyApp.Authz)
{:ok, columns} = Authzura.allowed_columns(session, Article, instance: MyApp.Authz)
:ok = Authzura.validate_columns(session, Article, [:id, :title], instance: MyApp.Authz)
```

`validate_columns/4` checks column names only. It is a building block, not
certification of a whole query.

## Untrusted input

Requests built from user input (a JSON API's query parameters, say) go
through the input functions, never through `where` or `order_by`.
`all_input/4` runs the request and `scope_input/4` returns the query. The
request is a map with `columns`, `filter`, `order_by`, `limit`, `offset` and
(for `all_input/4`) `preload`, as `Jason.decode!/1` returns them:

```elixir
alias MyApp.Article

request =
  Jason.decode!("""
  {
    "columns": ["id", "title"],
    "filter": {"status": {"_eq": "draft"}},
    "order_by": [{"id": "desc"}],
    "limit": 10,
    "preload": {"comments": {"columns": ["id", "body"], "order_by": [{"id": "desc"}]}}
  }
  """)

{:ok, input_rows} = Authzura.all_input(Article, session, request, instance: MyApp.Authz)

{:ok, input_query} =
  Authzura.scope_input(Article, session, Map.delete(request, "preload"), instance: MyApp.Authz)
```

- The queryable must be a bare schema or table name.
- `filter` is a Hasura `bool_exp` in input mode: every value is a literal,
  with no session variables, relationships or `_exists`, at most 8 levels
  and 100 nodes.
- `timestamptz` and `timestamp` values take ISO 8601
  (`2026-01-01T10:00:00+02:00`), the space-separated
  `2026-01-01 10:00:00[.ffffff]` and a bare date `2026-01-01` (its
  midnight), with or without an offset, and at most six fractional digits.
  A `timestamptz` without an offset is interpreted as UTC; a `timestamp`
  ignores an offset, as Postgres does. `date` values are `YYYY-MM-DD`.
  Permission filters and session values read the same forms, except that a
  `timestamptz` there must carry its offset (see
  [Security](security.md#unsupported-features)).
- A regular expression or `SIMILAR TO` pattern may not hold a backreference
  (`\1` to `\9`), and each statement of a read with any such pattern is
  bounded by `input_pattern_timeout` (see [Security](security.md#input-limits)).
- An operand beyond the column type's range (`40000` for a `smallint`,
  `1e39` for a `real`) is an invalid literal, in input, permissions and
  session values alike, since Postgres refuses it.
- Every column the request names (in `columns`, `filter` or `order_by`) must
  be one the role may select, otherwise `{:forbidden_columns, cols}`. The
  filter is parsed against the selectable columns only, so a hidden column
  and a name that does not exist give the same error, whatever its operator
  or literal. A relationship-shaped key is `:relationship_in_input`
  whether or not the relationship exists.
- A malformed request is `{:invalid_input, reason}`. Nothing is converted to
  an atom, and building never raises on decoded JSON.
- Input preloads are limited to 2 levels and 8 nodes.
- List-valued input is capped; see
  [Security](security.md#input-limits) for the limits and the error each
  one returns.
- `_similar`, `_regex` and their variants are checked by Postgres before the
  read, by a statement that reads no table. An invalid pattern is
  `{:invalid_input, {:invalid_pattern, column}}` from both `all_input/4` and
  `scope_input/4` (which needs the repo for that check).

The role's own permission filter, column list and limit are always applied
on top, and the input filter is evaluated only on the rows the permission
admits, unless `input_index_pushdown` is on (see [Security](security.md#input-is-fenced-behind-the-permission)).

## `order_by` forms

Prefer the single-key map form, `{"id": "desc"}`. The tuple forms differ: the
root takes `{column, direction}`, a preload takes Ecto's
`{direction, column}`.

## Preloads

`preload:` names **Hasura relationships**, not Ecto associations, and it is
executor-only. A relationship's value is read by its shape, never guessed:

- a name, or a list of names: leaf children (`comments: [:author]`)
- a keyword list or map: that relationship's options, with only the keys
  `columns`, `order_by` and `preload` (anything else is
  `{:unsupported_query, {:preload, name}}`)

```elixir
alias MyApp.Article

{:ok, nested} =
  Authzura.all(Article, session,
    instance: MyApp.Authz,
    preload: [
      :author,
      comments: [columns: [:id, :body], order_by: [desc: :id], preload: [:author]]
    ]
  )
```

The JSON form for `all_input/4` is
`{"preload": {"comments": {"columns": ["id"], "order_by": [{"id": "desc"}], "preload": ["author"]}}}`.

A relationship is followed only when it is declared on its parent table in
Hasura, can be preloaded (its key columns are of a batchable type, which
[`mix authzura.check`](https://hexdocs.pm/authzura/Mix.Tasks.Authzura.Check.html) reports otherwise), and the role
has a select permission on its target. Anything else is `:forbidden`. Each
level applies the target's own filter, columns and limit, so an array
relationship is bounded per parent by its target's limit. The root query and
every level run in one `REPEATABLE READ, READ ONLY` transaction, so they read
one snapshot, and an error at any level fails the whole call. A plain Ecto
`preload` in your query is translated when it maps exactly onto a Hasura
relationship. See `Authzura.Preload.Tree` for the grammar and result keys.

Inside a caller's open transaction the isolation level cannot be raised, so
preloads are refused unless you pass `in_transaction: :trust_isolation` to
say that transaction is already `REPEATABLE READ` or stronger.

### Indexes for preloads and relationship filters

A level bounded per parent (an array relationship whose target permission
has a `limit`, or an object relationship not on the target's primary key)
reads each parent through an index range only when the target has a btree
index on `(fk columns, first order column)`, stored in the order's direction
or its exact reverse. Add `(fk, order column, pk)` for each limited
relationship you preload, for example
`CREATE INDEX ON comments (article_id, id)` for comments ordered by id.
Without one the level reads and ranks every child of every parent, which is
correct but costs as many rows as exist.

A paged list (`order_by` plus `limit`) whose permission filters through a
relationship (`{"article": {"org_id": {"_eq": "X-Hasura-Org-Id"}}}`)
depends on the planner: Postgres may walk the order's index and probe the
relationship for every row until it fills the page, which on a large table
with a selective tenant is slow. Hasura's own SQL behaves the same. Index
the relationship's key columns on both sides, and where paged lists matter,
denormalize the tenant key onto the paged table so the filter is a plain
column comparison.

## Errors

Expected denials are `{:error, reason}`; the `!` variants raise
`Authzura.Error` carrying the same reason. The public reasons:

| Reason | Meaning |
|---|---|
| `:forbidden` | No permission for this role, table or relationship |
| `{:forbidden_columns, [column]}` | Columns the role may not select |
| `{:missing_session_variable, name}` | The filter needs a session variable the session lacks |
| `{:invalid_session_value, name, reason}` | A session variable does not cast to the column type |
| `{:invalid_session, kind, detail}` | `Authzura.Session.new/2` could not resolve a role |
| `{:unsupported_query, reason}` | The query uses something Authzura does not enforce |
| `{:invalid_input, reason}` | A malformed input request |
| `:root_field_disabled` | The permission disables the required root field: `select` (for `get/4`, both `select` and `select_by_pk`), or `select_aggregate` for a root aggregate |
| `:stale_permissions` | The generation is older than `max_staleness`, or an enum label or type it was loaded with has changed since (the next poll reloads) |
| `{:unsupported_column_type, column}` | The repo cannot decode a selected column's type (`{:type, name}` when the type is no selected column's) |
| `:not_ready` | No generation is published yet |
| `:multiple_results` | `one/3` matched more than one row |

`Authzura.JWT.verify/2` has its own reasons, listed on `Authzura.JWT`.

## Using with PgRest

[PgRest](https://github.com/agoodway/pgrest) serves Ecto schemas as a
PostgREST-compatible API. A runnable, test-only adapter lives in
`test/support/pgrest_example.ex` with scenarios in `test/pgrest_examples`.
PgRest is a pinned GitHub test dependency; the examples run with `mix test`.

- **Session.** The endpoint builds an `Authzura.Session` from verified session
  variables and puts `%{authz: %{instance: instance, session: session}}` into
  PgRest's `context_builder`. PgRest adds `path` (embed output names) and
  `root?` for each resource, preserving the Authzura state.
- **Rows.** The gate implements only `authorize_query/5`. For `:read`, it
  calls `Authzura.filter_rows/3` on PgRest's query and returns the filtered
  query with the permission options. Authzura errors deny the request.
  Each embedded resource is authorized independently, including aliased
  and nested paths.
- **Prefixes.** Resources must set `@schema_prefix` to the instance's
  `default_prefix`: `filter_rows/3` pins the root prefix, and PgRest rejects
  a hook query that changes the base scope's prefix.
- **Columns.** The returned `columns:` option carries the permission's physical
  column names. PgRest narrows stars to permitted columns and refuses explicit
  hidden columns in selects, filters and ordering with `42501` (403 for an
  authenticated session). Aliases of permitted columns are preserved.
- **Limits.** The returned `limit:` option caps rows per parent, including
  embedded collections, and clamps larger requested limits.
- **Aggregates and counts.** Both options require the permission's
  `allow_aggregations` flag and are denied by default. Root requests also
  require `select_aggregate` in `root_fields` (or `root_fields: :all`);
  nested aggregates need only the flag. The endpoint enables PgRest's
  aggregate support so the permission decides access.
- **Other operations.** Creates, updates, deletes and execution plans return
  `{:error, :unsupported}`. Plans are refused even though the example endpoint
  enables plan requests; they can expose bound values.

The resources need no authorization `scope/2` or `after_load/2` callbacks,
and the adapter does not parse PgRest's request AST. Nothing in `lib/` depends
on PgRest, and the adapter adds no public Authzura API.

See PgRest's [Limits of application policies](https://github.com/agoodway/pgrest/blob/main/docs/guides/authorization-and-rls.md#limits-of-application-policies).

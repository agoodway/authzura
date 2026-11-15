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
`mode: :filter_rows`. Only the `:instance` and `:table` options apply.

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
| `:root_field_disabled` | The permission disables the select root field (for `get/4`, both `select` and `select_by_pk`) |
| `:stale_permissions` | The generation is older than `max_staleness`, or an enum label or type it was loaded with has changed since (the next poll reloads) |
| `{:unsupported_column_type, column}` | The repo cannot decode a selected column's type (`{:type, name}` when the type is no selected column's) |
| `:not_ready` | No generation is published yet |
| `:multiple_results` | `one/3` matched more than one row |

`Authzura.JWT.verify/2` has its own reasons, listed on `Authzura.JWT`.

## Using with PgRest

[PgRest](https://github.com/agoodway/pgrest) serves Ecto schemas as a
PostgREST-compatible API. Authzura plugs into its extension points; a
runnable example lives in `test/pgrest_examples` and
`test/support/pgrest_example.ex`. Those tests are tagged `:pgrest` and run
only when a PgRest checkout sits next to this repository, in a sibling
directory named `pgrest`; otherwise `mix test` skips them.

- **Session.** A plug in front of `PgRest.Plug` builds the `Authzura.Session`
  (from a verified JWT, see [Sessions and JWT](#sessions-and-jwt)) and a
  `context_builder` puts it in the PgRest context.
- **Rows.** A resource's `scope/2` takes the row filter from
  `Authzura.filter_rows/3` (see [`filter_rows`](#filter_rows)). PgRest accepts
  only `where`, `join` and `distinct` from `scope/2`, and `filter_rows/3` adds
  nothing else to the query PgRest gave you. PgRest scopes embedded resources
  through their own `scope/2`, so the embedded table's permission applies too.
- **Columns.** PgRest's `readable:` is fixed per resource, not per role. In
  `after_load/2`, keep only the columns `Authzura.allowed_columns/3` lists
  (plus the embeds); everything else, including select aliases, is dropped.
- **Gate.** `scope/2` cannot deny a request, so a `PgRest.Authorization`
  module decides first. For the root and every embedded resource it calls
  `Authzura.filter_rows/3` and refuses on any error (no permission, a missing
  session variable) and on a permission with a `limit`, which `scope/2`
  cannot express. Refuse such requests rather than raise from `scope/2`.

What the gate checks, and what it does not:

- On the root it reads every column the request names with PgRest's own
  grammar (`PgRest.Grammar.Select` and `PgRest.Planner.Params`): select
  items with aliases, casts, JSON paths and aggregates, filters with `not`,
  `or` and `and` groups, and `order` terms, for the root and each embed at
  any depth, and refuses the request when the role may not read one of them
  (`Authzura.validate_columns/4`). Without this, a filter, `order` or alias on
  a hidden column would reveal its values even though the column is never
  returned.
- It fails closed: a query string PgRest's grammar rejects, an embed that is
  not an Ecto association of its parent (explicit `relationships:` are not
  followed), or parameters for an embed the select does not contain are
  refused.
- It follows PgRest's grammar by calling it, so it must be kept in step with
  the PgRest version. PgRest does not yet pass per-resource column lists to
  its authorization hook, which is why the gate parses the request itself.
- `*` names every column of its resource, spread embeds (`...rel(*)`) included,
  and is refused where the role has a hidden column: name the columns
  explicitly (`select=id,title`). A request with no `select` reads every
  column, as `*` does, and is refused the same way.
- The gate does not rely on `after_load/2` to hide a named or starred
  column, because PgRest skips it for spread embeds. The one case left to
  `after_load/2` is an empty `select=`: it names no column, so the gate
  passes it and the rows come back trimmed to the allowed columns. That is
  safe because an empty select has no embeds, spread or not.
- `columns` and `on_conflict` are ignored by PgRest on reads, so the gate
  ignores them too.
- The root check runs on single-segment routes (`/<table>`), the only route
  PgRest serves; any other path is a 404 before any resource is read.
- It covers reads only.

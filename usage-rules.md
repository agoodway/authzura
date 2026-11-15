# Authzura usage rules

Authzura enforces Hasura v2 select permissions on Ecto reads: row filters,
columns, limits, root fields and relationship preloads. Anything it cannot
enforce is denied. Full docs: the `Authzura` moduledoc and `docs/guides/`.

## Setup

- Start one instance per permission source, after the repo:
  `{Authzura, name: MyApp.Authz, repo: MyApp.Repo}`.
- Pass `instance: MyApp.Authz` to reads and `scope/3` (the default is
  `Authzura`); `status/1`, `diagnostics/1` and `reload/1` take it as their
  argument.
- Build the session with `Authzura.Session.new/2`, or from a JWT with
  `Authzura.JWT.verify/2`. Never construct `%Authzura.Session{}` by hand from
  request data.
- Run `mix authzura.check` in CI to see which permissions are denied or
  narrowed at load.

## Choosing a function

- Reading for a user: prefer the executors `Authzura.all/3`, `Authzura.one/3`
  and `Authzura.get/4`. They run the read read-only (a caller's open
  transaction keeps its own access mode) and add nothing after scoping.
- Composing into your own `Repo` call: `Authzura.scope/3`, as the last step.
- Filters, sorting or paging that come from a user, an LLM or any request:
  `Authzura.all_input/4` or `Authzura.scope_input/4`, never `scope/3` with
  your own `where`.
- Building another library's query (you enforce columns and limit yourself):
  `Authzura.filter_rows/3`. It returns `{:ok, query, permission}`.
- Inspecting a role: `Authzura.permission/3`, `Authzura.allowed_columns/3`,
  `Authzura.validate_columns/4`.

## Rules

- Never modify a query after `scope/3` or `filter_rows/3`. `or_where`,
  `exclude(:where)`, `select_merge`, joins and unions can undo enforcement.
- Never cache a scoped query across requests. It keeps the policy it was built
  with.
- Never put user-controlled values in your own `where`. Your predicates are
  trusted and may run on hidden rows, which can leak through errors or
  timing.
- After `filter_rows/3`, enforce `permission.columns` in the output and in
  every filter or order you add. Enforce `min(your limit, permission.limit)`
  per parent, and give each joined table its own `filter_rows/3`. Unions are
  rejected; use `scope/3`.
- Options such as `input_index_pushdown`, `read_only` and `admin_role` are
  instance configuration. Never derive them from request input.
- `input_index_pushdown: true` is opt-in: it gives index speed to AND-ed
  `_eq` and `_in` (100 values or fewer) and accepts a timing side channel. See
  the Security guide before enabling it.

## Errors

- Handle `{:error, reason}`. Every reason is listed in `Authzura.Error`.
- Treat `:forbidden` and `:root_field_disabled` as "not found" to the user.
  Don't reveal which one occurred.
- `:not_ready` and `:stale_permissions` mean the permissions aren't loaded or
  confirmed (`:not_ready` is normal at boot). With `poll_interval: nil` and a
  finite `max_staleness`, call `Authzura.reload/1` on a timer or reads go
  stale. Retry or fail the request; never fall back to an unscoped read.
- The `!` variants raise `Authzura.Error`. Use them only where a raise is the
  intended response.

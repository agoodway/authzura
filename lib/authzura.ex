defmodule Authzura do
  @moduledoc """
  Enforces Hasura v2 select permissions on Ecto reads.

  Authzura reads a Hasura v2 project's permission metadata and applies it to
  Ecto queries: row filters, columns, limits, root fields and relationship
  preloads. It is read-only, and anything it cannot enforce is denied (fail
  closed). Expected denials are `{:error, reason}`, catalogued in
  `Authzura.Error`; the `!` variants raise that exception.

  ## Choosing a function

  | You want to | Use |
  |---|---|
  | compose the permission into your own `Repo` call | `scope/3` |
  | enforce columns and the row limit yourself (integration primitive) | `filter_rows/3` |
  | have Authzura run the read | `all/3`, `one/3`, `get/4` (and the `!` variants) |
  | accept untrusted, Hasura-shaped (JSON) input | `scope_input/4`, `all_input/4` |
  | inspect what a role may do | `permission/3`, `allowed_columns/3`, `validate_columns/4` |
  | check readiness and freshness | `status/1`, `diagnostics/1`, `reload/1` |

  Prefer the executors (`all/3`, `one/3`, `get/4`, `all_input/4`): they run
  the read read-only (see `all/3` for the exceptions), load preloads from one
  snapshot and leave nothing to add after scoping.

  ## Example

  Add an instance to the supervision tree, after the repo (every option is
  in `Authzura.Options.instance!/1`):

      children = [
        MyApp.Repo,
        {Authzura, name: MyApp.Authz, repo: MyApp.Repo}
      ]

  Build a session from the request's claims, then read:

      {:ok, session} =
        Authzura.Session.new(%{"x-hasura-user-id" => "42"},
          allowed_roles: ["user"],
          default_role: "user"
        )

      case Authzura.all(MyApp.Article, session, instance: MyApp.Authz) do
        {:ok, rows} -> rows
        {:error, :forbidden} -> :not_found
        {:error, reason} -> {:error, reason}
      end

  With a JWT, `Authzura.JWT.verify/2` returns the session. The functions
  that take a session accept `instance:` as an option (default `Authzura`, the default
  `:name`); `status/1`, `diagnostics/1` and `reload/1` take it as their
  argument.

  ## Lifecycle

  Permissions load when the instance starts and are polled for changes
  (`poll_interval`). Until the first load succeeds every read is
  `{:error, :not_ready}`, which is also the normal, retryable state at boot;
  a generation not confirmed within `max_staleness`
  is `{:error, :stale_permissions}`. Run `mix authzura.check` against your
  metadata in CI.

  ## Scoping

  `scope/3` returns the caller's query with the role's select permission
  applied: the root table pinned to its schema, the row filter ANDed in, a
  select of exactly the permitted (or requested) columns, and the limit
  capped. Results are maps keyed by field atoms for schema queries and by
  column strings for table queries.

  **Scoping must be the last step.** Anything added to the returned query
  afterwards (`or_where`, `select_merge`, `exclude`, ...) can undo
  enforcement; the executors exist so nothing can be added in between.
  Build queries per request: a returned query keeps the policy it was built
  with.

  The caller's `where`, `order_by`, `join` and read-only CTEs are trusted
  developer code. Untrusted input belongs in the input APIs. Per-call
  options are documented in `Authzura.Options.call!/1`.

  ## Guides

  See the [Configuration](configuration.html), [Querying](querying.html),
  [Security](security.html) and [Compatibility](compatibility.html) guides
  for the full picture.
  """

  alias Authzura.{Error, Executor, Get, Input, Options, Plan, Scope, Session, Store, Telemetry}
  alias Authzura.Model.{Diagnostic, Permission}
  alias Ecto.{Query, Queryable}

  @doc """
  Returns a child spec for an instance, validating `opts` first.

  Raises `NimbleOptions.ValidationError` for invalid options. The child id is
  the instance name. The instance loads its permissions after it starts; until
  then reads are `{:error, :not_ready}`.

      iex> %{id: MyApp.Authz} = Authzura.child_spec(name: MyApp.Authz, repo: MyApp.Repo)
      iex> Authzura.child_spec(name: MyApp.Authz)
      ** (NimbleOptions.ValidationError) required :repo option not found, received options: [:name]
  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{name: name} = config = Options.instance!(opts)
    %{id: name, start: {Store, :start_link, [config]}}
  end

  @doc """
  Reports the instance's readiness, versions and freshness.

  Returns `ready?`, `fresh?`, the active generation's `seq` and
  `active_version`, the last `observed_version`, `last_confirmed_current_at`
  (monotonic milliseconds), `last_error` and `diagnostics_count`. It never
  waits for a running load.

  `last_error` is a bounded kind such as `:timeout` or `{:exception, module}`,
  never a raw reason. `instance` is the instance name (default `Authzura`).

      Authzura.status(MyApp.Authz)
      #=> %{ready?: true, fresh?: true, seq: 3, active_version: ..., ...}
  """
  @spec status(atom()) :: Store.status()
  def status(instance \\ __MODULE__), do: Store.status(instance)

  @doc """
  Returns the active snapshot's diagnostics: `{:ok, [Authzura.Model.Diagnostic.t()]}`,
  or `{:error, :not_ready}` before the first load.

  Each diagnostic records a role, table and operation that was refused
  (`severity: :deny`) or narrowed (`:warning`) at load. `mix authzura.check`
  prints the same list.

      {:ok, diagnostics} = Authzura.diagnostics(MyApp.Authz)
      Enum.filter(diagnostics, &(&1.severity == :deny))
  """
  @spec diagnostics(atom()) :: {:ok, [Diagnostic.t()]} | {:error, :not_ready}
  def diagnostics(instance \\ __MODULE__), do: Store.diagnostics(instance)

  @doc """
  Loads and publishes a new generation now, for example after migrations.

  Returns `:ok`, or `{:error, reason}` when the load fails (a database error
  or a source error such as `:unstable_source`); that reason is not one of the
  read denials. Success confirms freshness; a failure leaves the active
  generation and its freshness unchanged. Blocks until the load ends.

      :ok = Authzura.reload(MyApp.Authz)
  """
  @spec reload(atom()) :: :ok | {:error, term()}
  def reload(instance \\ __MODULE__), do: Store.reload(instance)

  @typedoc """
  Every reason a read can return in `{:error, reason}`.

  The full catalog, with what each means and whether it is a denial, bad
  input, misconfiguration or stale permissions, is in `Authzura.Error`.
  """
  @type reason ::
          Scope.reason()
          | Executor.reason()
          | Store.unavailable()
          | Input.reason()
          | Get.reason()

  @doc """
  Scopes `queryable` to the session's select permission. See "Scoping".

  Returns `{:ok, query}` or `{:error, reason}` (see `Authzura.Error`; the
  common ones are `:forbidden`, `{:forbidden_columns, cols}`,
  `:root_field_disabled` and `{:unsupported_query, _}`). Options:
  `instance:`, `columns:` and `table:`; `preload:` is rejected here, and
  `repo_opts:` and `in_transaction:` matter only to the executors (all in
  `Authzura.Options.call!/1`).

      {:ok, query} = Authzura.scope(MyApp.Article, session, columns: [:id, :title])
      MyApp.Repo.all(query)

  Emits `[:authzura, :scope, :start | :stop | :exception]`. Preloads are
  executor-only, so a `preload:` option or an Ecto preload fails with
  `{:unsupported_query, :preload_requires_execute}`.

  ## Trusted predicates

  The caller's own `where` (here and in `all/3` and `one/3`) is trusted
  code and is not fenced behind the permission filter: Postgres may
  evaluate it on rows the role cannot see. A predicate carrying a user's
  value (`like(a.title, ^search)`, say) can then fail or slow down because
  of a hidden row, and the error or the timing tells the user that row
  exists; the executors' `{:invalid_input, :rejected_by_database}` is such a
  signal. User-controlled filters belong in `scope_input/4` or
  `all_input/4`, whose filter is evaluated only on permitted rows.
  """
  @spec scope(Queryable.t(), Session.t(), keyword()) ::
          {:ok, Query.t()} | {:error, reason()}
  def scope(queryable, %Session{role: role} = session, opts \\ []) do
    opts = Options.call!(opts)

    Telemetry.access_span(:scope, %{instance: opts[:instance], role: role}, fn ->
      with {:ok, generation} <- current(opts),
           {:ok, %Plan{query: query}} <- Scope.build(queryable, session, generation, opts),
           do: {:ok, query}
    end)
  end

  @doc """
  Like `scope/3`, but returns the query and raises `Authzura.Error` on denial.

      query = Authzura.scope!(MyApp.Article, session)
  """
  @spec scope!(Queryable.t(), Session.t(), keyword()) :: Query.t()
  def scope!(queryable, %Session{} = session, opts \\ []),
    do: queryable |> scope(session, opts) |> unwrap!()

  @doc """
  Advanced integration primitive. ANDs the session's row permission into the
  query and returns the permission from the same policy generation:
  `{:ok, query, permission}` or `{:error, reason}`. Use it only when an
  integration owns the final SQL; otherwise use `scope/3` or the executors.

      {:ok, query, permission} = Authzura.filter_rows(MyApp.Article, session)
      limit =
        [requested_limit, permission.limit]
        |> Enum.reject(&is_nil/1)
        |> Enum.min(fn -> nil end)

  It adds no select, permission limit or ordering: the integration must
  enforce the permitted columns (in the output and in any filter or order the
  caller adds) and the row limit (per parent for nested reads) in its final
  SQL. Aggregates need their own authorization. Composing `or_where`,
  `exclude(:where)`, or changing the root or bindings undoes the filter.
  Input-derived predicates added later do not get the `*_input` APIs'
  hidden-row fence. Use `scope/3` or the executors for complete enforcement.
  Don't cache the result across requests.

  The caller's limit, offset and order are kept as given. An existing select,
  group_by/having/windows, lock or distinct is rejected exactly as in
  `scope/3`, and so is any union, intersect or except
  (`{:unsupported_query, :combination_requires_scope}`), since its branches
  cannot be enforced here. Joined tables are not filtered: each needs its own
  `filter_rows/3`. Ecto's `limit/3` replaces rather than lowers a limit, so
  the integration must apply `min(caller limit, permission.limit)`.
  `permission.columns` includes columns that `scope/3`'s default projection
  omits (`:other` kinds): select them only by name, and only if the repo can
  decode them.

  Every other check of `scope/3` applies (readiness, access, `root_fields`
  allowing `select`, prefix pinning, `table:`, query shape, session
  variables), so the denials are those of `scope/3`. The configured admin role gets no filter
  and a synthesized permission. Only the `:instance` and `:table` options
  apply; any other raises `NimbleOptions.ValidationError`.

  Emits the `[:authzura, :scope]` span with `mode: :filter_rows` in its
  metadata. There is no bang variant, as the result is a three-element tuple.
  """
  @spec filter_rows(Queryable.t(), Session.t(), keyword()) ::
          {:ok, Query.t(), Permission.t()} | {:error, reason()}
  def filter_rows(queryable, %Session{role: role} = session, opts \\ []) do
    opts = Options.filter_rows!(opts)

    Telemetry.access_span(
      :scope,
      %{instance: opts[:instance], role: role, mode: :filter_rows},
      fn ->
        with {:ok, generation} <- current(opts),
             do: Scope.filter_rows(queryable, session, generation, opts)
      end
    )
  end

  @doc """
  Returns the select permission that applies to `queryable`'s root table for
  the session's role. For the configured admin role it is a synthesized
  permission with every column, no filter and no limit.

  This is introspection, so `root_fields` is not enforced: a table whose
  select root field is disabled still returns its permission, which carries
  `root_fields`.

  Returns `{:ok, Authzura.Model.Permission.t()}` or `{:error, reason}` (for
  example `:forbidden`, `:not_ready`, `:stale_permissions`). Only `instance:`
  and `table:` matter.

      {:ok, permission} = Authzura.permission(session, MyApp.Article)
      permission.limit
  """
  @spec permission(Session.t(), Queryable.t(), keyword()) ::
          {:ok, Permission.t()} | {:error, reason()}
  def permission(%Session{} = session, queryable, opts \\ []) do
    opts = Options.call!(opts)

    with {:ok, generation} <- current(opts),
         do: Scope.permission(queryable, session, generation, opts)
  end

  @doc """
  Returns the physical columns the session's role may select on
  `queryable`'s root. Like `permission/3`, it ignores `root_fields`.

  Returns `{:ok, ["id", "title"]}` (column strings, whatever the queryable)
  or `{:error, reason}` as `permission/3` does.

      {:ok, columns} = Authzura.allowed_columns(session, MyApp.Article)
  """
  @spec allowed_columns(Session.t(), Queryable.t(), keyword()) ::
          {:ok, [String.t()]} | {:error, reason()}
  def allowed_columns(%Session{} = session, queryable, opts \\ []) do
    with {:ok, %Permission{columns: columns}} <- permission(session, queryable, opts),
         do: {:ok, columns}
  end

  @doc """
  Checks that the session's role may select every one of `columns` (field
  atoms or column strings) on `queryable`'s root.

  A building block, **not query certification**: it checks column names
  only, never the predicates of a query.

  Returns `:ok`, `{:error, {:forbidden_columns, cols}}` listing every column
  not allowed (virtual or unknown schema fields included), or another
  `{:error, reason}` as `permission/3` does.

      :ok = Authzura.validate_columns(session, MyApp.Article, [:id, :title])
  """
  @spec validate_columns(Session.t(), Queryable.t(), [atom() | String.t()], keyword()) ::
          :ok | {:error, reason()}
  def validate_columns(%Session{} = session, queryable, columns, opts \\ [])
      when is_list(columns) do
    opts = Options.call!(opts)

    with {:ok, generation} <- current(opts),
         do: Scope.validate_columns(queryable, session, generation, columns, opts)
  end

  @doc """
  Scopes `queryable` like `scope/3` and runs it, returning `{:ok, rows}` (a
  list of maps) or `{:error, reason}`; see `Authzura.Error`. Options:
  `instance:`, `columns:`, `table:`, `preload:`, `in_transaction:` and
  `repo_opts:`.

      {:ok, rows} = Authzura.all(MyApp.Article, session, columns: [:id, :title])

  The caller's own predicates are trusted and not fenced behind the
  permission filter; see "Trusted predicates" in `scope/3` before putting
  a user's value in one.

  The read runs in a `READ ONLY` transaction. Inside a caller's open
  transaction (`in_transaction:`, or any transaction on the process) the
  caller's access mode applies instead. With `read_only: :connection`, a
  read without preloads is one bare statement on read-only connections
  (see `Authzura.Options.instance!/1`). It runs only through the instance's repo: a different
  `put_dynamic_repo/1` gives `{:unsupported_query, :dynamic_repo}`.
  `repo_opts:` accepts only `:timeout`, `:log`, `:telemetry_options` and
  `:telemetry_event`. Emits `[:authzura, :execute, :start | :stop |
  :exception]`; see `Authzura.Executor`.

  ## Preloads

  `preload:` names Hasura relationships; the grammar is in
  `Authzura.Preload.Tree`. A relationship's value is read by its shape: a
  name or a list of names are leaf children, and a keyword list or map is
  always that relationship's options (`columns`, `order_by`, `preload`
  only):

      Authzura.all(Article, session,
        preload: [:author, comments: [columns: [:id, :body], order_by: [desc: :id], preload: [:author]]]
      )

  The JSON form for `all_input/4` is
  `{"preload": {"comments": {"columns": ["id"], "order_by": [{"id": "desc"}], "preload": ["author"]}}}`.

  Results nest under the caller's own term for each relationship: the atom
  or string given in `preload:`, or the Ecto association's name. Rows of an
  Ecto association are keyed by the related schema's field atoms; every
  other relationship's rows by column strings (see "Result keys" in
  `Authzura.Preload.Tree`). Columns read only to stitch levels together are
  never returned.

  The root query and every level run in one
  `REPEATABLE READ, READ ONLY` transaction with one policy generation and
  session, so every level reads the same snapshot. Inside a caller's open
  transaction the isolation level cannot be raised, so preloads give
  `{:unsupported_query, :preload_in_transaction}` unless
  `in_transaction: :trust_isolation` states the caller's transaction is
  already `REPEATABLE READ` or stronger. An error at any level fails the
  whole call.

  A plain Ecto preload in `queryable` (`preload(Article, comments: :author)`)
  is translated and merged with the option. The tree is bounded by
  `max_preload_depth` and `max_preload_nodes` (`{:unsupported_query,
  :preload_limit}`), checked before anything else.

  Two kinds of failure are kept apart:

    * An Ecto preload that cannot be translated faithfully (a custom query
      or function, a join-bound preload, `where:`, `preload_order:`,
      `through:`, or an association matching no Hasura relationship with the
      same target and mapping) is `{:unsupported_query, {:preload, name}}`.
      It is the caller's own code and does not depend on the role.
    * A relationship the role may not follow (undeclared, remote, not
      preloadable, or no select permission on its target) is `:forbidden`,
      whether it came from an Ecto preload or from `preload:`.
  """
  @spec all(Queryable.t(), Session.t(), keyword()) :: {:ok, [map()]} | {:error, reason()}
  def all(queryable, %Session{} = session, opts \\ []),
    do: execute(queryable, session, opts, :all)

  @doc """
  Like `all/3`, but returns the rows and raises `Authzura.Error` on denial.

      rows = Authzura.all!(MyApp.Article, session)
  """
  @spec all!(Queryable.t(), Session.t(), keyword()) :: [map()]
  def all!(queryable, %Session{} = session, opts \\ []),
    do: queryable |> all(session, opts) |> unwrap!()

  @doc """
  Like `all/3`, but returns at most one row: `{:ok, row}`, `{:ok, nil}` for
  none and `{:error, :multiple_results}` for more than one. Same options as
  `all/3`.

      {:ok, row} = Authzura.one(from(a in MyApp.Article, where: a.id == ^id), session)
  """
  @spec one(Queryable.t(), Session.t(), keyword()) ::
          {:ok, map() | nil} | {:error, reason()}
  def one(queryable, %Session{} = session, opts \\ []),
    do: execute(queryable, session, opts, :one)

  @doc """
  Like `one/3`, but returns the row (or `nil`) and raises `Authzura.Error` on
  denial, including `:multiple_results`.
  """
  @spec one!(Queryable.t(), Session.t(), keyword()) :: map() | nil
  def one!(queryable, %Session{} = session, opts \\ []),
    do: queryable |> one(session, opts) |> unwrap!()

  @doc """
  Reads the row of `queryable` whose primary key is `pk`, like `one/3` with
  the key equality as its only predicate: `{:ok, row}`, or `{:ok, nil}` when
  no row with that key exists or the permission hides it.

  `queryable` must be a bare schema, table or query (an alias, Ecto
  preloads and the like are fine; a `where`, `join`, combination, CTE,
  `limit` or `offset` is `{:unsupported_query, :get_requires_bare_root}`).
  `pk` is the value for a one-column key, or a keyword list or map naming
  every key column exactly once: `[org_id: 1, user_id: 2]`. The read
  applies the same row filter, columns, preloads and read-only execution as
  `one/3`, and is also allowed when the role's permission enables only the
  `select_by_pk` root field. Authzura builds the equality itself, casting
  each value like an input literal, and adds it as a plain condition next
  to the permission, not behind it, so the primary key index applies: it
  is built from values already cast to each column's type, so it can
  neither fail nor run long on a row the role cannot see. Its key equality
  is `OPERATOR(pg_catalog.=)` (whatever `input_index_pushdown` says), and for
  a `citext` key the `citext` extension's own qualified `=`, so an
  owner-defined operator never runs on a hidden row. A `citext` equality is
  not leakproof, so it is not pushed down and keeps the residual risks of the
  [Security](security.html#input-index-push-down) guide. If the extension's
  schema cannot be resolved, a `citext` key is refused with
  `{:invalid_input, [{[column], {:invalid_literal, {:unsupported_type, "citext"}}}]}`. See
  `Authzura.Get` for every reason; it emits the same
  `[:authzura, :execute, ...]` span as `one/3` (`mode: :one`). Same options
  as `all/3`.

      {:ok, article} = Authzura.get(MyApp.Article, session, 7)
      {:ok, member} = Authzura.get(MyApp.Member, session, org_id: 1, user_id: 2)
  """
  @spec get(Queryable.t(), Session.t(), term(), keyword()) ::
          {:ok, map() | nil} | {:error, reason() | Get.reason()}
  def get(queryable, %Session{} = session, pk, opts \\ []),
    do: execute_with(session, opts, :one, &Get.build(queryable, session, pk, &1, &2))

  @doc """
  Like `get/4`, but returns the row (or `nil`) and raises `Authzura.Error` on
  denial.
  """
  @spec get!(Queryable.t(), Session.t(), term(), keyword()) :: map() | nil
  def get!(queryable, %Session{} = session, pk, opts \\ []),
    do: queryable |> get(session, pk, opts) |> unwrap!()

  @doc """
  Scopes an untrusted, JSON-decoded request on a bare schema or table and
  returns `{:ok, query}` or `{:error, reason}`. See `Authzura.Input` for the
  request's keys (`columns`, `filter`, `order_by`, `limit`, `offset`).
  Options: `instance:`, `table:` and `columns:` (the caller's, used when the
  request omits `columns`); `preload:` is executor-only.

      request = %{"filter" => %{"title" => %{"_ilike" => "%elixir%"}}, "limit" => 20}
      {:ok, query} = Authzura.scope_input(MyApp.Article, session, request)
      MyApp.Repo.all(query, query_cache: false)

  The filter is parsed by the instance's source in input mode (every value
  a literal; no relationships or `_exists`; depth 8, 100 nodes), and every
  column the request names must be one the role may select. Errors are
  `{:invalid_input, reason}` and `{:forbidden_columns, cols}`, plus the
  denials of `scope/3`. Preloads are executor-only. Emits the same
  `[:authzura, :scope, ...]` span as `scope/3`.

  The filter is evaluated only on rows the permission admits, unless the
  instance sets `input_index_pushdown: true` (see "Index use" below). Its
  `SIMILAR TO` and regular-expression patterns are checked through the
  instance's repo before the query is returned, by a statement that reads
  no table; an invalid one is `{:invalid_input, {:invalid_pattern, column}}`.

  Every request shape is its own SQL text, and the client chooses the
  shapes. Run the returned query with `query_cache: false` (as
  `all_input/4` does), or Ecto's query cache and each connection's
  prepared statements keep one entry per shape until a restart. The
  instance's `input_pattern_timeout` is not applied here: it needs the
  transaction `all_input/4` opens.

  ## Index use

  By default the whole input sits behind the permission fence, so a filter
  cannot use an index. The instance option `input_index_pushdown: true`
  lets an AND-ed `_eq` or short `_in` on a plain leakproof column use one, at
  the cost of a timing side channel. What moves, what stays fenced and the
  trade-off are in `Authzura.Options.instance!/1` and
  [Security](security.html#input-index-push-down).
  """
  @spec scope_input(Queryable.t(), Session.t(), term(), keyword()) ::
          {:ok, Query.t()} | {:error, reason() | Input.reason()}
  def scope_input(queryable, %Session{role: role} = session, input, opts \\ []) do
    opts = Options.call!(opts)

    Telemetry.access_span(:scope, %{instance: opts[:instance], role: role}, fn ->
      with {:ok, generation} <- current(opts),
           {:ok, %Plan{query: query} = plan} <-
             Input.build(queryable, session, input, generation, opts),
           :ok <- Executor.check_input(plan),
           do: {:ok, query}
    end)
  end

  @doc """
  Like `scope_input/4`, but runs the query like `all/3` and returns
  `{:ok, rows}` or `{:error, reason}`, inside the same
  `[:authzura, :execute, ...]` span. The request may carry `preload:`,
  loaded as for `all/3`; its relationships nest under their names as
  strings. Options are those of `scope_input/4` plus `preload:`,
  `in_transaction:` and `repo_opts:`; the caller's `columns:` and `preload:`
  apply when the request omits them. An invalid `SIMILAR TO` or
  regular-expression pattern is
  `{:invalid_input, {:invalid_pattern, column}}`, refused before the read,
  and a read Postgres cancels (the instance's `input_pattern_timeout`, the
  database's own `statement_timeout` or a cancel) is
  `{:invalid_input, :statement_timeout}`. Its statements bypass
  Ecto's query cache and run unnamed, so request shapes never accumulate
  in a cache.

  ## Index use

  `input_index_pushdown: true` applies as for `scope_input/4`: see
  `Authzura.Options.instance!/1` and
  [Security](security.html#input-index-push-down).

      request = %{"columns" => ["id", "title"], "filter" => %{"id" => %{"_eq" => 1}}}
      {:ok, rows} = Authzura.all_input(MyApp.Article, session, request)
  """
  @spec all_input(Queryable.t(), Session.t(), term(), keyword()) ::
          {:ok, [map()]} | {:error, reason() | Input.reason()}
  def all_input(queryable, %Session{} = session, input, opts \\ []),
    do: execute_with(session, opts, :all, &Input.build(queryable, session, input, &1, &2))

  defp execute(queryable, session, opts, mode),
    do: execute_with(session, opts, mode, &Scope.build(queryable, session, &1, &2))

  # The execute span covers building the plan too, so every denial is
  # observable. `build` takes the generation and the build options.
  defp execute_with(%Session{role: role}, opts, mode, build) do
    opts = Options.call!(opts)
    metadata = %{instance: opts[:instance], role: role, mode: mode}

    Telemetry.access_span(:execute, metadata, fn ->
      with {:ok, generation} <- current(opts),
           {:ok, plan} <- build.(generation, build_opts(opts, mode)),
           do: Executor.run(plan, mode)
    end)
  end

  # `:one` needs only two rows to tell one from many.
  defp build_opts(opts, :all), do: [mode: :execute] ++ opts
  defp build_opts(opts, :one), do: [mode: :execute, max_rows: 2] ++ opts

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, reason}), do: raise(Error, reason: reason)

  defp current(opts), do: opts |> Keyword.fetch!(:instance) |> Store.current()
end

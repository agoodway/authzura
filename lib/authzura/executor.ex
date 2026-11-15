defmodule Authzura.Executor do
  @moduledoc """
  Runs an `Authzura.Plan` against the instance's repo.

  `run/2`:

    1. **Repo binding.** The calling process's `repo.get_dynamic_repo()` must
       be the repo the instance introspected; otherwise the call fails with
       `{:unsupported_query, :dynamic_repo}`.
    2. **Execution options** are an allowlist: `:timeout`, `:log`,
       `:telemetry_options` and `:telemetry_event`. Any other key, such as a
       source-changing `:prefix`, fails with
       `{:unsupported_query, {:option, key}}`.
    3. **Read-only.** Outside a transaction the read runs inside
       `repo.transaction/2` whose first statement is
       `SET TRANSACTION READ ONLY`, so trusted caller code that writes
       (a `nextval` in a fragment, say) fails with Postgres's
       `read_only_sql_transaction` error, which is raised. With the
       instance option `read_only: :connection` a read without preloads
       is one statement instead, while the Store's checks (at every load
       and poll) have found the connections read-only by themselves; after
       any failed check reads take the transaction path again until the
       next successful load. Inside a caller's
       open transaction the read runs as is: an open transaction's access
       mode cannot be changed, so the caller's transaction governs.
    4. **Preloads** (`plan.preloads`) load after the root query, one query
       per relationship (`Authzura.Preload.Loader`), each with the row
       filter compiled for the plan's session when the plan was built.
       - Outside a transaction the root query and every level run in one
         transaction whose first statement is
         `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`, so
         every level reads the root's snapshot.
       - Inside a caller's transaction the isolation level cannot be raised,
         so the call is `{:unsupported_query, :preload_in_transaction}`,
         unless `in_transaction: :trust_isolation` states the caller's
         transaction is already `REPEATABLE READ` or stronger. That claim is
         checked: a lower `transaction_isolation` is refused the same way.
       - An error at any level fails the whole call (the transaction is
         rolled back); no partial result is returned.
    5. **Results** are maps holding only the projection's public keys: the
       stitching columns read for preloads are stripped. A relationship
       nests under the caller's term for it, and its rows are keyed as
       described in `Authzura.Preload.Tree` ("Result keys"). A
       relationship whose name or key would overwrite a key of its parent
       row is `{:unsupported_query, {:preload, name}}`, before any query
       runs. In `:one` mode more than one row is `:multiple_results`,
       detected before any preload level loads.
    6. **Untrusted literals.** The `SIMILAR TO` and regular-expression
       literals of an input plan (`plan.input`) are checked first, in the
       same transaction, by a statement that reads no table (see
       `check_input/1`); a refused one is
       `{:invalid_input, {:invalid_pattern, column}}` and the read does not
       run. The read itself evaluates the input only on permitted rows (see
       `Authzura.Scope.build/4`), so it cannot fail on an input value. In a
       transaction the executor opened, the same statement sets the
       instance's `input_pattern_timeout` as a transaction-local
       `statement_timeout`; an input read Postgres cancels
       (`query_canceled`, whatever the cause) is
       `{:invalid_input, :statement_timeout}`.
    7. **Database rejections of literals.** A Postgres error the read
       itself raises for a literal the database alone can judge
       (`invalid_escape_sequence`, 22025, or `invalid_regular_expression`,
       2201B) is `{:invalid_input, :rejected_by_database}`; every other
       error is raised. After the input checks this can come only from a
       caller's own predicates in `Authzura.all/3` or `Authzura.one/3`
       (a `like/2` on a user's search text, say), which can leak a hidden
       row's existence: see "Trusted predicates" in `Authzura.scope/3`.
       Inside a caller's transaction the failed statement still aborts that
       transaction.
    8. **Undecodable values.** A selected value whose type the repo's
       Postgrex types module cannot decode (a PostGIS `geography` without
       its extension, say) is `{:error, {:unsupported_column_type, column}}`
       (`{:type, name}` instead of a column when no selected column has that
       type).
       Postgrex drops that connection (it logs the disconnect) and the pool
       reconnects. Such columns have base kind `:other`, which the default
       column set leaves out; they are read only when named.
    9. **Stale types.** In a read that binds enum labels in their own type
       (`plan.enum_comparisons?`), an enum label or enum type that changed
       since the generation was loaded (`invalid_text_representation`,
       22P02, or `undefined_object`, 42704) is
       `{:error, :stale_permissions}`: the generation no longer matches the
       database, and the next poll reloads it. In any other read those
       errors come from the caller's own code and are raised. The flag is
       per read, not per statement: in a read that does compare an enum,
       the same error from a caller's own predicate is also reported as
       `:stale_permissions`.

  The public executors (`Authzura.all/3`, `Authzura.one/3`) wrap scoping and
  `run/2` in one `[:authzura, :execute, :start | :stop | :exception]` span,
  so denials from scoping are observable too.

  In `:one` mode the plan should be built with `max_rows: 2` (see
  `Authzura.Scope.build/4`), so at most two rows are read.
  """

  alias Authzura.Model.Relationship
  alias Authzura.{Plan, Scope, Telemetry}
  alias Authzura.Preload.{Loader, Tree}
  alias Ecto.Adapters.SQL
  alias Postgrex.Error, as: PostgresError
  alias Postgrex.{QueryError, Result}

  @allowed_repo_opts [:timeout, :log, :telemetry_options, :telemetry_event]

  # Postgres errors caused by an untrusted literal rather than by the query:
  # 22025 (a LIKE pattern's escape) and 2201B (an invalid regular expression).
  @rejected_codes [:invalid_escape_sequence, :invalid_regular_expression]

  # Postgres errors that mean the generation no longer matches the database:
  # 22P02 (an enum label renamed since load) and 42704 (an enum type renamed
  # or moved). The next poll reloads; until then the read is denied.
  @stale_codes [:invalid_text_representation, :undefined_object]

  @undecodable ~r/^type `(.+)` can not be handled by the types module/

  # The executor's own constant statements are named (`cache_statement`):
  # prepared once per connection, each then costs one exchange instead of an
  # unnamed statement's two. Postgrex ignores the name on connections
  # started with `prepare: :unnamed` (PgBouncer setups).
  @read_only {"authzura_read_only", "SET TRANSACTION READ ONLY"}

  # `:read_committed` exists only so the consistency tests can show the
  # anomaly the snapshot prevents.
  @snapshot %{
    repeatable_read:
      {"authzura_snapshot", "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"},
    read_committed:
      {"authzura_snapshot_read_committed",
       "SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY"}
  }

  @isolation {"authzura_isolation", "SELECT current_setting('transaction_isolation')"}
  @snapshot_levels ["repeatable read", "serializable"]

  @type mode :: :all | :one
  @type reason ::
          :multiple_results
          | {:unsupported_query,
             :dynamic_repo | :preload_in_transaction | {:option, atom()} | {:preload, String.t()}}
          | {:invalid_input,
             :rejected_by_database | :statement_timeout | {:invalid_pattern, String.t()}}
          | :stale_permissions
          | {:unsupported_column_type, String.t() | {:type, String.t()}}
          | Loader.reason()

  @doc """
  Executes `plan`, returning every row (`:all`) or at most one (`:one`).
  """
  @spec run(Plan.t(), mode()) :: {:ok, [map()] | map() | nil} | {:error, reason()}
  def run(%Plan{repo: repo, exec: %{repo_opts: repo_opts}} = plan, mode)
      when mode in [:all, :one] do
    with :ok <- bound_repo(repo),
         :ok <- allowed_repo_opts(repo_opts),
         {:ok, layouts} <- layouts(plan),
         {:ok, rows} <- read(plan, %{repo: repo, mode: mode, layouts: layouts, own?: false}),
         do: shape(rows, mode)
  end

  defp bound_repo(repo) do
    case repo.get_dynamic_repo() do
      ^repo -> :ok
      _other -> {:error, {:unsupported_query, :dynamic_repo}}
    end
  end

  defp allowed_repo_opts(opts) do
    opts
    |> Keyword.keys()
    |> Enum.find(&(&1 not in @allowed_repo_opts))
    |> disallowed_option()
  end

  defp disallowed_option(nil), do: :ok
  defp disallowed_option(key), do: {:error, {:unsupported_query, {:option, key}}}

  defp read(plan, %{repo: repo} = env) do
    plan |> transaction(repo.in_transaction?(), repo) |> read(plan, env)
  rescue
    error in PostgresError -> rejected(error, plan, __STACKTRACE__)
    error in QueryError -> undecodable(error, plan, __STACKTRACE__)
  end

  # Postgrex cannot decode a value of a type its types module lacks (a
  # PostGIS type without its extension, say); it disconnects, and the pool
  # reconnects. Only `:other` columns can be such a type, so the error
  # names the selected `:other` column of that type (or of arrays of it).
  # A type no selected column has is reported as `{:type, name}`, never as
  # a guessed column; with no `:other` column selected at all, it came from
  # elsewhere (a parameter of a caller's fragment, say) and is raised.
  defp undecodable(
         %QueryError{message: message} = error,
         %Plan{other_columns: [_ | _] = columns},
         stacktrace
       ) do
    case Regex.run(@undecodable, message) do
      [_match, type] -> {:error, {:unsupported_column_type, column_of(columns, type)}}
      nil -> reraise(error, stacktrace)
    end
  end

  defp undecodable(error, %Plan{}, stacktrace), do: reraise(error, stacktrace)

  defp column_of(columns, type),
    do:
      Enum.find_value(columns, {:type, type}, fn {column, pg_type} ->
        pg_type in [type, "_" <> type] and column
      end)

  defp rejected(%PostgresError{postgres: %{code: code}}, _plan, _stacktrace)
       when code in @rejected_codes,
       do: {:error, {:invalid_input, :rejected_by_database}}

  # An input read cancelled (57014): the pattern timeout, the database's own
  # `statement_timeout`, or a cancel.
  defp rejected(
         %PostgresError{postgres: %{code: :query_canceled}},
         %Plan{input: ast},
         _stacktrace
       )
       when ast != nil,
       do: {:error, {:invalid_input, :statement_timeout}}

  # Only a read that binds enum labels in their own type can fail this way
  # because the generation is stale; any other such error is the caller's.
  defp rejected(
         %PostgresError{postgres: %{code: code}},
         %Plan{enum_comparisons?: true},
         _stacktrace
       )
       when code in @stale_codes,
       do: {:error, :stale_permissions}

  defp rejected(error, _plan, stacktrace), do: reraise(error, stacktrace)

  # How the read runs: as is inside the caller's transaction, or in a
  # transaction of its own that starts with the statement given. A caller's
  # transaction trusted for preloads is still checked: its isolation level
  # must give one snapshot.
  defp transaction(%Plan{preloads: nil}, true = _in_transaction, _repo), do: :as_is

  # The instance verified that its connections are read-only by themselves.
  defp transaction(%Plan{preloads: nil, exec: %{read_only: :connection}}, false, _repo),
    do: :as_is

  defp transaction(%Plan{preloads: nil}, false, _repo), do: {:transaction, @read_only}

  defp transaction(
         %Plan{exec: %{in_transaction: :trust_isolation, repo_opts: opts}} = plan,
         true,
         repo
       ),
       do: plan |> statement(:setup, fn -> named(repo, @isolation, opts) end) |> trusted()

  defp transaction(%Plan{}, true, _repo), do: in_transaction()

  defp transaction(%Plan{exec: %{isolation: isolation}}, false, _repo),
    do: {:transaction, Map.fetch!(@snapshot, isolation)}

  defp trusted(%Result{rows: [[level]]}) when level in @snapshot_levels, do: :as_is
  defp trusted(%Result{}), do: in_transaction()

  defp in_transaction, do: {:error, {:unsupported_query, :preload_in_transaction}}

  defp read({:error, _reason} = error, _plan, _env), do: error
  defp read(:as_is, plan, env), do: load(plan, env)

  defp read(
         {:transaction, statement},
         %Plan{exec: %{repo_opts: opts}} = plan,
         %{repo: repo} = env
       ) do
    repo.transaction(
      fn ->
        statement(plan, :transaction_control, fn -> named(repo, statement, opts) end)
        plan |> load(%{env | own?: true}) |> commit(repo)
      end,
      opts
    )
  end

  defp named(repo, {name, sql}, opts),
    do: SQL.query!(repo, sql, [], Keyword.put(opts, :cache_statement, name))

  # One `[:authzura, :query]` span per statement the executor issues at the root.
  defp statement(plan, category, fun),
    do: Telemetry.query(category, :root, telemetry(plan), fun)

  defp telemetry(%Plan{root: {_prefix, source}, exec: %{instance: instance}}),
    do: %{instance: instance, table: source}

  defp commit({:ok, rows}, _repo), do: rows
  defp commit({:error, reason}, repo), do: repo.rollback(reason)

  # The input's literals are checked first, in the same transaction. In
  # `:one` mode more than one root row fails before any level loads.
  defp load(%Plan{query: query} = plan, %{repo: repo, mode: mode} = env) do
    with :ok <- check_input(plan, pattern_timeout(plan, env)),
         rows = statement(plan, :data, fn -> repo.all(query, data_opts(plan)) end),
         :ok <- cardinality(rows, mode),
         do: preload(rows, plan, env)
  end

  @doc """
  Checks the literals of `plan.input` (the untrusted filter of
  `Authzura.Input`) that only the database can judge, with the adapter's
  `c:Authzura.Adapter.check_input/4` and the plan's repo and `repo_opts`:
  `:ok`, or `{:error, {:invalid_input, {:invalid_pattern, column}}}`. A plan
  without input needs no statement.
  """
  @spec check_input(Plan.t()) ::
          :ok | {:error, {:invalid_input, {:invalid_pattern, String.t()}}}
  def check_input(%Plan{} = plan), do: check_input(plan, nil)

  defp check_input(%Plan{input: nil}, _timeout), do: :ok

  defp check_input(
         %Plan{input: ast, repo: repo, adapter: adapter, exec: %{repo_opts: opts}} = plan,
         timeout
       ),
       do: adapter.check_input(repo, ast, timeout_opt(opts, timeout), telemetry(plan))

  defp timeout_opt(opts, nil), do: opts
  defp timeout_opt(opts, timeout), do: Keyword.put(opts, :statement_timeout, timeout)

  # The input's pattern timeout is set only in a transaction the executor
  # opened, where it ends with the read; never in a caller's.
  defp pattern_timeout(%Plan{exec: %{input_pattern_timeout: timeout}}, %{own?: true}), do: timeout
  defp pattern_timeout(%Plan{}, %{}), do: nil

  # A plan whose shape the client chose runs uncached: neither Ecto's query
  # cache nor a named prepared statement keeps it.
  defp data_opts(%Plan{cache_statements?: true, exec: %{repo_opts: opts}}), do: opts

  defp data_opts(%Plan{cache_statements?: false, exec: %{repo_opts: opts}}),
    do: Keyword.put(opts, :query_cache, false)

  defp cardinality([_first, _second | _rest], :one), do: {:error, :multiple_results}
  defp cardinality(_rows, _mode), do: :ok

  defp preload(rows, %Plan{preloads: nil, projection: projection}, _env),
    do: {:ok, public(rows, projection)}

  # The parent keys are read from the raw rows; the loader and the result
  # only ever see the public columns.
  defp preload(
         rows,
         %Plan{
           preloads: nodes,
           projection: projection,
           adapter: adapter,
           exec: %{hooks: hooks, instance: instance}
         } = plan,
         %{repo: repo, layouts: layouts}
       ) do
    opts = data_opts(plan)
    between_levels(hooks)
    keys = parent_keys(projection, nodes)
    values = Enum.map(rows, fn row -> Enum.map(keys, &Map.fetch!(row, &1)) end)
    rows = public(rows, projection)

    nodes = with_layouts(nodes, layouts)

    with {:ok, rows} <-
           Loader.load(nodes, rows, values, repo, adapter, opts, &finish/2, %{instance: instance}),
         do: {:ok, Enum.map(rows, &nest(&1, layouts))}
  end

  defp public(rows, projection) do
    private = for %{public?: false, key: key} <- projection, do: key
    drop_private(private, rows)
  end

  defp drop_private([], rows), do: rows
  defp drop_private(private, rows), do: Enum.map(rows, &Map.drop(&1, private))

  defp between_levels(%{between_levels: hook}), do: hook.()
  defp between_levels(%{}), do: :ok

  # The root row keys holding the parent columns the loader stitches on.
  defp parent_keys(projection, nodes) do
    keys = Map.new(projection, &{&1.column, &1.key})
    nodes |> Tree.parent_columns() |> Enum.map(&Map.fetch!(keys, &1))
  end

  # Result layout. The loader nests each relationship under its name and
  # keys rows by column; a layout gives each node its result key and, for an
  # Ecto association, the column-to-field map of its rows, computed once.
  # A relationship whose name or key would overwrite a key of its parent row
  # is refused before anything runs.

  defp layouts(%Plan{preloads: nil}), do: {:ok, nil}

  defp layouts(%Plan{preloads: nodes, projection: projection}) do
    layouts = Enum.map(nodes, &layout/1)
    public = for %{public?: true, key: key} <- projection, do: key
    public |> first_clash(public, layouts) |> no_clash(layouts)
  end

  defp layout(%{
         rel: %Relationship{name: name},
         key: key,
         schema: schema,
         columns: columns,
         children: children
       }) do
    fields = fields(schema, columns)

    %{
      name: name,
      key: key,
      columns: columns,
      fields: fields,
      keys: row_keys(fields, columns),
      children: Enum.map(children, &layout/1)
    }
  end

  defp fields(nil, _columns), do: nil

  defp fields(schema, columns),
    do:
      schema |> Scope.field_columns(columns) |> Map.new(fn {field, column} -> {column, field} end)

  defp row_keys(nil, columns), do: columns
  defp row_keys(fields, _columns), do: Map.values(fields)

  # `names` are the parent row's keys when the loader attaches a level,
  # `keys` its keys in the result.
  defp first_clash(names, keys, layouts), do: Enum.find_value(layouts, &clash(names, keys, &1))

  defp clash(names, keys, %{name: name, key: key} = layout),
    do: clash(name in names or key in keys, layout)

  defp clash(true, %{name: name}), do: {:error, {:unsupported_query, {:preload, name}}}

  defp clash(false, %{columns: columns, keys: keys, children: children}),
    do: first_clash(columns, keys, children)

  defp no_clash(nil, layouts), do: {:ok, layouts}
  defp no_clash(error, _layouts), do: error

  # Each node carries its layout to the loader, which finishes every
  # distinct value once (`finish/2`), bottom-up: parents that share a key
  # tuple keep sharing one finished term, however deep the tree.
  defp with_layouts(nodes, layouts) do
    Enum.zip_with(nodes, layouts, fn %{children: children} = node, %{children: inner} = layout ->
      %{node | children: with_layouts(children, inner)} |> Map.put(:layout, layout)
    end)
  end

  defp finish(%{layout: layout}, value), do: related(value, layout)

  # Moves each relationship's (already finished) value from its name to its
  # key; a relationship keyed by its own name stays where it is.
  defp nest(row, layouts), do: Enum.reduce(layouts, row, &move/2)

  defp move(%{name: name, key: name}, row), do: row

  defp move(%{name: name, key: key}, row) do
    {value, row} = Map.pop!(row, name)
    Map.put(row, key, value)
  end

  defp related(nil, _layout), do: nil
  defp related(rows, layout) when is_list(rows), do: Enum.map(rows, &related(&1, layout))

  defp related(row, %{fields: fields, children: children}) when is_map(row),
    do: row |> rekey(fields) |> nest(children)

  defp rekey(row, nil), do: row

  defp rekey(row, fields),
    do: Map.new(row, fn {key, value} -> {Map.get(fields, key, key), value} end)

  defp shape(rows, :all), do: {:ok, rows}
  defp shape([], :one), do: {:ok, nil}
  defp shape([row], :one), do: {:ok, row}
  defp shape([_first, _second | _rest], :one), do: {:error, :multiple_results}
end

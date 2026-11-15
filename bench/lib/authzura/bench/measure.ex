defmodule Authzura.Bench.Measure do
  @moduledoc """
  Measures one scenario on both engines and checks it against the
  benchmark targets. Test harness only.

  Only database work is compared, from the server's own counters:

    * **Statements and DB time** (`statements/4`). One engine at a time:
      warm-up requests (`:warmup`, default 6 per connection of the engine's
      pool, so every connection is past Postgres's switch to a generic plan
      after five executions of a prepared statement),
      `pg_stat_statements_reset()`, `n` requests, then the `authzura_bench`
      rows of `pg_stat_statements`. Each statement is
      `classify/1`d; `:background` ones (Hasura's `hdb_catalog` work, the
      statistics views, the type catalog) are dropped. DB time is planning
      plus execution. Authzura's named (cached) `SET TRANSACTION` is
      recorded by `pg_stat_statements` only on its first use per
      connection, so after warm-up it is missing from the counts, though it
      runs on every read.
    * **DB time ratio** (`db_time/2`). Five repetitions, alternating Hasura
      and Authzura; the ratio of the medians. The coefficient of variation
      (sample standard deviation over the mean, `Authzura.Bench.Stats.cv/1`)
      of the paired per-repetition ratios (Authzura's over Hasura's in the
      same repetition, so drift that hits both cancels) above 15 % is
      `:inconclusive`.
    * **Plan shape** (`plans/3`). Each data statement runs once more under
      `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` with the same parameters.
      Authzura's are captured from the repo's own query telemetry event and
      explained as the steady state runs them: prepared, executed five
      times, then explained as `EXECUTE`, so the plan is the one the plan
      cache settled on (a generic plan, when Postgres switched to one).
      Hasura's come from `POST /v1/graphql/explain`, which inlines the
      values, so they are custom plans. Only the scanned
      tables, the scan kinds, the index names and the root node's shared
      buffers are kept (`parse_plan/1`); SQL text, parameters and plan
      expressions stay in memory and are dropped.

  `check/3` evaluates the targets:

  | target | rule |
  |---|---|
  | `db_time` | Authzura's DB time at most 1.25 times Hasura's |
  | `data_statements` | exactly `1 + L` data statements per request |
  | `transaction_control` | `read_only: :connection` mode, `L = 0` only: none |
  | `indexes` | no sequential scan of a table Hasura reads through an index |
  | `buffers` | shared buffers at most 1.5 times Hasura's |
  """

  alias Authzura.Adapters.Postgres.InputCheck
  alias Authzura.Bench
  alias Authzura.Bench.{Env, Hasura, Repo, Scenarios, Stats}
  alias Authzura.Parity.{Read, Runner}

  @type engine :: :hasura | :authzura
  @type category :: :transaction_control | :setup | :data | :background
  @type verdict :: :pass | :fail | :inconclusive
  @type target :: verdict() | :not_applicable
  @type scan_kind :: :seq | :index | :index_only | :bitmap
  @type plan :: %{
          table_scans: [{String.t(), scan_kind(), String.t() | nil}],
          shared_buffers: non_neg_integer()
        }
  @type statements :: %{counts: %{atom() => float()}, db_ms: float()}
  @type db_time :: %{
          ratio: float(),
          cv: float(),
          verdict: verdict(),
          hasura_ms: float(),
          authzura_ms: float()
        }
  @type targets :: %{atom() => target()}
  @type result :: %{
          id: String.t(),
          preload_levels: non_neg_integer(),
          status: :measured,
          db_time: db_time(),
          statements: %{hasura: statements(), authzura: statements()},
          plans: %{hasura: [plan()], authzura: [plan()]},
          targets: targets(),
          verdict: verdict()
        }

  # Requests per pool connection before counting: Postgres plans a prepared
  # statement afresh for its first five executions on each connection.
  @warmup_per_connection 6
  # Hasura's default `HASURA_GRAPHQL_PG_CONNECTIONS`.
  @hasura_pool_size 50
  @custom_plans 5
  @explained "authzura_bench_explain"
  @parameter_types "SELECT parameter_types::text[] FROM pg_prepared_statements WHERE name = $1"
  @repetitions 5
  @max_cv 0.15
  @max_db_ratio 1.25
  @max_buffer_ratio 1.5
  @counted [:data, :transaction_control, :setup]
  @analyzed "ANALYZE, BUFFERS, FORMAT JSON"
  @order_providers ["Limit", "Result", "Nested Loop", "Merge Join", "Gather Merge"]
  @sorts ["Sort", "Incremental Sort"]

  @transaction_control ~r/\A\s*(BEGIN|COMMIT|END|ROLLBACK|ABORT|START\s+TRANSACTION|SET\s+TRANSACTION|SAVEPOINT|RELEASE)\b/i
  @setup ~r/\A\s*(SET\s+LOCAL\b|SELECT\s+(pg_catalog\.)?(set_config|current_setting)\s*\()/i
  # Authzura's pattern pre-check.
  @pattern_check InputCheck.marker()
  # A `pg_catalog` *relation* (not a function such as `pg_catalog.set_config`).
  @background ~r/hdb_catalog|pg_stat_statements|\bpg_catalog"?\."?pg_\w++"?(?!\s*\()/i

  @stats """
  SELECT s.query, s.calls, s.total_plan_time + s.total_exec_time
  FROM pg_stat_statements AS s
  JOIN pg_database AS d ON d.oid = s.dbid
  WHERE d.datname = $1
  """

  # Only this database's statistics are reset (userid 0 and queryid 0 mean all).
  @reset """
  SELECT pg_stat_statements_reset(0, (SELECT oid FROM pg_database WHERE datname = current_database()), 0)
  """

  @tracking ["pg_stat_statements.track_planning", "pg_stat_statements.track_utility"]

  @scan_kinds %{
    "Seq Scan" => :seq,
    "Index Scan" => :index,
    "Index Only Scan" => :index_only,
    "Bitmap Heap Scan" => :bitmap
  }

  @doc """
  The category of a `pg_stat_statements` query text. Background comes
  first, so a catalog read is never counted whatever it looks like.
  """
  @spec classify(String.t()) :: category()
  def classify(query) when is_binary(query) do
    cond do
      query =~ @background -> :background
      query =~ @transaction_control -> :transaction_control
      query =~ @setup or String.contains?(query, @pattern_check) -> :setup
      true -> :data
    end
  end

  @doc """
  Measures `scenario` and checks it: DB time (which also gives the
  statement counts, the median of the repetitions), plans and targets.

  Options: `:mode` (default `:default`), `:requests` (per repetition,
  default 200), `:warmup` (warm-up requests per engine, default 6 per
  connection of its pool) and `:hasura_pool_size` (default 50, Hasura's
  default pool).
  """
  @spec measure(Scenarios.scenario(), keyword()) :: result()
  def measure(%{id: id, preload_levels: levels} = scenario, opts \\ []) do
    mode = mode(opts)
    %{statements: statements} = db_time = db_time(scenario, opts)

    results = %{
      db_time: Map.delete(db_time, :statements),
      statements: statements,
      plans: %{hasura: plans(:hasura, scenario, opts), authzura: plans(:authzura, scenario, opts)}
    }

    targets = check(results, scenario, mode)

    Map.merge(results, %{
      id: id,
      preload_levels: levels,
      status: :measured,
      targets: targets,
      verdict: verdict(targets)
    })
  end

  @doc """
  Sends `n` requests for `scenario` to `engine` alone, after the warm-up
  requests (`warmup/2`) and a `pg_stat_statements_reset()`, and returns
  the statements per request by category and the DB milliseconds per
  request (planning plus execution) of the non-background statements.

  Options: `:mode` (default `:default`), `:warmup` and `:hasura_pool_size`.
  """
  @spec statements(engine(), Scenarios.scenario(), pos_integer(), keyword()) :: statements()
  def statements(engine, scenario, n \\ 200, opts \\ []) when is_integer(n) and n > 0 do
    request = requester(engine, scenario, opts)

    repeat(request, warmup(engine, opts))
    Repo.query!(@reset)
    repeat(request, n)

    %{rows: rows} = Repo.query!(@stats, [Env.database()])
    rows |> per_request(n) |> counted!(engine)
  end

  @doc """
  The warm-up requests for `engine`: `opts[:warmup]`, else 6 per
  connection of its pool (the bench repo's `:pool_size`, or
  `opts[:hasura_pool_size]`, default 50, for Hasura).
  """
  @spec warmup(engine(), keyword()) :: pos_integer()
  def warmup(engine, opts \\ []),
    do:
      Keyword.get_lazy(opts, :warmup, fn -> @warmup_per_connection * pool_size(engine, opts) end)

  defp pool_size(:authzura, _opts), do: Keyword.get(Repo.config(), :pool_size, 10)
  defp pool_size(:hasura, opts), do: Keyword.get(opts, :hasura_pool_size, @hasura_pool_size)

  @doc """
  `:ok` when the server tracks planning time and utility statements
  (`pg_stat_statements.track_planning` and `.track_utility` are `on`);
  raises otherwise, because DB time or the transaction-control counts
  would silently be wrong.
  """
  @spec ensure_tracking!() :: :ok
  def ensure_tracking! do
    case Enum.reject(@tracking, &(Repo.query!("SHOW #{&1}").rows == [["on"]])) do
      [] -> :ok
      off -> raise ArgumentError, "the benchmark needs #{Enum.join(off, " and ")} = on"
    end
  end

  @doc """
  Five alternating repetitions of `statements/4` (Hasura, Authzura,
  Hasura, ...), summarized by `summarize/2`. Also returns `:statements`,
  each engine's median counts and DB time.

  Options: those of `statements/4` and `:requests` (default 200).
  """
  @spec db_time(Scenarios.scenario(), keyword()) ::
          %{
            :statements => %{hasura: statements(), authzura: statements()},
            optional(atom()) => term()
          }
  def db_time(scenario, opts \\ []) do
    n = Keyword.get(opts, :requests, 200)

    runs =
      for _repetition <- 1..@repetitions, engine <- [:hasura, :authzura] do
        {engine, statements(engine, scenario, n, opts)}
      end

    hasura = for {:hasura, run} <- runs, do: run
    authzura = for {:authzura, run} <- runs, do: run

    hasura
    |> Enum.map(& &1.db_ms)
    |> summarize(Enum.map(authzura, & &1.db_ms))
    |> Map.put(:statements, %{hasura: median_run(hasura), authzura: median_run(authzura)})
  end

  @doc """
  The DB-time summary of each engine's repetitions, paired by position:
  the ratio of the medians (Authzura over Hasura), the coefficient of
  variation (sample standard deviation, `n - 1`) of the per-repetition
  ratios, and the verdict (`:inconclusive` above 15 %).
  """
  @spec summarize([float()], [float()]) :: db_time()
  def summarize([_ | _] = hasura, [_ | _] = authzura) when length(hasura) == length(authzura) do
    hasura_ms = Stats.median(hasura)
    authzura_ms = Stats.median(authzura)
    ratio = authzura_ms / hasura_ms
    cv = authzura |> Enum.zip_with(hasura, &(&1 / &2)) |> Stats.cv()

    %{
      ratio: ratio,
      cv: cv,
      verdict: db_verdict(ratio, cv),
      hasura_ms: hasura_ms,
      authzura_ms: authzura_ms
    }
  end

  @doc """
  The plan of each of `engine`'s data statements for `scenario`, from
  `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`.

  Options: `:mode` (default `:default`).
  """
  @spec plans(engine(), Scenarios.scenario(), keyword()) :: [plan()]
  def plans(engine, scenario, opts \\ [])

  def plans(:hasura, %{read: read, auth: auth}, _opts) do
    {graphql, variables} = Runner.graphql(read)
    {:ok, statements} = Hasura.explain(graphql, variables, auth)
    Enum.map(statements, &explain(&1, []))
  end

  def plans(:authzura, scenario, opts) do
    scenario
    |> capture(opts)
    |> Enum.filter(fn {query, _params} -> classify(query) == :data end)
    |> Enum.map(fn {query, params} -> steady_explain(query, params) end)
  end

  @doc """
  The scans and shared buffers of one `EXPLAIN (ANALYZE, BUFFERS, FORMAT
  JSON)` result. Buffers are the root node's hit plus read blocks (the
  root's counts include its children's, so each statement counts once);
  scans are listed in plan order; every expression is dropped.
  """
  @spec parse_plan([map()] | map()) :: plan()
  def parse_plan([explain]), do: parse_plan(explain)

  def parse_plan(%{"Plan" => root}),
    do: %{table_scans: scans(root), shared_buffers: buffers(root)}

  @doc """
  The root data statement of `scenario`'s Authzura read, `{sql, params}`, as
  `all_input/4` runs it, captured from the repo's query telemetry event.

  Options: `:mode` (default `:default`) and `:join_lift` (a boolean, passed to
  `Authzura.Test.InternalRead.all_input/5`). It defaults to `true`; `false`
  captures the original unlifted input SQL for matched controls.
  """
  @spec authzura_sql(Scenarios.scenario(), keyword()) :: {String.t(), list()}
  def authzura_sql(scenario, opts \\ []) do
    scenario
    |> capture(opts)
    |> Enum.find(fn {query, _params} -> classify(query) == :data end)
  end

  @doc """
  The raw `EXPLAIN (FORMAT JSON)` result of `{sql, params}`, node types
  kept (`pk_walk?/2` reads it), as the decoded map with the `"Plan"` key.

    * `:custom` runs once, unnamed, with the parameters bound: the plan
      `all_input/4` gets uncached.
    * `:generic` prepares the statement and explains `EXECUTE` under
      `SET plan_cache_mode = force_generic_plan`, so the plan is a generic one.

  Options: `:repo` (default the benchmark repo), `:analyze` (default `true`, adds `ANALYZE, BUFFERS`), and
  `:after_explain`, an optional unary callback for generic plans. It receives
  the prepared statement's name on the checked-out connection after EXPLAIN
  and before DEALLOCATE, so callers can inspect its plan-use counters. The
  default callback does nothing. The generic path issues RESET plan_cache_mode
  afterward (also on callback failure); callers using SET LOCAL must reapply
  their regime before subsequent reads in the same transaction.
  """
  @spec raw_plan({String.t(), list()}, :custom | :generic, keyword()) :: map()
  def raw_plan({sql, params}, regime, opts \\ []) when regime in [:custom, :generic] do
    [plan] =
      raw_explain(
        sql,
        params,
        regime,
        explain_options(Keyword.get(opts, :analyze, true)),
        Keyword.get(opts, :after_explain, &noop/1),
        Keyword.get(opts, :repo, Repo)
      )

    plan
  end

  defp explain_options(true), do: @analyzed
  defp explain_options(false), do: "FORMAT JSON"

  @doc """
  `false` unless `plan` has a `Limit` root. Otherwise true when it reads
  `table` in primary-key order: the order-providing path (the outer child of a `Limit`,
  `Result`, `Nested Loop`, `Merge Join` or `Gather Merge`; InitPlans are
  skipped, and a child without a `"Parent Relationship"` is taken by
  position) reaches an `Index Scan` or `Index Only Scan` on `<table>_pkey`
  before any `Sort` or `Incremental Sort`.
  """
  @spec pk_walk?([map()] | map(), String.t()) :: boolean()
  def pk_walk?([explain], table), do: pk_walk?(explain, table)

  def pk_walk?(%{"Plan" => %{"Node Type" => "Limit"} = root}, table),
    do: walks_pk?(root, table <> "_pkey")

  def pk_walk?(%{"Plan" => _root}, _table), do: false

  defp walks_pk?(%{"Node Type" => type}, _index) when type in @sorts, do: false

  defp walks_pk?(%{"Node Type" => type, "Index Name" => index}, index)
       when type in ["Index Scan", "Index Only Scan"],
       do: true

  defp walks_pk?(%{"Node Type" => type, "Plans" => [_ | _] = children}, index)
       when type in @order_providers,
       do: children |> outer() |> walks_pk?(index)

  defp walks_pk?(_node, _index), do: false

  # The outer child, else (a hand-written plan) the first one.
  defp outer(children),
    do: Enum.find(children, &(Map.get(&1, "Parent Relationship") == "Outer")) || hd(children)

  @doc "Evaluates the targets of `scenario`'s measured `results` in `mode`."
  @spec check(map(), Scenarios.scenario(), Bench.mode()) :: targets()
  def check(
        %{db_time: db_time, statements: %{authzura: %{counts: counts}}, plans: plans},
        %{preload_levels: levels},
        mode
      ) do
    %{
      db_time: db_verdict(db_time.ratio, db_time.cv),
      data_statements: exactly(Map.get(counts, :data, 0.0), 1 + levels),
      transaction_control:
        transaction_control(mode, levels, Map.get(counts, :transaction_control, 0.0)),
      indexes: indexes(plans),
      buffers: buffers_verdict(plans)
    }
  end

  @doc """
  Authzura's shared buffers over Hasura's, summed over the data
  statements; `nil` when Hasura read no buffer.
  """
  @spec buffer_ratio(%{hasura: [plan()], authzura: [plan()]}) :: float() | nil
  def buffer_ratio(%{hasura: hasura, authzura: authzura}) do
    case total_buffers(hasura) do
      0 -> nil
      total -> total_buffers(authzura) / total
    end
  end

  @doc """
  A scenario's verdict: `:fail` when a target fails, else `:inconclusive`
  when one is, else `:pass`.
  """
  @spec verdict(targets()) :: verdict()
  def verdict(targets) when is_map(targets) do
    values = Map.values(targets)

    cond do
      :fail in values -> :fail
      :inconclusive in values -> :inconclusive
      true -> :pass
    end
  end

  @doc false
  @spec handle_query([atom()], map(), map(), {pid(), reference()}) :: :ok
  def handle_query(_event, _measurements, %{query: query, params: params}, {pid, ref})
      when pid == self() do
    send(pid, {ref, query, params})
    :ok
  end

  def handle_query(_event, _measurements, _metadata, _config), do: :ok

  defp requester(:hasura, %{read: %Read{table: table} = read, auth: auth}, _opts) do
    {graphql, variables} = Runner.graphql(read)
    root_field = Read.root_field(table)
    fn -> {:ok, _rows} = Hasura.query(graphql, variables, root_field, auth) end
  end

  defp requester(:authzura, %{read: read, auth: auth}, opts) do
    instance = opts |> mode() |> Bench.instance()
    run_opts = Keyword.take(opts, [:join_lift])
    fn -> {:ok, _rows} = Runner.authzura(read, auth, instance, run_opts) end
  end

  defp repeat(request, n), do: Enum.each(1..n, fn _i -> request.() end)

  defp per_request(rows, n) do
    counted =
      for [query, calls, ms] <- rows,
          calls > 0,
          classify(query) != :background,
          do: {classify(query), calls, ms}

    counts =
      Map.new(@counted, fn category ->
        {category, Enum.sum(for {^category, calls, _ms} <- counted, do: calls) / n}
      end)

    %{counts: counts, db_ms: Enum.sum(for {_category, _calls, ms} <- counted, do: ms) / n}
  end

  # Hasura answers every scenario with at least one data statement; none
  # counted means the statements were misclassified, not that it is fast.
  defp counted!(%{counts: %{data: data}}, :hasura) when data == 0,
    do: raise(ArgumentError, "no Hasura data statement was counted")

  defp counted!(statements, _engine), do: statements

  defp median_run(runs) do
    counts =
      Map.new(@counted, fn category ->
        {category, runs |> Enum.map(&Map.fetch!(&1.counts, category)) |> Stats.median()}
      end)

    %{counts: counts, db_ms: runs |> Enum.map(& &1.db_ms) |> Stats.median()}
  end

  # Authzura's statements for one request, from its repo's query event, in
  # memory only. Only this process's statements are kept.
  defp capture(scenario, opts) do
    ref = make_ref()
    id = {__MODULE__, ref}
    request = requester(:authzura, scenario, opts)
    event = opts |> mode() |> Bench.query_event()

    :ok =
      :telemetry.attach(id, event, &__MODULE__.handle_query/4, {self(), ref})

    try do
      request.()
    after
      :telemetry.detach(id)
    end

    collect(ref, [])
  end

  defp collect(ref, acc) do
    receive do
      {^ref, query, params} -> collect(ref, [{query, params} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp explain(query, params),
    do: query |> raw_explain(params, :custom, @analyzed, &noop/1, Repo) |> parse_plan()

  defp mode(opts), do: Keyword.get(opts, :mode, :default)
  defp noop(_name), do: :ok

  defp raw_explain(query, params, :custom, options, _after_explain, repo) do
    %{rows: [[plan]]} = repo.query!("EXPLAIN (#{options}) " <> query, params)
    plan
  end

  defp raw_explain(query, params, :generic, options, after_explain, repo) do
    prepared(repo, query, params, fn execute ->
      repo.query!("SET plan_cache_mode = force_generic_plan")

      try do
        %{rows: [[plan]]} = repo.query!("EXPLAIN (#{options}) " <> execute)
        after_explain.(@explained)
        plan
      after
        repo.query!("RESET plan_cache_mode")
      end
    end)
  end

  # The plan the steady state runs: on one connection, the statement is
  # prepared and executed as many times as Postgres plans it afresh, so the
  # explained execution uses whichever plan its plan cache settled on.
  # `EXECUTE` takes no bind parameters, so each value is rendered as a
  # literal of its parameter's type by Postgres itself.
  defp steady_explain(query, params) do
    prepared(Repo, query, params, fn execute ->
      repeat(fn -> Repo.query!(execute) end, @custom_plans)
      explain(execute, [])
    end)
  end

  # Runs `fun` with the `EXECUTE` statement of `query` prepared on one
  # connection, and deallocates it afterwards.
  defp prepared(repo, query, params, fun) do
    repo.checkout(fn ->
      repo.query!("PREPARE #{@explained} AS " <> query)

      try do
        fun.("EXECUTE #{@explained}" <> arguments(repo, params))
      after
        repo.query!("DEALLOCATE #{@explained}")
      end
    end)
  end

  defp arguments(_repo, []), do: ""

  defp arguments(repo, params) do
    %{rows: [[types]]} = repo.query!(@parameter_types, [@explained])
    "(" <> (params |> Enum.zip_with(types, &literal(repo, &1, &2)) |> Enum.join(", ")) <> ")"
  end

  # The type names come from the catalog (`regtype` output is quoted).
  defp literal(repo, value, type) do
    %{rows: [[literal]]} = repo.query!("SELECT quote_nullable(($1::#{type})::text)", [value])
    "#{literal}::#{type}"
  end

  defp scans(node), do: own_scan(node) ++ Enum.flat_map(Map.get(node, "Plans", []), &scans/1)

  defp own_scan(%{"Node Type" => type, "Relation Name" => table} = node)
       when is_map_key(@scan_kinds, type) do
    kind = Map.fetch!(@scan_kinds, type)
    [{table, kind, index_name(kind, node)}]
  end

  defp own_scan(_node), do: []

  defp index_name(:seq, _node), do: nil
  defp index_name(:bitmap, node), do: bitmap_index(node)
  defp index_name(_kind, node), do: Map.get(node, "Index Name")

  defp bitmap_index(%{"Node Type" => "Bitmap Index Scan", "Index Name" => index}), do: index

  defp bitmap_index(node),
    do: node |> Map.get("Plans", []) |> Enum.find_value(&bitmap_index/1)

  defp buffers(node),
    do: Map.get(node, "Shared Hit Blocks", 0) + Map.get(node, "Shared Read Blocks", 0)

  defp db_verdict(_ratio, cv) when cv > @max_cv, do: :inconclusive
  defp db_verdict(ratio, _cv) when ratio <= @max_db_ratio, do: :pass
  defp db_verdict(_ratio, _cv), do: :fail

  defp exactly(count, expected) when abs(count - expected) < 1.0e-6, do: :pass
  defp exactly(_count, _expected), do: :fail

  defp transaction_control(:read_only_connection, 0, count), do: exactly(count, 0)
  defp transaction_control(_mode, _levels, _count), do: :not_applicable

  # Every table Hasura reads through an index, Authzura never scans
  # sequentially.
  defp indexes(%{hasura: hasura, authzura: authzura}) do
    indexed =
      for %{table_scans: scans} <- hasura,
          {table, kind, _} <- scans,
          kind != :seq,
          into: MapSet.new(),
          do: table

    sequential =
      for %{table_scans: scans} <- authzura,
          {table, :seq, _} <- scans,
          into: MapSet.new(),
          do: table

    if MapSet.disjoint?(indexed, sequential), do: :pass, else: :fail
  end

  defp total_buffers(plans), do: Enum.sum_by(plans, & &1.shared_buffers)

  defp buffers_verdict(%{hasura: hasura, authzura: authzura}) do
    if total_buffers(authzura) <= @max_buffer_ratio * total_buffers(hasura),
      do: :pass,
      else: :fail
  end
end

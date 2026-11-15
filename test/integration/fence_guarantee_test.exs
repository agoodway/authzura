defmodule Authzura.Integration.FenceGuaranteeTest do
  @moduledoc "Hidden-row regression evidence on committed rows across planner settings."

  use Authzura.CommittedCase, async: false

  import Authzura.SqlHelper, only: [outside_fence: 1]

  alias Authzura.Bench.Measure
  alias Authzura.HasuraFixture
  alias Authzura.TelemetryHelper
  alias Authzura.Test.InternalRead
  alias Ecto.Adapters.SQL
  alias Postgrex.Error, as: PostgresError

  @event [:authzura, :test, :repo, :query]
  @deep %{"author" => %{"org" => %{"id" => %{"_eq" => "X-Hasura-Org-Id"}}}}
  @shapes [
    {"deep", "comments", "article", "body"},
    {"fallback", "comments", "article", "body_partial"},
    {"nullable", "comments", "nullable_article", "body_nullable"},
    {"partitioned", "comments_part", "article", "body"}
  ]
  @parallel [
    debug_parallel_query: "on",
    max_parallel_workers_per_gather: "2",
    parallel_setup_cost: "0",
    parallel_tuple_cost: "0",
    min_parallel_table_scan_size: "0",
    min_parallel_index_scan_size: "0"
  ]
  # The original fourteen regimes, memoize off/on, and stronger parallel/JIT regimes.
  @planner_settings [
    custom: [plan_cache_mode: "force_custom_plan"],
    generic: [plan_cache_mode: "force_generic_plan"],
    no_nestloop: [enable_nestloop: "off"],
    no_hashjoin: [enable_hashjoin: "off"],
    no_mergejoin: [enable_mergejoin: "off"],
    no_seqscan: [enable_seqscan: "off"],
    no_indexscan: [enable_indexscan: "off", enable_indexonlyscan: "off"],
    no_bitmapscan: [enable_bitmapscan: "off"],
    join_order: [join_collapse_limit: "1"],
    cpu_zero: [cpu_tuple_cost: "0", cpu_index_tuple_cost: "0", cpu_operator_cost: "0"],
    page_costs: [random_page_cost: "100", seq_page_cost: "0.01"],
    parallel: [max_parallel_workers_per_gather: "2", parallel_setup_cost: "0"],
    cheap_probe: [probe_cost: "0.0001"],
    expensive_probe: [probe_cost: "100000"],
    memoize_off: [enable_memoize: "off"],
    memoize_on: [enable_memoize: "on"],
    forced_parallel: @parallel,
    forced_jit: [
      jit: "on",
      jit_above_cost: "0",
      jit_inline_above_cost: "0",
      jit_optimize_above_cost: "0"
    ]
  ]

  setup %{test: test} do
    metadata = metadata()

    off =
      HasuraFixture.start_instance!(:"#{test}_off", Repo, metadata, default_prefix: "fence_probe")

    on =
      HasuraFixture.start_instance!(:"#{test}_on", Repo, metadata,
        default_prefix: "fence_probe",
        input_index_pushdown: true
      )

    TelemetryHelper.forward!(test, [@event], caller_only: true)
    features = Application.fetch_env!(:authzura, :server_features)
    %{instances: %{false => off, true => on}, jit_available?: features.jit_available?}
  end

  test "the probe operator is the one Authzura's LIKE resolves to", %{instances: %{false => off}} do
    %{rows: [[true, true, "s", false]]} =
      Repo.query!("""
      SELECT p.proisstrict, p.provolatile = 'i', p.proparallel::text, p.proleakproof
      FROM pg_operator o JOIN pg_proc p ON p.oid = o.oprcode
      WHERE o.oid = 'fence_probe.~~(fence_probe.body_text,character varying)'::regoperator
      """)

    for {_role, table, _relationship, body} <- @shapes do
      assert_raise PostgresError, ~r/hidden row/, fn ->
        under_setting(:custom, fn ->
          input = %{columns: ["id"], filter: %{body => %{"_like" => "%7"}}}

          Authzura.all_input(table, HasuraFixture.session!("probe"), input,
            instance: off,
            in_transaction: :trust_isolation
          )
        end)
      end
    end
  end

  test "the probe fires on the unfenced statement under at least one setting",
       %{
         instances: %{false => off}
       } = context do
    fired =
      for {setting, _opts} <- active_settings(context),
          probe_fired?(off, setting),
          do: setting

    assert fired != [],
           "unfenced probe fired under #{length(fired)} settings: #{inspect(fired)}; expected at least one"
  end

  defp probe_fired?(instance, setting) do
    setting |> under_setting(fn -> unfenced_read(instance) end) |> control_fired?()
  end

  defp session(role), do: HasuraFixture.session!(role, %{"x-hasura-org-id" => "3"})

  defp unfenced_read(instance) do
    session = session("deep")

    assert {:ok, query} =
             Authzura.scope("comments", session, instance: instance, columns: ["id"])

    query = where(query, [c], fragment("? LIKE ?::varchar", field(c, "body"), ^"%7"))
    {sql, params} = SQL.to_sql(:all, Repo, query)
    Repo.query(sql, params)
  end

  test "each shape's marker matches exactly the rows its permission rejects", %{
    instances: %{false => off}
  } do
    for {role, table, _relationship, body} <- @shapes do
      session = session(role)

      assert {:ok, rows} =
               Authzura.all(table, session, instance: off, columns: ["id"])

      permitted = rows |> Enum.map(& &1["id"]) |> Enum.sort()

      %{rows: visible} =
        Repo.query!(
          "SELECT id FROM fence_probe.#{table} WHERE left(#{body}::text, 2) = 'V:' ORDER BY id"
        )

      assert permitted == List.flatten(visible)
      assert permitted != []

      %{rows: [[hidden]]} =
        Repo.query!(
          "SELECT count(*) FROM fence_probe.#{table} WHERE left(#{body}::text, 2) = 'H:' AND author_id = 3"
        )

      assert hidden > 0
    end
  end

  for {setting, _opts} <- @planner_settings do
    if setting == :forced_jit, do: @tag(:fence_jit)

    test "lifted all_input never evaluates the input on a hidden row under any setting: #{setting}",
         context do
      check_reads(context, unquote(setting), true)
    end

    if setting == :forced_jit, do: @tag(:fence_jit)

    test "unlifted all_input never evaluates the input on a hidden row under any setting: #{setting}",
         context do
      check_reads(context, unquote(setting), false)
    end
  end

  for {role, _table, _relationship, _body} = shape <- @shapes,
      pushdown? <- [false, true],
      lift? <- [false, true] do
    test "matched controls: #{role}, pushdown=#{pushdown?}, lift=#{lift?}", context do
      check_controls(context, unquote(Macro.escape(shape)), unquote(pushdown?), unquote(lift?))
    end
  end

  defp check_controls(
         %{instances: instances} = context,
         {role, _, _, _} = shape,
         pushdown?,
         lift?
       ) do
    instance = Map.fetch!(instances, pushdown?)

    settings = active_settings(context)

    fired =
      for {setting, _} <- settings,
          matched_control_fired?(instance, shape, setting, lift?, pushdown?),
          do: setting

    report =
      "shape=#{role} pushdown=#{pushdown?} lift=#{lift?}: #{length(fired)}/#{length(settings)} settings #{inspect(fired)}; skipped=#{inspect(skipped_controls(context))}"

    assert fired != [], report
    required = required_controls(context)
    assert required -- fired == [], "missing #{inspect(required -- fired)}; " <> report
  end

  defp active_settings(%{jit_available?: false}),
    do: Keyword.delete(@planner_settings, :forced_jit)

  defp active_settings(%{jit_available?: true}), do: @planner_settings

  defp skipped_controls(%{jit_available?: false}), do: [:forced_jit]
  defp skipped_controls(%{jit_available?: true}), do: []

  defp required_controls(%{jit_available?: false}), do: [:generic, :forced_parallel]
  defp required_controls(%{jit_available?: true}), do: [:generic, :forced_parallel, :forced_jit]

  defp matched_control_fired?(instance, shape, setting, lift?, pushdown?) do
    under_setting(setting, fn ->
      statement = check_shape(instance, shape, setting, lift?, pushdown?)
      matched_control(statement)
    end)
  end

  defp matched_control({sql, params}) do
    control = String.replace(sql, "CASE WHEN ", "CASE WHEN true OR ")
    refute control == sql
    Repo.query!("SAVEPOINT fence_control")
    result = Repo.query(control, params)
    Repo.query!("ROLLBACK TO SAVEPOINT fence_control")
    Repo.query!("RELEASE SAVEPOINT fence_control")
    control_fired?(result)
  end

  defp control_fired?({:ok, _result}), do: false

  defp control_fired?(
         {:error, %PostgresError{postgres: %{code: :raise_exception, message: "hidden row"}}}
       ),
       do: true

  defp control_fired?({:error, error}), do: raise(error)

  test "parallel workers launched", context do
    for {_pushdown?, instance} <- context.instances do
      under_setting(:forced_parallel, fn ->
        for shape <- @shapes do
          {_rows, statement} = read(instance, shape, true)
          assert_execution(statement, :forced_parallel)
        end
      end)
    end
  end

  @tag :fence_jit
  test "JIT ran", context do
    for {_pushdown?, instance} <- context.instances do
      under_setting(:forced_jit, fn ->
        for shape <- @shapes do
          {_rows, statement} = read(instance, shape, true)
          assert_execution(statement, :forced_jit)
        end
      end)
    end
  end

  defp check_reads(%{instances: instances}, setting, lift?) do
    Enum.each(instances, fn {pushdown?, instance} ->
      under_setting(setting, fn -> check_shapes(instance, setting, lift?, pushdown?) end)
    end)
  end

  defp check_shapes(instance, setting, lift?, pushdown?) do
    for shape <- @shapes, do: check_shape(instance, shape, setting, lift?, pushdown?)
  end

  defp check_shape(
         instance,
         {role, _table, _relationship, _body} = shape,
         setting,
         lift?,
         pushdown?
       ) do
    {rows, {sql, _params} = statement} = read(instance, shape, lift?)
    assert rows == expected(shape), "#{setting}: #{role}, lift=#{lift?}"
    assert rows != []
    assert sql =~ "CASE WHEN"
    outside = outside_fence(sql)
    assert String.contains?(outside, ~s|OPERATOR(pg_catalog.=)|) == pushdown?
    assert_lift(sql, role, lift?)

    # Generic-plan evidence comes from the EXPLAIN EXECUTE re-run of the
    # captured statement, not from inspecting the all_input execution's plan.
    assert_execution(statement, setting)
    statement
  end

  # The fallback shape runs identical EXISTS SQL with lifting enabled or disabled.
  defp assert_lift(sql, "fallback", _lift?), do: refute(sql =~ "INNER JOIN")
  defp assert_lift(sql, _role, false), do: refute(sql =~ "INNER JOIN")

  defp assert_lift(sql, role, true) when role in ["deep", "nullable", "partitioned"],
    do: assert(sql =~ "INNER JOIN")

  defp assert_execution({sql, params} = statement, :generic) do
    assert params != []
    assert sql =~ ~r/\$[1-9][0-9]*/
    observed = make_ref()

    after_explain = fn name ->
      %{rows: [[prepared_sql, true, generic_plans, custom_plans]]} =
        Repo.query!(
          """
          SELECT statement, from_sql, generic_plans, custom_plans
          FROM pg_prepared_statements WHERE name = $1
          """,
          [name]
        )

      assert prepared_sql == "PREPARE #{name} AS " <> sql
      assert generic_plans > 0
      assert custom_plans == 0
      send(self(), {observed, :generic_plan_observed})
    end

    assert %{"Plan" => _plan} = explain(statement, :generic, after_explain: after_explain)
    assert_received {^observed, :generic_plan_observed}
  end

  defp assert_execution(statement, :forced_parallel) do
    plan = explain(statement, :forced_parallel)
    assert workers(plan["Plan"]) > 0, inspect(plan)
  end

  defp assert_execution(statement, :forced_jit) do
    assert %{"JIT" => %{"Functions" => functions}} = explain(statement, :forced_jit)
    assert functions > 0
  end

  defp assert_execution(_statement, _setting), do: :ok

  defp read(instance, {role, table, _relationship, body}, lift?) do
    session = session(role)

    input = %{
      columns: ["id"],
      filter: %{body => %{"_like" => "%7"}, "author_id" => %{"_eq" => 3}},
      order_by: [{"id", :asc}]
    }

    {{:ok, rows}, statements} =
      TelemetryHelper.capture_statements(@event, fn ->
        run_read(instance, table, session, input, lift?)
      end)

    assert [statement] = statements
    {rows, statement}
  end

  defp run_read(instance, table, session, input, true),
    do:
      Authzura.all_input(table, session, input,
        instance: instance,
        in_transaction: :trust_isolation
      )

  defp run_read(instance, table, session, input, false),
    do:
      InternalRead.all_input(table, session, input, instance,
        join_lift: false,
        in_transaction: :trust_isolation
      )

  defp expected({_role, "comments_part", _relationship, _body}),
    do: expected("comments_part", "articles_part", "article_id")

  defp expected({_role, table, "nullable_article", _body}),
    do: expected(table, "articles", "nullable_article_id")

  defp expected({_role, table, _relationship, _body}),
    do: expected(table, "articles", "article_id")

  defp expected(table, articles, column) do
    %{rows: rows} =
      Repo.query!("""
      SELECT c.id FROM fence_probe.#{table} c
      JOIN fence_probe.#{articles} a ON a.id = c.#{column}
      JOIN fence_probe.users u ON u.id = a.author_id
      JOIN fence_probe.organizations o ON o.id = u.org_id
      WHERE o.id = 3 AND c.author_id = 3 AND c.id % 10 = 7 ORDER BY c.id
      """)

    Enum.map(rows, fn [id] -> %{"id" => id} end)
  end

  defp under_setting(setting, fun) do
    {:error, result} =
      Repo.transaction(fn ->
        Repo.query!("SET LOCAL search_path = fence_probe, pg_catalog")
        Repo.query!("SET LOCAL jit = off")
        Repo.query!("SET LOCAL plan_cache_mode = force_custom_plan")
        Enum.each(Keyword.fetch!(@planner_settings, setting), &set_option/1)
        Repo.rollback(fun.())
      end)

    result
  end

  defp set_option({:probe_cost, value}) do
    Repo.query!("ALTER FUNCTION fence_probe.guard(text, text) COST #{value}")
    Repo.query!("ALTER FUNCTION fence_probe.guard(fence_probe.body_text, varchar) COST #{value}")
  end

  defp set_option({key, value}), do: Repo.query!("SET LOCAL #{key} = #{value}")

  # Reuse Measure's parameter rendering on the test repo's checked-out connection.
  defp explain(statement, setting, opts \\ [])

  # Measure resets plan_cache_mode before returning; keep this test's
  # SET LOCAL regime active for the next captured read/control in the cell.
  defp explain(statement, :generic, opts) do
    Measure.raw_plan(statement, :generic, Keyword.put(opts, :repo, Repo))
  after
    Repo.query!("SET LOCAL plan_cache_mode = force_generic_plan")
  end

  defp explain(statement, _setting, opts),
    do: Measure.raw_plan(statement, :custom, Keyword.put(opts, :repo, Repo))

  defp workers(node),
    do:
      Map.get(node, "Workers Launched", 0) +
        Enum.sum_by(Map.get(node, "Plans", []), &workers/1)

  defp metadata do
    HasuraFixture.metadata([
      %{table: {"fence_probe", "organizations"}},
      %{
        table: {"fence_probe", "users"},
        object_relationships: [object("org", "organizations", "org_id")]
      },
      %{
        table: {"fence_probe", "articles"},
        object_relationships: [object("author", "users", "author_id")],
        array_relationships: [
          HasuraFixture.array_relationship("comments", {"fence_probe", "comments"}, %{
            "id" => "article_id"
          })
        ]
      },
      %{
        table: {"fence_probe", "articles_part"},
        object_relationships: [object("author", "users", "author_id")]
      },
      comments("comments", "articles"),
      comments("comments_part", "articles_part")
    ])
  end

  defp comments(table, articles) do
    permissions =
      for {role, shape_table, relationship, _body} <- @shapes, shape_table == table do
        HasuraFixture.select_permissions(role, "*", permission_filter(role, relationship))
      end

    %{
      table: {"fence_probe", table},
      object_relationships: [
        object("article", articles, "article_id"),
        object("nullable_article", articles, "nullable_article_id")
      ],
      select_permissions:
        List.flatten(permissions) ++ HasuraFixture.select_permissions("probe", "*")
    }
  end

  defp permission_filter("fallback", relationship),
    do: %{"_and" => [%{relationship => @deep}, %{"article" => %{"comments" => %{}}}]}

  defp permission_filter(_role, relationship), do: %{relationship => @deep}

  defp object(name, table, column),
    do: HasuraFixture.object_relationship(name, {"fence_probe", table}, %{column => "id"})
end

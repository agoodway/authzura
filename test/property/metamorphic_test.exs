defmodule Authzura.MetamorphicTest do
  @moduledoc """
  Metamorphic properties of Authzura alone, over generated permission
  batches (`Authzura.Gen`) and `Authzura.Test.Seed`'s committed rows.

  Each property loops over `AUTHZURA_PROP_BATCHES` batches (default 4) and
  spends `AUTHZURA_PROP_RUNS` cases in total (default 400, about 100 a
  batch: at about 50 a batch the 25 % guards fail on sampling noise
  alone, with only about ten array-preload cases each): per batch, one
  forced case per denial class (`Gen.sweep/0`), the rest drawn from the
  random stream with request seed `AUTHZURA_PROP_SEED + i + 1000 * k`
  (`k` is the property's own offset). Per batch it serves the batch's
  metadata, checks guard (a) (no `:deny` diagnostic at all; warnings appear
  on failure), runs the cases, then asserts the vacuity guards (b)-(d) on the
  random stream (`Authzura.Test.Vacuity`); guard (e) is asserted over the
  whole run, not per batch: the forced sweep gives every batch one case of
  each denial class and the first property asserts each case's reason, so
  the two are equivalent in practice.

  The suites otherwise call Authzura only through `all/3` with explicit
  columns and `all_input/4` (`Authzura.Parity.Runner`). "The other entry
  points agree" reaches the rest on the same cases: the default
  projection, `scope/3` and `scope_input/4` run by the caller's own
  `Repo.all`, `get/4` and `one/3`, and Ecto-schema queryables.
  A failure prints the command that replays it.

  Join-lift uses a separate random where-case stream without limits or
  preloads. It compares unordered and tied root multisets, and sequences
  only under a visible primary-key order. Failures report batch case,
  relationship-permission and executed-join counts for both push-down modes.
  """

  use Authzura.CommittedCase, async: false
  use ExUnitProperties

  alias Authzura.{Gen, HasuraFixture, SqlHelper, Store, TelemetryHelper, TestSource}
  alias Authzura.Gen.Catalog
  alias Authzura.Model.{Permission, Relationship, Snapshot, Table}
  alias Authzura.Parity.{Read, Runner, Verdict}
  alias Authzura.Test.{PermissionOracle, PublicReason, Schemas, Seed, Vacuity}
  alias Ecto.Type

  @moduletag :property

  @instance Module.concat(__MODULE__, Instance)
  @pushdown_instance Module.concat(__MODULE__, PushdownInstance)
  @repo_query [:authzura, :test, :repo, :query]
  @schemas %{
    {"public", "organizations"} => Schemas.Organization,
    {"public", "users"} => Schemas.User,
    {"public", "articles"} => Schemas.Article,
    {"public", "comments"} => Schemas.Comment,
    {"audit", "users"} => Schemas.AuditUser
  }
  # Rows compared per granted case by `get/4` and `one/3`.
  @keyed_rows 3
  @coverage_sample 1_500
  @degenerate_runs 60
  @oracle_checked 0.30

  setup context do
    :ok = Seed.insert!(Repo)
    opts = Map.get(context, :batch, [])
    metadata = 1 |> Gen.batch(opts) |> Gen.metadata()

    {@instance, agent} =
      HasuraFixture.start_instance_with_source!(@instance, Repo, metadata,
        admin_role: Gen.admin_role()
      )

    %{agent: agent, batch_opts: opts, metadata: metadata}
  end

  setup :setup_join_lift

  defp setup_join_lift(%{join_lift: true, metadata: metadata, test: test}) do
    {@pushdown_instance, agent} =
      HasuraFixture.start_instance_with_source!(@pushdown_instance, Repo, metadata,
        admin_role: Gen.admin_role(),
        input_index_pushdown: true
      )

    TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
    %{pushdown_agent: agent}
  end

  defp setup_join_lift(_context), do: :ok

  property "never raises; errors are public reasons", context do
    each_batch(context, 0, fn c, result, _batch ->
      case result do
        {:ok, _rows} ->
          assert c.denial == nil, "built to be denied with #{inspect(c.denial)}, but granted"

        {:error, reason} ->
          assert PublicReason.public_reason?(reason), "not a public reason: #{inspect(reason)}"

          assert c.denial == nil or Gen.expected_denial?(c.denial, reason),
                 "built for #{inspect(c.denial)}, denied with #{inspect(reason)}"
      end
    end)
  end

  property "visible keys are requested and allowed, at every preload level", context do
    each_batch(context, 1, fn c, result, batch ->
      with {:ok, rows} <- result do
        for {read, table, level_rows} <- level_rows(c.read, rows), row <- level_rows do
          assert MapSet.new(Map.keys(row)) == expected_keys(read)
          assert read.columns -- Gen.visible(batch, c.role, table) == []
        end
      end
    end)
  end

  @tag batch: [limits: false]
  property "input fence: rows(role, F) == rows(role) ∩ rows(admin, F)", context do
    each_batch(context, 2, &fence/3, &Vacuity.fence_failures/1)
  end

  property "root and per-parent counts are at most min(request, permission) limits", context do
    each_batch(context, 3, fn c, result, batch ->
      with {:ok, rows} <- result do
        root_limit = permission_limit(batch, c.role, c.read.table)
        assert length(rows) <= min_limit(c.read.limit, root_limit)

        for {read, parent, parent_rows} <- level_rows(c.read, rows),
            {name, _child} <- read.relationships,
            {:array, target, _mapping} <- [Catalog.relationship(parent, name)],
            limit = permission_limit(batch, c.role, target),
            limit != nil,
            row <- parent_rows do
          assert length(Map.fetch!(row, name)) <= limit
        end
      end
    end)
  end

  property "the same case twice gives the same result", context do
    each_batch(context, 4, fn c, result, _batch -> assert run(c) == result end)
  end

  @tag batch: [limits: false]
  property "paging: rows(limit, offset) == slice(rows(unpaged), offset, limit)", context do
    each_batch(context, 5, fn c, result, batch ->
      if keyed?(c, batch) and granted?(result) do
        assert {:ok, all} = run(unpaged(c))
        {:ok, rows} = result
        assert rows == Enum.slice(all, c.read.offset || 0, c.read.limit || length(all))
      end
    end)
  end

  @tag batch: [limits: false]
  property "rows are exactly what the permission admits, at every level (independent oracle)",
           context do
    each_batch(context, 6, &oracle/3, &oracle_failures/1)
  end

  @tag batch: [limits: false]
  property "the other entry points agree with all/3 and all_input/4", context do
    each_batch(context, 7, &entry_points/3)
  end

  @tag batch: [limits: false, join_lift: true], join_lift: true
  property "join-lift: the same row set; the same sequence when the order is total; push-down off and on",
           context do
    for i <- 1..batches() do
      batch = Gen.batch(i, context.batch_opts)
      load_lift_batch!(context, i, batch)
      {:ok, %{snapshot: snapshot}} = Store.current(@instance)
      seed = Gen.seed() + i + 8_000
      {:ok, store} = Agent.start_link(fn -> [] end)

      replayable(context, i, seed, fn ->
        check all(
                c <- lift_cases(batch),
                max_runs: max(div(runs(), batches()), 1),
                initial_seed: seed
              ) do
          observations =
            for instance <- [@instance, @pushdown_instance] do
              observation = lift_parity(c, batch, snapshot, instance)
              {instance, observation}
            end

          Agent.update(store, &(observations ++ &1))
        end

        for {instance, pushdown?} <- [{@instance, false}, {@pushdown_instance, true}] do
          observations = for {^instance, observation} <- Agent.get(store, & &1), do: observation
          stats = Vacuity.lift_stats(observations)
          report = "join-lift batch #{i}, seed #{seed}, pushdown=#{pushdown?}: #{inspect(stats)}"
          assert stats.incomplete == 0, "all-or-nothing lift violated: " <> report
          assert Vacuity.lift_failures(observations) == [], report
        end
      end)

      Agent.stop(store)
    end
  end

  @tag batch: [limits: false], join_lift: true
  test "join-lift pages with a unique tiebreaker include nullable and partial-NULL chains",
       context do
    filters = [
      {{"public", "articles"}, "editor", %{"editor" => %{"manager" => %{"id" => %{"_gt" => 0}}}}},
      {{"public", "users"}, "manager", %{"manager" => %{"manager" => %{"id" => %{"_gt" => 0}}}}},
      {{"public", "membership_notes"}, "membership",
       %{"membership" => %{"level" => %{"_gt" => 0}}}}
    ]

    batch =
      Enum.reduce(filters, Gen.batch(1, limits: false), fn {table, _name, filter}, batch ->
        put_in(batch, ["gen_0", table], %{"columns" => "*", "filter" => filter})
      end)

    load_lift_batch!(context, 1, batch)
    {:ok, %{snapshot: %{tables: tables}}} = Store.current(@instance)

    for {table, relationship, filter} <- filters do
      c = batch |> lift_cases() |> Gen.take(1, 1) |> hd() |> Gen.as_role("gen_0")

      read =
        Read.new(table,
          columns: Catalog.names(table),
          where: %{
            "_and" => [
              %{"id" => %{"_gt" => 0}},
              %{"id" => %{"_in" => Enum.uniq(Catalog.ids().user ++ Catalog.ids().article)}}
            ]
          },
          order_by: [asc: :org_id, desc: :id]
        )

      c = %{c | read: read}
      ctx = PermissionOracle.context(c, @instance)
      assert {:ok, expected} = PermissionOracle.rows(ctx, table, filter, read.where)
      assert expected != []
      assert Enum.any?(Enum.frequencies_by(expected, & &1["org_id"]), fn {_org, n} -> n > 1 end)
      assert {:ok, matching} = PermissionOracle.rows(ctx, table, %{}, read.where)
      {_kind, _target, mapping} = Catalog.relationship(table, relationship)

      nulls =
        Enum.filter(matching, fn row ->
          Enum.any?(mapping, fn {local, _} -> row[local] == nil end)
        end)

      assert nulls != []

      if map_size(mapping) > 1 do
        for local <- Map.keys(mapping) do
          assert Enum.any?(nulls, fn row ->
                   row[local] == nil and Enum.any?(Map.keys(mapping), &(row[&1] != nil))
                 end)
        end
      end

      for instance <- [@instance, @pushdown_instance] do
        assert {{:ok, all}, lifted} = executed_read(c, instance, true)
        assert lifted > 0
        assert multiset(all) == multiset(expected)
        assert MapSet.disjoint?(MapSet.new(all, & &1["id"]), MapSet.new(nulls, & &1["id"]))

        pages =
          for offset <- 0..div(length(all) + 1, 2) do
            page = %{c | read: %{read | limit: 2, offset: offset * 2}}

            assert {{:ok, unlifted}, unlifted_joins} = executed_read(page, instance, false)

            assert {{:ok, rows}, joins} = executed_read(page, instance, true)
            assert joins > 0
            assert unlifted_joins == 0
            assert rows == unlifted
            assert rows == Enum.slice(all, offset * 2, 2)

            assert :match =
                     Verdict.classify(
                       Verdict.context(page.read, tables),
                       {:ok, unlifted},
                       {:ok, rows}
                     )

            rows
          end

        assert List.flatten(pages) == all
      end
    end
  end

  test "every batch's random stream reaches the must-appear set (partial NULL keys at run time)",
       %{agent: agent} do
    for i <- 1..batches() do
      batch = Gen.batch(i)
      load!(agent, i, batch)
      cases = Gen.take(Gen.request(batch), Gen.seed() + i, @coverage_sample)

      failures = Vacuity.coverage_failures(cases, Enum.any?(cases, &partial_null?(&1, batch)))
      assert failures == [], "batch #{i}: #{Enum.join(failures, "; ")}"
    end
  end

  test "each degenerate generator fails a vacuity guard", %{agent: agent} do
    load!(agent, 1, Gen.batch(1, degenerate: :no_filters))
    assert guard_failed?(observe_all(Gen.batch(1, degenerate: :no_filters), []), "(c)")

    batch = Gen.batch(1)
    load!(agent, 1, batch)
    assert guard_failed?(observe_all(batch, degenerate: :no_preloads), "(d)")

    no_input = batch |> Gen.request(degenerate: :no_input_filter) |> Gen.take(1, @degenerate_runs)

    assert Vacuity.fence_failures(Enum.flat_map(no_input, &List.wrap(fence(&1, run(&1), batch)))) !=
             []

    for {batch, opts} <- [
          {Gen.batch(1, degenerate: :all_columns), []},
          {batch, [degenerate: :no_preloads]}
        ] do
      cases = batch |> Gen.request(opts) |> Gen.take(1, @coverage_sample)
      assert Vacuity.coverage_failures(cases, true) != []
    end
  end

  # Batches and guards.

  defp each_batch(context, k, body, guard \\ fn _extras -> [] end) do
    %{agent: agent, batch_opts: opts} = context

    log =
      Enum.flat_map(1..batches(), fn i ->
        batch = Gen.batch(i, opts)
        load!(agent, i, batch)
        seed = Gen.seed() + i + 1_000 * k
        {:ok, store} = Agent.start_link(fn -> [] end)

        checked = fn c ->
          result = run(c)
          extra = body.(c, result, batch)
          observation = Vacuity.observe(c, result, &run/1)
          Agent.update(store, &[{observation, extra} | &1])
        end

        replayable(context, i, seed, fn -> check_batch(batch, seed, checked) end)
        {random, _sweep} = store |> Agent.get(&Enum.reverse/1) |> Enum.split(random_runs())
        Agent.stop(store)

        {observations, extras} = Enum.unzip(random)
        failures = Vacuity.failures(observations) ++ guard.(extras)
        assert failures == [], "batch #{i} (request seed #{seed}): #{Enum.join(failures, "; ")}"
        observations
      end)

    assert Vacuity.denial_failures(log) == []
  end

  # The random stream first, then one forced case per denial class.
  defp check_batch(batch, seed, checked) do
    check all(c <- Gen.request(batch), max_runs: random_runs(), initial_seed: seed) do
      checked.(c)
    end

    for mutation <- Gen.sweep() do
      check all(c <- Gen.request(batch, mutation: mutation), max_runs: 1, initial_seed: seed) do
        checked.(c)
      end
    end
  end

  defp replayable(context, i, seed, fun) do
    fun.()
  rescue
    error in ExUnit.AssertionError ->
      command =
        "AUTHZURA_PROP_SEED=#{Gen.seed()} AUTHZURA_PROP_BATCHES=#{batches()} " <>
          "AUTHZURA_PROP_RUNS=#{runs()} mix test #{Path.relative_to_cwd(context.file)} " <>
          "--only test:#{inspect(Atom.to_string(context.test))}"

      message = "batch #{i}, request seed #{seed}; replay with:\n  #{command}\n" <> error.message
      reraise %{error | message: message}, __STACKTRACE__
  end

  # Serves `batch` and checks guard (a).
  defp load!(agent, i, batch, instance \\ @instance) do
    snapshot = HasuraFixture.snapshot!(Repo, Gen.metadata(batch))
    :ok = TestSource.put(agent, snapshot: snapshot, version: "batch-#{i}")
    :ok = Authzura.reload(instance)

    {:ok, diagnostics} = Authzura.diagnostics(instance)
    {denied, warnings} = Enum.split_with(diagnostics, &(&1.severity == :deny))

    assert denied == [],
           "batch #{i} has deny diagnostics: #{inspect(denied)}; warnings: #{inspect(warnings)}"
  end

  defp observe_all(batch, opts) do
    batch
    |> Gen.request(opts)
    |> Gen.take(1, @degenerate_runs)
    |> Enum.map(fn c -> Vacuity.observe(c, run(c), &run/1) end)
  end

  defp guard_failed?(log, guard),
    do: log |> Vacuity.failures() |> Enum.any?(&String.starts_with?(&1, guard))

  # No forced cases enter lift coverage. No request/permission limits or
  # preloads: tied and unordered reads must compare whole root multisets.
  # Paging with a unique final key is checked separately above.
  defp lift_cases(batch) do
    batch
    |> Gen.request(mutation: :none, degenerate: :no_preloads)
    |> filter(&(is_nil(&1.denial) and where?(&1)))
    |> map(&unpaged/1)
  end

  defp load_lift_batch!(context, i, batch) do
    load!(context.agent, i, batch)
    load!(context.pushdown_agent, i, batch, @pushdown_instance)
  end

  defp lift_parity(
         %{read: %Read{table: table}, role: role} = c,
         batch,
         %Snapshot{tables: tables, permissions: permissions},
         instance
       ) do
    counts = assert_lift_parity(c, batch, tables, instance)
    assert [lifted] = Enum.uniq(counts)
    %Permission{filter: filter} = Map.fetch!(permissions, {role, table, :select})
    nullable_hops = relationship_nulls(filter, tables[table], tables)
    lift_observation(nullable_hops, lifted, length(nullable_hops))
  end

  defp assert_lift_parity(%{read: %Read{table: table} = read} = c, batch, tables, instance) do
    orders = Enum.uniq([read.order_by, nil, tied_order(c, batch)])

    for order <- orders do
      c = %{c | read: %{read | order_by: order}}
      assert {{:ok, unlifted}, unlifted_joins} = executed_read(c, instance, false)
      assert {{:ok, lifted}, count} = executed_read(c, instance, true)
      if count > 0, do: assert(unlifted_joins == 0)
      # Verdict/Compare preserve multiplicity even when the projection hides the PK.
      unordered = Verdict.context(%{c.read | order_by: nil}, tables, divergences: [])
      assert :match = Verdict.classify(unordered, {:ok, unlifted}, {:ok, lifted})

      if keyed?(c, batch) and Gen.total_order?(batch, c, table, order) do
        ordered = Verdict.context(c.read, tables, divergences: [])
        assert :match = Verdict.classify(ordered, {:ok, unlifted}, {:ok, lifted})
      end

      count
    end
  end

  # Each hop is an AST occurrence: repeated names require separate aliases.
  defp lift_observation(nullable_hops, lifted, relationship_count) do
    %{
      rel_permission?: relationship_count > 0,
      lifted: lifted,
      incomplete?: lifted > 0 and lifted < relationship_count,
      fallback?: relationship_count > 0 and lifted == 0,
      nullable_chain?: lifted > 0 and Enum.any?(nullable_hops)
    }
  end

  defp tied_order(%{read: %Read{table: table}, role: role}, batch) do
    visible = Gen.visible(batch, role, table)

    (visible -- Catalog.pk(table))
    |> Enum.find(&Catalog.orderable?(table, &1))
    |> column_order()
  end

  defp column_order(nil), do: nil
  defp column_order(column), do: [asc: Catalog.atom(column)]

  # Measure the statement that actually executed, after Input/Scope and
  # all-or-nothing fallback; a compiler candidate is not evidence of a lift.
  defp executed_read(%{read: read, auth: auth}, instance, join_lift) do
    {result, [{sql, _params}]} =
      TelemetryHelper.capture_statements(@repo_query, fn ->
        Runner.authzura(read, auth, instance, join_lift: join_lift)
      end)

    {result, SqlHelper.occurrences(sql, "INNER JOIN")}
  end

  # Observation only: visit every relationship (also under fallback nodes)
  # and record whether a local mapping column is nullable. Lift selection
  # remains entirely the compiler's job and is measured from executed SQL.
  defp relationship_nulls(
         {:relationship, name, child},
         %Table{relationships: relationships, columns: columns},
         tables
       ) do
    %Relationship{target: target, mapping: mapping} = Map.fetch!(relationships, name)

    nullable? =
      Enum.any?(mapping, fn {local, _remote} -> Map.fetch!(columns, local).nullable? end)

    [nullable? | relationship_nulls(child, tables[target], tables)]
  end

  defp relationship_nulls({:exists, ref, child}, _table, tables),
    do: relationship_nulls(child, tables[ref], tables)

  defp relationship_nulls({:not, child}, table, tables),
    do: relationship_nulls(child, table, tables)

  defp relationship_nulls({group, children}, table, tables) when group in [:and, :or],
    do: Enum.flat_map(children, &relationship_nulls(&1, table, tables))

  defp relationship_nulls(_leaf, _table, _tables), do: []

  # The fence compares whole root rows: every column the role sees, no
  # paging, no preloads. The input filter names only such columns, so two
  # rows with the same visible values pass or fail it together and the
  # multiset intersection is exact even without a visible key.
  defp fence(c, result, batch) do
    if where?(c) and granted?(result) do
      f = whole_root(c, batch)
      assert {:ok, filtered} = run(f)
      assert {:ok, permitted} = run(drop_where(f))
      assert {:ok, matching} = run(Gen.oracle(f))
      assert multiset(filtered) == intersection(multiset(permitted), multiset(matching))
      if length(filtered) < length(permitted), do: :stricter, else: :same
    end
  end

  # Root: the role's unpaged rows are exactly the oracle's, projected on
  # what the role sees. Nested: every child row is one the oracle admits
  # for the target, and belongs to its parent when both sides selected the
  # mapping columns.
  defp oracle(%{denial: nil} = c, {:ok, rows}, batch) do
    if :session_boundary in c.tags do
      nil
    else
      ctx = PermissionOracle.context(c, @instance)
      nested_oracle(c, rows, batch, ctx)
      root_oracle(c, batch, ctx)
    end
  end

  defp oracle(_c, _result, _batch), do: nil

  defp root_oracle(%{read: %Read{table: table} = read, role: role} = c, batch, ctx) do
    visible = Gen.visible(batch, role, table)
    permission = Gen.permission(batch, role, table)

    case PermissionOracle.rows(ctx, table, permission["filter"], read.where) do
      {:ok, expected} ->
        assert {:ok, actual} = run(whole_root(c, batch))
        assert multiset(actual) == multiset(Enum.map(expected, &Map.take(&1, visible)))
        :checked

      :unsupported ->
        :unsupported
    end
  end

  defp nested_oracle(%{read: read, role: role}, rows, batch, ctx) do
    for {parent_read, parent, parent_rows} <- level_rows(read, rows),
        {name, child} <- parent_read.relationships,
        {_kind, target, mapping} = Catalog.relationship(parent, name),
        filter = Gen.permission(batch, role, target)["filter"],
        {:ok, admitted} <- [PermissionOracle.rows(ctx, target, filter)],
        allowed = MapSet.new(admitted, &Map.take(&1, child.columns)),
        row <- parent_rows,
        kid <- row |> Map.fetch!(name) |> List.wrap() do
      assert MapSet.member?(allowed, Map.take(kid, child.columns)),
             "#{name}: #{inspect(kid)} is not a row the role may read"

      if Map.keys(mapping) -- Map.keys(row) == [] and Map.values(mapping) -- child.columns == [],
        do:
          assert(PermissionOracle.linked?(row, kid, mapping), "#{name}: child of another parent")
    end
  end

  # Every check runs unpaged, so rows compare as multisets whatever the
  # order; preload-free, so `scope/3` and `scope_input/4` can run it.
  defp entry_points(%{denial: nil, read: %Read{relationships: []}} = c, {:ok, _rows}, batch) do
    {:ok, session} = Runner.session(c.auth)
    whole = whole_root(c, batch)
    assert {:ok, rows} = run(whole)

    default_projection(c, session, batch)
    caller_run(unpaged(c), session)
    by_key(whole, session, rows, batch)
    schema_root(unpaged(c), session)
  end

  defp entry_points(_c, _result, _batch), do: nil

  # No `columns`: every visible column (the catalog has no `:other` kind).
  defp default_projection(%{read: %Read{table: table} = read, role: role}, session, batch) do
    visible = MapSet.new(Gen.visible(batch, role, table))

    for row <- default_rows(read, session) do
      assert MapSet.new(Map.keys(row)) == visible
    end
  end

  defp default_rows(%Read{where: nil} = read, session) do
    assert {:ok, rows} = Authzura.all(Runner.query(read), session, instance: @instance)
    rows
  end

  defp default_rows(%Read{table: {_schema, name}} = read, session) do
    request = read |> Runner.input() |> Map.delete("columns")
    assert {:ok, rows} = Authzura.all_input(name, session, request, instance: @instance)
    rows
  end

  # The scoped query, run by the caller's own repo, reads what the executor does.
  defp caller_run(%{read: %Read{where: nil, columns: columns} = read} = c, session) do
    assert {:ok, query} =
             Authzura.scope(Runner.query(read), session, instance: @instance, columns: columns)

    assert multiset(Repo.all(query)) == multiset(granted!(run(c)))
  end

  defp caller_run(%{read: %Read{table: {_schema, name}} = read} = c, session) do
    assert {:ok, query} =
             Authzura.scope_input(name, session, Runner.input(read), instance: @instance)

    assert multiset(Repo.all(query, query_cache: false)) == multiset(granted!(run(c)))
  end

  # `get/4` and `one/3` find each of a few rows by its key, with every
  # visible column; a key the role cannot see is refused.
  defp by_key(%{read: %Read{table: table, columns: columns}} = c, session, rows, batch) do
    pk = Catalog.pk(table)

    if keyed?(c, batch) do
      for row <- Enum.take(rows, @keyed_rows) do
        key = Map.take(row, pk)
        opts = [instance: @instance, columns: columns]
        assert Authzura.get(root(table), session, key, opts) == {:ok, row}
        assert Authzura.one(where_key(table, key), session, opts) == {:ok, row}
      end
    else
      hidden_key(table, pk, session)
    end
  end

  defp hidden_key(_table, [], _session), do: :ok

  defp hidden_key(table, pk, session) do
    key = Map.new(pk, &{&1, 1})
    assert {:error, _reason} = Authzura.get(root(table), session, key, instance: @instance)
  end

  # A schema root reads the same rows, keyed by field atoms and loaded with
  # the schema's types (dumped back here to compare).
  defp schema_root(%{read: %Read{table: table, where: nil} = read} = c, session)
       when is_map_key(@schemas, table) do
    fields = Enum.map(read.columns, &Catalog.atom/1)
    schema = Map.fetch!(@schemas, table)
    assert {:ok, rows} = Authzura.all(schema, session, instance: @instance, columns: fields)
    assert multiset(Enum.map(rows, &dumped(&1, schema))) == multiset(granted!(run(c)))
  end

  defp schema_root(_c, _session), do: :ok

  defp dumped(row, schema) do
    Map.new(row, fn {field, value} ->
      {:ok, dumped} = Type.dump(schema.__schema__(:type, field), value)
      {Atom.to_string(field), dumped}
    end)
  end

  defp root({schema, name}), do: from(t in name, prefix: ^schema)

  defp where_key(table, key) do
    Enum.reduce(key, root(table), fn {column, value}, query ->
      where(query, [t], field(t, ^Catalog.atom(column)) == ^value)
    end)
  end

  defp granted!({:ok, rows}), do: rows

  # A composite-key preload, read with the root's key columns the role
  # sees added, so a returned parent with one NULL key part can be told.
  defp partial_null?(%{tags: tags, read: %Read{table: table} = read, role: role} = c, batch) do
    if :rel_composite in tags do
      keys = Enum.filter(["org_id", "user_id"], &(&1 in Gen.visible(batch, role, table)))
      read = %{read | columns: Enum.uniq(read.columns ++ keys)}
      Vacuity.partial_null?(read, run(%{c | read: read}))
    else
      false
    end
  end

  defp oracle_failures(extras) do
    checked = Enum.count(extras, &(&1 == :checked))
    total = Enum.count(extras, &(&1 != nil))

    cond do
      total == 0 -> ["(oracle) no granted case"]
      checked / total < @oracle_checked -> ["(oracle) #{checked}/#{total} granted cases checked"]
      true -> []
    end
  end

  # Running cases.

  defp run(c), do: Runner.authzura(c.read, c.auth, @instance)

  defp granted?(result), do: match?({:ok, _rows}, result)

  defp where?(%{read: %Read{where: where}}), do: where != nil

  defp drop_where(%{read: %Read{} = read} = c), do: %{c | read: %{read | where: nil}}

  defp unpaged(%{read: %Read{} = read} = c), do: %{c | read: %{read | limit: nil, offset: nil}}

  defp whole_root(%{read: %Read{} = read, role: role} = c, batch) do
    columns = Gen.visible(batch, role, read.table)
    %{c | read: %{read | columns: columns, limit: nil, offset: nil, relationships: []}}
  end

  # The root is ordered by its primary key, so paging is well defined.
  defp keyed?(%{denial: nil, read: %Read{table: table}, role: role}, batch) do
    pk = Catalog.pk(table)
    pk != [] and pk -- Gen.visible(batch, role, table) == []
  end

  defp keyed?(_c, _batch), do: false

  defp multiset(rows), do: Enum.frequencies(rows)

  defp intersection(left, right) do
    for {row, n} <- left, m = Map.get(right, row, 0), m > 0, into: %{}, do: {row, min(n, m)}
  end

  defp permission_limit(batch, role, table),
    do: batch |> Gen.permission(role, table) |> Map.get("limit")

  defp min_limit(nil, nil), do: :infinity
  defp min_limit(request, nil), do: request
  defp min_limit(nil, permission), do: permission
  defp min_limit(request, permission), do: min(request, permission)

  # {read, table, rows} for every level, rows flattened across parents.
  defp level_rows(%Read{table: table} = read, rows), do: level_rows(read, table, rows)

  defp level_rows(%Read{relationships: relationships} = read, table, rows) do
    nested =
      Enum.flat_map(relationships, fn {name, child} ->
        {_kind, target, _mapping} = Catalog.relationship(table, name)
        children = Enum.flat_map(rows, &(&1 |> Map.fetch!(name) |> List.wrap()))
        level_rows(child, target, children)
      end)

    [{read, table, rows} | nested]
  end

  defp expected_keys(%Read{columns: columns, relationships: relationships}),
    do: MapSet.new(columns ++ Enum.map(relationships, &elem(&1, 0)))

  defp batches, do: Gen.env_integer("AUTHZURA_PROP_BATCHES", 4)

  defp runs, do: Gen.env_integer("AUTHZURA_PROP_RUNS", 400)

  # The sweep is part of each batch's share of the runs.
  defp random_runs, do: max(div(runs(), batches()) - length(Gen.sweep()), 1)
end

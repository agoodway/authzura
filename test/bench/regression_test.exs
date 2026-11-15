defmodule Authzura.Bench.RegressionTest do
  # The bench/TRIAGE.md regressions that need only the seeded :small
  # benchmark database, not its Hasura:
  # mix test --only bench test/bench/regression_test.exs
  # (those that need the Hasura are in hasura_regression_test.exs)
  use ExUnit.Case, async: false

  alias Authzura.Bench
  alias Authzura.Bench.{Measure, Repo, Scenarios}

  @moduletag :bench

  setup_all do
    children = Enum.uniq(Enum.flat_map(Bench.modes(), &Bench.children/1))
    Enum.each(children, &start_supervised!/1)
    Enum.each(Bench.modes(), &(:ok = Authzura.reload(Bench.instance(&1))))
    :ok
  end

  describe "indexes" do
    test "no index on a bench table is a leading prefix of another" do
      %{rows: redundant} =
        Repo.query!("""
        SELECT a.indexrelid::regclass::text, b.indexrelid::regclass::text
        FROM pg_index AS a
        JOIN pg_index AS b ON b.indrelid = a.indrelid AND b.indexrelid <> a.indexrelid
        JOIN pg_class AS c ON c.oid = a.indrelid
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND NOT a.indisunique AND a.indnatts < b.indnatts
          AND (b.indkey::int2[])[0:a.indnatts - 1] = (a.indkey::int2[])[0:a.indnatts - 1]
        """)

      assert redundant == []
    end

    # At :small the planner hashes `users` (10 000 rows) and `organizations`
    # (100 rows) instead of probing their primary keys, by cost (TRIAGE:
    # documented gap). These pin that each preload statement keeps a form an
    # index can serve: with sequential scans priced out, every one is read
    # through its primary key.
    test "preload-object can read users through users_pkey" do
      assert {"users", :index, "users_pkey"} in indexable_scans("preload-object")
    end

    test "preload-nested-3 can read users and organizations through their primary keys" do
      scans = indexable_scans("preload-nested-3")

      assert {"users", :index, "users_pkey"} in scans
      assert {"organizations", :index, "organizations_pkey"} in scans
    end
  end

  describe "plans" do
    # The selective relationship read must avoid a comments_pkey walk for
    # every organization, with bound values and with a generic cached plan.
    test "deep plans no primary-key walk for orgs 1..40 (custom and generic)" do
      scenario = Scenarios.fetch!("input-rel-permission")

      for org <- 1..40, regime <- [:custom, :generic] do
        plan =
          scenario
          |> Scenarios.with_org(org)
          |> Measure.authzura_sql()
          |> Measure.raw_plan(regime)

        refute Measure.pk_walk?(plan, "comments"), "org #{org} (#{regime}) walks comments_pkey"
      end
    end

    # The unlifted control walks the key in both regimes; the helper must see it.
    test "input-rel-broad-limit walks comments_pkey (custom and generic)" do
      scenario = Scenarios.fetch!("input-rel-broad-limit")

      for regime <- [:custom, :generic] do
        plan = scenario |> Measure.authzura_sql(join_lift: false) |> Measure.raw_plan(regime)

        assert Measure.pk_walk?(plan, "comments"), "#{regime} plan does not walk comments_pkey"
      end
    end
  end

  describe "data statements" do
    for mode <- Bench.modes() do
      test "Authzura runs exactly 1 + L data statements per request (#{mode})" do
        for %{id: id, preload_levels: levels} = scenario <- Scenarios.all() do
          %{counts: counts} = Measure.statements(:authzura, scenario, 20, mode: unquote(mode))
          assert counts.data == 1 + levels, "#{id}: #{inspect(counts)}"
        end
      end
    end

    test "read_only_connection mode runs no transaction control when L = 0" do
      for %{id: id, preload_levels: 0} = scenario <- Scenarios.all() do
        %{counts: counts} =
          Measure.statements(:authzura, scenario, 20, mode: :read_only_connection)

        assert counts.transaction_control == 0, "#{id}: #{inspect(counts)}"
      end
    end
  end

  # Authzura's scans for scenario `id` with sequential scans priced out on
  # the one connection both the read and its EXPLAIN run on.
  defp indexable_scans(id) do
    scenario = Scenarios.fetch!(id)

    Repo.checkout(fn ->
      Repo.query!("SET enable_seqscan = off")

      try do
        for %{table_scans: scans} <- Measure.plans(:authzura, scenario), scan <- scans, do: scan
      after
        Repo.query!("RESET enable_seqscan")
      end
    end)
  end
end

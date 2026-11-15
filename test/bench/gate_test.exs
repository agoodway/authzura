defmodule Authzura.Bench.GateTest do
  # Needs the seeded :small benchmark database and its Hasura (see
  # bench/README.md): mix test --only bench test/bench
  use ExUnit.Case, async: false

  alias Authzura.Bench
  alias Authzura.Bench.{Gate, Repo, Scenarios}
  alias Authzura.Parity.Runner

  @moduletag :bench

  setup_all do
    Enum.each(Bench.children(), &start_supervised!/1)
    :ok = Authzura.reload(Bench.instance())
    :ok
  end

  test "every scenario passes the gate at :small" do
    assert {passed, []} = Gate.check(Scenarios.all())
    assert Enum.map(passed, & &1.id) == Scenarios.ids()
  end

  test "the permission guard ignores request pagination and filters" do
    assert {[], [{"page-1000", :permission_filters_nothing}]} =
             Gate.check([with_role(Scenarios.fetch!("page-1000"), "open")])
  end

  test "a planted difference aborts that scenario by id" do
    flat = Scenarios.fetch!("flat-tenant")
    other = Scenarios.fetch!("columns-narrow")

    drop_last = fn scenario ->
      %{authzura: {:ok, rows}} = result = Gate.run(scenario, Bench.instance())
      %{result | authzura: {:ok, Enum.drop(rows, -1)}}
    end

    run = fn
      %{id: "flat-tenant"} = scenario -> drop_last.(scenario)
      scenario -> Gate.run(scenario, Bench.instance())
    end

    assert {[^other], [{"flat-tenant", {:verdict, {:mismatch, _message}}}]} =
             Gate.check([flat, other], run: run)
  end

  test "a Hasura 200 with errors aborts that scenario by id" do
    %{read: read} = flat = Scenarios.fetch!("flat-tenant")
    hidden = %{flat | read: %{read | columns: ["internal_notes" | read.columns]}}

    assert {[], [{"flat-tenant", {:hasura_error, "validation-failed"}}]} = Gate.check([hidden])
  end

  test "an instance with an admin_role is refused" do
    name = Authzura.Bench.AdminInstance

    start_supervised!(
      {Authzura,
       name: name,
       repo: Repo,
       source: {Authzura.Sources.Hasura, []},
       admin_role: "root",
       poll_interval: nil,
       max_staleness: :infinity}
    )

    :ok = Authzura.reload(name)

    assert {[], [{"flat-tenant", :admin_role_configured}]} =
             Gate.check([Scenarios.fetch!("flat-tenant")], instance: name)
  end

  # The tests below need no Hasura: `mirror/1` stands Authzura's own rows in
  # for Hasura's, then `plant` changes one side.
  describe "planted differences without a Hasura" do
    test "an empty preload level aborts the scenario, at any depth" do
      no_author = mirror(fn rows -> Enum.map(rows, &Map.put(&1, "author", nil)) end)

      assert {[], [{"preload-object", {:empty_level, ["author"]}}]} =
               Gate.check([Scenarios.fetch!("preload-object")], run: no_author)

      no_org =
        mirror(fn rows ->
          update_in(rows, [Access.all(), "comments", Access.all()], &no_org/1)
        end)

      assert {[], [{"preload-nested-3", {:empty_level, ["comments", "author", "org"]}}]} =
               Gate.check([Scenarios.fetch!("preload-nested-3")], run: no_org)
    end

    test "a missing nested row aborts the scenario" do
      drop_comment =
        mirror(& &1, fn [%{"comments" => [_ | rest]} = row | rows] ->
          [%{row | "comments" => rest} | rows]
        end)

      assert {[], [{"preload-array-limited", {:verdict, {:mismatch, _message}}}]} =
               Gate.check([Scenarios.fetch!("preload-array-limited")], run: drop_comment)
    end

    test "a column difference aborts the scenario" do
      extra = mirror(& &1, fn [row | rows] -> [Map.put(row, "body", "x") | rows] end)
      changed = mirror(& &1, fn [row | rows] -> [%{row | "title" => "x"} | rows] end)

      assert {[], [{"flat-tenant", {:verdict, {:leak, _message}}}]} =
               Gate.check([Scenarios.fetch!("flat-tenant")], run: extra)

      assert {[], [{"flat-tenant", {:verdict, {:mismatch, _message}}}]} =
               Gate.check([Scenarios.fetch!("flat-tenant")], run: changed)
    end

    test "every level of every scenario is non-empty" do
      assert {passed, []} = Gate.check(Scenarios.all(), run: mirror(& &1))
      assert Enum.map(passed, & &1.id) == Scenarios.ids()
    end
  end

  # A `:run` for `Gate.check/2` that uses Authzura's rows on both sides,
  # passed through `both` and then `authzura` for Authzura's side.
  defp mirror(both, authzura \\ & &1) do
    fn %{read: read, auth: auth} ->
      {:ok, rows} = Runner.authzura(read, auth, Bench.instance())
      %{hasura: {:ok, both.(rows)}, authzura: {:ok, rows |> both.() |> authzura.()}}
    end
  end

  defp no_org(%{"author" => author} = comment),
    do: %{comment | "author" => %{author | "org" => nil}}

  defp with_role(scenario, role), do: %{scenario | auth: Scenarios.auth(role)}
end

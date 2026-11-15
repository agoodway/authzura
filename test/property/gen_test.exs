defmodule Authzura.GenTest do
  @moduledoc """
  Pure tests of the case generators: determinism, coverage of the accepted
  operators and the must-appear list, no `json` filters, no atoms from
  generated names, boundary forms only where they apply, the degenerate
  switches, and the preload and ordering bounds.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Authzura.Gen
  alias Authzura.Gen.{Catalog, Filter}
  alias Authzura.Parity.Read

  @gen_roles Enum.map(0..15, &"gen_#{&1}")

  # Keys of a case and of `Authzura.Parity.Read`, the auth tag, booleans.
  @fixed_atoms [:id, :role, :read, :auth, :allowed_roles, :denial, :twin, :tags, :input_tags] ++
                 [:jwt, nil, true, false | Map.keys(%Read{columns: []})]

  defp take(generator, seed, n), do: Gen.take(generator, seed, n)

  test "same seed, same first 50 cases" do
    assert take(Gen.request(Gen.batch(1)), 42, 50) == take(Gen.request(Gen.batch(1)), 42, 50)
    assert Gen.batch(2) == Gen.batch(2)
    refute Gen.batch(1) == Gen.batch(2)
  end

  test "a batch has sixteen roles, plus a no-limit twin for each limited one" do
    batch = Gen.batch(1)
    assert @gen_roles -- Map.keys(batch) == []

    for {role, permissions} <- batch, role not in @gen_roles do
      assert [base] = Regex.run(~r/^gen_\d+(?=_twin$)/, role)
      assert permissions == Gen.unlimited(batch[base])
      assert Enum.any?(batch[base], fn {_table, permission} -> permission["limit"] end)
    end

    no_limits = Gen.batch(1, limits: false)
    assert Enum.sort(Map.keys(no_limits)) == Enum.sort(@gen_roles)

    for {_role, permissions} <- no_limits,
        {_table, permission} <- permissions,
        do: refute(Map.has_key?(permission, "limit"))
  end

  test "every operator, input operator and static must-appear item appears within 2 000 samples" do
    cases = take(Gen.request(Gen.batch(1)), 9, 2_000)

    assert missing(cases, & &1.tags, Gen.static_must_appear()) == []
    assert Gen.missing_coverage(Gen.batch(1)) == []

    # Input filters can only name columns the role sees, so whether a
    # batch reaches, say, `assignees` depends on its roles: count the
    # input operators over the four batches of a run.
    inputs = Enum.flat_map(1..4, &take(Gen.request(Gen.batch(&1)), 9, 1_000))
    assert missing(inputs, & &1.input_tags, Gen.input_operators()) == []

    boundary = take(Gen.request(Gen.batch(1), mutation: :session_boundary), 9, 3_000)
    assert missing(boundary, &session_values/1, Gen.boundary_forms()) == []
  end

  test "boundary forms go to a referenced variable of their kind" do
    batch = Gen.batch(1)

    for c <- take(Gen.request(batch, mutation: :session_boundary), 4, 300) do
      root = Gen.permission(batch, c.role, c.read.table)
      referenced = Filter.session_refs(root["filter"])
      sent = for {name, value} <- Gen.variables(c), value in Gen.boundary_forms(), do: name

      assert sent != [] and sent -- referenced == []

      assert Enum.all?(
               sent,
               &(Catalog.variable_kind(&1) in [:int, :bool, :int_array, :text_array])
             )
    end
  end

  test "a role_not_allowed case requests a role outside its allowed roles" do
    for %{denial: :role_not_allowed, auth: {:jwt, _claims, requested}} = c <-
          take(Gen.request(Gen.batch(1)), 5, 500) do
      refute requested in c.allowed_roles
    end
  end

  test "a mutation sweep always builds its denial class" do
    batch = Gen.batch(1)

    for {mutation, denial} <- Enum.zip(Gen.sweep(), Gen.denials()),
        c <- take(Gen.request(batch, mutation: mutation), 3, 20),
        do: assert(c.denial == denial, "#{mutation}: #{inspect(c.denial)}")
  end

  test "each degenerate switch removes its source of variety" do
    for {_role, permissions} <- Gen.batch(1, degenerate: :no_filters),
        {_table, permission} <- permissions,
        do: assert(permission["filter"] == %{})

    for {_role, permissions} <- Gen.batch(1, degenerate: :all_columns),
        {_table, permission} <- permissions,
        do: assert(permission["columns"] == "*")

    batch = Gen.batch(1)

    for c <- take(Gen.request(batch, degenerate: :no_preloads), 3, 200),
        do: assert(c.read.relationships == [] or c.denial == :forbidden)

    for c <- take(Gen.request(batch, degenerate: :no_input_filter), 3, 200),
        c.read.where != nil,
        do: assert(c.denial != nil or c.read.where == %{})
  end

  test "no filter references a json column; names never become atoms" do
    batch = Gen.batch(3)
    cases = take(Gen.request(batch), 7, 300)

    for {_role, permissions} <- batch, {_table, %{"filter" => filter}} <- permissions do
      refute "meta" in keys(filter)
      assert Enum.all?(keys(filter), &is_binary/1)
      assert %{depth: depth, nodes: nodes} = Gen.stats(filter)
      assert depth <= 6 and nodes <= 40
    end

    for %{read: read} <- cases, {_path, _kind, _table, _parent, level} <- Gen.levels(read) do
      refute "meta" in keys(level.where)
      assert Enum.all?(level.columns, &is_binary/1)
      assert Enum.all?(level.relationships, fn {name, _read} -> is_binary(name) end)
      assert Enum.all?(level.order_by || [], fn {_dir, column} -> column in Catalog.atoms() end)
    end

    # Every atom in a batch or a case is a fixed one: no generated name or
    # value becomes an atom.
    allowed = MapSet.new(@fixed_atoms ++ Gen.fixed_atoms())
    assert MapSet.difference(atoms([batch | cases]), allowed) == MapSet.new()
  end

  property "where-cases preload at most 2 deep, all/3 cases at most 3; every level is totally ordered" do
    batch = Gen.batch(1)

    check all %{read: read} = c <- Gen.request(batch), max_runs: 300 do
      levels = Gen.levels(read)
      {max_depth, max_nodes} = if read.where, do: {2, 8}, else: {3, 16}

      assert levels |> Enum.map(fn {path, _, _, _, _} -> length(path) end) |> Enum.max() <=
               max_depth

      assert length(levels) - 1 <= max_nodes
      assert read.where == nil or Catalog.where_root?(read.table)

      for {_path, kind, table, _parent, %Read{order_by: order}} <- levels,
          kind in [:root, :array] do
        assert Gen.total_order?(batch, c, table, order), "#{inspect(table)}: #{inspect(order)}"
      end
    end
  end

  defp missing(cases, values, expected),
    do: expected -- (cases |> Enum.flat_map(values) |> Enum.uniq())

  defp session_values(c), do: c |> Gen.variables() |> Map.values()

  defp atoms(term) when is_atom(term), do: MapSet.new([term])
  defp atoms(term) when is_struct(term), do: term |> Map.from_struct() |> atoms()
  defp atoms(term) when is_map(term), do: term |> Map.to_list() |> atoms()
  defp atoms(term) when is_tuple(term), do: term |> Tuple.to_list() |> atoms()

  defp atoms(term) when is_list(term),
    do: Enum.reduce(term, MapSet.new(), &MapSet.union(atoms(&1), &2))

  defp atoms(_term), do: MapSet.new()

  defp keys(nil), do: []
  defp keys(map) when is_map(map), do: Enum.flat_map(map, fn {k, v} -> [k | keys(v)] end)
  defp keys(list) when is_list(list), do: Enum.flat_map(list, &keys/1)
  defp keys(_leaf), do: []
end

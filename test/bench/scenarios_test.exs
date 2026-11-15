defmodule Authzura.Bench.ScenariosTest do
  use ExUnit.Case, async: true

  alias Authzura.Bench.Scenarios
  alias Authzura.Parity.Read

  @ids ~w(
    flat-tenant author-or-published exists-member rel-filter-3hop session-array-in
    columns-narrow input-filter input-regex limit-permission page-1000
    preload-object preload-array-limited preload-nested-3
    input-selective input-pk input-rel-permission preload-large-batch
  )

  @array_relationships ["comments"]

  test "scenario ids are the fixed list, unique strings, pk-ordered at every level" do
    scenarios = Scenarios.all()

    assert Enum.map(scenarios, & &1.id) == @ids
    assert Scenarios.ids() == @ids
    assert Enum.all?(scenarios, &is_binary(&1.id))
    assert scenarios |> Enum.map(& &1.id) |> Enum.uniq() |> length() == length(@ids)

    for %{id: id, read: read} <- scenarios do
      assert ordered_by_pk?(read, :root), "#{id}: a root or array level is not pk-ordered"
    end
  end

  test "auth is always a JWT for the role, and preload_levels counts the preload nodes" do
    for %{auth: {:jwt, claims, role}} <- Scenarios.all() do
      session = Map.fetch!(claims, "https://hasura.io/jwt/claims")

      assert session["x-hasura-default-role"] == role
      assert session["x-hasura-allowed-roles"] == [role]
    end

    levels = Map.new(Scenarios.all(), &{&1.id, &1.preload_levels})

    assert levels["flat-tenant"] == 0
    assert levels["preload-object"] == 1
    assert levels["preload-array-limited"] == 1
    assert levels["preload-nested-3"] == 3
    assert levels["preload-large-batch"] == 1
  end

  # Regression pins for the input path's index use and for a large preload
  # batch, which the original scenarios did not reach.
  test "input scenarios filter on selective, indexed columns and under a relationship permission" do
    by_id = Map.new(Scenarios.all(), &{&1.id, &1})

    assert %{"author_id" => %{"_eq" => _}} = by_id["input-selective"].read.where
    assert %{"id" => %{"_in" => [_ | _]}} = by_id["input-pk"].read.where

    assert %{read: %Read{table: {"public", "comments"}}, auth: {:jwt, _, "deep"}} =
             by_id["input-rel-permission"]

    assert by_id["preload-large-batch"].read.limit >= 1_000
  end

  test "an input scenario's root is a public table, as all_input/4 requires" do
    for %{read: %Read{where: where, table: table}} <- Scenarios.all(), where != nil do
      assert {"public", _name} = table
    end
  end

  defp ordered_by_pk?(
         %Read{order_by: order, relationships: relationships, columns: columns},
         :root
       ) do
    order == [asc: :id] and "id" in columns and Enum.all?(relationships, &nested_ok?/1)
  end

  defp nested_ok?({name, %Read{order_by: order, relationships: relationships, columns: columns}})
       when name in @array_relationships,
       do: order == [asc: :id] and "id" in columns and Enum.all?(relationships, &nested_ok?/1)

  defp nested_ok?(
         {_object, %Read{order_by: nil, relationships: relationships, columns: columns}}
       ),
       do: "id" in columns and Enum.all?(relationships, &nested_ok?/1)
end

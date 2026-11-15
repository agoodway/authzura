defmodule Authzura.Model.DefaultsTest do
  use ExUnit.Case, async: true

  alias Authzura.Model.{Column, Relationship}

  test "Column defaults nullable? to true" do
    column =
      struct!(Column, name: "id", pg_type: "bigint", base_kind: :bigint, ecto_type: :integer)

    assert column.nullable?
    assert column.enum_labels == nil
  end

  test "Column requires ecto_type" do
    assert_raise ArgumentError, ~r/ecto_type/, fn ->
      struct!(Column, name: "id", pg_type: "bigint", base_kind: :bigint)
    end
  end

  test "Relationship defaults preloadable? to false (the Validator grants it)" do
    rel = struct!(Relationship, name: "r", kind: :object, target: {"public", "t"}, mapping: [])
    refute rel.preloadable?
  end
end

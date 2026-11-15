defmodule Authzura.SchemaFieldsTest do
  use ExUnit.Case, async: true

  alias Authzura.{SchemaFields, Scope}
  alias Authzura.Test.Schemas.Article

  test "maps fields and columns in both directions, cached per schema definition" do
    %{by_column: by_column, by_field: by_field, rank: rank} = fields = SchemaFields.get(Article)

    for field <- Article.__schema__(:fields) do
      column = Atom.to_string(Article.__schema__(:field_source, field))
      assert by_field[field] == column
      assert by_column[column] == field
    end

    assert rank |> Enum.sort_by(&elem(&1, 1)) |> Enum.map(&elem(&1, 0)) ==
             Article.__schema__(:fields)

    assert :persistent_term.get({SchemaFields, Article, Article.__schema__(:hash)}) == fields
    assert SchemaFields.get(Article) == fields
  end

  test "Scope lookups use the maps and keep field order" do
    [first, second | _rest] = Article.__schema__(:fields)
    [c1, c2] = Enum.map([first, second], &Scope.column_for(Article, &1))

    assert Scope.field_columns(Article, [c2, c1, "nope", c1]) == [{first, c1}, {second, c2}]
    assert Scope.field_for(Article, c2) == second
    assert Scope.field_for(Article, "nope") == nil
    assert Scope.column_for(Article, :nope) == nil
  end
end

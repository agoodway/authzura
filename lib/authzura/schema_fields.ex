defmodule Authzura.SchemaFields do
  @moduledoc """
  An Ecto schema's field-to-column maps, built once per schema definition.

  The maps are cached in `:persistent_term` under the schema module and its
  `__schema__(:hash)`, so a recompiled schema gets fresh maps. Only a new
  key is ever written (an equal term put again is a no-op), which never
  triggers `:persistent_term`'s global collection.
  """

  @typedoc """
  `fields` lists `{field, column}` in field order, `by_column` maps each
  column to its first field in field order, `by_field` each field to its
  column, and `rank` each field to its position.
  """
  @type t :: %{
          fields: [{atom(), String.t()}],
          by_column: %{String.t() => atom()},
          by_field: %{atom() => String.t()},
          rank: %{atom() => non_neg_integer()}
        }

  @doc "Returns the maps of `schema`, building and caching them on first use."
  @spec get(module()) :: t()
  def get(schema) when is_atom(schema) do
    key = {__MODULE__, schema, schema.__schema__(:hash)}

    case :persistent_term.get(key, nil) do
      nil -> cache(key, build(schema))
      fields -> fields
    end
  end

  @doc "Maps each column of `schema` to its first field, in field order."
  @spec by_column(module()) :: %{String.t() => atom()}
  def by_column(schema), do: schema |> get() |> Map.fetch!(:by_column)

  @doc "Maps each field of `schema` to its column."
  @spec by_field(module()) :: %{atom() => String.t()}
  def by_field(schema), do: schema |> get() |> Map.fetch!(:by_field)

  defp cache(key, fields) do
    :persistent_term.put(key, fields)
    fields
  end

  defp build(schema) do
    pairs =
      schema.__schema__(:fields)
      |> Enum.with_index()
      |> Enum.map(fn {field, i} -> {field, field |> source(schema) |> Atom.to_string(), i} end)

    %{
      fields: Enum.map(pairs, fn {field, column, _i} -> {field, column} end),
      by_column:
        pairs |> Enum.reverse() |> Map.new(fn {field, column, _i} -> {column, field} end),
      by_field: Map.new(pairs, fn {field, column, _i} -> {field, column} end),
      rank: Map.new(pairs, fn {field, _column, i} -> {field, i} end)
    }
  end

  defp source(field, schema), do: schema.__schema__(:field_source, field)
end

defmodule Authzura.Model.Table do
  @moduledoc """
  A tracked table or view with its columns, primary key and relationships.

  `indexes` lists the key columns of each valid btree index on plain
  columns that is not partial, in index order, each with the order it
  stores (`:asc` is ASC NULLS LAST, `:desc` DESC NULLS FIRST, plus
  `:asc_nulls_first` and `:desc_nulls_last`). `INCLUDE` columns are left
  out, and so are indexes on a non-default operator class or collation. The
  preload loader uses it to decide whether a limited level can read each
  parent through an index range.
  """

  alias Authzura.Model.{Column, Relationship}

  # Sorting is refused on these kinds: `json` has no ordering, and the
  # others (`point`, say, or an unknown extension type) may have none. An
  # array sorts only when its element does (`point[]` has no ordering).
  @unorderable [:json, :decodable, :other]

  @enforce_keys [:schema, :name]
  defstruct [
    :schema,
    :name,
    kind: :table,
    columns: %{},
    primary_key: [],
    indexes: [],
    relationships: %{}
  ]

  @type table_ref :: {schema :: String.t(), name :: String.t()}

  @type t :: %__MODULE__{
          schema: String.t(),
          name: String.t(),
          kind: :table | :view,
          columns: %{String.t() => Column.t()},
          primary_key: [String.t()],
          indexes: [[{String.t(), :asc | :asc_nulls_first | :desc | :desc_nulls_last}]],
          relationships: %{String.t() => Relationship.t()}
        }

  @doc "Returns the `{schema, name}` reference of a table."
  @spec ref(t()) :: table_ref()
  def ref(%__MODULE__{schema: schema, name: name}), do: {schema, name}

  @doc """
  Looks the table `ref` up in `tables`, or returns `{:error, {:unknown_table, ref}}`
  when it is missing or not a table.
  """
  @spec fetch(%{table_ref() => t()}, table_ref()) ::
          {:ok, t()} | {:error, {:unknown_table, table_ref()}}
  def fetch(tables, ref) do
    case tables do
      %{^ref => %__MODULE__{} = table} -> {:ok, table}
      _missing -> {:error, {:unknown_table, ref}}
    end
  end

  @doc """
  The columns of `allowed` that a read selects when none are named: every
  one except those of base kind `:other`: an extension type the repo's
  Postgrex types cannot decode (introspection asks the repo's types module, so a PostGIS
  `geography` is a default column when the repo has the PostGIS types, and
  `:other` when it does not), a composite, or an array of either. Those
  stay selectable by name. Order is kept.

  A decodable extension column is therefore selected by default, and a schema
  query casts it through the schema's field type: a field whose type does not
  match the decoded value (`:map` against a `%Geo.Point{}`, say) raises an Ecto
  load error.
  """
  @spec default_columns(t(), [String.t()]) :: [String.t()]
  def default_columns(%__MODULE__{columns: columns}, allowed) when is_list(allowed),
    do: Enum.reject(allowed, &other_kind?(columns, &1))

  @doc "Whether `column` belongs in a default column set (see `default_columns/2`)."
  @spec default_column?(t(), String.t()) :: boolean()
  def default_column?(%__MODULE__{columns: columns}, column), do: not other_kind?(columns, column)

  @doc """
  The columns of `names` that have base kind `:other`, as
  `{name, pg_type}` pairs, in order.
  """
  @spec other_kind_columns(t(), [String.t()]) :: [{String.t(), String.t()}]
  def other_kind_columns(%__MODULE__{columns: columns}, names) when is_list(names),
    do:
      for(
        name <- names,
        %{^name => %Column{base_kind: :other, pg_type: pg_type}} <- [columns],
        do: {name, pg_type}
      )

  defp other_kind?(columns, name), do: match?(%{^name => %Column{base_kind: :other}}, columns)

  @doc """
  Checks that Postgres can sort `table` by every one of `columns`. A column
  of a kind it cannot order (`json`, or an unknown type), or one the table
  does not have, is `{:error, {:invalid_input, {:order_by, :unorderable}}}`.
  """
  @spec orderable(t(), [String.t()]) ::
          :ok | {:error, {:invalid_input, {:order_by, :unorderable}}}
  def orderable(%__MODULE__{columns: columns}, names) when is_list(names) do
    names
    |> Enum.all?(&sortable?(columns, &1))
    |> orderable_result()
  end

  defp sortable?(columns, name) do
    case columns do
      %{^name => %Column{base_kind: :array, element_kind: kind}} -> orderable_kind?(kind)
      %{^name => %Column{base_kind: kind}} -> orderable_kind?(kind)
      %{} -> false
    end
  end

  # An array whose element kind is unknown is refused.
  defp orderable_kind?(kind), do: kind != nil and kind not in @unorderable

  defp orderable_result(true), do: :ok
  defp orderable_result(false), do: {:error, {:invalid_input, {:order_by, :unorderable}}}
end

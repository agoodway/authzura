defmodule Authzura.Model.Permission do
  @moduledoc """
  A permission for one role, table and operation, independent of its source.

  `columns` has wildcards already expanded. `column_set` holds the same
  columns as a `MapSet` for membership checks (`allows?/2`); it is set when a
  generation is published (and for the admin permission), and `nil` on a
  permission straight from a source. `status` is `:ok` or
  `{:denied, diagnostics}`; a denied permission grants nothing.
  """

  alias Authzura.AST
  alias Authzura.Model.{Diagnostic, Table}

  @enforce_keys [:role, :table, :operation]
  defstruct [
    :role,
    :table,
    :operation,
    filter: nil,
    columns: [],
    column_set: nil,
    limit: nil,
    allow_aggregations: false,
    root_fields: :all,
    check: nil,
    presets: %{},
    backend_only: false,
    status: :ok
  ]

  @type root_field :: :select | :select_by_pk | :select_aggregate

  @type operation :: :select | :insert | :update | :delete

  @type t :: %__MODULE__{
          role: String.t(),
          table: Table.table_ref(),
          operation: operation(),
          filter: AST.t() | nil,
          columns: [String.t()],
          column_set: MapSet.t(String.t()) | nil,
          limit: non_neg_integer() | nil,
          allow_aggregations: boolean(),
          root_fields: :all | [root_field()],
          check: AST.t() | nil,
          presets: map(),
          backend_only: boolean(),
          status: :ok | {:denied, [Diagnostic.t()]}
        }

  @doc """
  The full select permission the configured admin role gets on `table`:
  every introspected column, no filter and no limit.
  """
  @spec admin(String.t(), Table.t()) :: t()
  def admin(role, %Table{columns: columns} = table) when is_binary(role) do
    %__MODULE__{
      role: role,
      table: Table.ref(table),
      operation: :select,
      filter: {:and, []},
      columns: columns |> Map.keys() |> Enum.sort(),
      column_set: columns |> Map.keys() |> MapSet.new()
    }
  end

  @doc "Returns `permission` with its `column_set` built from its columns."
  @spec indexed(t()) :: t()
  def indexed(%__MODULE__{columns: columns} = permission),
    do: %{permission | column_set: MapSet.new(columns)}

  @doc "Whether `permission` allows `column`."
  @spec allows?(t(), String.t()) :: boolean()
  def allows?(%__MODULE__{column_set: %MapSet{} = set}, column), do: MapSet.member?(set, column)
  def allows?(%__MODULE__{columns: columns}, column), do: column in columns
end

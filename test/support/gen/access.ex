defmodule Authzura.Gen.Access do
  @moduledoc """
  What a generated role may do on a table: the columns its permission
  grants, whether the list root is enabled, and the session variables its
  filter references. `env` is `Authzura.Gen`'s per-role map with the
  role's `permissions`.
  """

  alias Authzura.Gen.{Catalog, Filter}

  @doc "Whether a permission exposes the list root field."
  @spec root_enabled?(map()) :: boolean()
  def root_enabled?(%{"query_root_fields" => fields}), do: "select" in fields
  def root_enabled?(_permission), do: true

  @doc "The columns of `table` the role may not select."
  @spec hidden(map(), Catalog.table()) :: [String.t()]
  def hidden(%{permissions: permissions}, table),
    do: Catalog.names(table) -- level_columns(permissions[table], table)

  @doc """
  Relationships of `table`, not yet in `preloaded`, to a table the role
  has no permission on.
  """
  @spec unpermitted(map(), Catalog.table(), [{String.t(), term()}]) :: [String.t()]
  def unpermitted(%{permissions: permissions}, table, preloaded) do
    for {name, {_kind, target, _mapping}} <- Catalog.relationships(table),
        not Map.has_key?(permissions, target),
        not List.keymember?(preloaded, name, 0),
        do: name
  end

  @doc "The session variables (lowercase) the role's permission on `table` references."
  @spec referenced(map(), Catalog.table()) :: [String.t()]
  def referenced(%{permissions: permissions}, table), do: permissions |> Map.get(table) |> refs()

  defp refs(%{"filter" => filter}), do: Filter.session_refs(filter)
  defp refs(nil), do: []

  @doc "The columns a permission grants (none without one)."
  @spec visible_columns(map() | nil, Catalog.table()) :: [String.t()]
  def visible_columns(nil, _table), do: []
  def visible_columns(%{"columns" => "*"}, table), do: Catalog.names(table)
  def visible_columns(%{"columns" => columns}, _table), do: columns

  @doc """
  The columns a level may use: the permission's, or every column of a
  table the role has no permission on (that level is denied anyway).
  """
  @spec level_columns(map() | nil, Catalog.table()) :: [String.t()]
  def level_columns(nil, table), do: Catalog.names(table)
  def level_columns(permission, table), do: visible_columns(permission, table)
end

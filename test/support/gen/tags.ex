defmodule Authzura.Gen.Tags do
  @moduledoc """
  The coverage tags of a generated case: its mutation or denial class,
  each level's relationship shape and access (hidden keys, a target whose
  root is disabled), the root's paging and view forms, and the operator
  tags of every permission filter the read touches.
  """

  import Authzura.Gen.Access, only: [level_columns: 2, root_enabled?: 1]

  alias Authzura.Gen
  alias Authzura.Gen.{Catalog, Filter}
  alias Authzura.Parity.Read

  @doc "The coverage tags of the finished case `c`, built from `draft` for the role's `env`."
  @spec tags(map(), map(), map()) :: [atom()]
  def tags(%{read: read} = c, %{mutation: mutation}, env) do
    levels = Gen.levels(read)

    level_tags =
      Enum.flat_map(levels, fn {_path, _kind, table, _parent, _read} = level ->
        level_tags(level, env) ++ permission_tags(env.permissions[table], table)
      end)

    (mutation_tags(mutation, c.denial) ++ level_tags ++ read_tags(read))
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp permission_tags(%{"filter" => filter}, table), do: Filter.tags(filter, table)
  defp permission_tags(nil, _table), do: []

  defp mutation_tags(:none, nil), do: []
  defp mutation_tags(:none, denial), do: [denial]
  defp mutation_tags(mutation, _denial), do: [mutation]

  defp read_tags(%Read{table: table, limit: limit, offset: offset}) do
    [
      if(table == Catalog.view(), do: :view_root),
      if(offset != nil, do: :offset),
      if(limit == 0, do: :limit_zero)
    ]
  end

  defp level_tags({_path, :root, table, nil, _read}, env), do: hidden_pk_tags(env, table)

  defp level_tags({path, kind, target, parent, _read}, env) do
    {_kind, _target, mapping} = Catalog.relationship(parent, List.last(path))

    shape_tags(kind, mapping, parent, target) ++
      access_tags(env, mapping, parent, target) ++ hidden_pk_tags(env, target)
  end

  defp shape_tags(kind, mapping, parent, target) do
    [
      if(kind == :object, do: :rel_object, else: :rel_array),
      if(map_size(mapping) > 1, do: :rel_composite),
      if(target == parent, do: :rel_self)
    ]
  end

  defp access_tags(env, mapping, parent, target) do
    hidden_key? =
      hidden_key?(env, parent, Map.keys(mapping)) or hidden_key?(env, target, Map.values(mapping))

    [root_disabled_tag(env.permissions[target]), if(hidden_key?, do: :hidden_fk_role)]
  end

  defp root_disabled_tag(nil), do: nil

  defp root_disabled_tag(permission),
    do: if(root_enabled?(permission), do: nil, else: :preload_target_root_disabled)

  defp hidden_key?(%{permissions: permissions}, table, columns),
    do: permissions[table] != nil and columns -- level_columns(permissions[table], table) != []

  defp hidden_pk_tags(env, table) do
    pk = Catalog.pk(table)
    if pk != [] and hidden_key?(env, table, pk), do: [:hidden_pk_role], else: []
  end
end

defmodule Authzura.Gen.Batch do
  @moduledoc """
  Draws `Authzura.Gen`'s permission batches: for each of the sixteen
  roles, a select permission on about nine tables in ten (columns, filter,
  an optional limit and root fields), completed so every permission
  operator and boundary variable kind appears (`missing_coverage/1`), and
  a no-limit twin per limited role. See `Authzura.Gen.batch/2`.
  """

  import StreamData, except: [filter: 2, filter: 3]

  import Authzura.Gen.Access, only: [root_enabled?: 1]

  alias Authzura.Gen
  alias Authzura.Gen.{Catalog, Filter, Mutation}

  @doc "The batch drawn with `seed`; `limits:`, `degenerate:` and `join_lift:` as in `Authzura.Gen.batch/2`."
  @spec build(integer(), keyword()) :: Gen.batch()
  def build(seed, opts) do
    degenerate = Keyword.get(opts, :degenerate)

    seed
    |> draw(degenerate, Keyword.take(opts, [:join_lift]))
    |> complete(degenerate)
    |> with_limits(Keyword.get(opts, :limits, true))
  end

  @doc "`permissions` without their limits."
  @spec unlimited(%{Catalog.table() => Gen.permission()}) :: %{
          Catalog.table() => Gen.permission()
        }
  def unlimited(permissions),
    do:
      Map.new(permissions, fn {table, permission} -> {table, Map.delete(permission, "limit")} end)

  @doc "See `Authzura.Gen.missing_coverage/1`."
  @spec missing_coverage(Gen.batch()) :: [atom()]
  def missing_coverage(batch) do
    permissions = for {role, ps} <- batch, role in Gen.roles(), {table, p} <- ps, do: {table, p}

    ops =
      for {table, p} <- permissions, tag <- Filter.tags(p["filter"], table), uniq: true, do: tag

    kinds =
      for {_table, p} <- permissions,
          root_enabled?(p),
          name <- Filter.session_refs(p["filter"]),
          uniq: true,
          do: Catalog.variable_kind(name)

    (Filter.operators() -- ops) ++ (Mutation.boundary_kinds() -- kinds)
  end

  @doc "A non-empty subset of `columns`, in order, keeping each with chance `weight` in 10."
  @spec subset([String.t()], 1..9) :: StreamData.t([String.t()])
  def subset(columns, weight \\ 6)
  def subset([], _weight), do: constant([])

  def subset(columns, weight) do
    columns
    |> Enum.map(fn _column ->
      frequency([{weight, constant(true)}, {10 - weight, constant(false)}])
    end)
    |> fixed_list()
    |> map(&kept(columns, &1))
  end

  defp kept(columns, keep) do
    case for({column, true} <- Enum.zip(columns, keep), do: column) do
      [] -> [hd(columns)]
      picked -> picked
    end
  end

  # Places missing features until none is missing; a placement can
  # replace the only filter that carried another tag, hence the loop.
  defp complete(batch, nil), do: complete(batch, missing_coverage(batch), [])
  defp complete(batch, _degenerate), do: batch

  defp complete(batch, [], _used), do: batch

  defp complete(batch, [tag | _rest], used) do
    {table, filter} = Filter.feature(tag)
    role = Enum.find(Gen.roles(), &placeable?(batch, used, &1, table))
    batch = put_in(batch, [role, table, "filter"], filter)
    complete(batch, missing_coverage(batch), [{role, table} | used])
  end

  defp placeable?(batch, used, role, table) do
    case Gen.permission(batch, role, table) do
      nil -> false
      permission -> root_enabled?(permission) and {role, table} not in used
    end
  end

  defp draw(seed, degenerate, filter_opts) do
    permissions =
      Gen.roles()
      |> Enum.map(fn _role -> role_permissions(degenerate, filter_opts) end)
      |> fixed_list()
      |> resize(30)
      |> seeded(seed)
      |> Enum.at(0)

    Gen.roles() |> Enum.zip(permissions) |> Map.new()
  end

  defp with_limits(batch, false), do: Map.new(batch, fn {role, p} -> {role, unlimited(p)} end)

  defp with_limits(batch, true) do
    twins =
      for {role, permissions} <- batch,
          Enum.any?(permissions, fn {_table, p} -> Map.has_key?(p, "limit") end),
          into: %{},
          do: {"#{role}_twin", unlimited(permissions)}

    Map.merge(batch, twins)
  end

  # Permissions.

  defp role_permissions(degenerate, filter_opts) do
    Catalog.tracked()
    |> Enum.map(fn table ->
      frequency([
        {1, constant(nil)},
        {9, map(table_permission(table, degenerate, filter_opts), &{table, &1})}
      ])
    end)
    |> fixed_list()
    |> map(fn entries -> entries |> Enum.reject(&is_nil/1) |> Map.new() end)
  end

  defp table_permission(table, degenerate, filter_opts) do
    fixed_map(%{
      "columns" => permission_columns(table, degenerate),
      "filter" => permission_filter(table, degenerate, filter_opts),
      "limit" => frequency([{7, constant(nil)}, {3, limit()}]),
      "query_root_fields" => root_fields(Catalog.pk(table))
    })
    |> map(&(&1 |> Map.reject(fn {_key, value} -> is_nil(value) end) |> by_pk_root(table)))
  end

  # Hasura refuses `select_by_pk` (inconsistent metadata) for a role that
  # cannot select every primary key column; such a permission keeps no
  # root field instead.
  defp by_pk_root(%{"query_root_fields" => ["select_by_pk"], "columns" => columns} = p, table)
       when is_list(columns) do
    if Catalog.pk(table) -- columns == [], do: p, else: %{p | "query_root_fields" => []}
  end

  defp by_pk_root(permission, _table), do: permission

  # Mostly small, so a limit binds on the seed's few children per parent.
  defp limit,
    do: frequency([{3, constant(1)}, {2, constant(2)}, {1, constant(3)}, {1, constant(4)}])

  defp permission_columns(_table, :all_columns), do: constant("*")

  defp permission_columns(table, _degenerate),
    do: frequency([{3, constant("*")}, {7, subset(Catalog.names(table), 7)}])

  defp permission_filter(_table, :no_filters, _filter_opts), do: constant(%{})

  defp permission_filter(table, _degenerate, filter_opts),
    do: Filter.permission(table, filter_opts)

  defp root_fields([]), do: frequency([{9, constant(nil)}, {1, constant([])}])

  defp root_fields(_pk),
    do: frequency([{17, constant(nil)}, {2, constant([])}, {1, constant(["select_by_pk"])}])
end

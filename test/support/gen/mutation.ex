defmodule Authzura.Gen.Mutation do
  @moduledoc """
  The mutations `Authzura.Gen` applies to a granted-shaped draft: each
  changes one thing so the case is denied for one reason (a hidden or
  unknown column, a preload target without permission, a missing or
  uncastable session variable, a role outside the allowed roles) or sends
  a session boundary form for a referenced variable of its kind.
  """

  import StreamData, except: [filter: 2, filter: 3]

  import Authzura.Gen.Access, only: [hidden: 2, referenced: 2, unpermitted: 3]

  alias Authzura.Gen
  alias Authzura.Gen.{Catalog, Filter}
  alias Authzura.Parity.Read

  @boundary %{
    int: [" 1", "01", "+1", "1.0", "", "32768", "2147483648", "9223372036854775808"],
    bool: ["TRUE", "t", ""],
    int_array: ["{1, 2}", ~s|{"1","2"}|, "{NULL,1}"],
    text_array: [~s|{"a b","c\\"d"}|, "{NULL,a}"]
  }
  @uncastable %{int: "abc", bool: "maybe", int_array: "{1,abc}", text_array: ~s|{"a|}

  @unknown_column "no_such_column"

  @doc "The variable kinds boundary forms exist for."
  @spec boundary_kinds() :: [atom()]
  def boundary_kinds, do: Map.keys(@boundary)

  @doc "Every session boundary form."
  @spec boundary_forms() :: [String.t()]
  def boundary_forms, do: @boundary |> Map.values() |> List.flatten() |> Enum.uniq()

  @doc "Whether `mutation` can be applied to a case rooted at `table`."
  @spec applies?(atom(), map(), Catalog.table()) :: boolean()
  def applies?(:missing_variable, env, table), do: referenced(env, table) != []
  def applies?(:uncastable_value, env, table), do: castable(env, table) != []
  def applies?(:session_boundary, env, table), do: boundary_names(env, table) != []
  def applies?(:hidden_in_columns, env, table), do: hidden(env, table) != []

  def applies?(:preload_target_without_permission, env, table),
    do: unpermitted(env, table, []) != []

  def applies?(_mutation, _env, _table), do: true

  # Mutations: each changes one thing so the case is denied for one
  # reason, or is returned unchanged when the role offers no way to do it.

  @doc """
  `draft` with `mutation` applied: denied for one reason, a boundary
  session value, or unchanged when the role offers no way to do it.
  """
  @spec mutate(atom(), map(), map()) :: StreamData.t(map())
  def mutate(_mutation, %{denial: denial} = draft, _env) when denial != nil, do: constant(draft)

  def mutate(:root_disabled, draft, _env),
    do: constant(%{draft | denial: :root_disabled, mutation: :root_disabled})

  def mutate(:hidden_in_columns, %{read: read} = draft, env),
    do:
      pick(hidden(env, read.table), draft, &denied(draft, :hidden_in_columns, columns(read, &1)))

  def mutate(:hidden_in_filter, %{read: %Read{where: nil}} = draft, _env), do: constant(draft)

  def mutate(:hidden_in_filter, %{read: read} = draft, env) do
    read.table
    |> Catalog.filterable(hidden(env, read.table))
    |> pick(draft, fn column ->
      where = Filter.and_where(read.where, %{column => %{"_is_null" => false}})
      denied(draft, :hidden_in_filter, %{read | where: where})
    end)
  end

  # A caller's own Ecto `order_by` is trusted code in `Authzura.all/3`
  # (see the Querying guide), so only an input `order_by` is denied.
  def mutate(:hidden_in_order, %{read: %Read{where: nil}} = draft, _env), do: constant(draft)

  def mutate(:hidden_in_order, %{read: read} = draft, env) do
    env
    |> hidden(read.table)
    |> Enum.filter(&Catalog.orderable?(read.table, &1))
    |> pick(draft, &denied(draft, :hidden_in_order, ordered(read, &1)))
  end

  def mutate(:hidden_in_preload_columns, %{read: read} = draft, env) do
    read
    |> nested_options(fn _kind, target -> hidden(env, target) end)
    |> pick_nested(draft, &columns/2, :hidden_in_preload_columns)
  end

  def mutate(:hidden_in_preload_order, %{read: read} = draft, env) do
    read
    |> nested_options(fn
      :array, target -> Enum.filter(hidden(env, target), &Catalog.orderable?(target, &1))
      :object, _target -> []
    end)
    |> pick_nested(draft, &ordered/2, :hidden_in_preload_order)
  end

  def mutate(:unknown_column, %{read: %Read{where: nil} = read} = draft, _env),
    do: constant(denied(draft, :unknown_column, columns(read, @unknown_column)))

  def mutate(:unknown_column, %{read: read} = draft, _env) do
    where = Filter.and_where(read.where, %{@unknown_column => %{"_eq" => 1}})

    [columns(read, @unknown_column), %{read | where: where}]
    |> member_of()
    |> map(&denied(draft, :unknown_column, &1))
  end

  def mutate(:preload_target_without_permission, %{read: read} = draft, env),
    do:
      pick(
        unpermitted(env, read.table, read.relationships),
        draft,
        &unpermitted_preload(draft, &1)
      )

  def mutate(:missing_variable, draft, env) do
    pick(referenced(env, draft.read.table), draft, fn name ->
      session(draft, :missing_variable, Map.delete(draft.vars, name))
    end)
  end

  def mutate(:uncastable_value, draft, env) do
    pick(castable(env, draft.read.table), draft, fn name ->
      value = Map.fetch!(@uncastable, Catalog.variable_kind(name))
      session(draft, :uncastable_value, Map.put(draft.vars, name, value))
    end)
  end

  def mutate(:role_not_allowed, %{role: role} = draft, _env) do
    map(others(role), fn others ->
      %{
        draft
        | allowed: others,
          requested: role,
          denial: :role_not_allowed,
          mutation: :role_not_allowed
      }
    end)
  end

  # The kind is drawn first, so a rarely referenced kind is not drowned
  # out by a common one.
  def mutate(:session_boundary, draft, env) do
    env
    |> boundary_names(draft.read.table)
    |> Enum.group_by(&Catalog.variable_kind/1)
    |> Map.values()
    |> member_of()
    |> bind(&member_of/1)
    |> bind(&boundary(draft, &1))
  end

  defp boundary(draft, name) do
    @boundary
    |> Map.fetch!(Catalog.variable_kind(name))
    |> member_of()
    |> map(&%{draft | vars: Map.put(draft.vars, name, &1), mutation: :session_boundary})
  end

  defp pick([], draft, _change), do: constant(draft)
  defp pick(options, _draft, change), do: options |> member_of() |> map(change)

  # A preload of `name`, whose target the role has no permission on,
  # ordered by the target's key.
  defp unpermitted_preload(%{read: %Read{table: table} = read} = draft, name) do
    {kind, target, _mapping} = Catalog.relationship(table, name)
    columns = with [] <- Catalog.pk(target), do: [hd(Catalog.names(target))]
    order = if kind == :array, do: Enum.map(columns, &{:asc, Catalog.atom(&1)})
    child = Read.nested(columns: columns, order_by: order)
    read = %{read | relationships: read.relationships ++ [{name, child}]}
    %{draft | read: read, denial: :forbidden, mutation: :preload_target_without_permission}
  end

  defp denied(draft, mutation, read),
    do: %{draft | read: read, denial: :forbidden_columns, mutation: mutation}

  defp session(draft, denial, vars), do: %{draft | vars: vars, denial: denial, mutation: denial}

  defp columns(%Read{columns: columns} = read, column), do: %{read | columns: columns ++ [column]}

  defp ordered(%Read{order_by: order} = read, column),
    do: %{read | order_by: [{:asc, Catalog.atom(column)} | order || []]}

  # Nested levels `{path, columns}` where `columns_for.(kind, target)`
  # offers columns.
  defp nested_options(read, columns_for) do
    for {[_ | _] = path, kind, target, _parent, _read} <- Gen.levels(read),
        columns = columns_for.(kind, target),
        columns != [],
        do: {path, columns}
  end

  defp pick_nested([], draft, _change, _mutation), do: constant(draft)

  defp pick_nested(options, %{read: read} = draft, change, mutation) do
    bind(member_of(options), fn {path, columns} ->
      map(member_of(columns), &denied(draft, mutation, update_level(read, path, change, &1)))
    end)
  end

  defp update_level(read, [], change, column), do: change.(read, column)

  defp update_level(%Read{relationships: relationships} = read, [name | rest], change, column) do
    relationships =
      Enum.map(relationships, fn
        {^name, child} -> {name, update_level(child, rest, change, column)}
        other -> other
      end)

    %{read | relationships: relationships}
  end

  defp castable(env, table),
    do:
      env
      |> referenced(table)
      |> Enum.filter(&Map.has_key?(@uncastable, Catalog.variable_kind(&1)))

  defp boundary_names(env, table),
    do:
      env |> referenced(table) |> Enum.filter(&Map.has_key?(@boundary, Catalog.variable_kind(&1)))

  defp others(role),
    do: map(list_of(member_of(Gen.roles() -- [role]), min_length: 1, max_length: 2), &Enum.uniq/1)
end

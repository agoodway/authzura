defmodule Authzura.Test.PermissionOracle do
  @moduledoc """
  An oracle for which rows a permission filter admits that does not trust
  Authzura's permission compiler.

  `rows/4` rewrites a permission `bool_exp` into an input filter and reads
  it as the admin role through `Authzura.all_input/4` (input mode: plain
  comparisons, no relationships). The parts that only the permission
  compiler handles are resolved here instead:

    * a relationship `{rel: X}` becomes `{key: {_in: keys}}`, the keys of
      the parent rows (read by the admin with no filter) whose mapping
      columns equal those of some target row admitted by `X`, recursively.
      A NULL mapping column links nothing
    * `_exists` becomes `%{}` (true) or `{_or: []}` (false), from whether
      its table has a row admitted by its `_where`
    * a session variable becomes its value, cast by the variable's kind
    * `$` aliases and `_and`/`_or`/`_not` keep their meaning

  Every value the generators compare is non-NULL, so input mode's plain
  `=`/`<>` agree with the permission mode's null-aware forms. A filter on
  a table outside `public` (where `all_input` cannot read), or a value
  that does not cast, is `:unsupported`.
  """

  alias Authzura.Gen
  alias Authzura.Gen.{Catalog, Filter}
  alias Authzura.Parity.{Hasura, Read, Runner}
  alias Authzura.Util

  @list_keys %{"_and" => "_and", "$and" => "_and", "_or" => "_or", "$or" => "_or"}
  @not_keys ~w(_not $not)
  @exists_keys ~w(_exists $exists)
  @element ~r/"((?:[^"\\]|\\.)*)"|([^,]+)/

  @type ctx :: %{instance: atom(), auth: Hasura.auth(), vars: %{String.t() => String.t()}}

  @doc "The oracle context for case `c` on `instance`: the admin session and `c`'s variables."
  @spec context(Gen.case_t(), atom()) :: ctx()
  def context(c, instance),
    do: %{instance: instance, auth: Gen.oracle(c).auth, vars: Gen.variables(c)}

  @doc """
  The rows of `table` (every column) that `filter` admits, ANDed with
  the input filter `input`, or `:unsupported`.
  """
  @spec rows(ctx(), Catalog.table(), map(), map() | nil) :: {:ok, [map()]} | :unsupported
  def rows(ctx, table, filter, input \\ nil) do
    with {:ok, rewritten} <- rewrite(ctx, table, filter),
         do: admin_rows(ctx, table, Filter.and_where(rewritten, input))
  end

  defp admin_rows(ctx, {"public", _name} = table, filter) do
    read = Read.new(table, columns: Catalog.names(table), where: filter || %{})

    case Runner.authzura(read, ctx.auth, ctx.instance) do
      {:ok, rows} -> {:ok, rows}
      {:error, _reason} -> :unsupported
    end
  end

  defp admin_rows(_ctx, _table, _filter), do: :unsupported

  defp rewrite(ctx, table, map) when is_map(map) do
    with {:ok, parts} <- map |> Map.to_list() |> Util.map_ok(&entry(ctx, table, &1)),
         do: {:ok, conjunction(parts)}
  end

  defp conjunction([]), do: %{}
  defp conjunction([part]), do: part
  defp conjunction(parts), do: %{"_and" => parts}

  defp entry(ctx, table, {key, list}) when is_map_key(@list_keys, key) and is_list(list) do
    with {:ok, kids} <- Util.map_ok(list, &rewrite(ctx, table, &1)),
         do: {:ok, %{Map.fetch!(@list_keys, key) => kids}}
  end

  defp entry(ctx, table, {key, body}) when key in @not_keys do
    with {:ok, body} <- rewrite(ctx, table, body), do: {:ok, %{"_not" => body}}
  end

  defp entry(ctx, _table, {key, %{"_table" => %{"schema" => s, "name" => n}, "_where" => where}})
       when key in @exists_keys do
    with {:ok, rows} <- rows(ctx, {s, n}, where),
         do: {:ok, if(rows == [], do: %{"_or" => []}, else: %{})}
  end

  defp entry(ctx, table, {key, body}) do
    case Catalog.relationship(table, key) do
      {_kind, target, mapping} -> related(ctx, table, target, mapping, body)
      nil -> column(ctx, key, body)
    end
  end

  defp related(ctx, table, target, mapping, body) do
    key = Catalog.key(table)

    with {:ok, targets} <- rows(ctx, target, body),
         {:ok, parents} <- admin_rows(ctx, table, %{}) do
      keys =
        for parent <- parents, Enum.any?(targets, &linked?(parent, &1, mapping)), do: parent[key]

      {:ok, %{key => %{"_in" => keys}}}
    end
  end

  @doc "Whether `child` belongs to `parent` through `mapping` (a NULL links nothing)."
  @spec linked?(map(), map(), %{String.t() => String.t()}) :: boolean()
  def linked?(parent, child, mapping),
    do:
      Enum.all?(mapping, fn {local, remote} ->
        parent[local] != nil and parent[local] == child[remote]
      end)

  defp column(ctx, column, ops) when is_map(ops) do
    with {:ok, ops} <- ops |> Map.to_list() |> Util.map_ok(&operand(ctx, &1)),
         do: {:ok, %{column => Map.new(ops)}}
  end

  defp column(ctx, column, value) do
    with {:ok, value} <- literal(ctx, value), do: {:ok, %{column => value}}
  end

  defp operand(ctx, {op, value}) do
    with {:ok, value} <- literal(ctx, value), do: {:ok, {op, value}}
  end

  defp literal(ctx, value) do
    if Filter.session_ref?(value), do: variable(ctx, String.downcase(value)), else: {:ok, value}
  end

  defp variable(%{vars: vars}, name) do
    case Map.fetch(vars, name) do
      {:ok, raw} -> name |> Catalog.variable_kind() |> cast(raw)
      :error -> :unsupported
    end
  end

  defp cast(:int, raw), do: integer(raw)
  defp cast(:text, raw), do: {:ok, raw}
  defp cast(:bool, "true"), do: {:ok, true}
  defp cast(:bool, "false"), do: {:ok, false}

  defp cast(:int_array, raw),
    do: with({:ok, items} <- array(raw), do: Util.map_ok(items, &integer/1))

  defp cast(:text_array, raw), do: array(raw)
  defp cast(_kind, _raw), do: :unsupported

  defp integer(raw) do
    case Integer.parse(raw) do
      {n, ""} -> {:ok, n}
      _other -> :unsupported
    end
  end

  # The array literals `Authzura.Gen` sends: `{1,2}` or `{"a,b","c"}`.
  defp array("{}"), do: {:ok, []}

  defp array("{" <> rest) do
    with true <- String.ends_with?(rest, "}"),
         inner = String.trim_trailing(rest, "}"),
         elements = Regex.scan(@element, inner),
         false <- Enum.any?(elements, &match?([_, "", "NULL"], &1)) do
      {:ok, Enum.map(elements, &element/1)}
    else
      _other -> :unsupported
    end
  end

  defp array(_raw), do: :unsupported

  defp element([_match, quoted]), do: String.replace(quoted, ~r/\\(.)/, "\\1")
  defp element([_match, "", bare]), do: bare
end

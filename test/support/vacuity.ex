defmodule Authzura.Test.Vacuity do
  @moduledoc """
  The vacuity guards of the property suite, as functions returning the
  guards that fail (`[]` when all hold), so the guards themselves can be
  tested against degenerate generators.

  An observation (`observe/3`) records one case of a batch's **random**
  stream (never the forced sweep). Per batch:

    * (b) at least 70 % of non-denial, non-boundary cases are granted
    * (c) at least 25 % of those granted are restricted but non-empty:
      fewer rows than the admin reads, measured without any limit (the
      no-limit twin role), so an ignored row filter gives 0 %
    * (d) at least 25 % of granted cases with an array preload whose root
      returned rows return a nested row. Cases with an empty root are left
      out: they say nothing about preloads, and root emptiness is (c)'s
      concern; with them in, one batch in four measured near 33 % and the
      guard failed on noise

  Over the whole run, (e) every denial class is denied as built
  (`denial_failures/1`). An empty denominator fails its guard. The fence
  guard (`fence_failures/1`) asks that at least 10 % of fence checks have
  an input filter that removes a permitted row, and `coverage_failures/2`
  that a batch's random stream reaches every must-appear tag.
  """

  alias Authzura.Gen
  alias Authzura.Gen.Catalog
  alias Authzura.Parity.Read

  @granted 0.70
  @restricted 0.25
  @nested 0.25
  @stricter 0.10

  @type observation :: %{
          denial: Gen.denial() | nil,
          plain?: boolean(),
          granted?: boolean(),
          denied_as_built?: boolean(),
          restricted?: boolean(),
          array_preload?: boolean(),
          nested_row?: boolean()
        }

  @doc """
  Observes case `c` and its `result`; `run` reads another case (for the
  restriction measure).
  """
  @spec observe(Gen.case_t(), {:ok, [map()]} | {:error, term()}, (Gen.case_t() -> term())) ::
          observation()
  def observe(c, result, run) do
    %{
      denial: c.denial,
      plain?: c.denial == nil and :session_boundary not in c.tags,
      granted?: match?({:ok, _rows}, result),
      denied_as_built?: denied_as_built?(c, result),
      restricted?: restricted?(c, result, run),
      array_preload?: arrays(c.read) != [] and match?({:ok, [_ | _]}, result),
      nested_row?: nested_row?(c.read, result)
    }
  end

  @doc "The failing per-batch guards (b)-(d) over `log`."
  @spec failures([observation()]) :: [String.t()]
  def failures(log) do
    plain = Enum.filter(log, & &1.plain?)
    granted = Enum.filter(plain, & &1.granted?)
    arrays = Enum.filter(granted, & &1.array_preload?)

    [
      share("(b) non-denial cases granted", Enum.count(granted), length(plain), @granted),
      share(
        "(c) granted cases restricted but non-empty",
        Enum.count(granted, & &1.restricted?),
        length(granted),
        @restricted
      ),
      share(
        "(d) array preloads with a nested row",
        Enum.count(arrays, & &1.nested_row?),
        length(arrays),
        @nested
      )
    ]
    |> Enum.reject(&is_nil/1)
  end

  @doc "Guard (e): the denial classes never denied as built in `log`."
  @spec denial_failures([observation()]) :: [String.t()]
  def denial_failures(log) do
    seen = for %{denied_as_built?: true, denial: denial} <- log, uniq: true, do: denial

    case Gen.denials() -- seen do
      [] -> []
      missing -> ["(e) denial classes never denied as built: #{inspect(missing)}"]
    end
  end

  @doc """
  The fence guard over `outcomes` (`:stricter` or `:same` per fence
  check; `nil` for a case that was not one).
  """
  @spec fence_failures([:stricter | :same | nil]) :: [String.t()]
  def fence_failures(outcomes) do
    checks = Enum.reject(outcomes, &is_nil/1)

    "fence checks whose input filter removes a permitted row"
    |> share(Enum.count(checks, &(&1 == :stricter)), length(checks), @stricter)
    |> List.wrap()
  end

  @doc """
  The must-appear tags the random `cases` of a batch never reach;
  `:partial_null_key` counts only when `partial_null?` (seen at run time).
  """
  @spec coverage_failures([Gen.case_t()], boolean()) :: [String.t()]
  def coverage_failures(cases, partial_null?) do
    seen = cases |> Enum.flat_map(&Gen.coverage_tags/1) |> Enum.uniq()
    runtime = if partial_null?, do: [:partial_null_key], else: []

    case Gen.must_appear() -- (seen ++ runtime) do
      [] -> []
      missing -> ["must-appear tags never reached: #{inspect(missing)}"]
    end
  end

  @doc """
  Whether a granted membership preload returned a parent row with one key
  column NULL (the parent's key columns must be selected to tell).
  """
  @spec partial_null?(Read.t(), {:ok, [map()]} | {:error, term()}) :: boolean()
  def partial_null?(%Read{table: table, relationships: relationships}, {:ok, rows}) do
    Enum.any?(relationships, fn {name, _child} ->
      case Catalog.relationship(table, name) do
        {:object, target, mapping} when map_size(mapping) > 1 ->
          target == Catalog.memberships() and
            Enum.any?(rows, &partial_key?(&1, Map.keys(mapping)))

        _other ->
          false
      end
    end)
  end

  def partial_null?(_read, _result), do: false

  defp partial_key?(row, columns) do
    values = Enum.map(columns, &Map.get(row, &1, :unselected))
    :unselected not in values and nil in values and Enum.any?(values, &(&1 != nil))
  end

  defp share(name, _part, 0, _min), do: "#{name}: no cases"

  defp share(name, part, whole, min) do
    if part / whole < min, do: "#{name}: #{part}/#{whole}, below #{round(min * 100)} %"
  end

  defp denied_as_built?(%{denial: nil}, _result), do: false

  defp denied_as_built?(%{denial: denial}, {:error, reason}),
    do: Gen.expected_denial?(denial, reason)

  defp denied_as_built?(_c, _result), do: false

  defp restricted?(%{denial: nil, read: %Read{} = read} = c, {:ok, _rows}, run) do
    unlimited = without_limit(%{c | read: %{read | limit: nil, offset: nil}})

    with {:ok, [_ | _] = rows} <- run.(unlimited),
         {:ok, all} <- run.(Gen.oracle(c)) do
      length(rows) < length(all)
    else
      _other -> false
    end
  end

  defp restricted?(_c, _result, _run), do: false

  defp without_limit(%{twin: nil} = c), do: c
  defp without_limit(%{twin: twin} = c), do: Gen.as_role(c, twin)

  defp nested_row?(read, {:ok, rows}),
    do: Enum.any?(arrays(read), fn path -> rows |> nested(path) |> Enum.any?() end)

  defp nested_row?(_read, _result), do: false

  defp arrays(read), do: for({path, :array, _table, _parent, _read} <- Gen.levels(read), do: path)

  defp nested(rows, []), do: rows

  defp nested(rows, [name | rest]),
    do: rows |> Enum.flat_map(&(&1 |> Map.fetch!(name) |> List.wrap())) |> nested(rest)
end

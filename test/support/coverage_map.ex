defmodule Authzura.Test.CoverageMap do
  @moduledoc """
  Parses `docs/hasura-test-coverage.md` into its four tables and matches
  Hasura source paths against them.

  The map is read by the sweep (`test/hasura_scenarios/sweep_test.exs`), which
  proves that every Hasura select-permission test is accounted for. Parsing
  is strict: a missing or empty table, an unknown header, an unknown catalog
  status, or a divergence diagnosis that does not begin `intended` or
  `stage-one gap, fails closed` raises `ArgumentError`.

  A source cell may name several files in backticks. A brace group
  (`{a,b}`) and `*` expand like a shell glob, a trailing `/` names a
  directory, and a leading `_` or `...` abbreviates the previous full
  basename in the same cell (`_limit_2.yaml`, `..._session_vars.yaml`).
  """

  @statuses ["covered", "partial → ported", "missing → ported"]
  @diagnosis ~r/^(intended|stage-one gap, fails closed)/

  @tables [
    catalog: {"Scenario catalog", ["#", "Catalog item", "Status", "Tests"]},
    extra: {"Extra scenarios ported", ["Hasura source", "Scenario", "Test"]},
    divergences: {"Divergences", ["Test", "Hasura", "Authzura", "Diagnosis"]},
    out_of_scope: {"Out of scope", ["Hasura source", "Reason"]}
  ]

  @type row :: %{optional(atom()) => String.t()}
  @type t :: %{
          catalog: [row()],
          extra: [row()],
          divergences: [row()],
          out_of_scope: [row()]
        }

  @doc "Parses the map file at `path`; raises `ArgumentError` on a malformed map."
  @spec parse!(Path.t()) :: t()
  def parse!(path), do: path |> File.read!() |> parse_string!()

  @doc "Parses the map's markdown `text`; raises `ArgumentError` on a malformed map."
  @spec parse_string!(String.t()) :: t()
  def parse_string!(text) when is_binary(text) do
    sections = split_sections(text)
    Map.new(@tables, fn {key, spec} -> {key, table!(sections, key, spec)} end)
  end

  @doc """
  True when the source cell `cell` names the inventory path `path`
  (relative to Hasura's `server/` directory).
  """
  @spec names?(String.t(), String.t()) :: boolean()
  def names?(cell, path) do
    cell
    |> sources()
    |> Enum.any?(&matches?(&1, path))
  end

  @doc """
  True when `cell` names `path` exactly, or a file with its basename, in
  backticks, with no glob (used for the catalog's free-text cells).
  """
  @spec mentions?(String.t(), String.t()) :: boolean()
  def mentions?(cell, path) do
    base = Path.basename(path)

    cell
    |> sources()
    |> Enum.any?(fn
      {:path, entry, _} -> entry == path or Path.basename(entry) == base
      {:shorthand, _, _} -> false
    end)
  end

  @doc """
  The file entries of `cell` (directory entries excluded) that match none of
  `paths`.
  """
  @spec unmatched(String.t(), [String.t()]) :: [String.t()]
  def unmatched(cell, paths) do
    cell
    |> sources()
    |> Enum.reject(fn source ->
      directory?(source) or Enum.any?(paths, &matches?(source, &1))
    end)
    |> Enum.map(&elem(&1, 1))
  end

  defp directory?({:path, entry, _}), do: String.ends_with?(entry, "/")
  defp directory?({:shorthand, _, _}), do: false

  @doc """
  The backticked source entries of a cell. A bare file name resolves against
  the directory of the previous entry, and shorthand is kept with the
  previous full entry for `names?/2`.
  """
  @spec sources(String.t()) :: [{:path | :shorthand, String.t(), String.t() | nil}]
  def sources(cell) do
    ~r/`([^`]+)`/
    |> Regex.scan(cell, capture: :all_but_first)
    |> List.flatten()
    |> Enum.map_reduce(nil, &resolve/2)
    |> elem(0)
  end

  @doc "The `file:line` references (a line list is `file:1,2`) in a test cell."
  @spec references(String.t()) :: [{String.t(), pos_integer()}]
  def references(cell) do
    ~r/`?([\w\/]+\.exs?):(\d+(?:[,-]\d+)*)`?/
    |> Regex.scan(cell, capture: :all_but_first)
    |> Enum.flat_map(fn [file, lines] ->
      lines |> String.split(~r/[,-]/) |> Enum.map(&{file, String.to_integer(&1)})
    end)
  end

  defp resolve("..." <> rest, previous), do: {{:shorthand, rest, previous}, previous}
  defp resolve("_" <> _ = rest, previous), do: {{:shorthand, rest, previous}, previous}
  defp resolve(entry, nil), do: {{:path, entry, nil}, entry}
  defp resolve("tests-py/" <> _ = entry, _previous), do: {{:path, entry, nil}, entry}
  defp resolve("lib/" <> _ = entry, _previous), do: {{:path, entry, nil}, entry}

  defp resolve(entry, previous) do
    full =
      if String.contains?(entry, "/"),
        do: root(previous) <> entry,
        else: Path.join(Path.dirname(previous), entry)

    {{:path, full, nil}, full}
  end

  # Entries like `boolexp/search/*.yaml` are relative to the last tree named.
  defp root(previous) do
    case Regex.run(~r{\A(tests-py/queries/graphql_query/|lib/api-tests/src/Test/)}, previous) do
      [_, root | _] -> root
      nil -> ""
    end
  end

  defp matches?({:path, entry, _}, path), do: glob_match?(entry, path)

  defp matches?({:shorthand, _rest, nil}, _path), do: false

  defp matches?({:shorthand, rest, previous}, path) do
    base = Path.basename(path)
    lead = String.replace_suffix(base, rest, "")

    Path.dirname(path) == Path.dirname(previous) and String.ends_with?(base, rest) and
      lead != "" and String.starts_with?(Path.basename(previous), lead)
  end

  defp glob_match?(entry, path) do
    entry |> expand_braces() |> Enum.any?(&single_match?(&1, path))
  end

  defp single_match?(entry, path) do
    if String.ends_with?(entry, "/") do
      String.starts_with?(path, entry)
    else
      regex =
        entry
        |> String.split("*")
        |> Enum.map_join(".*", &Regex.escape/1)

      Regex.match?(~r/\A#{regex}\z/, path)
    end
  end

  defp expand_braces(entry) do
    case Regex.run(~r/\{([^{}]*)\}/, entry, return: :index) do
      nil ->
        [entry]

      [{start, len}, {inner_start, inner_len}] ->
        head = binary_part(entry, 0, start)
        tail = binary_part(entry, start + len, byte_size(entry) - start - len)

        entry
        |> binary_part(inner_start, inner_len)
        |> String.split(",")
        |> Enum.flat_map(&expand_braces(head <> &1 <> tail))
    end
  end

  defp split_sections(text) do
    ~r/^## (.+)$/m
    |> Regex.split(text, include_captures: true)
    |> Enum.drop(1)
    |> Enum.chunk_every(2)
    |> Map.new(fn ["## " <> title, body] -> {String.trim(title), body} end)
  end

  defp table!(sections, key, {title, headers}) do
    body =
      case Map.fetch(sections, title) do
        {:ok, body} -> body
        :error -> raise ArgumentError, "missing section #{inspect(title)}"
      end

    body
    |> String.split("\n")
    |> Enum.filter(&String.starts_with?(&1, "|"))
    |> Enum.map(&cells/1)
    |> data!(title, headers)
    |> Enum.map(&row!(key, headers, &1))
  end

  defp data!([headers, _rule | [_ | _] = data], _title, headers), do: data

  defp data!([header, _rule | [_ | _]], title, _headers),
    do: raise(ArgumentError, "unknown header in #{inspect(title)}: #{inspect(header)}")

  defp data!(_rows, title, _headers),
    do: raise(ArgumentError, "missing or empty table #{inspect(title)}")

  defp row!(key, headers, cells) when length(cells) == length(headers),
    do:
      headers
      |> Enum.map(&field_name/1)
      |> Enum.zip(cells)
      |> Map.new()
      |> filled!()
      |> check!(key)

  defp row!(_key, headers, cells),
    do: raise(ArgumentError, "row #{inspect(cells)} does not have #{length(headers)} cells")

  defp filled!(row) do
    case Enum.find(row, fn {_field, cell} -> cell == "" end) do
      nil -> row
      {field, _} -> raise ArgumentError, "empty #{field} cell in #{inspect(row)}"
    end
  end

  defp check!(%{status: status} = row, :catalog) when status in @statuses, do: row

  defp check!(%{status: status}, :catalog),
    do: raise(ArgumentError, "unknown status #{inspect(status)}")

  defp check!(%{diagnosis: diagnosis} = row, :divergences) do
    if Regex.match?(@diagnosis, diagnosis),
      do: row,
      else: raise(ArgumentError, "unknown diagnosis #{inspect(diagnosis)}")
  end

  defp check!(row, _key), do: row

  @fields %{
    "#" => :number,
    "Catalog item" => :item,
    "Status" => :status,
    "Tests" => :tests,
    "Hasura source" => :source,
    "Scenario" => :scenario,
    "Test" => :test,
    "Hasura" => :hasura,
    "Authzura" => :authzura,
    "Diagnosis" => :diagnosis,
    "Reason" => :reason
  }

  defp field_name(header), do: Map.fetch!(@fields, header)

  # Splits on unescaped pipes: a pipe inside backticks (a regex or `||`) would
  # need escaping in markdown anyway, so cells never contain a bare one.
  defp cells(line) do
    line
    |> String.trim()
    |> String.trim("|")
    |> String.split(~r/(?<!\\)\|/)
    |> Enum.map(&String.trim/1)
  end
end

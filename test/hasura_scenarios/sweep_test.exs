defmodule Authzura.HasuraScenarios.SweepTest do
  @moduledoc """
  Proves that every Hasura v2.51.6 select-permission test is accounted for.

  `hasura_inventory.tsv` lists each path of the sweep, with its status and the
  Authzura test that covers it. The inventory is built outside the repo from
  the v2.51.6 tag of a sparse clone, read from the tag's tree so the working
  tree's HEAD does not matter:

      git clone --filter=blob:none --sparse --depth 1 --branch v2.51.6 \\
        https://github.com/hasura/graphql-engine.git "$TMPDIR/hasura-v2.51.6"
      git -C "$TMPDIR/hasura-v2.51.6" sparse-checkout set \\
        server/tests-py/queries/graphql_query server/lib/api-tests/src/Test
      cd "$TMPDIR/hasura-v2.51.6"
      { git ls-tree -r --name-only v2.51.6 -- server/tests-py/queries/graphql_query \\
          | sed 's#^server/##' \\
          | grep -E '^tests-py/queries/graphql_query/(permissions|boolexp/basic|boolexp/search|boolexp/jsonb|limits)/[^/]*\\.yaml$'
        git grep -lE 'select_permissions|SelectPermission|DisableRootFields|selectPermission' \\
          v2.51.6 -- 'server/lib/api-tests/src/Test/*.hs' | sed 's#^v2.51.6:server/##'
      } | LC_ALL=C sort -u

  The sweep checks the inventory against `docs/hasura-test-coverage.md`:

    * every path is named by the table its status implies (`ported` and
      `divergence` by the Extra scenarios, the catalog or the Divergences;
      `out_of_scope` by Out of scope) and by no other;
    * every file entry of an Extra or Out of scope row names an inventory path;
    * every cited test exists, a ported test is not skipped, and every
      divergence test carries `@tag :hasura_divergence`.
  """

  use ExUnit.Case, async: true

  alias Authzura.Test.CoverageMap

  @map_path "docs/hasura-test-coverage.md"
  @inventory_path "test/hasura_scenarios/hasura_inventory.tsv"
  @scenarios "test/hasura_scenarios"
  @statuses ~w(ported divergence out_of_scope)

  # Hasura files that rows name although the inventory command does not list
  # them (they are reached through another harness); reviewed by hand.
  @reviewed_beyond_the_command [
    "lib/api-tests/src/Test/Regression/ObjectRelationshipsLimit7936Spec.hs",
    "lib/api-tests/src/Test/Regression/LongIdentifiers3796Spec.hs",
    "lib/api-tests/src/Test/Regression/AggregateBoolExpConflictSpec.hs",
    "lib/api-tests/src/Test/Regression/DropColumnWithPermissions8415Spec.hs",
    "lib/api-tests/src/Test/Databases/Postgres/DataValidation/RemoteSourcePermissionPredicateSpec.hs",
    "lib/api-tests/src/Test/Databases/Postgres/BackendOnlyPermissionsSpec.hs",
    "lib/api-tests/src/Test/Schema/DataValidations/Permissions/{InsertSpec,UpdateSpec}.hs",
    "lib/api-tests/src/Test/Schema/CustomFieldsSpec.hs",
    "lib/api-tests/src/Test/Schema/DefaultValues/DefaultValuesSpec.hs"
  ]

  @test_line ~r/^\s*test "((?:[^"\\]|\\.)*)"/
  @boundary ~r/^\s*(end|describe |setup |defp? )/

  setup_all do
    index = for file <- Path.wildcard("test/**/*_test.exs"), into: %{}, do: {file, index(file)}
    inventory = read_inventory()

    %{
      map: CoverageMap.parse!(@map_path),
      inventory: inventory,
      paths: Enum.map(inventory, & &1.path),
      index: index
    }
  end

  defp read_inventory do
    @inventory_path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(fn line ->
      [path, status, test] = line |> String.split("\t") |> pad(3)
      %{path: path, status: status, test: test}
    end)
  end

  defp pad(fields, size), do: fields ++ List.duplicate("", size - length(fields))

  # One pass over a test file: its line count and its tests, each with the
  # tags above it (back to the previous block boundary).
  defp index(file) do
    {tests, _pending, count} =
      file
      |> File.stream!()
      |> Stream.with_index(1)
      |> Enum.reduce({[], [], 0}, &scan/2)

    %{count: count, tests: Enum.reverse(tests)}
  end

  defp scan({line, number}, {tests, pending, _count}) do
    cond do
      match = Regex.run(@test_line, line) ->
        [_, name] = match
        tags = Enum.join(pending)

        test = %{
          line: number,
          name: name,
          divergence?: String.contains?(tags, ":hasura_divergence"),
          skipped?: String.contains?(tags, "skip")
        }

        {[test | tests], [], number}

      Regex.match?(@boundary, line) ->
        {tests, [], number}

      true ->
        {tests, [line | pending], number}
    end
  end

  defp file_key(file) do
    if String.contains?(file, "/"), do: file, else: Path.join(@scenarios, file)
  end

  defp find_test(index, file, name) do
    index
    |> Map.get(file_key(file), %{tests: []})
    |> Map.fetch!(:tests)
    |> Enum.find(&(&1.name == name))
  end

  defp line_in_file?(index, file, line) do
    case Map.get(index, file_key(file)) do
      %{count: count} -> line in 1..count//1
      nil -> false
    end
  end

  # The test at or above `line` of `file`, or nil when the line is outside the
  # file or above its first test.
  defp enclosing(index, file, line) do
    case Map.get(index, file_key(file)) do
      %{count: count, tests: tests} when line in 1..count//1 ->
        tests |> Enum.take_while(&(&1.line <= line)) |> List.last()

      _ ->
        nil
    end
  end

  defp split_test(test) do
    [file, name] = String.split(test, ": ", parts: 2)
    {file, name}
  end

  defp valid_map(status \\ "covered"),
    do: """
    ## Scenario catalog

    | # | Catalog item | Status | Tests |
    |---|---|---|---|
    | 1 | an item | #{status} | `a_test.exs:1` |

    ## Extra scenarios ported

    | Hasura source | Scenario | Test |
    |---|---|---|
    | `a.yaml` | a | `a_test.exs:1` |

    ## Divergences

    | Test | Hasura | Authzura | Diagnosis |
    |---|---|---|---|
    | `a_test.exs:1` | a | b | intended: because |

    ## Out of scope

    | Hasura source | Reason |
    |---|---|
    | `b.yaml` | a reason |
    """

  describe "the coverage map" do
    test "parses; empty or unknown forms are rejected", %{map: map} do
      assert %{catalog: [_ | _], extra: [_ | _], divergences: [_ | _], out_of_scope: [_ | _]} =
               map

      assert %{} = CoverageMap.parse_string!(valid_map())

      assert_raise ArgumentError, fn -> CoverageMap.parse_string!("") end

      assert_raise ArgumentError, ~r/unknown status/, fn ->
        "maybe" |> valid_map() |> CoverageMap.parse_string!()
      end
    end

    test "rejects an unknown header, an empty table, a bad diagnosis and an empty cell" do
      good = valid_map()

      assert_raise ArgumentError, ~r/unknown header/, fn ->
        good
        |> String.replace("| Hasura source | Reason |", "| Source | Reason |")
        |> CoverageMap.parse_string!()
      end

      assert_raise ArgumentError, ~r/missing or empty/, fn ->
        good |> String.replace("| `b.yaml` | a reason |\n", "") |> CoverageMap.parse_string!()
      end

      assert_raise ArgumentError, ~r/unknown diagnosis/, fn ->
        good |> String.replace("intended: because", "a bug") |> CoverageMap.parse_string!()
      end

      assert_raise ArgumentError, ~r/empty reason cell/, fn ->
        good |> String.replace("| a reason |", "|  |") |> CoverageMap.parse_string!()
      end

      assert_raise ArgumentError, ~r/empty scenario cell/, fn ->
        good
        |> String.replace("| a | `a_test.exs:1` |\n\n## Div", "|  | `a_test.exs:1` |\n\n## Div")
        |> CoverageMap.parse_string!()
      end
    end

    test "every cited test line exists", %{map: map, index: index} do
      cells =
        Enum.map(map.catalog, &{&1.number, &1.tests}) ++
          Enum.map(map.extra, &{&1.source, &1.test}) ++
          Enum.map(map.divergences, &{&1.test, &1.test})

      for {row, cell} <- cells, {file, line} <- CoverageMap.references(cell) do
        assert line_in_file?(index, file, line), "#{row}: #{file}:#{line} does not exist"
      end
    end

    test "every file entry of an Extra or Out of scope row names an inventory path", %{
      map: map,
      paths: paths
    } do
      for %{source: source} <- map.extra ++ map.out_of_scope do
        unmatched = CoverageMap.unmatched(source, paths) -- @reviewed_beyond_the_command
        assert unmatched == [], "not in the inventory: #{source}"
      end
    end
  end

  describe "the inventory" do
    test "has well-formed rows", %{inventory: inventory} do
      assert [_ | _] = inventory
      assert inventory == Enum.uniq_by(inventory, & &1.path)
      assert inventory == Enum.sort_by(inventory, & &1.path)

      for %{path: path, status: status, test: test} <- inventory do
        assert status in @statuses, "#{path}: unknown status #{inspect(status)}"
        assert status == "out_of_scope" == (test == ""), "#{path}: test cell and status disagree"
      end
    end

    test "every row's test exists; ported tests run, divergence tests are tagged", %{
      inventory: inventory,
      index: index
    } do
      for %{path: path, status: status, test: test} <- inventory, test != "" do
        {file, name} = split_test(test)
        found = find_test(index, file, name)

        assert found, "#{path}: no test #{inspect(name)} in #{file}"
        assert found.divergence? == (status == "divergence"), "#{path}: #{test} is mis-tagged"
        assert found.skipped? == (status == "divergence"), "#{path}: #{test} is mis-skipped"
      end
    end

    test "every path is named by the table its status implies, and only by it", %{
      inventory: inventory,
      map: map
    } do
      for %{path: path, status: status} <- inventory do
        named = named_by(map, path)

        assert consistent?(status, named),
               "#{path} (#{status}) is named by #{inspect(named)} in #{@map_path}"
      end
    end

    test "every divergence row of the map is tagged :hasura_divergence", %{map: map, index: index} do
      for %{test: cell} <- map.divergences, {file, line} <- CoverageMap.references(cell) do
        test = enclosing(index, file, line)
        assert test && test.divergence?, "#{file}:#{line} is not tagged :hasura_divergence"
      end
    end
  end

  # The map tables that name `path`: the catalog and the Divergences count as
  # the ported and the divergence side, Extra scenarios as either.
  defp named_by(map, path) do
    catalog = Enum.any?(map.catalog, &CoverageMap.mentions?("#{&1.item} #{&1.tests}", path))
    divergences = Enum.any?(map.divergences, &CoverageMap.mentions?(&1.test, path))
    extra = Enum.any?(map.extra, &CoverageMap.names?(&1.source, path))
    out = Enum.any?(map.out_of_scope, &CoverageMap.names?(&1.source, path))

    [catalog: catalog, divergences: divergences, extra: extra, out_of_scope: out]
    |> Enum.filter(&elem(&1, 1))
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  defp consistent?("out_of_scope", named), do: named == [:out_of_scope]
  defp consistent?(_status, named), do: named != [] and :out_of_scope not in named
end

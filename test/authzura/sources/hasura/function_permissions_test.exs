defmodule Authzura.Sources.Hasura.FunctionPermissionsTest do
  use Authzura.DataCase, async: true

  import Authzura.HasuraFixture, only: [function_grants: 2]

  alias Authzura.HasuraFixture
  alias Authzura.Model.Diagnostic
  alias Authzura.Sources.Hasura.Metadata

  defp translate(functions, opts \\ []) do
    [%{table: {"public", "articles"}}]
    |> HasuraFixture.metadata([functions: functions] ++ opts)
    |> Metadata.translate_functions(Keyword.get(opts, :source, "default"))
  end

  defp assert_denied(diagnostics, reason, paths) do
    assert Enum.map(diagnostics, & &1.path) == paths

    assert Enum.all?(
             diagnostics,
             &match?(%Diagnostic{severity: :deny, reason: ^reason}, &1)
           )
  end

  test "a string name is in the public schema" do
    assert {%{{"public", "search"} => roles}, []} =
             translate([function_grants("search", ["user"])])

    assert roles == MapSet.new(["user"])
  end

  test "an object reference carries its schema, which defaults to public" do
    functions = [
      function_grants({"api", "search"}, ["user", "editor"]),
      %{function: %{name: "recent"}, permissions: [%{role: "user"}]}
    ]

    assert {map, []} = translate(functions)

    assert map == %{
             {"api", "search"} => MapSet.new(["user", "editor"]),
             {"public", "recent"} => MapSet.new(["user"])
           }
  end

  test "a tracked function without permissions is recorded with no roles" do
    assert {%{{"public", "open"} => roles}, []} = translate([%{function: "open"}])
    assert MapSet.size(roles) == 0

    assert {%{{"public", "shut"} => roles}, []} = translate([function_grants("shut", [])])
    assert MapSet.size(roles) == 0
  end

  test "a function listed twice is granted to no role, and the repeat is denied" do
    functions = [
      function_grants("search", ["a"]),
      function_grants({"public", "search"}, ["b"]),
      function_grants("other", ["a"])
    ]

    assert {map, [diagnostic]} = translate(functions)

    assert map == %{
             {"public", "search"} => MapSet.new(),
             {"public", "other"} => MapSet.new(["a"])
           }

    assert %Diagnostic{
             severity: :deny,
             function: {"public", "search"},
             path: ["functions", "1"],
             reason: :duplicate_function
           } = diagnostic
  end

  test "a function listed three times yields exactly two duplicate diagnostics" do
    functions = [
      function_grants("search", ["a"]),
      function_grants("search", ["b"]),
      function_grants({"public", "search"}, ["c"])
    ]

    assert {map, diagnostics} = translate(functions)
    assert map == %{{"public", "search"} => MapSet.new()}
    assert_denied(diagnostics, :duplicate_function, [["functions", "1"], ["functions", "2"]])
  end

  test "a duplicated entry with bad permissions keeps its per-permission diagnostics" do
    functions = [
      %{function: "f", permissions: [%{role: 1}]},
      %{function: "f", permissions: [%{role: "a"}, %{}]}
    ]

    assert {map, diagnostics} = translate(functions)
    assert map == %{{"public", "f"} => MapSet.new()}

    assert diagnostics |> Enum.map(&{&1.path, &1.reason}) |> Enum.sort() == [
             {["functions", "0", "permissions", "0"], :invalid_function_permission},
             {["functions", "1"], :duplicate_function},
             {["functions", "1", "permissions", "1"], :invalid_function_permission}
           ]

    assert Enum.all?(diagnostics, &match?(%Diagnostic{severity: :deny}, &1))
  end

  test "functions of another source are ignored" do
    metadata =
      HasuraFixture.metadata([],
        sources: [
          %{
            name: "other",
            kind: "postgres",
            tables: [],
            functions: [function_grants("search", ["user"])]
          }
        ]
      )

    assert {%{}, []} == Metadata.translate_functions(metadata, "default")

    assert {%{{"public", "search"} => _roles}, []} =
             Metadata.translate_functions(metadata, "other")
  end

  test "an unknown source, or metadata without functions, translates nothing" do
    assert {%{}, []} == Metadata.translate_functions(%{}, "default")
    assert {%{}, []} == Metadata.translate_functions(nil, "default")
    assert {%{}, []} == translate([])
    assert {%{}, []} == Metadata.translate_functions(HasuraFixture.metadata([]), "nope")
  end

  test "exposed_as does not change the grants" do
    entry = %{
      function: "f",
      configuration: %{exposed_as: "mutation"},
      permissions: [%{role: "user"}]
    }

    assert {%{{"public", "f"} => roles}, []} = translate([entry])
    assert roles == MapSet.new(["user"])
  end

  describe "malformed entries" do
    test "an entry that is not a function reference is denied and recorded nowhere" do
      functions = [
        "search",
        %{permissions: [%{role: "user"}]},
        %{function: 7, permissions: [%{role: "user"}]},
        %{function: %{schema: "api"}, permissions: [%{role: "user"}]},
        %{function: %{schema: 1, name: "f"}, permissions: [%{role: "user"}]}
      ]

      assert {map, diagnostics} = translate(functions)
      assert map == %{}
      assert_denied(diagnostics, :invalid_function, for(i <- 0..4, do: ["functions", "#{i}"]))
    end

    test "permissions that are not a list deny the function's grants" do
      assert {%{{"public", "f"} => roles}, [diagnostic]} =
               translate([%{function: "f", permissions: "user"}])

      assert MapSet.size(roles) == 0

      assert %Diagnostic{
               severity: :deny,
               function: {"public", "f"},
               path: ["functions", "0", "permissions"],
               reason: :invalid_function_permissions
             } = diagnostic
    end

    test "a permission without a string role is denied, the others kept" do
      permissions = [%{role: "user"}, %{role: 3}, %{}, "x", %{role: "editor"}]

      assert {%{{"public", "f"} => granted}, diagnostics} =
               translate([%{function: "f", permissions: permissions}])

      assert granted == MapSet.new(["user", "editor"])
      assert Enum.all?(diagnostics, &(&1.function == {"public", "f"}))

      assert_denied(
        diagnostics,
        :invalid_function_permission,
        for(j <- [1, 2, 3], do: ["functions", "0", "permissions", "#{j}"])
      )
    end

    test "an inherited role is not granted" do
      metadata =
        HasuraFixture.metadata([],
          inherited_roles: [%{role_name: "combo", role_set: ["a", "b"]}],
          functions: [function_grants("f", ["combo", "a"])]
        )

      assert {%{{"public", "f"} => granted}, [diagnostic]} =
               Metadata.translate_functions(metadata, "default")

      assert granted == MapSet.new(["a"])
      assert %Diagnostic{severity: :deny, role: "combo", function: {"public", "f"}} = diagnostic
    end
  end
end

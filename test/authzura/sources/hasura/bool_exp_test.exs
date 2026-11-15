defmodule Authzura.Sources.Hasura.BoolExpTest do
  use Authzura.DataCase, async: true

  doctest Authzura.Sources.Hasura.BoolExp

  alias Authzura.Adapters.Postgres
  alias Authzura.AST
  alias Authzura.Model.{Column, Relationship, Table}
  alias Authzura.Sources.Hasura.BoolExp

  @articles {"public", "articles"}
  @users {"public", "users"}
  @refs [@articles, @users, {"audit", "users"}, {"public", "comments"}]
  @permission_limits %{binding_depth: 15, syntactic_depth: 32, nodes: 1000}
  @input_limits %{binding_depth: 15, syntactic_depth: 8, nodes: 100}

  setup do
    {:ok, tables, _fks} = Postgres.introspect(Repo, @refs)

    tables =
      tables
      |> put_relationship(@articles, "author", @users, [{"author_id", "id"}])
      |> put_relationship(@users, "manager", @users, [{"manager_id", "id"}])
      |> Map.put({"public", "docs"}, docs_table())

    %{tables: tables}
  end

  defp put_relationship(tables, ref, name, target, mapping) do
    rel = %Relationship{name: name, kind: :object, target: target, mapping: mapping}
    update_in(tables, [ref, Access.key!(:relationships)], &Map.put(&1, name, rel))
  end

  defp docs_table do
    column = %Column{name: "raw", pg_type: "json", base_kind: :json, ecto_type: :map}
    %Table{schema: "public", name: "docs", columns: %{"raw" => column}}
  end

  defp ctx(tables, ref, limits, extra \\ %{}) do
    Map.merge(%{table: tables[ref], tables: tables, adapter: Postgres, limits: limits}, extra)
  end

  defp permission(json, tables, ref \\ @articles),
    do: BoolExp.parse(json, :permission, ctx(tables, ref, @permission_limits))

  defp input(json, tables, ref \\ @articles),
    do: BoolExp.parse(json, :input, ctx(tables, ref, @input_limits))

  describe "empty and combined forms" do
    test "{} is an empty and", %{tables: tables} do
      assert {:ok, {:and, []}} = permission(%{}, tables)
    end

    test "_or: [] is an empty or and _and: [] an empty and", %{tables: tables} do
      assert {:ok, {:or, []}} = permission(%{"_or" => []}, tables)
      assert {:ok, {:and, []}} = permission(%{"_and" => []}, tables)
    end

    test "_not: {} negates an empty and", %{tables: tables} do
      assert {:ok, {:not, {:and, []}}} = permission(%{"_not" => %{}}, tables)
    end

    test "a multi-key object is an and of its keys", %{tables: tables} do
      json = %{"is_published" => %{"_eq" => true}, "title" => %{"_eq" => "a"}}

      assert {:ok,
              {:and,
               [
                 {:compare, "is_published", :eq, {:literal, true}},
                 {:compare, "title", :eq, {:literal, "a"}}
               ]}} = permission(json, tables)
    end

    test "a column with several operators is an and of them", %{tables: tables} do
      assert {:ok, {:and, [{:compare, "id", :gt, _}, {:compare, "id", :lt, _}]}} =
               permission(%{"id" => %{"_gt" => 1, "_lt" => 9}}, tables)
    end

    test "a column with no operators is an empty and", %{tables: tables} do
      assert {:ok, {:and, []}} = permission(%{"id" => %{}}, tables)
    end

    test "_and and _or keep their list order", %{tables: tables} do
      json = %{"_or" => [%{"title" => %{"_eq" => "b"}}, %{"title" => %{"_eq" => "a"}}]}

      assert {:ok,
              {:or,
               [
                 {:compare, "title", :eq, {:literal, "b"}},
                 {:compare, "title", :eq, {:literal, "a"}}
               ]}} = permission(json, tables)
    end
  end

  describe "$ aliases" do
    test "logic aliases", %{tables: tables} do
      json = %{"$and" => [%{"$or" => []}, %{"$not" => %{}}]}
      assert {:ok, {:and, [{:or, []}, {:not, {:and, []}}]}} = permission(json, tables)
    end

    test "$exists", %{tables: tables} do
      json = %{
        "$exists" => %{"_table" => %{"schema" => "audit", "name" => "users"}, "_where" => %{}}
      }

      assert {:ok, {:exists, {"audit", "users"}, {:and, []}}} = permission(json, tables)
    end

    test "$ operators", %{tables: tables} do
      assert {:ok, {:compare, "id", :in, {:literal, [1, 2]}}} =
               permission(%{"id" => %{"$in" => [1, 2]}}, tables)

      assert {:ok, {:compare, "assignees", :has_key, {:session, "x-hasura-user-id"}}} =
               permission(%{"assignees" => %{"$has_key" => "X-Hasura-User-Id"}}, tables)
    end

    test "_ne and _neq are both :neq", %{tables: tables} do
      assert {:ok, {:compare, "id", :neq, {:literal, 1}}} =
               permission(%{"id" => %{"_ne" => 1}}, tables)

      assert {:ok, {:compare, "id", :neq, {:literal, 1}}} =
               permission(%{"id" => %{"$neq" => 1}}, tables)
    end
  end

  describe "shorthand equality" do
    test "a bare value means _eq", %{tables: tables} do
      assert {:ok, {:compare, "author_id", :eq, {:session, "x-hasura-user-id"}}} =
               permission(%{"author_id" => "X-HASURA-USER-ID"}, tables)

      assert {:ok, {:compare, "id", :eq, {:literal, 7}}} = permission(%{"id" => 7}, tables)
    end
  end

  describe "permission mode" do
    test "strings whose folded form starts with x-hasura- are session values", %{tables: tables} do
      assert {:ok, {:compare, "title", :eq, {:session, "x-hasura-org-name"}}} =
               permission(%{"title" => %{"_eq" => "X-Hasura-Org-Name"}}, tables)
    end

    test "a session value for an array operator stays one session value", %{tables: tables} do
      assert {:ok, {:compare, "id", :in, {:session, "x-hasura-ids"}}} =
               permission(%{"id" => %{"_in" => "x-hasura-ids"}}, tables)
    end

    test "list elements are never session values", %{tables: tables} do
      assert {:error, [{["id", "_in"], {:invalid_literal, {:invalid_value, "int8"}}}]} =
               permission(%{"id" => %{"_in" => ["X-Hasura-User-Id"]}}, tables)
    end

    test "Hasura's legacy REQ_USER_ID is the user id session variable", %{tables: tables} do
      assert {:ok, {:compare, "author_id", :eq, {:session, "x-hasura-user-id"}}} =
               permission(%{"author_id" => "req_user_id"}, tables)
    end

    test "literals are cast at parse time", %{tables: tables} do
      ref = "F2A0D6B4-6D0B-4D52-9E52-3A4B0C1D2E3F"

      assert {:ok,
              {:compare, "external_ref", :eq, {:literal, "f2a0d6b4-6d0b-4d52-9e52-3a4b0c1d2e3f"}}} =
               permission(%{"external_ref" => %{"_eq" => ref}}, tables)

      assert {:ok, {:compare, "status", :in, {:literal, ["draft"]}}} =
               permission(%{"status" => %{"_in" => ["draft"]}}, tables)
    end

    test "a literal that does not cast is an invalid literal", %{tables: tables} do
      assert {:error, [{["id", "_eq"], {:invalid_literal, {:invalid_value, "int8"}}}]} =
               permission(%{"id" => %{"_eq" => "abc"}}, tables)

      assert {:error, [{["status"], {:invalid_literal, {:invalid_value, "article_status"}}}]} =
               permission(%{"status" => "bogus"}, tables)
    end

    test "a null literal is kept for the compiler", %{tables: tables} do
      assert {:ok, {:compare, "editor_id", :eq, {:literal, nil}}} =
               permission(%{"editor_id" => %{"_eq" => nil}}, tables)
    end

    test "_is_null takes a JSON boolean, never a session value", %{tables: tables} do
      assert {:ok, {:compare, "editor_id", :is_null, {:literal, true}}} =
               permission(%{"editor_id" => %{"_is_null" => true}}, tables)

      assert {:error, [{["editor_id", "_is_null"], {:invalid_literal, {:invalid_value, "bool"}}}]} =
               permission(%{"editor_id" => %{"_is_null" => "X-Hasura-Flag"}}, tables)
    end

    test "_exists parses _where against its own table", %{tables: tables} do
      json = %{
        "_exists" => %{
          "_table" => %{"schema" => "public", "name" => "users"},
          "_where" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}}
        }
      }

      assert {:ok,
              {:exists, {"public", "users"},
               {:compare, "id", :eq, {:session, "x-hasura-user-id"}}}} =
               permission(json, tables)
    end

    test "_exists accepts a bare table name in the public schema", %{tables: tables} do
      json = %{"_exists" => %{"_table" => "users", "_where" => %{}}}
      assert {:ok, {:exists, {"public", "users"}, {:and, []}}} = permission(json, tables)
    end
  end

  describe "input mode" do
    test "every value is a literal", %{tables: tables} do
      assert {:ok, {:compare, "title", :eq, {:literal, "x-hasura-user-id"}}} =
               input(%{"title" => %{"_eq" => "x-hasura-user-id"}}, tables)

      assert {:ok, {:compare, "title", :eq, {:literal, "X-Hasura-User-Id"}}} =
               input(%{"title" => "X-Hasura-User-Id"}, tables)

      assert {:ok, {:compare, "title", :in, {:literal, ["X-Hasura-User-Id"]}}} =
               input(%{"title" => %{"_in" => ["X-Hasura-User-Id"]}}, tables)

      assert {:ok, {:compare, "assignees", :contains, {:literal, %{"X-Hasura-User-Id" => true}}}} =
               input(%{"assignees" => %{"_contains" => %{"X-Hasura-User-Id" => true}}}, tables)
    end

    test "a null operand is rejected", %{tables: tables} do
      assert {:error, [{["title", "_eq"], :null_operand}]} =
               input(%{"title" => %{"_eq" => nil}}, tables)

      assert {:error, [{["title"], :null_operand}]} = input(%{"title" => nil}, tables)

      assert {:error, [{["title", "_is_null"], :null_operand}]} =
               input(%{"title" => %{"_is_null" => nil}}, tables)
    end

    test "literals are cast", %{tables: tables} do
      assert {:error, [{["id", "_eq"], {:invalid_literal, {:invalid_value, "int8"}}}]} =
               input(%{"id" => %{"_eq" => "abc"}}, tables)
    end

    test "relationships and _exists are rejected", %{tables: tables} do
      assert {:error, [{["author"], :relationship_in_input}]} = input(%{"author" => %{}}, tables)

      assert {:error, [{["_exists"], :relationship_in_input}]} =
               input(%{"_exists" => %{"_table" => "users", "_where" => %{}}}, tables)
    end
  end

  describe "relationship keys" do
    test "the value parses against the target table", %{tables: tables} do
      assert {:ok, {:relationship, "author", {:compare, "email", :eq, {:literal, "a@b.c"}}}} =
               permission(%{"author" => %{"email" => %{"_eq" => "a@b.c"}}}, tables)
    end

    test "a target column unknown on the target is unknown", %{tables: tables} do
      assert {:error, [{["author", "title"], {:unknown_field, "title"}}]} =
               permission(%{"author" => %{"title" => %{"_eq" => "x"}}}, tables)
    end

    test "an empty relationship filter still names the relationship", %{tables: tables} do
      assert {:ok, {:relationship, "author", {:and, []}}} = permission(%{"author" => %{}}, tables)
    end
  end

  describe "errors" do
    test "an unknown key is an unknown field", %{tables: tables} do
      assert {:error, [{["nope"], {:unknown_field, "nope"}}]} = permission(%{"nope" => 1}, tables)

      assert {:error, [{["_or", "1", "nope"], {:unknown_field, "nope"}}]} =
               permission(%{"_or" => [%{}, %{"nope" => 1}]}, tables)
    end

    test "column comparison operators are unsupported", %{tables: tables} do
      for op <- ~w(_ceq _cne _cneq _cgt _clt _cgte _clte $ceq) do
        assert {:error, [{["author_id", ^op], {:unsupported, :column_comparison}}]} =
                 permission(%{"author_id" => %{op => "editor_id"}}, tables)
      end
    end

    test "_cast is unsupported", %{tables: tables} do
      assert {:error, [{["assignees", "_cast"], {:unsupported, :cast}}]} =
               permission(%{"assignees" => %{"_cast" => %{"String" => %{"_eq" => "x"}}}}, tables)
    end

    test "computed fields and remote relationships are unsupported", %{tables: tables} do
      unsupported = %{
        @articles => %{"word_count" => :computed_field, "crm" => :remote_relationship}
      }

      ctx = ctx(tables, @articles, @permission_limits, %{unsupported: unsupported})

      assert {:error, [{["word_count"], {:unsupported, :computed_field}}]} =
               BoolExp.parse(%{"word_count" => %{"_gt" => 1}}, :permission, ctx)

      assert {:error, [{["crm"], {:unsupported, :remote_relationship}}]} =
               BoolExp.parse(%{"crm" => %{}}, :permission, ctx)
    end

    test "unknown operators and operators the adapter does not support", %{tables: tables} do
      for op <- ~w(_foo _st_within _jsonb_path_exists eq) do
        assert {:error, [{["title", ^op], {:unknown_operator, ^op}}]} =
                 permission(%{"title" => %{op => "x"}}, tables)
      end
    end

    test "an operator whose left side does not fit the column is a type mismatch", %{
      tables: tables
    } do
      assert {:error, [{["id", "_like"], {:operator_type_mismatch, "_like", "int8"}}]} =
               permission(%{"id" => %{"_like" => "1%"}}, tables)

      assert {:error, [{["title", "_has_key"], {:operator_type_mismatch, "_has_key", "text"}}]} =
               permission(%{"title" => %{"_has_key" => "a"}}, tables)

      assert {:ok, {:compare, "email", :ilike, {:literal, "%@x"}}} =
               permission(%{"email" => %{"_ilike" => "%@x"}}, tables, @users)
    end

    test "a permission predicate on a json column is unsupported, _is_null included",
         %{tables: tables} do
      docs = {"public", "docs"}

      for value <- [
            %{"_is_null" => true},
            %{"$is_null" => false},
            %{"_eq" => %{"a" => 1}},
            %{"_is_null" => true, "_eq" => 1},
            %{},
            "x"
          ] do
        assert {:error, [{["raw"], {:unsupported, :json_column}}]} =
                 permission(%{"raw" => value}, tables, docs)
      end
    end

    test "input on a json column takes only _is_null", %{tables: tables} do
      docs = {"public", "docs"}

      assert {:ok, {:compare, "raw", :is_null, {:literal, true}}} =
               input(%{"raw" => %{"_is_null" => true}}, tables, docs)

      assert {:error, [{["raw"], {:unsupported, :json_column}}]} =
               input(%{"raw" => %{"_eq" => %{"a" => 1}}}, tables, docs)
    end

    test "_exists on an unknown table", %{tables: tables} do
      json = %{"_exists" => %{"_table" => %{"schema" => "nope", "name" => "x"}, "_where" => %{}}}

      assert {:error, [{["_exists", "_table"], {:unknown_table, {"nope", "x"}}}]} =
               permission(json, tables)
    end

    test "a non-string operator key keeps its error with a string path", %{tables: tables} do
      assert {:error, [{["title", ":eq"], {:unknown_operator, :eq}}]} =
               input(%{"title" => %{:eq => "x"}}, tables)

      assert {:error, [{["title", "1"], {:unknown_operator, 1}}, {["title", "_bad"], _}]} =
               input(%{"title" => %{1 => "x", "_bad" => "y"}}, tables)
    end

    test "malformed shapes are errors, never raises", %{tables: tables} do
      assert {:error, [{[], :invalid_expression}]} = permission("x", tables)
      assert {:error, [{[], :invalid_expression}]} = permission([%{}], tables)
      assert {:error, [{["_and"], :invalid_expression}]} = permission(%{"_and" => %{}}, tables)
      assert {:error, [{["_not"], :invalid_expression}]} = permission(%{"_not" => []}, tables)
      assert {:error, [{["_or", "0"], :invalid_expression}]} = permission(%{"_or" => [1]}, tables)
      assert {:error, [{["author"], :invalid_expression}]} = permission(%{"author" => 5}, tables)

      assert {:error, [{["_exists"], :invalid_expression}]} =
               permission(%{"_exists" => %{}}, tables)

      assert {:error, [{["_exists", "_table"], :invalid_expression}]} =
               permission(%{"_exists" => %{"_table" => 5, "_where" => %{}}}, tables)

      assert {:error, [{[], :invalid_expression}]} = permission(%{1 => 2}, tables)

      assert {:error, [{["id", "_eq"], {:invalid_literal, _}}]} =
               permission(%{"id" => %{"_eq" => [1]}}, tables)
    end

    test "errors accumulate in document order", %{tables: tables} do
      json = %{"_and" => [%{"a" => 1}, %{"id" => %{"_eq" => "x"}}, %{"b" => 1}]}

      assert {:error,
              [
                {["_and", "0", "a"], {:unknown_field, "a"}},
                {["_and", "1", "id", "_eq"], {:invalid_literal, _}},
                {["_and", "2", "b"], {:unknown_field, "b"}}
              ]} = permission(json, tables)
    end
  end

  describe "limits" do
    defp managers(0, inner), do: inner
    defp managers(n, inner), do: %{"manager" => managers(n - 1, inner)}

    defp nots(0), do: %{}
    defp nots(n), do: %{"_not" => nots(n - 1)}

    defp ors(n), do: %{"_or" => List.duplicate(%{"id" => %{"_eq" => 1}}, n)}

    test "binding depth over 15 is too deep", %{tables: tables} do
      assert {:ok, ast} = permission(managers(15, %{}), tables, @users)
      assert AST.binding_depth(ast) == 15

      assert {:error, [{path, :too_deep}]} = permission(managers(16, %{}), tables, @users)
      assert path == List.duplicate("manager", 16)
    end

    test "_exists counts towards binding depth", %{tables: tables} do
      json = managers(15, %{"_exists" => %{"_table" => "users", "_where" => %{}}})
      assert {:error, [{_path, :too_deep}]} = permission(json, tables, @users)
    end

    test "syntactic depth over the permission limit is too deep", %{tables: tables} do
      assert {:ok, ast} = permission(nots(31), tables)
      assert AST.syntactic_depth(ast) == 32
      assert {:error, [{path, :too_deep}]} = permission(nots(32), tables)
      assert path == List.duplicate("_not", 32)
    end

    test "single-key objects do not add a level", %{tables: tables} do
      json = Enum.reduce(1..31, %{}, fn _level, inner -> %{"_and" => [inner]} end)
      assert {:ok, ast} = permission(json, tables)
      assert AST.syntactic_depth(ast) == 32
    end

    test "syntactic depth over the input limit is too deep", %{tables: tables} do
      assert {:ok, _ast} = input(nots(7), tables)
      assert {:error, [{_path, :too_deep}]} = input(nots(8), tables)
    end

    test "node count over the limit is too large", %{tables: tables} do
      assert {:ok, ast} = permission(ors(999), tables)
      assert AST.node_count(ast) == 1000
      assert {:error, [{_path, :too_large}]} = permission(ors(1000), tables)

      assert {:ok, _ast} = input(ors(99), tables)
      assert {:error, [{_path, :too_large}]} = input(ors(100), tables)
    end

    test "invalid nodes count towards the limit", %{tables: tables} do
      json = %{"_or" => List.duplicate(%{"nope" => 1}, 5000)}
      assert {:error, errors} = permission(json, tables)
      assert Enum.count_until(errors, 1002) <= 1001
      assert List.last(errors) |> elem(1) == :too_large
    end
  end
end

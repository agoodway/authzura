defmodule Authzura.CompilerTest do
  use Authzura.DataCase, async: true

  import Authzura.SqlHelper

  alias Authzura.{Compiler, FilterFixture}
  alias Authzura.Compiler.Aliases
  alias Authzura.Model.{Column, Table}
  alias Ecto.Adapters.SQL
  alias Ecto.{Query, SubQuery}

  doctest Aliases
  doctest Compiler, only: [public_reason: 1]

  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @order {"public", "Order"}
  @view {"public", "published_articles"}

  setup do
    %{
      tables: FilterFixture.tables(Repo),
      session: FilterFixture.session(%{"x-hasura-user-id" => "1"})
    }
  end

  defp compiled(tables, ref, json, session) do
    {:ok, dynamic} = FilterFixture.compile(tables, ref, json, session)
    FilterFixture.scoped(ref, dynamic, pk(ref))
  end

  defp sql(tables, ref, json, session), do: tables |> compiled(ref, json, session) |> sql()

  defp pk(@order), do: "Id"
  defp pk(_ref), do: "id"

  # Every subquery reachable from the query's where clauses, depth first.
  defp subqueries(%Query{wheres: wheres}) do
    Enum.flat_map(wheres, fn %{subqueries: subs} ->
      Enum.flat_map(subs, fn %SubQuery{query: query} -> [query | subqueries(query)] end)
    end)
  end

  describe "comparisons" do
    test "a non-null column compiles to plain =", %{tables: t, session: s} do
      assert sql(t, @articles, %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}, s) ==
               ~s|SELECT a0."id" FROM "public"."articles" AS a0 WHERE (a0."author_id" = $1::bigint)|
    end

    test "a nullable column compiles to Hasura's null-aware form", %{tables: t, session: s} do
      assert sql(t, @articles, %{"editor_id" => %{"_eq" => 2}}, s) ==
               ~s|SELECT a0."id" FROM "public"."articles" AS a0 WHERE (| <>
                 ~s|(a0."editor_id" = $1::bigint) OR ((a0."editor_id" IS NULL) AND ($2::bigint IS NULL)))|
    end

    # A session value is never NULL, so the null arm is always false and is
    # left out: same truth table, and a plain `col = $n` plans better.
    test "a session value on a nullable column compiles to plain = and <>", %{
      tables: t,
      session: s
    } do
      assert sql(t, @articles, %{"editor_id" => %{"_eq" => "X-Hasura-User-Id"}}, s) ==
               ~s|SELECT a0."id" FROM "public"."articles" AS a0 WHERE (a0."editor_id" = $1::bigint)|

      assert sql(t, @articles, %{"editor_id" => %{"_neq" => "X-Hasura-User-Id"}}, s) ==
               ~s|SELECT a0."id" FROM "public"."articles" AS a0 WHERE (a0."editor_id" != $1::bigint)|

      assert sql(
               t,
               @articles,
               %{"author" => %{"manager_id" => %{"_eq" => "X-Hasura-User-Id"}}},
               s
             ) =~
               ~s|(su0."manager_id" = $1::bigint)|
    end

    test "input mode uses plain = on a nullable column", %{tables: t, session: s} do
      ast = FilterFixture.parse!(t, @articles, %{"editor_id" => %{"_eq" => 2}})
      {:ok, dynamic} = Compiler.compile(ast, FilterFixture.ctx(t, @articles, s, mode: :input))
      {sql, [2]} = SQL.to_sql(:all, Repo, FilterFixture.scoped(@articles, dynamic))
      assert sql =~ ~s|WHERE (a0."editor_id" = $1::bigint)|
    end

    test "empty groups are constant", %{tables: t, session: s} do
      assert sql(t, @articles, %{"_and" => []}, s) =~ "WHERE (TRUE)"
      assert sql(t, @articles, %{"_or" => []}, s) =~ "WHERE (FALSE)"
    end
  end

  describe "relationships" do
    test "one correlated EXISTS per node, on the prefixed target", %{tables: t, session: s} do
      assert sql(t, @articles, %{"author" => %{"org_id" => %{"_eq" => 1}}}, s) ==
               ~s|SELECT a0."id" FROM "public"."articles" AS a0 WHERE | <>
                 ~s|(exists((SELECT 1 FROM "public"."users" AS su0 | <>
                 ~s|WHERE ((su0."id" = a0."author_id") AND (su0."org_id" = $1::bigint)))))|
    end

    test "three hops nest three EXISTS with aliases 1, 2 and 3", %{tables: t, session: s} do
      filter = %{"article" => %{"author" => %{"org" => %{"name" => %{"_eq" => "one"}}}}}
      query = compiled(t, @comments, filter, s)

      assert Enum.map(subqueries(query), & &1.from.as) == [
               Aliases.at(1),
               Aliases.at(2),
               Aliases.at(3)
             ]

      sql = sql(query)
      assert [_, _, _] = Regex.scan(~r/exists\(/, sql)
      assert sql =~ ~s|"public"."organizations"|
    end

    test "sibling nodes get separate EXISTS clauses at the same alias", %{tables: t, session: s} do
      filter = %{
        "_and" => [
          %{"comments" => %{"author_id" => %{"_eq" => 1}}},
          %{"comments" => %{"body" => %{"_eq" => "b"}}}
        ]
      }

      query = compiled(t, @articles, filter, s)
      assert Enum.map(subqueries(query), & &1.from.as) == [Aliases.at(1), Aliases.at(1)]
    end

    test "a multi-column mapping correlates every pair", %{tables: t, session: s} do
      sql = sql(t, {"public", "membership_notes"}, %{"membership" => %{}}, s)
      assert sql =~ ~s|(so0."org_id" = m0."org_id")|
      assert sql =~ ~s|(so0."user_id" = m0."user_id")|
    end
  end

  describe "_exists" do
    test "is uncorrelated: no parent_as", %{tables: t, session: s} do
      filter = %{
        "_exists" => %{
          "_table" => "users",
          "_where" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}, "is_admin" => %{"_eq" => true}}
        }
      }

      [sub] = t |> compiled(@articles, filter, s) |> subqueries()
      assert sub.from.as == Aliases.at(1)
      refute inspect(sub.wheres) =~ "parent_as"
    end

    test "public.users and audit.users are distinct schema-qualified sources", %{
      tables: t,
      session: s
    } do
      exists = fn schema ->
        %{"_exists" => %{"_table" => %{"schema" => schema, "name" => "users"}, "_where" => %{}}}
      end

      assert sql(t, @articles, exists.("audit"), s) =~ ~s|FROM "audit"."users" AS|
      assert sql(t, @articles, exists.("public"), s) =~ ~s|FROM "public"."users" AS|
      refute sql(t, @articles, exists.("audit"), s) =~ ~s|"public"."users"|
    end
  end

  describe "quoting and views" do
    test ~s("Order" and "line item" are quoted), %{tables: t, session: s} do
      assert sql(t, @order, %{"line item" => %{"_eq" => "widget"}}, s) =~
               ~s|FROM "public"."Order" AS O0 WHERE ((O0."line item" = $1::varchar) OR | <>
                 ~s|((O0."line item" IS NULL) AND ($2::varchar IS NULL)))|
    end

    test "a view compiles null-aware forms and a manual relationship", %{tables: t, session: s} do
      assert sql(t, @view, %{"author_id" => %{"_eq" => 1}}, s) =~
               ~s|OR ((p0."author_id" IS NULL) AND ($2::bigint IS NULL))|

      assert sql(t, @view, %{"author" => %{}}, s) =~
               ~s|exists((SELECT 1 FROM "public"."users" AS su0 WHERE ((su0."id" = p0."author_id")|
    end
  end

  describe "session errors" do
    test "a missing session variable", %{tables: t} do
      assert FilterFixture.compile(
               t,
               @articles,
               %{"author" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}}},
               FilterFixture.session()
             ) == {:error, {:missing_session_variable, "x-hasura-user-id"}}
    end

    test "a value that does not cast", %{tables: t} do
      session = FilterFixture.session(%{"x-hasura-user-id" => "abc"})

      assert {:error, {:invalid_session_value, "x-hasura-user-id", {:invalid_value, _type}}} =
               FilterFixture.compile(
                 t,
                 @articles,
                 %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}},
                 session
               )
    end

    test "a malformed array session value", %{tables: t} do
      session = FilterFixture.session(%{"x-hasura-ids" => "{1,"})

      assert {:error, {:invalid_session_value, "x-hasura-ids", _reason}} =
               FilterFixture.compile(t, @articles, %{"id" => %{"_in" => "X-Hasura-Ids"}}, session)
    end
  end

  describe "validation mode" do
    test "type-checks session references without values", %{tables: t} do
      ast = FilterFixture.parse!(t, @articles, %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}})
      assert {:ok, _dynamic} = Compiler.compile(ast, FilterFixture.ctx(t, @articles, :validate))
    end

    test "rejects an unknown column", %{tables: t} do
      ast = {:compare, "no_such_col", :eq, {:session, "x-hasura-user-id"}}

      assert {:error, {:unknown_column, @articles, "no_such_col"}} =
               Compiler.compile(ast, FilterFixture.ctx(t, @articles, :validate))
    end

    test "rejects a session value on a column kind that cannot be bound", %{tables: t} do
      %{columns: %{"title" => title} = columns} = articles = t[@articles]
      columns = Map.put(columns, "title", %{title | base_kind: :other})
      tables = Map.put(t, @articles, %{articles | columns: columns})
      ast = {:compare, "title", :eq, {:session, "x-hasura-user-id"}}

      assert {:error, {:unsupported_type, "text"}} =
               Compiler.compile(ast, FilterFixture.ctx(tables, @articles, :validate))
    end

    test "a malformed node is an error, also after a valid sibling", %{tables: t} do
      ctx = FilterFixture.ctx(t, @articles, :validate)
      assert Compiler.compile(nil, ctx) == {:error, :invalid_filter}
      assert Compiler.compile({:or, [{:and, []}, {:bogus}]}, ctx) == {:error, :invalid_filter}
      assert Compiler.compile({:and, [{:bogus}, {:and, []}]}, ctx) == {:error, :invalid_filter}
    end

    test "binding depth 15 compiles and executes", %{tables: t, session: s} do
      ast = Enum.reduce(1..15, {:and, []}, fn _level, inner -> {:exists, @articles, inner} end)
      {:ok, dynamic} = Compiler.compile(ast, FilterFixture.ctx(t, @articles, s))
      query = FilterFixture.scoped(@articles, dynamic)

      assert List.last(subqueries(query)).from.as == Aliases.at(15)
      assert Repo.all(query) == []
    end

    test "malformed operands and sessions are errors, not raises", %{tables: t, session: s} do
      weird = {:compare, "id", :eq, {:weird, 1}}
      nil_list = {:compare, "id", :in, {:literal, nil}}
      not_a_list = {:compare, "id", :in, {:literal, 1}}
      session_ref = {:compare, "id", :eq, {:session, "x-hasura-user-id"}}

      for ast <- [weird, nil_list, not_a_list], session <- [s, :validate] do
        assert Compiler.compile(ast, FilterFixture.ctx(t, @articles, session)) ==
                 {:error, :invalid_filter}
      end

      for session <- [%{"x-hasura-user-id" => "1"}, nil] do
        assert Compiler.compile(session_ref, FilterFixture.ctx(t, @articles, session)) ==
                 {:error, :invalid_filter}
      end
    end

    test "a non-column entry is an error, not a raise", %{tables: t, session: s} do
      table = t[@articles]
      broken = %{table | columns: Map.put(table.columns, "id", :not_a_column)}
      ctx = %{FilterFixture.ctx(t, @articles, s) | table: broken}

      assert Compiler.compile({:compare, "id", :eq, {:literal, 1}}, ctx) ==
               {:error, :invalid_filter}

      assert Compiler.compile({:compare, "id", :bogus, {:literal, 1}}, ctx) ==
               {:error, {:unsupported_operator, :bogus}}
    end

    test "rejects binding depth past the alias pool", %{tables: t} do
      ast =
        Enum.reduce(1..16, {:and, []}, fn _level, inner -> {:exists, @articles, inner} end)

      assert {:error, :too_deep} =
               Compiler.compile(ast, FilterFixture.ctx(t, @articles, :validate))
    end
  end

  describe "pushdown/3" do
    defmodule NoPushdownAdapter do
      @moduledoc false
    end

    defp probe do
      %Table{
        schema: "public",
        name: "t",
        columns: %{
          "id" => %Column{
            name: "id",
            pg_type: "int8",
            base_kind: :bigint,
            ecto_type: :integer,
            eq_leakproof?: true
          }
        }
      }
    end

    test "an adapter without index_pushdown?/2 pushes nothing" do
      ast = {:compare, "id", :eq, {:literal, 1}}

      assert Compiler.pushdown(ast, probe(), Authzura.Adapters.Postgres) == {:and, [ast]}
      assert Compiler.pushdown(ast, probe(), NoPushdownAdapter) == nil
    end

    test "an _in of more than 100 values is not pushed" do
      at_cap = {:compare, "id", :in, {:literal, Enum.to_list(1..100)}}
      over_cap = {:compare, "id", :in, {:literal, Enum.to_list(1..101)}}

      assert Compiler.pushdown(at_cap, probe(), Authzura.Adapters.Postgres) == {:and, [at_cap]}
      assert Compiler.pushdown(over_cap, probe(), Authzura.Adapters.Postgres) == nil
    end
  end
end

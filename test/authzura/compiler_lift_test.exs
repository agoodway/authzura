defmodule Authzura.CompilerLiftTest do
  # Scratch tables are created inside each test's sandbox transaction, so
  # they never reach another test and roll back with it.
  use Authzura.DataCase, async: true

  import Authzura.SqlHelper

  alias Authzura.{Compiler, FilterFixture}
  alias Authzura.Compiler.Aliases
  alias Authzura.Gen.Catalog
  alias Authzura.Model.{Relationship, Table}
  alias Ecto.Adapters.SQL

  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @notes {"public", "membership_notes"}
  @users {"public", "users"}
  @view {"public", "published_articles"}

  # Root ids of the rows the row-level tests insert, far above every seed.
  @base 900_000

  setup do
    %{
      tables: FilterFixture.tables(Repo),
      session: FilterFixture.session(%{"x-hasura-user-id" => "1"})
    }
  end

  defp lift(tables, ref, json, session, budget \\ 7) do
    tables
    |> FilterFixture.parse!(ref, json)
    |> Compiler.lift(FilterFixture.ctx(tables, ref, session), budget)
  end

  defp lifted_query(ref, lifted) do
    ref
    |> FilterFixture.root()
    |> Compiler.apply_joins(lifted)
    |> where(^lifted.condition)
  end

  defp lifted_sql(tables, ref, json, session, budget \\ 7) do
    {:ok, lifted} = lift(tables, ref, json, session, budget)
    ref |> lifted_query(lifted) |> sql()
  end

  defp compiled_sql(tables, ref, json, session) do
    {:ok, dynamic} = FilterFixture.compile(tables, ref, json, session)
    ref |> FilterFixture.scoped(dynamic) |> sql()
  end

  # Nothing lifts: no joins, and the very SQL `compile/2` gives, with its EXISTS.
  defp assert_fallback(tables, ref, json, session, budget \\ 7) do
    assert {:ok, %{joins: [], condition: condition}} = lift(tables, ref, json, session, budget)
    sql = ref |> FilterFixture.scoped(condition) |> sql()
    assert sql == compiled_sql(tables, ref, json, session)
    refute sql =~ "JOIN"
    assert occurrences(sql, "exists(") > 0
    sql
  end

  defp put_relationship(tables, ref, %Relationship{name: name} = relationship),
    do: update_in(tables, [ref, Access.key!(:relationships)], &Map.put(&1, name, relationship))

  defp object(name, target, mapping),
    do: %Relationship{name: name, kind: :object, target: target, mapping: mapping}

  # Runs `ddl`, introspects `names` (in `public`) and merges them into `tables`.
  defp scratch(tables, ddl, names) do
    Map.merge(tables, FilterFixture.scratch!(Repo, ddl, names))
  end

  # The root ids `query` returns, in order, as a sorted list (so duplicates show).
  defp ids(query), do: query |> where([r], field(r, "id") >= ^@base) |> Repo.all() |> Enum.sort()

  defp lifted_ids(tables, ref, json, session) do
    {:ok, lifted} = lift(tables, ref, json, session)
    ref |> lifted_query(lifted) |> ids()
  end

  defp unlifted_ids(tables, ref, json, session) do
    {:ok, dynamic} = FilterFixture.compile(tables, ref, json, session)
    ref |> FilterFixture.scoped(dynamic) |> ids()
  end

  test "Catalog nullable relationships match introspected object mappings", %{tables: tables} do
    nullable =
      for {_ref, %Table{kind: :table, columns: columns, relationships: relationships}} <- tables,
          {name, %Relationship{kind: :object, mapping: mapping}} <- relationships,
          Enum.any?(mapping, fn {local, _remote} -> Map.fetch!(columns, local).nullable? end),
          uniq: true,
          do: name

    assert Enum.sort(nullable) == Enum.sort(Catalog.nullable_relationships())
  end

  test "an adapter without the optional lossless-pair callback does not lift", %{
    tables: tables,
    session: session
  } do
    ast = FilterFixture.parse!(tables, @comments, %{"article" => %{}})
    # Empty comparisons compile without any adapter operators, isolating the callback default.
    ctx = %{FilterFixture.ctx(tables, @comments, session) | adapter: __MODULE__}

    assert {:ok, %{joins: [], condition: condition}} =
             Compiler.lift(ast, ctx, 7)

    assert {:ok, ^condition} = Compiler.compile(ast, ctx)
  end

  describe "completeness" do
    test "only a nonempty lift with no remaining EXISTS is complete", %{tables: t, session: s} do
      deep = %{"article" => %{"author" => %{"org" => %{"id" => %{"_eq" => 1}}}}}
      assert {:ok, %{joins: [_, _, _]}} = lift(t, @comments, deep, s)
      assert {:ok, %{joins: [_]}} = lift(t, @comments, %{"article" => %{}}, s)

      # Boolean operators over comparisons need no EXISTS and remain complete.
      for child <- [
            %{"_or" => [%{"id" => %{"_eq" => 1}}, %{"id" => %{"_eq" => 2}}]},
            %{"_not" => %{"id" => %{"_eq" => 1}}}
          ] do
        assert {:ok, %{joins: [_]}} =
                 lift(t, @comments, %{"article" => child}, s)
      end

      for filter <- [%{}, %{"id" => %{"_eq" => 1}}] do
        assert {:ok, %{joins: []}} = lift(t, @comments, filter, s)
      end

      assert {:ok, %{joins: []}} = lift(t, @comments, deep, s, 2)
      assert {:ok, %{joins: []}} = lift(t, @comments, deep, s, 0)
    end

    test "array, _exists, _or and _not subtrees fall back in full", %{
      tables: t,
      session: s
    } do
      for child <- [
            %{"comments" => %{}},
            %{"_exists" => %{"_table" => "users", "_where" => %{}}},
            %{"_or" => [%{"author" => %{}}, %{"id" => %{"_eq" => 1}}]},
            %{"_not" => %{"author" => %{}}}
          ] do
        assert {:ok, %{joins: []} = lifted} =
                 lift(t, @comments, %{"article" => child}, s)

        assert sql(lifted_query(@comments, lifted)) =~ "exists("
      end

      filter = %{"_and" => [%{"article" => %{}}, %{"_not" => %{"article" => %{}}}]}
      assert {:ok, %{joins: []}} = lift(t, @comments, filter, s)
      # A later successful hop must preserve an earlier incomplete subtree.
      reversed = %{"_and" => [%{"_not" => %{"article" => %{}}}, %{"article" => %{}}]}
      assert {:ok, %{joins: []}} = lift(t, @comments, reversed, s)
      ast = FilterFixture.parse!(t, @comments, filter)

      assert {:ok, %{joins: []}} =
               Compiler.lift_public(ast, FilterFixture.ctx(t, @comments, s), 7)
    end
  end

  describe "lifted chains" do
    test "an _and chain of object relationships onto strict keys lifts to inner joins", %{
      tables: t,
      session: s
    } do
      filter = %{"article" => %{"author" => %{"org" => %{"name" => %{"_eq" => "one"}}}}}

      assert {:ok, %{joins: joins}} = lift(t, @comments, filter, s)

      assert Enum.map(joins, &{&1.source, &1.binding}) == [
               {@articles, Aliases.at(1)},
               {@users, Aliases.at(2)},
               {{"public", "organizations"}, Aliases.at(3)}
             ]

      sql = lifted_sql(t, @comments, filter, s)
      assert occurrences(sql, "INNER JOIN") == 3
      assert occurrences(sql, "exists(") == 0

      assert sql ==
               ~s|SELECT c0."id" FROM "public"."comments" AS c0 | <>
                 ~s|INNER JOIN "public"."articles" AS a1 ON a1."id" = c0."article_id" | <>
                 ~s|INNER JOIN "public"."users" AS u2 ON u2."id" = a1."author_id" | <>
                 ~s|INNER JOIN "public"."organizations" AS o3 ON o3."id" = u2."org_id" | <>
                 ~s|WHERE ((a1."id" = c0."article_id") AND | <>
                 ~s|((u2."id" = a1."author_id") AND ((o3."id" = u2."org_id") AND (o3."name" = $1::varchar))))|
    end

    test "the condition re-checks every ON equality", %{tables: t, session: s} do
      filter = %{"membership" => %{"level" => %{"_gt" => 1}}}
      {:ok, %{joins: [join]} = lifted} = lift(t, @notes, filter, s)
      sql = @notes |> lifted_query(lifted) |> sql()
      [_select, where] = String.split(sql, " WHERE ")

      on = ~s|(o1."org_id" = m0."org_id") AND (o1."user_id" = m0."user_id")|
      assert sql =~ ~s|ON #{on} WHERE|
      assert where =~ on
      assert join.binding == Aliases.at(1)
    end

    test "session variables inside the chain bind as in compile/2", %{tables: t, session: s} do
      filter = %{"article" => %{"author" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}}}}
      {:ok, lifted} = lift(t, @comments, filter, s)
      {sql, params} = SQL.to_sql(:all, Repo, lifted_query(@comments, lifted))

      assert occurrences(sql, "INNER JOIN") == 2
      assert sql =~ ~s|(u2."id" = $1::bigint)|
      assert params == [1]

      assert lift(t, @comments, filter, FilterFixture.session()) ==
               FilterFixture.compile(t, @comments, filter, FilterFixture.session())

      assert {:error, {:missing_session_variable, "x-hasura-user-id"}} =
               t
               |> FilterFixture.parse!(@comments, filter)
               |> Compiler.lift_public(
                 FilterFixture.ctx(t, @comments, FilterFixture.session()),
                 7
               )
    end

    test "nullable editor and composite org_memberships mappings lift", %{tables: t, session: s} do
      editor = lifted_sql(t, @articles, %{"editor" => %{"role" => %{"_eq" => "x"}}}, s)
      assert editor =~ ~s|INNER JOIN "public"."users" AS u1 ON u1."id" = a0."editor_id"|
      assert occurrences(editor, "exists(") == 0

      membership = lifted_sql(t, @notes, %{"membership" => %{}}, s)

      assert membership =~
               ~s|INNER JOIN "public"."org_memberships" AS o1 | <>
                 ~s|ON (o1."org_id" = m0."org_id") AND (o1."user_id" = m0."user_id")|
    end

    test "a manual mapping onto the key lifts, from a view root", %{tables: t, session: s} do
      sql = lifted_sql(t, @view, %{"author" => %{"org_id" => %{"_eq" => 1}}}, s)
      assert sql =~ ~s|INNER JOIN "public"."users" AS u1 ON u1."id" = p0."author_id"|
      assert occurrences(sql, "exists(") == 0
    end

    test "the same relationship twice takes two joins", %{tables: t, session: s} do
      filter = %{
        "_and" => [
          %{"author" => %{"org_id" => %{"_eq" => 1}}},
          %{"author" => %{"role" => %{"_eq" => "x"}}}
        ]
      }

      {:ok, %{joins: joins}} = lift(t, @articles, filter, s)
      assert Enum.map(joins, & &1.binding) == [Aliases.at(1), Aliases.at(2)]

      sql = lifted_sql(t, @articles, filter, s)
      assert sql =~ ~s|INNER JOIN "public"."users" AS u1 ON u1."id" = a0."author_id"|
      assert sql =~ ~s|INNER JOIN "public"."users" AS u2 ON u2."id" = a0."author_id"|
    end

    test "an array subtree falls back with byte-identical compile SQL", %{tables: t, session: s} do
      filter = %{"article" => %{"comments" => %{"body" => %{"_eq" => "b"}}}}
      assert_fallback(t, @comments, filter, s)
    end

    test "an _or subtree falls back with byte-identical compile SQL", %{tables: t, session: s} do
      filter = %{
        "article" => %{"_or" => [%{"author" => %{"id" => %{"_eq" => 1}}}, %{"editor" => %{}}]}
      }

      assert_fallback(t, @comments, filter, s)
    end

    test "complete siblings use distinct aliases", %{tables: t, session: s} do
      filter = %{
        "_and" => [
          %{"author" => %{"manager" => %{"role" => %{"_eq" => "x"}}}},
          %{"author" => %{"org" => %{}}},
          %{"author" => %{}}
        ]
      }

      assert {:ok, %{joins: joins}} = lift(t, @articles, filter, s)
      join_bindings = Enum.map(joins, & &1.binding)
      assert join_bindings == Enum.map(1..5, &Aliases.at/1)
      bindings = Enum.uniq([Aliases.at(0) | join_bindings])
      assert [_, _, _, _, _, _] = bindings
    end

    test "siblings with a nested _exists fall back in full", %{tables: t, session: s} do
      filter = %{
        "_and" => [
          %{"author" => %{"manager" => %{"role" => %{"_eq" => "x"}}}},
          %{"author" => %{"org" => %{}}},
          %{"_exists" => %{"_table" => "users", "_where" => %{"is_admin" => %{"_eq" => true}}}},
          %{"author" => %{"articles" => %{}}}
        ]
      }

      assert_fallback(t, @articles, filter, s)
    end
  end

  describe "fallbacks keep compile/2's SQL" do
    test "under _or or _not", %{tables: t, session: s} do
      rel = %{"author" => %{"org_id" => %{"_eq" => 1}}}

      assert_fallback(t, @articles, %{"_or" => [rel, %{"id" => %{"_eq" => 2}}]}, s)
      assert_fallback(t, @articles, %{"_not" => rel}, s)
    end

    test "_and inside _or", %{tables: t, session: s} do
      filter = %{"_or" => [%{"_and" => [%{"author" => %{}}, %{"editor" => %{}}]}, %{}]}
      assert_fallback(t, @articles, filter, s)
    end

    test "an array relationship", %{tables: t, session: s} do
      assert_fallback(t, @articles, %{"comments" => %{"body" => %{"_eq" => "b"}}}, s)
    end

    # A manual array relationship whose mapping is the target's whole key
    # passes rules 3 and 4: only its kind keeps the EXISTS.
    test "a manual array relationship onto the whole key", %{tables: t, session: s} do
      array = %Relationship{
        name: "own_article",
        kind: :array,
        target: @articles,
        mapping: [{"article_id", "id"}]
      }

      t = put_relationship(t, @comments, array)
      assert_fallback(t, @comments, %{"own_article" => %{"title" => %{"_eq" => "x"}}}, s)
    end

    test "nothing inside an EXISTS that did not lift", %{tables: t, session: s} do
      assert_fallback(t, @users, %{"articles" => %{"author" => %{"org" => %{}}}}, s)
    end

    test "a manual mapping onto non-key columns", %{tables: t, session: s} do
      t = put_relationship(t, @comments, object("peer", @articles, [{"author_id", "author_id"}]))
      assert_fallback(t, @comments, %{"peer" => %{"id" => %{"_eq" => 1}}}, s)
    end

    test "a mapping that covers only part of a composite key", %{tables: t, session: s} do
      partial = object("org_member", {"public", "org_memberships"}, [{"org_id", "org_id"}])
      t = put_relationship(t, @notes, partial)
      assert_fallback(t, @notes, %{"org_member" => %{}}, s)
    end

    test "a view target", %{tables: t, session: s} do
      # Given a key, only the `kind: :view` check keeps the EXISTS.
      t =
        t
        |> update_in([@view], &%{&1 | strict_key?: true, primary_key: ["id"]})
        |> put_relationship(@comments, object("published", @view, [{"article_id", "id"}]))

      assert_fallback(t, @comments, %{"published" => %{"title" => %{"_eq" => "x"}}}, s)
    end

    test "a deferrable key", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE TABLE lift_def (id bigint PRIMARY KEY DEFERRABLE)",
            "CREATE TABLE lift_def_ref (id bigint PRIMARY KEY, def_id bigint)"
          ],
          ~w(lift_def lift_def_ref)
        )
        |> put_relationship(
          {"public", "lift_def_ref"},
          object("def", {"public", "lift_def"}, [{"def_id", "id"}])
        )

      refute t[{"public", "lift_def"}].strict_key?
      assert_fallback(t, {"public", "lift_def_ref"}, %{"def" => %{}}, s)
    end

    test "an inheritance parent", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE TABLE lift_parent (id bigint PRIMARY KEY)",
            "CREATE TABLE lift_child () INHERITS (lift_parent)",
            "CREATE TABLE lift_parent_ref (id bigint PRIMARY KEY, parent_id bigint)",
            "INSERT INTO lift_parent VALUES (1)",
            "INSERT INTO lift_child VALUES (1)",
            "INSERT INTO lift_parent_ref VALUES (#{@base}, 1)"
          ],
          ~w(lift_parent lift_parent_ref)
        )
        |> put_relationship(
          {"public", "lift_parent_ref"},
          object("parent", {"public", "lift_parent"}, [{"parent_id", "id"}])
        )

      refute t[{"public", "lift_parent"}].strict_key?
      assert_fallback(t, {"public", "lift_parent_ref"}, %{"parent" => %{}}, s)

      # The parent's scan sees id 1 twice: a join would return the row twice.
      assert %{rows: [[2]]} =
               Repo.query!(
                 "SELECT count(*) FROM lift_parent_ref r JOIN lift_parent p ON p.id = r.parent_id"
               )
    end

    test "a float8 local against a bigint key (9007199254740992 / 9007199254740993)", %{
      tables: t,
      session: s
    } do
      t =
        t
        |> scratch(
          [
            "CREATE TABLE lift_big (id bigint PRIMARY KEY)",
            "CREATE TABLE lift_float (id bigint PRIMARY KEY, big double precision)",
            "INSERT INTO lift_big VALUES (9007199254740992), (9007199254740993)",
            "INSERT INTO lift_float VALUES (#{@base}, 9007199254740992)"
          ],
          ~w(lift_big lift_float)
        )
        |> put_relationship(
          {"public", "lift_float"},
          object("big_key", {"public", "lift_big"}, [{"big", "id"}])
        )

      ref = {"public", "lift_float"}
      assert_fallback(t, ref, %{"big_key" => %{}}, s)
      assert unlifted_ids(t, ref, %{"big_key" => %{}}, s) == [@base]

      # Both keys equal the float: the lifted join would return the row twice.
      assert %{rows: [[2]]} =
               Repo.query!("SELECT count(*) FROM lift_float f JOIN lift_big b ON b.id = f.big")
    end

    test "citext and bpchar pairs", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE TABLE lift_text_key (k text PRIMARY KEY)",
            "CREATE TABLE lift_text_ref (id bigint PRIMARY KEY, ci citext, bp char(4))"
          ],
          ~w(lift_text_key lift_text_ref)
        )
        |> put_relationship(
          {"public", "lift_text_ref"},
          object("by_ci", {"public", "lift_text_key"}, [{"ci", "k"}])
        )
        |> put_relationship(
          {"public", "lift_text_ref"},
          object("by_bp", {"public", "lift_text_key"}, [{"bp", "k"}])
        )

      assert_fallback(t, {"public", "lift_text_ref"}, %{"by_ci" => %{}}, s)
      assert_fallback(t, {"public", "lift_text_ref"}, %{"by_bp" => %{}}, s)
    end

    # Text equality follows the collation the comparison resolves to, which
    # can be the local column's nondeterministic one while the key is
    # unique only under its own: `'a'` then matches both `'A'` and `'a'`.
    # Introspection does not record collations, so no text-family pair lifts.
    @tag :icu
    test "varchar → text and text → text pairs: a nondeterministic collation multiplies rows",
         %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE COLLATION lift_ci (provider = icu, locale = 'und-u-ks-level2', " <>
              "deterministic = false)",
            "CREATE TABLE lift_code (k text PRIMARY KEY)",
            "CREATE TABLE lift_code_ref (id bigint PRIMARY KEY, " <>
              "vc varchar(8) COLLATE lift_ci, tx text COLLATE lift_ci)",
            "INSERT INTO lift_code VALUES ('A'), ('a')",
            "INSERT INTO lift_code_ref VALUES (#{@base}, 'a', 'a')"
          ],
          ~w(lift_code lift_code_ref)
        )
        |> put_relationship(
          {"public", "lift_code_ref"},
          object("by_vc", {"public", "lift_code"}, [{"vc", "k"}])
        )
        |> put_relationship(
          {"public", "lift_code_ref"},
          object("by_tx", {"public", "lift_code"}, [{"tx", "k"}])
        )

      ref = {"public", "lift_code_ref"}
      assert_fallback(t, ref, %{"by_vc" => %{}}, s)
      assert_fallback(t, ref, %{"by_tx" => %{}}, s)
      assert unlifted_ids(t, ref, %{"by_vc" => %{}}, s) == [@base]

      assert %{rows: [[2]]} =
               Repo.query!("SELECT count(*) FROM lift_code_ref r JOIN lift_code c ON c.k = r.vc")
    end

    @tag :temporal_key
    test "a temporal key the mapping covers only in part", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE EXTENSION IF NOT EXISTS btree_gist",
            "CREATE TABLE lift_tp (id bigint, valid daterange, " <>
              "PRIMARY KEY (id, valid WITHOUT OVERLAPS))",
            "CREATE TABLE lift_tp_ref (id bigint PRIMARY KEY, tp_id bigint)",
            "INSERT INTO lift_tp VALUES (1, '[2026-01-01,2026-02-01)'), " <>
              "(1, '[2026-03-01,2026-04-01)')",
            "INSERT INTO lift_tp_ref VALUES (#{@base}, 1)"
          ],
          ~w(lift_tp lift_tp_ref)
        )
        |> put_relationship(
          {"public", "lift_tp_ref"},
          object("tp", {"public", "lift_tp"}, [{"tp_id", "id"}])
        )

      assert %Table{strict_key?: true, primary_key: ["id", "valid"]} = t[{"public", "lift_tp"}]
      ref = {"public", "lift_tp_ref"}
      assert_fallback(t, ref, %{"tp" => %{}}, s)
      assert unlifted_ids(t, ref, %{"tp" => %{}}, s) == [@base]

      assert %{rows: [[2]]} =
               Repo.query!("SELECT count(*) FROM lift_tp_ref r JOIN lift_tp p ON p.id = r.tp_id")
    end

    test "over budget (including budget 0) or over the alias pool, nothing lifts", %{
      tables: t,
      session: s
    } do
      chain = %{"article" => %{"author" => %{"org" => %{}}}}
      assert_fallback(t, @comments, chain, s, 0)
      assert_fallback(t, @comments, chain, s, 2)
      assert {:ok, %{joins: [_, _, _]}} = lift(t, @comments, chain, s, 3)

      # Eight managers is over the seven-join limit, whatever the budget.
      managers = fn n -> Enum.reduce(1..n, %{}, fn _, acc -> %{"manager" => acc} end) end
      assert_fallback(t, @users, managers.(8), s, 100)
      assert {:ok, %{joins: [_, _, _, _, _, _, _]}} = lift(t, @users, managers.(7), s, 100)

      # Seven joins plus nine non-lifted levels need alias 16: nothing lifts,
      # although each alone fits.
      nested =
        Enum.reduce(1..9, %{}, fn
          level, acc when rem(level, 2) == 1 -> %{"articles" => acc}
          _level, acc -> %{"author" => acc}
        end)

      assert_fallback(t, @users, %{"_and" => [managers.(7), nested]}, s)
      assert_fallback(t, @users, %{"_and" => [managers.(6), nested]}, s)
    end

    test "empty permissions lift nothing", %{tables: t, session: s} do
      assert {:ok, %{joins: [], condition: condition}} = lift(t, @articles, %{}, s)
      assert @articles |> FilterFixture.scoped(condition) |> sql() =~ "WHERE (TRUE)"
    end

    test "errors are compile/2's", %{tables: t} do
      ast = {:relationship, "author", {:compare, "nope", :eq, {:literal, 1}}}
      ctx = FilterFixture.ctx(t, @articles, FilterFixture.session())

      assert Compiler.lift(ast, ctx, 7) == Compiler.compile(ast, ctx)
      assert Compiler.lift_public(ast, ctx, 7) == {:error, :forbidden}

      for invalid <- [{:bogus}, {:or, [{:bogus}]}] do
        ast = {:and, [{:relationship, "author", {:and, []}}, invalid]}
        assert Compiler.lift(ast, ctx, 7) == Compiler.compile(ast, ctx)
        assert Compiler.lift_public(ast, ctx, 7) == {:error, :forbidden}
      end
    end
  end

  describe "pairs that lift" do
    test "uuid → uuid and enum → enum pairs lift and multiply no row", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE TYPE lift_mood AS ENUM ('a', 'b')",
            "CREATE TABLE lift_uuid_key (id uuid PRIMARY KEY, v int)",
            "CREATE TABLE lift_enum_key (id lift_mood PRIMARY KEY, v int)",
            "CREATE TABLE lift_same_ref (id bigint PRIMARY KEY, u uuid, m lift_mood)",
            "INSERT INTO lift_uuid_key VALUES " <>
              "('00000000-0000-0000-0000-000000000001', 1), " <>
              "('00000000-0000-0000-0000-000000000002', 2)",
            "INSERT INTO lift_enum_key VALUES ('a', 1), ('b', 2)",
            "INSERT INTO lift_same_ref VALUES " <>
              "(#{@base}, '00000000-0000-0000-0000-000000000001', 'a'), " <>
              "(#{@base + 1}, '00000000-0000-0000-0000-000000000002', 'b'), " <>
              "(#{@base + 2}, NULL, NULL)"
          ],
          ~w(lift_uuid_key lift_enum_key lift_same_ref)
        )
        |> put_relationship(
          {"public", "lift_same_ref"},
          object("by_uuid", {"public", "lift_uuid_key"}, [{"u", "id"}])
        )
        |> put_relationship(
          {"public", "lift_same_ref"},
          object("by_enum", {"public", "lift_enum_key"}, [{"m", "id"}])
        )

      ref = {"public", "lift_same_ref"}
      by_uuid = %{"by_uuid" => %{"v" => %{"_eq" => 1}}}
      by_enum = %{"by_enum" => %{"v" => %{"_eq" => 2}}}

      assert lifted_sql(t, ref, by_uuid, s) =~ ~s|ON l1."id" = l0."u"|
      assert lifted_sql(t, ref, by_enum, s) =~ ~s|ON l1."id" = l0."m"|
      assert lifted_ids(t, ref, by_uuid, s) == [@base]
      assert unlifted_ids(t, ref, by_uuid, s) == [@base]
      assert lifted_ids(t, ref, by_enum, s) == [@base + 1]
      assert unlifted_ids(t, ref, by_enum, s) == [@base + 1]
    end

    test "same-kind pairs of different types keep the EXISTS (float8 → float4, enums of two schemas)",
         %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE TYPE lift_tone AS ENUM ('a', 'b')",
            "CREATE SCHEMA lift_other",
            "CREATE TYPE lift_other.lift_tone AS ENUM ('a', 'b')",
            "CREATE TABLE lift_real_key (id real PRIMARY KEY)",
            "CREATE TABLE lift_tone_key (id lift_other.lift_tone PRIMARY KEY)",
            "CREATE TABLE lift_kind_ref (id bigint PRIMARY KEY, f float8, m lift_tone)"
          ],
          ~w(lift_real_key lift_tone_key lift_kind_ref)
        )
        |> put_relationship(
          {"public", "lift_kind_ref"},
          object("by_real", {"public", "lift_real_key"}, [{"f", "id"}])
        )
        |> put_relationship(
          {"public", "lift_kind_ref"},
          object("by_tone", {"public", "lift_tone_key"}, [{"m", "id"}])
        )

      ref = {"public", "lift_kind_ref"}
      assert %{base_kind: :float, pg_type: "float8"} = t[ref].columns["f"]

      assert %{base_kind: :float, pg_type: "float4"} =
               t[{"public", "lift_real_key"}].columns["id"]

      assert %{pg_type: "lift_tone", type_schema: "public"} = t[ref].columns["m"]

      assert %{pg_type: "lift_tone", type_schema: "lift_other"} =
               t[{"public", "lift_tone_key"}].columns["id"]

      assert_fallback(t, ref, %{"by_real" => %{}}, s)
      assert_fallback(t, ref, %{"by_tone" => %{}}, s)
    end

    test "int4 → int8 pairs lift", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          ["CREATE TABLE lift_int_ref (id bigint PRIMARY KEY, small smallint, mid integer)"],
          ~w(lift_int_ref)
        )
        |> put_relationship(
          {"public", "lift_int_ref"},
          object("by_mid", @users, [{"mid", "id"}])
        )
        |> put_relationship(
          {"public", "lift_int_ref"},
          object("by_small", @users, [{"small", "id"}])
        )

      ref = {"public", "lift_int_ref"}
      assert lifted_sql(t, ref, %{"by_mid" => %{}}, s) =~ ~s|ON u1."id" = l0."mid"|
      assert lifted_sql(t, ref, %{"by_small" => %{}}, s) =~ ~s|ON u1."id" = l0."small"|
    end

    test "a partitioned target lifts and multiplies no row", %{tables: t, session: s} do
      t =
        t
        |> scratch(
          [
            "CREATE TABLE lift_part (id bigint PRIMARY KEY, v int) PARTITION BY RANGE (id)",
            "CREATE TABLE lift_part_1 PARTITION OF lift_part FOR VALUES FROM (0) TO (10)",
            "CREATE TABLE lift_part_2 PARTITION OF lift_part FOR VALUES FROM (10) TO (20)",
            "CREATE TABLE lift_part_ref (id bigint PRIMARY KEY, part_id bigint)",
            "INSERT INTO lift_part VALUES (1, 1), (11, 1), (12, 2)",
            "INSERT INTO lift_part_ref VALUES " <>
              "(#{@base}, 1), (#{@base + 1}, 11), (#{@base + 2}, 12), (#{@base + 3}, NULL)"
          ],
          ~w(lift_part lift_part_ref)
        )
        |> put_relationship(
          {"public", "lift_part_ref"},
          object("part", {"public", "lift_part"}, [{"part_id", "id"}])
        )

      ref = {"public", "lift_part_ref"}
      filter = %{"part" => %{"v" => %{"_eq" => 1}}}
      assert lifted_sql(t, ref, filter, s) =~ ~s|INNER JOIN "public"."lift_part" AS l1|
      assert lifted_ids(t, ref, filter, s) == [@base, @base + 1]
      assert unlifted_ids(t, ref, filter, s) == [@base, @base + 1]
    end
  end

  describe "rows" do
    setup do
      Enum.each(
        [
          "INSERT INTO organizations VALUES (#{@base}, 'one'), (#{@base + 1}, 'two')",
          "INSERT INTO users (id, org_id, manager_id, email, role) VALUES " <>
            "(#{@base}, #{@base}, NULL, 'lift0@x', 'editor'), " <>
            "(#{@base + 1}, #{@base + 1}, #{@base}, 'lift1@x', 'viewer'), " <>
            "(#{@base + 2}, #{@base}, #{@base + 1}, 'lift2@x', 'editor')",
          "INSERT INTO articles (id, org_id, author_id, editor_id, status, is_published, title) " <>
            "VALUES (#{@base}, #{@base}, #{@base}, NULL, 'draft', true, 'a'), " <>
            "(#{@base + 1}, #{@base}, #{@base + 1}, #{@base + 2}, 'draft', true, 'b'), " <>
            "(#{@base + 2}, #{@base + 1}, #{@base + 2}, #{@base}, 'draft', false, 'c')",
          "INSERT INTO comments VALUES " <>
            "(#{@base}, #{@base}, #{@base}, 'x'), (#{@base + 1}, #{@base}, #{@base + 1}, 'y'), " <>
            "(#{@base + 2}, #{@base + 1}, #{@base}, 'x'), (#{@base + 3}, #{@base + 2}, #{@base}, 'z')",
          "INSERT INTO org_memberships VALUES (#{@base}, #{@base}, 1), (#{@base}, #{@base + 1}, 2)",
          "INSERT INTO membership_notes VALUES " <>
            "(#{@base}, #{@base}, #{@base}, 'n'), (#{@base + 1}, #{@base}, NULL, 'n'), " <>
            "(#{@base + 2}, NULL, #{@base + 1}, 'n'), (#{@base + 3}, #{@base}, #{@base + 1}, 'n')"
        ],
        &Repo.query!/1
      )
    end

    # A lifted join that matched more than one target row would repeat a root
    # id; a dropped NULL or dangling key would lose one.
    test "lifted reads return exactly the unlifted rows, none repeated", %{
      tables: t,
      session: s
    } do
      cases = [
        {@comments, %{"article" => %{"author" => %{"org" => %{"name" => %{"_eq" => "one"}}}}},
         [@base, @base + 1, @base + 3]},
        {@articles, %{"editor" => %{"role" => %{"_eq" => "editor"}}}, [@base + 1, @base + 2]},
        {@users, %{"manager" => %{"manager" => %{}}}, [@base + 2]},
        {@notes, %{"membership" => %{"level" => %{"_gte" => 1}}}, [@base, @base + 3]},
        {@articles,
         %{
           "_and" => [
             %{"author" => %{"org_id" => %{"_eq" => @base}}},
             %{"author" => %{"role" => %{"_eq" => "editor"}}}
           ]
         }, [@base, @base + 2]},
        {@view, %{"author" => %{"manager" => %{}}}, [@base + 1]},
        {@comments, %{"article" => %{"comments" => %{"body" => %{"_eq" => "y"}}}},
         [@base, @base + 1]}
      ]

      for {ref, filter, expected} <- cases do
        assert unlifted_ids(t, ref, filter, s) == expected, inspect(filter)
        assert lifted_ids(t, ref, filter, s) == expected, inspect(filter)
      end
    end
  end
end

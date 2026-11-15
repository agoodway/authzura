defmodule Authzura.Integration.InputJoinLiftTest do
  @moduledoc "Relationship lifting and the execute-only input fence."

  use Authzura.CommittedCase, async: false

  import Authzura.SqlHelper

  alias Authzura.{FilterFixture, HasuraFixture, Options, Scope, Store, TelemetryHelper}
  alias Authzura.Parity.Fixture
  alias Authzura.Test.InternalRead
  alias Authzura.Test.Schemas.Comment
  alias Ecto.Adapters.SQL

  @moduletag :capture_log

  @repo_query [:authzura, :test, :repo, :query]
  @comments {"public", "comments"}
  @deep %{"article" => %{"author" => %{"org" => %{"id" => %{"_eq" => "X-Hasura-Org-Id"}}}}}
  @columns ~w(id article_id body)
  @input %{columns: @columns, filter: %{"body" => %{"_like" => "%"}}}
  @estimate "::int = ANY('{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}'::int[])"

  # Unlifted goldens were captured before Compiler or Scope was edited.
  # The lifted_input golden records the shipped INNER JOIN shape.
  @golden %{
    lifted_input:
      {~s|SELECT c0."article_id", c0."body", c0."id" FROM "public"."comments" AS c0 INNER JOIN "public"."articles" AS a1 ON a1."id" = c0."article_id" INNER JOIN "public"."users" AS u2 ON u2."id" = a1."author_id" INNER JOIN "public"."organizations" AS o3 ON o3."id" = u2."org_id" WHERE (((a1."id" = c0."article_id") AND ((u2."id" = a1."author_id") AND ((o3."id" = u2."org_id") AND (o3."id" = $1::bigint)))) AND (CASE WHEN ((a1."id" = c0."article_id") AND ((u2."id" = a1."author_id") AND ((o3."id" = u2."org_id") AND (o3."id" = $2::bigint)))) THEN c0."body" LIKE $3::varchar ELSE false END)::int = ANY('{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}'::int[]))|,
       [1, 1, "%"]},
    scope:
      {~s|SELECT c0."article_id", c0."body", c0."id" FROM "public"."comments" AS c0 WHERE (exists((SELECT 1 FROM "public"."articles" AS sa0 WHERE ((sa0."id" = c0."article_id") AND exists((SELECT 1 FROM "public"."users" AS ssu0 WHERE ((ssu0."id" = sa0."author_id") AND exists((SELECT 1 FROM "public"."organizations" AS ssso0 WHERE ((ssso0."id" = ssu0."org_id") AND (ssso0."id" = $1::bigint)))))))))))|,
       [1]},
    get:
      {~s|SELECT c0."article_id", c0."body", c0."id" FROM "public"."comments" AS c0 WHERE (c0."id" OPERATOR(pg_catalog.=) $1::bigint) AND (exists((SELECT 1 FROM "public"."articles" AS sa0 WHERE ((sa0."id" = c0."article_id") AND exists((SELECT 1 FROM "public"."users" AS ssu0 WHERE ((ssu0."id" = sa0."author_id") AND exists((SELECT 1 FROM "public"."organizations" AS ssso0 WHERE ((ssso0."id" = ssu0."org_id") AND (ssso0."id" = $2::bigint))))))))))) LIMIT $3|,
       [1, 1, 2]},
    filter_rows:
      {~s|SELECT c0."id", c0."article_id", c0."author_id", c0."body" FROM "public"."comments" AS c0 WHERE (exists((SELECT 1 FROM "public"."articles" AS sa0 WHERE ((sa0."id" = c0."article_id") AND exists((SELECT 1 FROM "public"."users" AS ssu0 WHERE ((ssu0."id" = sa0."author_id") AND exists((SELECT 1 FROM "public"."organizations" AS ssso0 WHERE ((ssso0."id" = ssu0."org_id") AND (ssso0."id" = $1::bigint)))))))))))|,
       [1]},
    one:
      {~s|SELECT c0."article_id", c0."body", c0."id" FROM "public"."comments" AS c0 WHERE (c0."id" = 1) AND (exists((SELECT 1 FROM "public"."articles" AS sa0 WHERE ((sa0."id" = c0."article_id") AND exists((SELECT 1 FROM "public"."users" AS ssu0 WHERE ((ssu0."id" = sa0."author_id") AND exists((SELECT 1 FROM "public"."organizations" AS ssso0 WHERE ((ssso0."id" = ssu0."org_id") AND (ssso0."id" = $1::bigint))))))))))) LIMIT $2|,
       [1, 2]},
    scope_input:
      {~s|SELECT c0."article_id", c0."body", c0."id" FROM "public"."comments" AS c0 WHERE (exists((SELECT 1 FROM "public"."articles" AS sa0 WHERE ((sa0."id" = c0."article_id") AND exists((SELECT 1 FROM "public"."users" AS ssu0 WHERE ((ssu0."id" = sa0."author_id") AND exists((SELECT 1 FROM "public"."organizations" AS ssso0 WHERE ((ssso0."id" = ssu0."org_id") AND (ssso0."id" = $1::bigint)))))))))) AND CASE WHEN exists((SELECT 1 FROM "public"."articles" AS sa0 WHERE ((sa0."id" = c0."article_id") AND exists((SELECT 1 FROM "public"."users" AS ssu0 WHERE ((ssu0."id" = sa0."author_id") AND exists((SELECT 1 FROM "public"."organizations" AS ssso0 WHERE ((ssso0."id" = ssu0."org_id") AND (ssso0."id" = $2::bigint)))))))))) THEN c0."body" LIKE $3::varchar ELSE false END)|,
       [1, 1, "%"]}
  }

  defp permissions do
    [
      {"deep", @deep},
      {"partial", %{"_and" => [@deep, %{"article" => %{"comments" => %{}}}]}},
      {"or", %{"_and" => [@deep, %{"_or" => [%{"article" => %{}}, %{"id" => %{"_eq" => 1}}]}]}},
      {"not", %{"_and" => [@deep, %{"_not" => %{"article" => %{"id" => %{"_eq" => 99}}}}]}},
      {"exists", %{"_and" => [@deep, %{"_exists" => %{"_table" => "users", "_where" => %{}}}]}},
      {"column", %{"id" => %{"_gt" => 0}}},
      {"empty", %{}}
    ]
  end

  defp metadata do
    tables = FilterFixture.relationship_tables() ++ [%{table: {"public", "organizations"}}]

    comment_permissions =
      Enum.flat_map(permissions(), fn {role, filter} ->
        HasuraFixture.select_permissions(role, "*", filter)
      end)

    tables
    |> Enum.map(fn
      %{table: @comments} = entry ->
        Map.put(entry, :select_permissions, comment_permissions)

      entry ->
        Map.put(entry, :select_permissions, HasuraFixture.select_permissions("deep", "*"))
    end)
    |> HasuraFixture.metadata()
  end

  setup %{test: test} do
    Fixture.seed!(Repo)
    metadata = metadata()
    off = HasuraFixture.start_instance!(:"#{test}_off", Repo, metadata, admin_role: "admin")
    on = HasuraFixture.start_instance!(:"#{test}_on", Repo, metadata, input_index_pushdown: true)
    TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
    %{off: off, on: on, session: session("deep")}
  end

  defp session(role), do: HasuraFixture.session!(role, %{"x-hasura-org-id" => "1"})

  defp public(instance, input \\ @input, role \\ "deep"),
    do:
      TelemetryHelper.capture_statements(@repo_query, fn ->
        Authzura.all_input("comments", session(role), input, instance: instance)
      end)

  defp internal(instance, input, join_lift, role \\ "deep"),
    do:
      TelemetryHelper.capture_statements(@repo_query, fn ->
        InternalRead.all_input("comments", session(role), input, instance, join_lift: join_lift)
      end)

  test "the deep permission is lifted: inner joins, no exists, one CASE WHEN", %{off: off} do
    assert {{:ok, rows}, [{sql, _params}]} = public(off)
    assert Enum.map(rows, & &1["id"]) |> Enum.sort() == [1, 2, 3, 5, 6]
    assert occurrences(sql, "INNER JOIN") == 3
    refute sql =~ "exists("
    assert occurrences(sql, "CASE WHEN") == 1
  end

  test "the CASE references every lifted alias", %{off: off} do
    assert {{:ok, _rows}, [{sql, _params}]} = public(off)
    {outside, condition, _input} = fence_split(sql)

    for equality <- [
          ~s|a1."id" = c0."article_id"|,
          ~s|u2."id" = a1."author_id"|,
          ~s|o3."id" = u2."org_id"|
        ] do
      assert condition =~ equality
      assert outside =~ equality
    end

    assert condition =~ ~s|o3."id" = $2::bigint|
  end

  test "the estimate wrapper uses twenty ones", %{off: off} do
    assert {{:ok, _rows}, [{sql, [1, 1, "%"]}]} = public(off)
    assert {sql, [1, 1, "%"]} == @golden.lifted_input
    assert sql =~ "(CASE WHEN "
    assert sql =~ " ELSE false END)" <> @estimate
    assert occurrences(sql, @estimate) == 1

    assert {{:ok, _rows}, [unlifted]} = internal(off, @input, false)
    assert unlifted == @golden.scope_input

    for role <- ~w(partial or not exists column empty admin) do
      assert {{:ok, lifted_rows}, [{fallback, _params}]} = public(off, @input, role)
      assert {{:ok, unlifted_rows}, [{unlifted, _params}]} = internal(off, @input, false, role)
      assert Enum.sort(lifted_rows) == Enum.sort(unlifted_rows)
      assert fallback == unlifted
      refute fallback =~ "INNER JOIN"
      refute fallback =~ @estimate
    end
  end

  test "push-down on: the hoisted conjunct sits beside the lifted permission; same row set as push-down off",
       %{on: on, off: off} do
    input = put_in(@input, [:filter], %{"id" => %{"_in" => [1, 3, 4, 6]}})
    assert {{:ok, off_rows}, _sql} = public(off, input)
    assert {{:ok, on_rows}, [{sql, _params}]} = public(on, input)
    assert Enum.sort(on_rows) == Enum.sort(off_rows)
    assert Enum.map(on_rows, & &1["id"]) |> Enum.sort() == [1, 3, 6]
    {outside, _condition, fenced} = fence_split(sql)
    assert outside =~ ~s|o3."id"|
    assert outside =~ ~s|c0."id" OPERATOR(pg_catalog.=)|
    assert fenced =~ ~s|c0."id"|
    assert occurrences(sql, "INNER JOIN") == 3
  end

  test "an order_by ending in id returns the same sequence lifted and unlifted", %{
    off: off,
    on: on
  } do
    input = Map.put(@input, :order_by, [{"article_id", :desc}, {"id", :asc}])

    for instance <- [off, on] do
      assert {{:ok, rows}, [{sql, _params}]} = public(instance, input)
      assert {{:ok, ^rows}, _sql} = internal(instance, input, false)
      assert Enum.map(rows, & &1["id"]) == [3, 5, 6, 1, 2]
      assert sql =~ ~s|ORDER BY c0."article_id" DESC, c0."id"|
    end
  end

  test "pages with a unique tiebreaker are equal lifted and unlifted", %{off: off, on: on} do
    for instance <- [off, on], offset <- [0, 2, 4, 6] do
      input =
        Map.merge(@input, %{
          order_by: [{"article_id", :asc}, {"id", :desc}],
          limit: 2,
          offset: offset
        })

      assert {{:ok, rows}, _sql} = public(instance, input)
      assert {{:ok, ^rows}, _sql} = internal(instance, input, false)
      assert length(rows) == min(2, max(5 - offset, 0))
    end
  end

  test "preloads on a lifted read return the same tree", %{off: off} do
    input =
      Map.merge(@input, %{
        order_by: [{"id", :asc}],
        # Input preloads are capped at two levels; the permission still lifts all three hops.
        preload: %{"article" => %{"preload" => ["author"]}}
      })

    assert {{:ok, rows}, [{root, _params} | levels]} = public(off, input)
    assert {{:ok, ^rows}, [_root | unlifted_levels]} = internal(off, input, false)
    assert [_, _, _, _, _] = rows
    assert [_, _] = levels
    assert levels == unlifted_levels
    assert occurrences(root, "INNER JOIN") == 3
    assert Enum.all?(rows, &match?(%{"article" => %{"author" => %{"org_id" => 1}}}, &1))
  end

  test "a query with a join or a union is still {:invalid_input, :not_a_root}", %{
    off: off,
    session: session
  } do
    joined = from(c in "comments", join: a in "articles", on: a.id == c.article_id)
    combined = from(c in "comments", union_all: ^from(c in "comments"))

    for query <- [joined, combined] do
      assert Authzura.all_input(query, session, @input, instance: off) ==
               {:error, {:invalid_input, :not_a_root}}
    end
  end

  test "scope_input/4, scope/3, filter_rows/3 and all/3 SQL is unchanged", %{
    off: off,
    session: session
  } do
    assert {:ok, input} = Authzura.scope_input("comments", session, @input, instance: off)
    assert SQL.to_sql(:all, Repo, input) == @golden.scope_input
    assert {:ok, scoped} = Authzura.scope("comments", session, instance: off, columns: @columns)
    assert SQL.to_sql(:all, Repo, scoped) == @golden.scope
    assert {:ok, filtered, _permission} = Authzura.filter_rows(Comment, session, instance: off)
    assert SQL.to_sql(:all, Repo, filtered) == @golden.filter_rows

    assert {{:ok, _rows}, [all]} =
             TelemetryHelper.capture_statements(@repo_query, fn ->
               Authzura.all("comments", session, instance: off, columns: @columns)
             end)

    assert all == @golden.scope

    assert {{:ok, _row}, [one]} =
             TelemetryHelper.capture_statements(@repo_query, fn ->
               Authzura.one(from(c in "comments", where: c.id == 1), session,
                 instance: off,
                 columns: @columns
               )
             end)

    assert one == @golden.one

    assert {{:ok, _row}, [get]} =
             TelemetryHelper.capture_statements(@repo_query, fn ->
               Authzura.get("comments", session, 1, instance: off, columns: @columns)
             end)

    assert get == @golden.get
  end

  describe "internal" do
    test "caller joins keep their positions and count against the budget", %{
      off: off,
      session: session
    } do
      assert {:ok, generation} = Store.current(off)

      opts = execute_opts(off)

      for count <- [1, 4, 5] do
        query = caller_joins(count)

        assert {:ok, plan} = Scope.build(query, session, generation, opts)
        assert Enum.take(plan.query.joins, count) == query.joins
        assert length(plan.query.joins) == if(count <= 4, do: count + 3, else: count)

        assert String.contains?(sql(plan.query), @estimate) == count <= 4
      end
    end

    test "seven caller joins clamp the budget to zero", %{off: off, session: session} do
      assert {:ok, generation} = Store.current(off)

      opts = execute_opts(off)

      for count <- [7, 8] do
        query = caller_joins(count)

        assert {:ok, plan} = Scope.build(query, session, generation, opts)
        assert plan.query.joins == query.joins
        sql = sql(plan.query)
        assert sql =~ "exists("
        refute sql =~ @estimate
      end
    end
  end

  defp execute_opts(instance),
    do:
      [mode: :execute, input_filter: dynamic(field(as(:__authzura_0), "id") > 0)] ++
        Options.call!(instance: instance, columns: @columns)

  defp caller_joins(count) do
    Enum.reduce(1..count, from(c in "comments"), fn _, query ->
      join(query, :inner, [], o in "organizations", on: o.id == 1)
    end)
  end
end

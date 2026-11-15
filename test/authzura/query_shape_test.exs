defmodule Authzura.QueryShapeTest do
  use ExUnit.Case, async: true

  import Ecto.Query

  alias Authzura.QueryShape
  alias Authzura.Test.Schemas.{Article, Comment}
  alias Ecto.Queryable

  defp check(queryable, mode \\ :scope),
    do: queryable |> Queryable.to_query() |> QueryShape.validate(mode)

  defp rejects(queryable, reason, mode \\ :scope),
    do: assert(check(queryable, mode) == {:error, {:unsupported_query, reason}})

  describe "sources" do
    test "a fragment or values root is rejected" do
      rejects(from(f in fragment("SELECT 1 AS id")), :fragment_source)
      rejects(from(v in values([%{id: 1}], %{id: :integer})), :fragment_source)
    end

    test "a subquery root is rejected" do
      rejects(from(s in subquery(from(a in Article))), :subquery_source)
    end

    test "a modifying CTE is rejected at any depth" do
      update = from(a in "articles", update: [set: [title: "x"]])
      delete = from(a in "articles")

      rejects(with_cte(Article, "w", as: ^update, operation: :update_all), :modifying_cte)
      rejects(with_cte(Article, "w", as: ^delete, operation: :delete_all), :modifying_cte)

      inner = "readable" |> from() |> with_cte("w", as: ^delete, operation: :delete_all)
      rejects(with_cte(Article, "outer", as: ^inner), :modifying_cte)

      joined = from(a in Article, join: s in subquery(inner), on: true)
      rejects(joined, :modifying_cte)

      ordered = from(a in Article, order_by: exists(subquery(from(r in inner, select: 1))))
      rejects(ordered, :modifying_cte)
    end

    test "a fragment CTE is rejected" do
      rejects(with_cte(Article, "w", as: fragment("SELECT 1")), :fragment_cte)
    end
  end

  describe "clauses" do
    test "an existing select or select_merge is rejected" do
      rejects(from(a in Article, select: a.id), :existing_select)
      rejects(from(a in Article, select_merge: %{x: a.id}), :existing_select)
    end

    test "group_by, having and windows are rejected" do
      rejects(from(a in Article, group_by: a.org_id), :aggregate)
      rejects(from(a in Article, having: count(a.id) > 1), :aggregate)
      rejects(from(a in Article, windows: [w: [partition_by: a.org_id]]), :aggregate)
    end

    test "a lock is rejected" do
      rejects(from(a in Article, lock: "FOR UPDATE"), :lock)
    end

    test "distinct of any form is rejected" do
      rejects(from(a in Article, distinct: true), :distinct)
      rejects(from(a in Article, distinct: [desc: a.id]), :distinct)
    end

    test "with_ties is rejected" do
      rejects(from(a in Article, order_by: a.id, limit: 1, with_ties: true), :with_ties)
    end

    test "a non-integer limit or offset is rejected" do
      rejects(from(a in Article, limit: a.org_id), :limit)
      rejects(from(a in Article, offset: a.org_id), :limit)
    end
  end

  describe "preloads and combinations" do
    test "a preload is rejected in :scope mode and accepted in :execute mode" do
      rejects(preload(Article, :author), :preload_requires_execute)
      assert check(preload(Article, :author), :execute) == :ok
    end

    test "branches over different tables are rejected" do
      rejects(union_all(Article, ^from(c in Comment)), :combination_tables)
      rejects(union(from(a in "articles"), ^from(c in "comments")), :combination_tables)
    end

    test "a combination with a preload is rejected" do
      rejects(Article |> preload(:author) |> union_all(^from(a in Article)), :combination_preload)

      branch = preload(Article, :author)
      rejects(union_all(Article, ^branch), :combination_preload, :execute)
    end

    test "a branch with its own select or unsupported clause is rejected" do
      rejects(union_all(Article, ^from(a in Article, select: a.id)), :combination_shape)
      rejects(union_all(Article, ^from(a in Article, distinct: true)), :combination_shape)
      rejects(union_all(Article, ^from(a in Article, group_by: a.id)), :combination_shape)
      rejects(union_all(Article, ^from(a in "articles")), :combination_shape)
    end
  end

  describe "aliases" do
    test "an :__authzura_* binding is rejected" do
      rejects(from(a in Article, as: :__authzura_0), :reserved_alias)

      rejects(
        from(a in Article, join: c in Comment, as: :__authzura_3, on: true),
        :reserved_alias
      )

      rejects(union_all(Article, ^from(a in Article, as: :__authzura_1)), :reserved_alias)
    end
  end

  describe "accepted shapes" do
    test "a read-only CTE named after an authorized table" do
      cte = from(a in "articles", prefix: "public", where: a.id == 1)
      assert check(with_cte(Article, "articles", as: ^cte)) == :ok
    end

    test "a same-table union_all" do
      assert check(Article |> union_all(^from(a in Article, where: a.id > 1)) |> limit(3)) == :ok
    end

    test "pinned limits and offsets, joins, wheres and order_bys" do
      n = 5

      query =
        from(a in Article,
          as: :a,
          join: c in Comment,
          on: c.article_id == a.id,
          where: a.id > 0,
          order_by: [desc: a.id],
          limit: ^n,
          offset: ^n
        )

      assert check(query) == :ok
    end
  end
end

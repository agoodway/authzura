defmodule Authzura.HasuraScenarios.ComparisonsTest do
  @moduledoc """
  The `where` comparisons of
  `tests-py/queries/graphql_query/boolexp/basic/select_author_article_where_*.yaml`
  (paths relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server). Hasura runs
  each as an admin `where` on `author` with its `articles`; here each is the
  admin role's input filter with `articles` preloaded. A role whose
  permission hides an author shows the filter ANDed with the permission.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  alias Authzura.Test.HasuraSchemas.BoolexpAuthor

  @author {"hasura_boolexp", "author"}
  @article {"hasura_boolexp", "article"}
  @articles %{"columns" => ["id", "title", "content"], "order_by" => [%{"id" => "asc"}]}

  setup %{test: test} do
    %{
      instance:
        start!(test, [
          %{
            table: @author,
            array_relationships: [
              %{
                name: "articles",
                using: %{foreign_key_constraint_on: %{table: @article, column: "author_id"}}
              }
            ],
            select_permissions: [
              %{
                role: "registered",
                permission: %{columns: "*", filter: %{"is_registered" => %{"_eq" => true}}}
              }
            ]
          },
          %{
            table: @article,
            select_permissions: [%{role: "registered", permission: %{columns: "*", filter: %{}}}]
          }
        ])
    }
  end

  # Options: `role` (default admin), `order` (the authors' id direction) and
  # `articles` (merged into the preload of `articles`).
  defp authors(instance, filter, opts \\ []) do
    all_input(
      BoolexpAuthor,
      instance,
      Keyword.get(opts, :role, "admin"),
      %{},
      %{
        "columns" => ["id", "name"],
        "filter" => filter,
        "order_by" => [%{"id" => Keyword.get(opts, :order, "asc")}]
      },
      preload: %{"articles" => Map.merge(@articles, Keyword.get(opts, :articles, %{}))}
    )
  end

  defp author(id, articles),
    do: %{:id => id, :name => "Author #{id}", "articles" => Enum.map(articles, &article/1)}

  defp article(id),
    do: %{"id" => id, "title" => "Article #{id}", "content" => "Sample article content #{id}"}

  # select_author_article_where_gt.yaml
  test "_gt", %{instance: i} do
    assert authors(i, %{"id" => %{"_gt" => 2}}) == {:ok, [author(3, [4])]}
  end

  # select_author_article_where_gte.yaml
  test "_gte", %{instance: i} do
    assert authors(i, %{"id" => %{"_gte" => 2}}) == {:ok, [author(2, [3]), author(3, [4])]}
  end

  # select_author_article_where_lt.yaml
  test "_lt", %{instance: i} do
    assert authors(i, %{"id" => %{"_lt" => 2}}) == {:ok, [author(1, [1, 2])]}
  end

  # select_author_article_where_not_lt.yaml (both cases give the same rows)
  test "_not _lt reads like _gte", %{instance: i} do
    expected = {:ok, [author(2, [3]), author(3, [4])]}

    assert authors(i, %{"_not" => %{"id" => %{"_lt" => 2}}}) == expected
    assert authors(i, %{"id" => %{"_gte" => 2}}) == expected
  end

  # select_author_article_where_in.yaml
  test "_in", %{instance: i} do
    assert authors(i, %{"name" => %{"_in" => ["Author 2", "Author 3"]}}) ==
             {:ok, [author(2, [3]), author(3, [4])]}
  end

  # select_author_article_where_and_in.yaml, with `_and` as a list (see the
  # divergence below for Hasura's single-object form).
  test "_and of two _in conditions, as a list", %{instance: i} do
    filter = %{
      "_and" => [
        %{"name" => %{"_in" => ["Author 2", "Author 3"]}, "id" => %{"_in" => [1, 2]}}
      ]
    }

    assert authors(i, filter) == {:ok, [author(2, [3])]}
  end

  # select_author_article_where_in_empty_array_postgres.yaml
  test "_in [] returns no authors", %{instance: i} do
    assert authors(i, %{"name" => %{"_in" => []}}) == {:ok, []}
  end

  # select_author_article_where_{nin_empty_array,nin_empty_array_postgres}.yaml
  test "_nin [] returns every author", %{instance: i} do
    assert authors(i, %{"name" => %{"_nin" => []}}) ==
             {:ok, [author(1, [1, 2]), author(2, [3]), author(3, [4])]}
  end

  # Negative controls: the permission hides author 3 whatever the filter
  # asks, and a role without a permission is denied.
  test "a role's permission is ANDed with the comparison", %{instance: i} do
    assert authors(i, %{"id" => %{"_gte" => 2}}, role: "registered") ==
             {:ok, [author(2, [3])]}

    assert authors(i, %{"id" => %{"_gt" => 2}}, role: "registered") == {:ok, []}

    assert authors(i, %{"name" => %{"_nin" => []}}, role: "registered") ==
             {:ok, [author(1, [1, 2]), author(2, [3])]}
  end

  test "a role without a permission is denied", %{instance: i} do
    assert authors(i, %{"id" => %{"_gt" => 2}}, role: "nobody") == {:error, :forbidden}
  end

  describe "Hasura's GraphQL input forms" do
    # select_author_article_where_and_in.yaml sends `_and: {...}`; GraphQL
    # coerces a single object to a one-element list. JSON input has no such
    # coercion, so the object is rejected.
    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): JSON input has no GraphQL list coercion, so " <>
             "`_and` as an object is {:invalid_input, [{[\"_and\"], :invalid_expression}]}; send a list"
    test "_and of two _in conditions, as a single object", %{instance: i} do
      filter = %{
        "_and" => %{"name" => %{"_in" => ["Author 2", "Author 3"]}, "id" => %{"_in" => [1, 2]}}
      }

      assert authors(i, filter) == {:ok, [author(2, [3])]}
    end

    # A selection's own `where` argument
    # (select_author_article_where_{lte,neq,nin}.yaml) is GraphQL surface: a
    # preload takes only columns, order_by and preload, so it is rejected.
    @skip "Hasura divergence (intended): a preload takes no `where`, so the selection is " <>
            "{:unsupported_query, {:preload, \"articles\"}}"

    @tag :hasura_divergence
    @tag skip: @skip
    test "_lte with articles where id > 1", %{instance: i} do
      where = %{"where" => %{"id" => %{"_gt" => 1}}}

      assert authors(i, %{"id" => %{"_lte" => 2}}, order: "desc", articles: where) ==
               {:ok, [author(2, [3]), author(1, [2])]}
    end

    @tag :hasura_divergence
    @tag skip: @skip
    test "_neq with articles where is_published != false", %{instance: i} do
      nested = %{
        "columns" => ["id", "title", "content", "is_published"],
        "where" => %{"is_published" => %{"_neq" => false}}
      }

      published = Map.put(article(4), "is_published", true)

      assert authors(i, %{"name" => %{"_neq" => "Author 1"}}, articles: nested) ==
               {:ok, [author(2, []), %{author(3, []) | "articles" => [published]}]}
    end

    @tag :hasura_divergence
    @tag skip: @skip
    test "_nin with articles where id > 1", %{instance: i} do
      where = %{"where" => %{"id" => %{"_gt" => 1}}}

      assert authors(i, %{"name" => %{"_nin" => ["Author 2", "Author 3"]}}, articles: where) ==
               {:ok, [author(1, [2])]}
    end
  end
end

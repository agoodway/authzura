defmodule Authzura.HasuraScenarios.LimitsTest do
  @moduledoc """
  Limits ported from Hasura v2.51.6's
  `tests-py/queries/graphql_query/limits/` (paths relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server). Hasura runs
  them as admin; the caller's limit is the query's own `limit`.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  @article {"hasura_limits", "article"}
  @columns ["id", "title", "content"]
  @author_preload %{"author" => %{"columns" => ["id", "name"]}}

  setup %{test: test} do
    %{
      instance:
        start!(test, [
          %{table: {"hasura_limits", "author"}},
          %{
            table: @article,
            object_relationships: [
              %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
            ]
          }
        ])
    }
  end

  defp newest_first(query, instance),
    do: all(query, instance, "admin", %{}, columns: @columns, preload: @author_preload)

  defp newest, do: table(@article, desc: :id)

  defp article(id, author_id),
    do: %{
      "id" => id,
      "title" => "Article #{id}",
      "content" => "Sample article content #{id}",
      "author" => %{"id" => author_id, "name" => "Author #{author_id}"}
    }

  # select_query_article_limit_1.yaml
  test "limit 1, ordered by id desc, with the author", %{instance: i} do
    assert newest_first(limit(newest(), 1), i) == {:ok, [article(3, 2)]}
  end

  # select_query_article_limit_2.yaml
  test "limit 2, ordered by id desc, with the author", %{instance: i} do
    assert newest_first(limit(newest(), 2), i) == {:ok, [article(3, 2), article(2, 1)]}
  end

  # select_query_article_limit_null.yaml
  test "no limit returns every row", %{instance: i} do
    assert newest_first(newest(), i) == {:ok, [article(3, 2), article(2, 1), article(1, 1)]}
  end

  # select_query_article_neg_limit_error.yaml
  test "a negative limit is an error", %{instance: i} do
    n = -1

    assert newest() |> limit(^n) |> offset(1) |> newest_first(i) ==
             {:error, {:unsupported_query, :limit}}
  end
end

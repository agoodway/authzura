defmodule Authzura.Integration.InputOracleTest do
  @moduledoc """
  Regression tests for the error oracle: an input predicate that could fail
  only when it is evaluated must never report on rows the permission filter
  hides.

  Ecto runs named prepared statements, and after five executions Postgres
  may switch a statement to a generic plan, where a pattern is a parameter
  compiled on first evaluation. Each test first warms the statement past
  that point (150 requests, enough for every pooled connection), then
  compares a guess that matches only a hidden row with one that matches
  nothing. The two must be indistinguishable.
  """

  use Authzura.CommittedCase, async: false

  alias Authzura.{HasuraFixture, Store, TestSource}

  @articles {"public", "articles"}
  @users {"public", "users"}

  @warm_up 150
  @samples 20
  @hidden_title "Q3 layoffs: 40 people"

  # Permission shapes the planner may evaluate after a cheaper input qual.
  @roles %{
    "rel" => %{"author" => %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}},
    "inperm" => %{"org_id" => %{"_in" => "X-Hasura-Org-Ids"}},
    "two" => %{
      "_or" => [
        %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}},
        %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}},
        %{"editor_id" => %{"_eq" => "X-Hasura-User-Id"}}
      ]
    }
  }

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions:
          for {role, filter} <- @roles do
            %{role: role, permission: %{columns: ["id", "title"], filter: filter}}
          end
      },
      %{table: @users, select_permissions: []}
    ])
  end

  setup %{test: test} do
    Repo.query!("insert into public.organizations values (1, 'one'), (2, 'two')")

    Repo.query!("""
    insert into public.users (id, org_id, email, role, salary) values
      (1, 1, 'a@x.com', 'editor', 100), (3, 2, 'c@x.com', 'viewer', 300)
    """)

    Repo.query!("""
    insert into public.articles
      (id, org_id, author_id, editor_id, status, is_published, title, internal_notes, assignees)
    values
      (1, 1, 1, 1, 'draft', false, 'one', 'n1', '{}'),
      (4, 2, 3, 3, 'draft', false, '#{@hidden_title}', 'hidden', '{}')
    """)

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp session(role) do
    HasuraFixture.session!(role, %{
      "x-hasura-org-id" => "1",
      "x-hasura-user-id" => "1",
      "x-hasura-org-ids" => "{1}"
    })
  end

  # Makes the instance's source return `ast` from `parse_input/2`.
  defp fix_input!(instance, ast) do
    {:ok, %{config: %{source: {TestSource, opts}}}} = Store.current(instance)
    TestSource.put(Keyword.fetch!(opts, :agent), input: ast)
  end

  defp run(role, input, instance),
    do: Authzura.all_input("articles", session(role), input, instance: instance)

  defp samples(role, input, instance),
    do: 1..@samples |> Enum.map(fn _n -> run(role, input, instance) end) |> Enum.uniq()

  defp warm_up(role, input, instance),
    do: Enum.each(1..@warm_up, fn _n -> run(role, input, instance) end)

  defp guessing(guard, pattern),
    do: %{
      "filter" => %{
        "_or" => [%{"title" => %{"_nlike" => guard}}, %{"title" => %{"_regex" => pattern}}]
      }
    }

  test "the hidden row is really hidden", %{instance: i} do
    for role <- Map.keys(@roles) do
      assert run(role, %{}, i) == {:ok, [%{"id" => 1, "title" => "one"}]}, role
    end
  end

  test "an invalid regex fails the same whether or not a hidden row matches the guess",
       %{instance: i} do
    for role <- Map.keys(@roles) do
      warm_up(role, guessing("warm%", "ok"), i)

      hit = samples(role, guessing("Q3%", "("), i)
      miss = samples(role, guessing("ZZ%", "("), i)

      assert {role, hit} == {role, miss}
      assert {role, hit} == {role, [{:error, {:invalid_input, {:invalid_pattern, "title"}}}]}
    end
  end

  test "an invalid SIMILAR TO pattern is refused before the query runs", %{instance: i} do
    for {op, pattern} <- [{"_similar", "("}, {"_nsimilar", "("}, {"_iregex", "a{2,1}"}] do
      assert {op, run("rel", %{"filter" => %{"title" => %{op => pattern}}}, i)} ==
               {op, {:error, {:invalid_input, {:invalid_pattern, "title"}}}}
    end
  end

  test "every error Postgres raises for a pattern is invalid_pattern, never raised",
       %{instance: i} do
    # 2200C (more than two escape-double-quote separators), 2201B and
    # 22025, from both input functions.
    for {op, pattern} <- [
          {"_similar", ~S(a\"b\"c\"d)},
          {"_nsimilar", ~S(\"\"\")},
          {"_regex", "[[:nope:]]"},
          {"_niregex", "a**"},
          {"_regex", "\\"},
          {"_similar", "a{2,1}"}
        ] do
      input = %{"filter" => %{"title" => %{op => pattern}}}
      expected = {:error, {:invalid_input, {:invalid_pattern, "title"}}}

      assert {op, pattern, run("rel", input, i)} == {op, pattern, expected}

      assert {op, pattern, Authzura.scope_input("articles", session("rel"), input, instance: i)} ==
               {op, pattern, expected}
    end
  end

  test "the input predicate is evaluated only on permitted rows", %{instance: i} do
    # A LIKE pattern that fails whenever it is evaluated. The Hasura parser
    # refuses it, so it comes from the instance's source directly: this
    # isolates the permission gate from the up-front pattern checks.
    fenced = fn guard ->
      {:or,
       [
         {:compare, "title", :nlike, {:literal, guard}},
         {:compare, "title", :like, {:literal, "%\\"}}
       ]}
    end

    for role <- Map.keys(@roles) do
      fix_input!(i, fenced.("warm%"))
      warm_up(role, %{"filter" => %{}}, i)

      fix_input!(i, fenced.("Q3%"))
      hit = samples(role, %{"filter" => %{}}, i)
      fix_input!(i, fenced.("ZZ%"))
      miss = samples(role, %{"filter" => %{}}, i)

      assert {role, hit} == {role, miss}
      assert {role, hit} == {role, [{:ok, [%{"id" => 1, "title" => "one"}]}]}
    end
  end
end

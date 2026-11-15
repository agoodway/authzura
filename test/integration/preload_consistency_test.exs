defmodule Authzura.Integration.PreloadConsistencyTest do
  use Authzura.CommittedCase

  alias Authzura.{HasuraFixture, Store, TelemetryHelper, TestSource}
  alias Authzura.Store.Generation

  @articles {"public", "articles"}
  @comments {"public", "comments"}

  @mine %{"article" => %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}}
  @hand_over "update public.articles set author_id = 2 where id = 1"
  @repo_query [:authzura, :test, :repo, :query]

  # A comment is readable only while its article is authored by the session
  # user, so the child query re-reads the parent's ownership.
  defp metadata(comment_permissions) do
    HasuraFixture.metadata([
      %{
        table: @articles,
        array_relationships: [
          %{
            name: "comments",
            using: %{foreign_key_constraint_on: %{table: @comments, column: "article_id"}}
          }
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title", "author_id"], filter: %{}}}
        ]
      },
      %{
        table: @comments,
        object_relationships: [
          %{name: "article", using: %{foreign_key_constraint_on: "article_id"}},
          # Not unique on the target: every comment of the same article.
          %{
            name: "sibling",
            using: %{
              manual_configuration: %{
                remote_table: @comments,
                column_mapping: %{article_id: "article_id"}
              }
            }
          }
        ],
        select_permissions: comment_permissions
      }
    ])
  end

  # The comments table is no longer tracked: a level that read this
  # generation's tables would be :forbidden.
  defp untracked do
    HasuraFixture.metadata([
      %{
        table: @articles,
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title", "author_id"], filter: %{}}}
        ]
      }
    ])
  end

  # The SQL this process sent, in order.
  defp queries, do: TelemetryHelper.received_queries(@repo_query)

  defp readable,
    do: [%{role: "user", permission: %{columns: ["id", "body"], filter: @mine}}]

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one')",
        "insert into public.users (id, org_id, email, role) values (1, 1, 'a@x.com', 'editor'), (2, 1, 'b@x.com', 'editor')",
        "insert into public.articles (id, org_id, author_id, status, is_published, title) values (1, 1, 1, 'draft', false, 'one')",
        "insert into public.comments (id, article_id, author_id, body) values (10, 1, 2, 'first'), (11, 1, 2, 'second')"
      ],
      &Repo.query!/1
    )

    agent =
      start_supervised!(
        {TestSource, snapshot: HasuraFixture.snapshot!(Repo, metadata(readable())), version: "A"}
      )

    start_supervised!(
      {Authzura,
       name: test,
       repo: Repo,
       source: {TestSource, agent: agent},
       poll_interval: nil,
       max_staleness: :infinity}
    )

    :ok = Authzura.reload(test)
    %{instance: test, agent: agent}
  end

  defp session, do: HasuraFixture.session!("user", %{"x-hasura-user-id" => "1"})

  defp articles(instance, opts) do
    Authzura.all(
      from(a in "articles", order_by: a.id),
      session(),
      [instance: instance, preload: [comments: [order_by: [asc: :id]]]] ++ opts
    )
  end

  # Hands article 1 to user 2 on another connection, between the root read
  # and the comments level, under `isolation`.
  defp raced(instance, isolation) do
    articles(instance,
      isolation: isolation,
      between_levels: fn -> OtherRepo.query!(@hand_over) end
    )
  end

  # The same race under READ COMMITTED loses the comments: the anomaly the
  # snapshot prevents is real, so the repeatable-read assertion means something.
  defp assert_detects_anomaly(instance) do
    Repo.query!("update public.articles set author_id = 1 where id = 1")

    assert {:ok, [%{"id" => 1, "author_id" => 1, comments: []}]} =
             raced(instance, :read_committed)
  end

  test "every level reads the root's snapshot", %{instance: i} do
    assert {:ok,
            [
              %{
                "id" => 1,
                "author_id" => 1,
                comments: [
                  %{"id" => 10, "body" => "first"},
                  %{"id" => 11, "body" => "second"}
                ]
              }
            ]} = raced(i, :repeatable_read)

    assert OtherRepo.query!("select author_id from public.articles").rows == [[2]]
    assert_detects_anomaly(i)
  end

  test "a reload between levels does not change the generation in use", %{
    instance: i,
    agent: agent
  } do
    revoked = HasuraFixture.snapshot!(Repo, untracked())
    {:ok, %Generation{seq: before}} = Store.current(i)

    reload = fn ->
      TestSource.put(agent, snapshot: revoked, version: "B")
      :ok = Authzura.reload(i)
    end

    assert {:ok, [%{comments: [%{"id" => 10}, %{"id" => 11}]}]} =
             articles(i, between_levels: reload)

    assert {:ok, %Generation{seq: later}} = Store.current(i)
    assert later > before
    assert {:error, :forbidden} = articles(i, [])
  end

  test "an error at any level fails the whole call", %{instance: i, test: test} do
    TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
    me = HasuraFixture.session!("user", %{"x-hasura-user-id" => "1"})

    assert {:error, {:unsupported_query, {:object_cardinality, "sibling"}}} =
             Authzura.all("articles", me, instance: i, preload: [comments: [:sibling]])

    assert [
             "begin",
             "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
             root,
             _comments,
             _siblings,
             "rollback"
           ] =
             queries()

    assert root =~ ~r/^SELECT .* FROM "public"."articles"/
  end

  # Every level's filter is compiled with the plan, so a session error at
  # any level is refused before a statement runs.
  test "a level's session error is refused before any statement", %{instance: i, test: test} do
    TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

    assert {:error, {:missing_session_variable, "x-hasura-user-id"}} =
             Authzura.all("articles", HasuraFixture.session!("user"),
               instance: i,
               preload: [:comments]
             )

    assert queries() == []
  end
end

defmodule Authzura.Integration.PreloadApiTest do
  use Authzura.CommittedCase

  alias Authzura.{HasuraFixture, TelemetryHelper}
  alias Authzura.Test.Schemas.{Article, User}

  defmodule PostedComment do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "comments" do
      field(:article_id, :integer)
      field(:text, :string, source: :body)
    end
  end

  defmodule Post do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "articles" do
      field(:title, :string)
      has_many(:comments, PostedComment, foreign_key: :article_id)
    end
  end

  # Its `author` field reads author_id, like the Hasura `author` relationship.
  defmodule AuthoredPost do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "articles" do
      field(:title, :string)
      field(:author, :integer, source: :author_id)
    end
  end

  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @users {"public", "users"}
  @repo_query [:authzura, :test, :repo, :query]

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
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
        select_permissions: [
          %{
            role: "user",
            permission: %{columns: ["id", "body", "article_id", "author_id"], filter: %{}}
          }
        ]
      },
      %{
        table: @users,
        object_relationships: [
          %{name: "manager", using: %{foreign_key_constraint_on: "manager_id"}}
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "manager_id"], filter: %{}}}
        ]
      }
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one')",
        "insert into public.users (id, org_id, email, role) values (1, 1, 'a@x.com', 'editor')",
        """
        insert into public.articles (id, org_id, author_id, status, is_published, title) values
          (1, 1, 1, 'draft', false, 'one'), (2, 1, 1, 'draft', false, 'two')
        """,
        """
        insert into public.comments (id, article_id, author_id, body) values
          (12, 1, 1, 'c'), (10, 1, 1, 'a'), (11, 2, 1, 'b')
        """
      ],
      &Repo.query!/1
    )

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp session, do: HasuraFixture.session!("user")

  defp by_id(queryable), do: from(q in queryable, order_by: q.id)

  defp comments(ids, article_id),
    do:
      Enum.map(
        ids,
        &%{"id" => &1, "article_id" => article_id, "author_id" => 1, "body" => body(&1)}
      )

  defp body(10), do: "a"
  defp body(11), do: "b"
  defp body(12), do: "c"

  # A `manager` chain `depth` relationships deep.
  @forged {:__authzura_ecto_assoc__, NoSuchSchema, []}
  @set_repeatable_read "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"

  # The SQL this process sent, in order.
  defp queries, do: TelemetryHelper.received_queries(@repo_query)

  defp managers(1), do: :manager
  defp managers(depth), do: [manager: [preload: managers(depth - 1)]]

  describe "all/3" do
    test "nests comments under each article", %{instance: i} do
      assert {:ok,
              [
                %{id: 1, title: "one", author_id: 1, comments: one},
                %{id: 2, title: "two", author_id: 1, comments: two}
              ]} =
               Authzura.all(by_id(Article), session(),
                 instance: i,
                 preload: [comments: [order_by: [asc: :id]]]
               )

      assert one == comments([10, 12], 1)
      assert two == comments([11], 2)
    end

    # Both articles share author 1: the loader finishes that value once, so
    # the parents share one term even though it has a nested relationship.
    test "parents sharing a key share one nested value", %{instance: i} do
      assert {:ok, [%{author: one}, %{author: two}]} =
               Authzura.all(by_id(Article), session(),
                 instance: i,
                 preload: [author: [preload: [:manager]]]
               )

      assert one == %{"id" => 1, "manager_id" => nil, manager: nil}
      assert :erts_debug.same(one, two)
    end

    test "strips stitching columns the caller did not request", %{instance: i} do
      assert {:ok, [first, second]} =
               Authzura.all(by_id(Article), session(),
                 instance: i,
                 columns: [:title],
                 preload: [comments: [columns: [:body], order_by: [desc: :id]]]
               )

      assert first == %{title: "one", comments: [%{"body" => "c"}, %{"body" => "a"}]}
      assert second == %{title: "two", comments: [%{"body" => "b"}]}
    end

    test "keys follow the caller's terms", %{instance: i} do
      assert {:ok, [%{"id" => 2, "comments" => [%{"id" => 11}]}]} =
               Authzura.all(where(by_id("articles"), [a], a.id == 2), session(),
                 instance: i,
                 preload: %{"comments" => %{"columns" => ["id"]}}
               )
    end

    test "translates and loads a plain Ecto preload", %{instance: i} do
      query = Post |> by_id() |> preload(:comments)

      assert {:ok, [%{id: 1, title: "one", comments: one}, %{id: 2, comments: two}]} =
               Authzura.all(query, session(), instance: i)

      assert Enum.sort_by(one, & &1.id) == [
               %{id: 10, article_id: 1, text: "a"},
               %{id: 12, article_id: 1, text: "c"}
             ]

      assert two == [%{id: 11, article_id: 2, text: "b"}]
    end

    test "rejects an over-limit tree before any query runs", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      assert {:error, {:unsupported_query, :preload_limit}} =
               Authzura.all(User, session(), instance: i, preload: managers(5))

      refute_received {:telemetry, @repo_query, _meta}
    end

    test "runs every level in one repeatable-read, read-only transaction", %{
      instance: i,
      test: test
    } do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      assert {:ok, [_one, _two]} =
               Authzura.all(Article, session(), instance: i, preload: [:comments])

      assert_received {:telemetry, @repo_query, %{query: "begin"}}

      assert_received {:telemetry, @repo_query,
                       %{query: "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"}}

      assert_received {:telemetry, @repo_query, %{query: "SELECT " <> _root}}
      assert_received {:telemetry, @repo_query, %{query: "SELECT " <> _comments}}
      assert_received {:telemetry, @repo_query, %{query: "commit"}}
    end
  end

  describe "result keys" do
    test "a relationship key that would overwrite a column is refused up front", %{
      instance: i,
      test: test
    } do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      assert {:error, {:unsupported_query, {:preload, "author"}}} =
               Authzura.all(AuthoredPost, session(), instance: i, preload: [:author])

      assert queries() == []
    end

    test "a relationship keyed like a stripped stitching column is kept", %{instance: i} do
      assert {:ok, [%{title: "one", author: %{"id" => 1, "manager_id" => nil}} = row, _two]} =
               Authzura.all(by_id(AuthoredPost), session(),
                 instance: i,
                 columns: [:title],
                 preload: [:author]
               )

      assert Map.keys(row) |> Enum.sort() == [:author, :title]
    end

    test "the internal Ecto association marker cannot be forged", %{instance: i} do
      assert {:error, {:unsupported_query, {:preload, "comments"}}} =
               Authzura.all(Article, session(), instance: i, preload: [comments: @forged])
    end
  end

  describe "one/3" do
    test "preloads the single row", %{instance: i} do
      assert {:ok, %{id: 2, comments: [%{"id" => 11}]}} =
               Authzura.one(where(Article, [a], a.id == 2), session(),
                 instance: i,
                 preload: [comments: [columns: [:id]]]
               )
    end
  end

  describe "one/3 with several roots" do
    test "fails before any level loads", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      assert {:error, :multiple_results} =
               Authzura.one(Article, session(), instance: i, preload: [:comments])

      assert ["begin", @set_repeatable_read, "SELECT " <> _root, "rollback"] = queries()
    end
  end

  describe "inside a caller's transaction" do
    test "a trusted transaction below repeatable read is refused", %{instance: i} do
      opts = [instance: i, preload: [:comments], in_transaction: :trust_isolation]

      for level <- ["READ COMMITTED", "READ UNCOMMITTED"] do
        assert {:ok, {:error, {:unsupported_query, :preload_in_transaction}}} =
                 Repo.transaction(fn ->
                   Repo.query!("SET TRANSACTION ISOLATION LEVEL #{level}")
                   Authzura.all(Article, session(), opts)
                 end)
      end

      assert {:ok, {:ok, [_one, _two]}} =
               Repo.transaction(fn ->
                 Repo.query!("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                 Authzura.all(Article, session(), opts)
               end)
    end

    test "preloads are refused unless isolation is trusted", %{instance: i} do
      opts = [instance: i, preload: [:comments]]

      assert {:ok, {:error, {:unsupported_query, :preload_in_transaction}}} =
               Repo.transaction(fn -> Authzura.all(Article, session(), opts) end)

      assert {:ok, {:ok, [%{comments: [_, _]}, %{comments: [_]}]}} =
               Repo.transaction(fn ->
                 Repo.query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")

                 Authzura.all(
                   by_id(Article),
                   session(),
                   [in_transaction: :trust_isolation] ++ opts
                 )
               end)
    end
  end

  describe "all_input/4 preload grammar" do
    test "only the JSON form is accepted", %{instance: i} do
      for preload <- [
            [:comments],
            %{comments: %{}},
            %{"comments" => @forged},
            %{"comments" => %{"columns" => [:id]}},
            %{"comments" => true},
            %{"comments" => 1},
            %{"comments" => ~D[2026-11-14]},
            {"comments", %{}}
          ] do
        assert {:error, {:invalid_input, {:preload, :invalid}}} =
                 Authzura.all_input(Article, session(), %{"preload" => preload}, instance: i)
      end
    end
  end

  describe "all_input/4" do
    test "loads an allowed preload", %{instance: i} do
      input = %{"preload" => %{"comments" => %{"order_by" => [%{"id" => "desc"}]}}}

      assert {:ok, [%{"comments" => one, id: 1}, %{"comments" => two, id: 2}]} =
               Authzura.all_input(
                 Article,
                 session(),
                 Map.put(input, "order_by", [%{"id" => "asc"}]),
                 instance: i
               )

      assert one == comments([12, 10], 1)
      assert two == comments([11], 2)
    end
  end
end

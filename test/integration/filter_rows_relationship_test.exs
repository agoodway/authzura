defmodule Authzura.Integration.FilterRowsRelationshipTest do
  use Authzura.DataCase, async: true

  alias Authzura.HasuraFixture
  alias Authzura.Model.Permission
  alias Authzura.Test.Schemas.{Article, User}

  defmodule PublishedArticle do
    @moduledoc false
    use Ecto.Schema

    @primary_key {:id, :integer, autogenerate: false}
    schema "published_articles" do
      field(:org_id, :integer)
      field(:author_id, :integer)
      field(:title, :string)
    end
  end

  @users {"public", "users"}
  @articles {"public", "articles"}
  @published {"public", "published_articles"}
  @mine %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}

  # The view grants more than the relationship's target table does. `articles` and `published`
  # map the same column pair to different tables.
  defp metadata(articles_root_fields \\ nil) do
    articles =
      %{columns: ["id", "title"], filter: @mine, limit: 5}
      |> then(
        &if articles_root_fields,
          do: Map.put(&1, :query_root_fields, articles_root_fields),
          else: &1
      )

    HasuraFixture.metadata([
      %{
        table: @users,
        array_relationships: [
          HasuraFixture.fk_relationship("articles", %{table: @articles, column: "author_id"}),
          HasuraFixture.array_relationship("published", @published, %{"id" => "author_id"})
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id"], filter: %{}}},
          %{role: "viewer", permission: %{columns: ["id"], filter: %{}}}
        ]
      },
      %{
        table: @articles,
        select_permissions: [%{role: "user", permission: articles}]
      },
      %{
        table: @published,
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title", "author_id"], filter: %{}}},
          %{role: "viewer", permission: %{columns: ["id", "title", "author_id"], filter: %{}}}
        ]
      }
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one')",
        """
        insert into public.users (id, org_id, email, role) values
          (1, 1, 'a@x.com', 'editor'), (2, 1, 'b@x.com', 'viewer')
        """,
        """
        insert into public.articles
          (id, org_id, author_id, editor_id, status, is_published, title, internal_notes)
        values
          (1, 1, 1, 2, 'published', true, 'one', 'n1'),
          (2, 1, 2, null, 'published', true, 'two', 'n2'),
          (3, 1, 2, null, 'draft', false, 'three', null)
        """
      ],
      &Repo.query!/1
    )

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp user(id),
    do: HasuraFixture.session!("user", %{"x-hasura-user-id" => Integer.to_string(id)})

  defp ids(query), do: query |> Repo.all() |> Enum.map(& &1.id) |> Enum.sort()

  test "without a relationship the view's own permission applies", %{instance: i} do
    assert {:ok, query, %Permission{columns: ["id", "title", "author_id"], table: @published}} =
             Authzura.filter_rows(PublishedArticle, user(1), instance: i)

    assert ids(query) == [1, 2]
  end

  test "a relationship authorizes the view by its target table's permission", %{instance: i} do
    for parent <- [User, @users, Ecto.Queryable.to_query(User)] do
      assert {:ok, query, %Permission{columns: ["id", "title"], limit: 5, table: @articles}} =
               Authzura.filter_rows(PublishedArticle, user(1),
                 instance: i,
                 relationship: {parent, "articles"}
               )

      assert ids(query) == [1]
    end
  end

  test "a role without a permission on the target is forbidden although the view grants it",
       %{instance: i} do
    viewer = HasuraFixture.session!("viewer", %{"x-hasura-user-id" => "2"})

    assert {:ok, _query, %Permission{}} =
             Authzura.filter_rows(PublishedArticle, viewer, instance: i)

    assert Authzura.filter_rows(PublishedArticle, viewer,
             instance: i,
             relationship: {User, "articles"}
           ) == {:error, :forbidden}
  end

  test "an unknown relationship is forbidden, or falls back to the root's own table",
       %{instance: i} do
    assert Authzura.filter_rows(PublishedArticle, user(1),
             instance: i,
             relationship: {User, "missing"}
           ) == {:error, :forbidden}

    assert Authzura.filter_rows(PublishedArticle, user(1),
             instance: i,
             relationship: {Article, "missing"}
           ) == {:error, :forbidden}

    assert {:ok, query, %Permission{table: @published}} =
             Authzura.filter_rows(PublishedArticle, user(1),
               instance: i,
               relationship: {User, "missing"},
               missing_relationship: :root
             )

    assert ids(query) == [1, 2]
  end

  test "a relationship mapping other columns than expected counts as missing", %{instance: i} do
    opts = [instance: i, relationship: {User, "articles"}]

    assert {:ok, _query, %Permission{table: @articles}} =
             Authzura.filter_rows(
               PublishedArticle,
               user(1),
               opts ++ [relationship_mapping: [{"id", "author_id"}]]
             )

    wrong = opts ++ [relationship_mapping: [{"id", "editor_id"}]]

    assert Authzura.filter_rows(PublishedArticle, user(1), wrong) == {:error, :forbidden}

    assert {:ok, _query, %Permission{table: @published}} =
             Authzura.filter_rows(
               PublishedArticle,
               user(1),
               wrong ++ [missing_relationship: :root]
             )
  end

  test "root_field: false skips the root field check under a relationship", %{instance: i} do
    assert {:ok, _query, %Permission{table: @articles}} =
             Authzura.filter_rows(PublishedArticle, user(1),
               instance: i,
               relationship: {User, "articles"},
               root_field: false
             )
  end

  test "the target table's root fields are enforced for the relationship path", %{test: test} do
    i = HasuraFixture.start_instance!(:"#{test} by pk", Repo, metadata(["select_by_pk"]))
    opts = [instance: i, relationship: {User, "articles"}]

    assert {:ok, _query, %Permission{table: @published}} =
             Authzura.filter_rows(PublishedArticle, user(1), instance: i)

    assert Authzura.filter_rows(PublishedArticle, user(1), opts) ==
             {:error, :root_field_disabled}

    assert {:ok, _query, %Permission{table: @articles}} =
             Authzura.filter_rows(PublishedArticle, user(1), opts ++ [root_field: :select_by_pk])

    assert {:ok, _query, %Permission{table: @articles}} =
             Authzura.filter_rows(PublishedArticle, user(1), opts ++ [root_field: false])
  end

  describe "relationship_target" do
    @mapping [{"id", "author_id"}]

    test "a relationship over the same columns to another table is missing", %{instance: i} do
      opts = [instance: i, relationship: {User, "published"}, relationship_mapping: @mapping]

      # Without a target check the other table's permission (every row) would authorize articles.
      assert {:ok, query, %Permission{table: @published}} =
               Authzura.filter_rows(Article, user(1), opts)

      assert ids(query) == [1, 2, 3]

      assert Authzura.filter_rows(Article, user(1), opts ++ [relationship_target: @articles]) ==
               {:error, :forbidden}

      assert Authzura.filter_rows(Article, user(1), opts ++ [relationship_target: Article]) ==
               {:error, :forbidden}

      assert {:ok, query, %Permission{table: @articles}} =
               Authzura.filter_rows(
                 Article,
                 user(1),
                 opts ++ [relationship_target: @articles, missing_relationship: :root]
               )

      assert ids(query) == [1]
    end

    test "a relationship to one of the given tables applies its target's permission",
         %{instance: i} do
      opts = [instance: i, relationship: {User, "articles"}, relationship_mapping: @mapping]

      for target <- [@articles, Article, [PublishedArticle, @articles]] do
        assert {:ok, query, %Permission{table: @articles}} =
                 Authzura.filter_rows(
                   PublishedArticle,
                   user(1),
                   opts ++ [relationship_target: target]
                 )

        assert ids(query) == [1]
      end

      assert Authzura.filter_rows(
               PublishedArticle,
               user(1),
               opts ++ [relationship_target: PublishedArticle]
             ) == {:error, :forbidden}
    end

    test "a malformed target is rejected", %{instance: i} do
      for target <- [[], "articles", {"public"}, Enum, [@articles, nil]] do
        assert_raise NimbleOptions.ValidationError, fn ->
          Authzura.filter_rows(PublishedArticle, user(1),
            instance: i,
            relationship: {User, "articles"},
            relationship_target: target
          )
        end
      end
    end
  end

  test "a malformed relationship option is rejected", %{instance: i} do
    assert_raise NimbleOptions.ValidationError, fn ->
      Authzura.filter_rows(PublishedArticle, user(1), instance: i, relationship: "articles")
    end

    for parent <- [nil, Enum, :not_a_module] do
      assert_raise NimbleOptions.ValidationError, fn ->
        Authzura.filter_rows(PublishedArticle, user(1),
          instance: i,
          relationship: {parent, "articles"}
        )
      end
    end

    assert_raise NimbleOptions.ValidationError, fn ->
      Authzura.filter_rows(PublishedArticle, user(1), instance: i, missing_relationship: :deny)
    end
  end
end

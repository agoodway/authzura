defmodule Authzura.Bench.Metadata do
  @moduledoc """
  The benchmark's Hasura metadata (format v3), applied to the bench Hasura
  and read back by Authzura from `hdb_catalog`. Test harness only. It
  tracks `organizations`, `users`, `org_memberships`, `articles` and
  `comments` and has these roles; none is `admin`, and no role is the
  instance's `admin_role`:

    * `tenant` - articles of the session's organization; also reads
      comments of those articles, and all users and organizations (the
      preload targets of the `preload-*` scenarios)
    * `author` - own articles `_or` published ones
    * `member` - published articles, when the session user has a
      membership (`_exists` on `org_memberships`)
    * `deep` - comments whose article's author's organization is the
      session's: a three-hop filter
    * `limited` - published articles, capped at 50 rows, and comments
      capped at 2 per parent
    * `arr` - articles of the organizations in the session array variable
      (`_in`)
    * `broad` - published articles, and comments whose article is
      published: a permission about half the rows satisfy (the
      `*-broad-limit` scenarios). The unlifted relationship control walks
      an ordered index; the measured PG18 lifted generic plan does not
    * `open` - every article. It is a negative control for the gate's
      permission guard and no scenario uses it
  """

  alias Authzura.HasuraFixture

  @organizations {"public", "organizations"}
  @users {"public", "users"}
  @memberships {"public", "org_memberships"}
  @articles {"public", "articles"}
  @comments {"public", "comments"}

  @article_columns ["id", "org_id", "author_id", "status", "is_published", "title"]
  @comment_columns ["id", "article_id", "author_id", "body"]
  @user_columns ["id", "org_id", "email", "role"]

  @user_id "X-Hasura-User-Id"
  @org_id "X-Hasura-Org-Id"

  @limit_articles 50
  @limit_comments 2

  @doc "The tracked tables, `[{schema, name}]`."
  @spec tables() :: [{String.t(), String.t()}]
  def tables, do: [@organizations, @users, @memberships, @articles, @comments]

  @doc "The metadata document."
  @spec build() :: map()
  def build do
    [organizations(), users(), memberships(), articles(), comments()]
    |> HasuraFixture.metadata()
    |> put_in(["sources", Access.at(0), "configuration"], %{
      "connection_info" => %{"database_url" => %{"from_env" => "HASURA_GRAPHQL_DATABASE_URL"}}
    })
  end

  defp organizations do
    %{
      table: @organizations,
      select_permissions: [perm("tenant", ["id", "name"], %{})]
    }
  end

  defp users do
    %{
      table: @users,
      object_relationships: [HasuraFixture.fk_relationship("org", "org_id")],
      select_permissions: [perm("tenant", @user_columns, %{})]
    }
  end

  defp memberships, do: %{table: @memberships}

  defp articles do
    %{
      table: @articles,
      object_relationships: [
        HasuraFixture.fk_relationship("author", "author_id"),
        HasuraFixture.fk_relationship("org", "org_id")
      ],
      array_relationships: [
        HasuraFixture.fk_relationship("comments", %{table: @comments, column: "article_id"})
      ],
      select_permissions: [
        perm("tenant", @article_columns, %{"org_id" => %{"_eq" => @org_id}}),
        perm("author", @article_columns, %{
          "_or" => [%{"author_id" => %{"_eq" => @user_id}}, %{"is_published" => %{"_eq" => true}}]
        }),
        perm("member", @article_columns, %{
          "_and" => [
            %{"is_published" => %{"_eq" => true}},
            %{
              "_exists" => %{
                "_table" => %{"schema" => "public", "name" => "org_memberships"},
                "_where" => %{"user_id" => %{"_eq" => @user_id}}
              }
            }
          ]
        }),
        perm("limited", @article_columns, %{"is_published" => %{"_eq" => true}}, @limit_articles),
        perm("arr", @article_columns, %{"org_id" => %{"_in" => "X-Hasura-Org-Ids"}}),
        perm("broad", @article_columns, %{"status" => %{"_eq" => "published"}}),
        perm("open", @article_columns, %{})
      ]
    }
  end

  defp comments do
    %{
      table: @comments,
      object_relationships: [
        HasuraFixture.fk_relationship("article", "article_id"),
        HasuraFixture.fk_relationship("author", "author_id")
      ],
      select_permissions: [
        perm("tenant", @comment_columns, %{
          "article" => %{"org_id" => %{"_eq" => @org_id}}
        }),
        perm("deep", @comment_columns, %{
          "article" => %{"author" => %{"org" => %{"id" => %{"_eq" => @org_id}}}}
        }),
        perm("broad", @comment_columns, %{"article" => %{"is_published" => %{"_eq" => true}}}),
        perm("limited", @comment_columns, %{}, @limit_comments)
      ]
    }
  end

  defp perm(role, columns, filter, limit \\ nil) do
    permission = Map.merge(%{columns: columns, filter: filter}, limit_entry(limit))
    %{role: role, permission: permission}
  end

  defp limit_entry(nil), do: %{}
  defp limit_entry(limit), do: %{limit: limit}
end

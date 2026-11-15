defmodule Authzura.Integration.GetTest do
  use Authzura.CommittedCase

  alias Authzura.{Error, HasuraFixture, TelemetryHelper}
  alias Authzura.Test.Schemas.Article

  @articles {"public", "articles"}
  @users {"public", "users"}
  @memberships {"public", "org_memberships"}
  @published {"public", "published_articles"}
  @repo_query [:authzura, :test, :repo, :query]

  # The SQL and params of the read the executor ran in this process.
  defp read_query do
    assert_receive {:telemetry, @repo_query, %{query: "SELECT " <> _ = sql, params: params}}
    {sql, params}
  end

  defp permission(role, columns, extra \\ %{}),
    do: %{role: role, permission: Map.merge(%{columns: columns, filter: %{}}, extra)}

  defp metadata do
    published = %{"is_published" => %{"_eq" => true}}

    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: [
          permission("user", ["id", "title", "author_id"], %{filter: published}),
          permission("pk_only", ["id", "title"], %{
            filter: published,
            query_root_fields: ["select_by_pk"]
          }),
          permission("no_roots", ["id", "title"], %{query_root_fields: []}),
          permission("aggregate_only", ["id", "title"], %{
            query_root_fields: ["select_aggregate"]
          }),
          permission("hidden_pk", ["title"])
        ]
      },
      %{table: @users, select_permissions: [permission("user", ["id", "email"])]},
      %{
        table: @memberships,
        select_permissions: [permission("user", ["org_id", "user_id", "level"])]
      },
      %{table: @published, select_permissions: [permission("user", ["id", "title"])]}
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one'), (2, 'two')",
        "insert into public.users (id, org_id, email, role) values (1, 1, 'a@x.com', 'editor')",
        """
        insert into public.articles (id, org_id, author_id, status, is_published, title) values
          (1, 1, 1, 'draft', false, 'hidden'), (2, 1, 1, 'published', true, 'shown')
        """,
        "insert into public.org_memberships values (1, 1, 5), (2, 1, 7)"
      ],
      &Repo.query!/1
    )

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata(), admin_role: "admin")}
  end

  defp session(role \\ "user"), do: HasuraFixture.session!(role)

  describe "get/4" do
    test "returns the row with that primary key, like one/3", %{instance: i} do
      assert {:ok, %{id: 2, title: "shown", author_id: 1} = row} =
               Authzura.get(Article, session(), 2, instance: i)

      assert Authzura.one(where(Article, [a], a.id == 2), session(), instance: i) == {:ok, row}

      assert {:ok, %{"id" => 2, "title" => "shown"}} =
               Authzura.get("articles", session(), 2, instance: i, columns: ["id", "title"])
    end

    test "a row the permission hides is nil", %{instance: i} do
      assert Authzura.get(Article, session(), 1, instance: i) == {:ok, nil}
      assert Authzura.get(Article, session(), 404, instance: i) == {:ok, nil}

      assert Authzura.get(Article, session("admin"), 1, instance: i) |> elem(1) |> Map.get(:id) ==
               1
    end

    test "a select_by_pk-only role can get, but not all/3 or one/3", %{instance: i} do
      assert {:ok, %{id: 2, title: "shown"}} =
               Authzura.get(Article, session("pk_only"), 2, instance: i)

      assert Authzura.get(Article, session("pk_only"), 1, instance: i) == {:ok, nil}

      assert Authzura.all(Article, session("pk_only"), instance: i) ==
               {:error, :root_field_disabled}

      assert Authzura.one(where(Article, [a], a.id == 2), session("pk_only"), instance: i) ==
               {:error, :root_field_disabled}
    end

    test "a role with neither select nor select_by_pk is root_field_disabled", %{instance: i} do
      for role <- ["no_roots", "aggregate_only"] do
        assert Authzura.get(Article, session(role), 2, instance: i) ==
                 {:error, :root_field_disabled},
               role
      end

      assert Authzura.get(Article, session("nobody"), 2, instance: i) == {:error, :forbidden}
    end

    test "every primary key column must be one the role may select", %{instance: i} do
      assert Authzura.get(Article, session("hidden_pk"), 2, instance: i) ==
               {:error, {:forbidden_columns, ["id"]}}
    end

    test "a composite key needs every key column and nothing else", %{instance: i} do
      expected = %{"org_id" => 2, "user_id" => 1, "level" => 7}

      for pk <- [[org_id: 2, user_id: 1], %{"user_id" => 1, "org_id" => 2}] do
        assert Authzura.get("org_memberships", session(), pk, instance: i) == {:ok, expected}
      end

      assert Authzura.get("org_memberships", session(), [org_id: 3, user_id: 1], instance: i) ==
               {:ok, nil}

      for pk <- [
            2,
            [org_id: 2],
            %{"org_id" => 2, "user_id" => 1, "level" => 7},
            [org_id: 2, user_id: 1, org_id: 3],
            %{"org_id" => 2, :org_id => 2},
            [],
            %{1 => 2}
          ] do
        assert Authzura.get("org_memberships", session(), pk, instance: i) ==
                 {:error, {:invalid_input, {:primary_key, :invalid}}},
               inspect(pk)
      end
    end

    test "key values are cast to the column type", %{instance: i} do
      assert Authzura.get(Article, session(), "x", instance: i) ==
               {:error,
                {:invalid_input, [{["id"], {:invalid_literal, {:invalid_value, "int8"}}}]}}

      assert Authzura.get(Article, session(), nil, instance: i) ==
               {:error, {:invalid_input, [{["id"], :null_operand}]}}

      assert {:ok, %{id: 2}} = Authzura.get(Article, session(), [id: 2], instance: i)
      assert {:ok, %{id: 2}} = Authzura.get(Article, session(), %{"id" => 2}, instance: i)
    end

    test "a key value is cast to the column type, never read as SQL", %{instance: i} do
      assert Authzura.get("articles", session(), "2 or true", instance: i) ==
               {:error,
                {:invalid_input, [{["id"], {:invalid_literal, {:invalid_value, "int8"}}}]}}
    end

    test "the key is a plain bound equality ANDed with the permission",
         %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      assert {:ok, %{"id" => 2}} =
               Authzura.get("articles", session(), 2, instance: i, columns: ["id"])

      {sql, params} = read_query()
      assert sql =~ ~r/WHERE \(\w+\."id" OPERATOR\(pg_catalog\.=\) \$1::bigint\) AND \(/
      refute sql =~ "CASE"
      assert [2 | _permission] = params
    end

    # With sequential scans priced out, a fenced key (`CASE WHEN permission
    # THEN key ...`) would still be a Seq Scan; a plain conjunct is not.
    test "the primary key index serves the read", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
      assert {:ok, %{id: 2}} = Authzura.get(Article, session(), 2, instance: i, columns: [:id])
      {sql, params} = read_query()

      {:ok, plan} =
        Repo.transaction(fn ->
          Repo.query!("SET LOCAL enable_seqscan = off")
          Repo.query!("EXPLAIN " <> sql, params).rows |> List.flatten() |> Enum.join("\n")
        end)

      assert plan =~ "articles_pkey", plan
    end

    test "only a bare schema or table", %{instance: i} do
      for queryable <- [
            where(Article, [a], a.id == 1),
            join(Article, :inner, [a], u in "users", on: u.id == a.author_id),
            limit(Article, 1),
            offset(Article, 1),
            union(Article, ^from(a in Article))
          ] do
        assert Authzura.get(queryable, session(), 2, instance: i) ==
                 {:error, {:unsupported_query, :get_requires_bare_root}}
      end

      assert {:ok, %{id: 2}} = Authzura.get(from(a in Article, as: :a), session(), 2, instance: i)
    end

    test "a table without a primary key", %{instance: i} do
      assert Authzura.get("published_articles", session(), 2, instance: i) ==
               {:error, {:unsupported_query, :no_primary_key}}
    end

    test "preloads load as for one/3", %{instance: i} do
      assert Authzura.get(Article, session(), 2,
               instance: i,
               columns: [:id],
               preload: [author: [columns: [:id, :email]]]
             ) == {:ok, %{id: 2, author: %{"id" => 1, "email" => "a@x.com"}}}

      assert Authzura.get(Article, session(), 1, instance: i, preload: [:author]) == {:ok, nil}
    end

    test "get!/4 raises on denial", %{instance: i} do
      assert %{id: 2} = Authzura.get!(Article, session(), 2, instance: i, columns: [:id])
      assert Authzura.get!(Article, session(), 1, instance: i) == nil

      assert %Error{reason: :root_field_disabled} =
               catch_error(Authzura.get!(Article, session("no_roots"), 2, instance: i))
    end
  end
end

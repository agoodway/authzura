defmodule Authzura.Integration.ScopeTest do
  use Authzura.DataCase, async: true

  import Authzura.SqlHelper

  alias Authzura.{Error, HasuraFixture, Scope, TelemetryHelper}
  alias Authzura.Model.Permission
  alias Authzura.Test.Schemas.{Article, AuditUser, User}
  alias Ecto.Adapters.SQL
  alias Ecto.Adapters.SQL.Sandbox
  alias Ecto.Query

  defmodule Headline do
    @moduledoc false
    use Ecto.Schema

    @primary_key false
    schema "articles" do
      field(:id, :integer)
      field(:headline, :string, source: :title)
      field(:internal_notes, :string)
      field(:preview, :string, virtual: true)
    end
  end

  @articles {"public", "articles"}
  @users {"public", "users"}
  @audit_users {"audit", "users"}

  @mine %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}
  @article_columns ["id", "org_id", "author_id", "editor_id", "title", "is_published"]

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: @article_columns, filter: @mine}},
          %{role: "capped", permission: %{columns: ["id", "title"], filter: %{}, limit: 2}},
          %{
            role: "noroot",
            permission: %{columns: ["id"], filter: %{}, query_root_fields: []}
          },
          %{
            role: "reader",
            permission: %{
              columns: ["id"],
              filter: %{"author" => %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}}
            }
          }
        ]
      },
      %{
        table: @users,
        select_permissions: [
          %{
            role: "user",
            permission: %{
              columns: ["id", "email"],
              filter: %{"id" => %{"_eq" => "X-Hasura-User-Id"}}
            }
          },
          %{role: "public_only", permission: %{columns: ["id"], filter: %{}}}
        ]
      },
      %{
        table: @audit_users,
        select_permissions: [%{role: "user", permission: %{columns: ["id", "note"], filter: %{}}}]
      }
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one'), (2, 'two')",
        """
        insert into public.users (id, org_id, email, role) values
          (1, 1, 'a@x.com', 'editor'), (2, 1, 'b@x.com', 'viewer'), (3, 2, 'c@x.com', 'viewer')
        """,
        """
        insert into public.articles
          (id, org_id, author_id, editor_id, status, is_published, title, internal_notes)
        values
          (1, 1, 1, 3, 'draft', false, 'one', 'n1'),
          (2, 1, 1, null, 'published', true, 'two', 'n2'),
          (3, 1, 1, 2, 'draft', false, 'three', null),
          (4, 1, 2, 3, 'published', true, 'four', null),
          (5, 2, 3, 1, 'draft', false, 'five', null)
        """,
        "insert into audit.users values (1, 'audited'), (9, 'nine')"
      ],
      &Repo.query!/1
    )

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp user(id),
    do: HasuraFixture.session!("user", %{"x-hasura-user-id" => Integer.to_string(id)})

  defp user_or("user"), do: user(1)
  defp user_or(role), do: HasuraFixture.session!(role)

  defp scoped!(queryable, session, instance, opts \\ []) do
    {:ok, query} = Authzura.scope(queryable, session, [instance: instance] ++ opts)
    query
  end

  defp ids(rows), do: rows |> Enum.map(& &1.id) |> Enum.sort()

  describe "columns" do
    test "the SELECT list holds only the requested, allowed columns", %{instance: i} do
      query = scoped!(Article, user(1), i, columns: [:id, :title])

      assert sql(query) =~ ~s(SELECT a0."id", a0."title" FROM "public"."articles" AS a0)

      assert Repo.all(query) |> Enum.sort() == [
               %{id: 1, title: "one"},
               %{id: 2, title: "two"},
               %{id: 3, title: "three"}
             ]
    end

    test "the default projection is every allowed column", %{instance: i} do
      [row | _rows] = Article |> scoped!(user(1), i) |> Repo.all()

      assert row |> Map.keys() |> Enum.sort() ==
               ~w(author_id editor_id id is_published org_id title)a

      [row | _rows] = "articles" |> scoped!(user(1), i) |> Repo.all()
      assert row |> Map.keys() |> Enum.sort() == Enum.sort(@article_columns)
    end

    test "an unpermitted column is forbidden", %{instance: i} do
      assert Authzura.scope(Article, user(1), instance: i, columns: [:id, :internal_notes]) ==
               {:error, {:forbidden_columns, ["internal_notes"]}}

      assert Authzura.scope("articles", user(1), instance: i, columns: ["id", "body"]) ==
               {:error, {:forbidden_columns, ["body"]}}
    end

    test "a field with a source authorizes its column", %{instance: i} do
      query = scoped!(Headline, user(1), i, columns: [:headline])
      assert sql(query) =~ ~s(SELECT a0."title" FROM)

      assert query |> Repo.all() |> Enum.sort() == [
               %{headline: "one"},
               %{headline: "three"},
               %{headline: "two"}
             ]

      # The default maps allowed columns back to fields; internal_notes is not allowed.
      [row | _rows] = Headline |> scoped!(user(1), i) |> Repo.all()
      assert row |> Map.keys() |> Enum.sort() == [:headline, :id]
    end

    test "an explicit empty column list is refused", %{instance: i} do
      assert Authzura.scope(Article, user(1), instance: i, columns: []) ==
               {:error, {:unsupported_query, :empty_columns}}
    end

    test "a virtual or unknown field is forbidden", %{instance: i} do
      assert {:error, {:forbidden_columns, ["preview"]}} =
               Authzura.scope(Headline, user(1), instance: i, columns: [:preview])

      assert {:error, {:forbidden_columns, ["nope"]}} =
               Authzura.scope(Headline, user(1), instance: i, columns: [:id, :nope])
    end
  end

  describe "prefixes" do
    test "@schema_prefix beats put_query_prefix, and a from prefix beats both", %{instance: i} do
      query = AuditUser |> put_query_prefix("public") |> scoped!(user(1), i)
      assert sql(query) =~ ~s(FROM "audit"."users")

      assert query |> Repo.all() |> Enum.sort() == [
               %{id: 1, note: "audited"},
               %{id: 9, note: "nine"}
             ]

      query =
        from(u in AuditUser, prefix: "public") |> put_query_prefix("audit") |> scoped!(user(1), i)

      assert sql(query) =~ ~s(FROM "public"."users")
      assert Repo.all(query) == [%{id: 1}]
    end

    test "a repo prefix option cannot redirect the scoped query", %{instance: i} do
      query = scoped!(Article, user(1), i, columns: [:id])
      assert query |> Repo.all(prefix: "audit") |> ids() == [1, 2, 3]
    end

    test "search_path cannot redirect the scoped query", %{instance: i} do
      Repo.query!("SET LOCAL search_path TO audit")
      query = scoped!("users", user(1), i)
      assert Repo.all(query) == [%{"id" => 1, "email" => "a@x.com"}]
    end

    test "public.users and audit.users keep their own permissions", %{instance: i} do
      assert "users" |> scoped!(user(1), i) |> Repo.all() == [%{"id" => 1, "email" => "a@x.com"}]

      audit = from(u in "users", prefix: "audit") |> scoped!(user(1), i) |> Repo.all()

      assert Enum.sort(audit) == [
               %{"id" => 1, "note" => "audited"},
               %{"id" => 9, "note" => "nine"}
             ]

      prefixed = "users" |> put_query_prefix("audit") |> scoped!(user(1), i) |> Repo.all()
      assert Enum.sort(prefixed) == Enum.sort(audit)

      assert Authzura.scope(AuditUser, HasuraFixture.session!("public_only"), instance: i) ==
               {:error, :forbidden}

      assert User |> scoped!(HasuraFixture.session!("public_only"), i) |> Repo.all() |> ids() == [
               1,
               2,
               3
             ]
    end

    test "table: is an assertion", %{instance: i} do
      assert {:ok, _query} = Authzura.scope(Article, user(1), instance: i, table: @articles)

      assert Authzura.scope(Article, user(1), instance: i, table: {"audit", "articles"}) ==
               {:error, {:unsupported_query, :table_mismatch}}

      assert Authzura.scope(AuditUser, user(1), instance: i, table: @users) ==
               {:error, {:unsupported_query, :table_mismatch}}
    end
  end

  describe "roles" do
    test "a role without a permission is forbidden", %{instance: i} do
      assert Authzura.scope(Article, HasuraFixture.session!("nobody"), instance: i) ==
               {:error, :forbidden}
    end

    test "without an admin role, admin is just a role", %{instance: i} do
      assert Authzura.scope(Article, HasuraFixture.session!("admin"), instance: i) ==
               {:error, :forbidden}
    end

    test "the configured admin role sees every row and column", %{test: test} do
      instance =
        HasuraFixture.start_instance!(Module.concat(test, Admin), Repo, metadata(),
          admin_role: "admin"
        )

      rows = Article |> scoped!(HasuraFixture.session!("admin"), instance) |> Repo.all()
      assert ids(rows) == [1, 2, 3, 4, 5]
      assert %{internal_notes: "n1", body: nil} = Enum.find(rows, &(&1.id == 1))

      assert AuditUser
             |> scoped!(HasuraFixture.session!("admin"), instance)
             |> Repo.all()
             |> ids() == [1, 9]

      assert Authzura.scope(from(t in "missing_table"), HasuraFixture.session!("admin"),
               instance: instance
             ) ==
               {:error, :forbidden}
    end

    test "a missing session variable is reported", %{instance: i} do
      assert Authzura.scope(Article, HasuraFixture.session!("user"), instance: i) ==
               {:error, {:missing_session_variable, "x-hasura-user-id"}}
    end
  end

  describe "root fields and limits" do
    test "a root aggregate requires select_aggregate or all root fields" do
      permission = %Permission{role: "user", table: @articles, operation: :select}

      for fields <- [:all, [:select_aggregate], [:select, :select_aggregate]] do
        assert Scope.root_field(%{permission | root_fields: fields}, :select_aggregate) == :ok
      end

      for fields <- [[], [:select], [:select_by_pk]] do
        assert Scope.root_field(%{permission | root_fields: fields}, :select_aggregate) ==
                 {:error, :root_field_disabled}
      end
    end

    test "a table without the select root field is disabled", %{instance: i} do
      assert Authzura.scope(Article, HasuraFixture.session!("noroot"), instance: i) ==
               {:error, :root_field_disabled}
    end

    test "the effective limit is min(caller, permission)", %{instance: i} do
      capped = HasuraFixture.session!("capped")

      assert Article |> limit(10) |> scoped!(capped, i) |> Repo.all() |> length() == 2
      assert Article |> limit(1) |> scoped!(capped, i) |> Repo.all() |> length() == 1
      assert Article |> scoped!(capped, i) |> Repo.all() |> length() == 2

      n = 1
      assert Article |> limit(^n) |> scoped!(capped, i) |> Repo.all() |> length() == 1
      n = 7
      assert Article |> limit(^n) |> scoped!(capped, i) |> Repo.all() |> length() == 2
    end

    test "a pinned limit or offset that is not a nonnegative integer is rejected", %{
      instance: i
    } do
      for role <- ["capped", "user"], n <- [-1, "3", 1.5] do
        assert Authzura.scope(limit(Article, ^n), user_or(role), instance: i) ==
                 {:error, {:unsupported_query, :limit}}

        assert Authzura.scope(offset(Article, ^n), user_or(role), instance: i) ==
                 {:error, {:unsupported_query, :offset}}
      end

      n = 1
      assert {:ok, _query} = Authzura.scope(offset(Article, ^n), user(1), instance: i)
    end
  end

  describe "aliases" do
    test "a caller join aliased like a relationship does not mis-correlate", %{instance: i} do
      reader = HasuraFixture.session!("reader", %{"x-hasura-org-id" => "1"})

      # The caller's :author is the editor; the permission's author relationship
      # must still follow author_id.
      query = from(a in Article, join: u in User, as: :author, on: u.id == a.editor_id)
      assert query |> scoped!(reader, i) |> Repo.all() |> ids() == [1, 3, 4]
    end

    test "an existing root alias is reused", %{instance: i} do
      query = from(a in Article, as: :a, where: a.id > 1) |> scoped!(user(1), i, columns: [:id])

      refute Map.has_key?(query.aliases, :__authzura_0)
      assert query.from.as == :a
      assert query |> Repo.all() |> ids() == [2, 3]
    end
  end

  describe "accepted shapes" do
    test "a read-only CTE named articles cannot shadow the table", %{instance: i} do
      fake =
        from(u in "users", prefix: "public", select: %{id: u.id, author_id: 1, title: "fake"})

      query =
        Article |> with_cte("articles", as: ^fake) |> scoped!(user(1), i, columns: [:id, :title])

      assert sql(query) =~ ~s(FROM "public"."articles" AS a0)
      assert query |> Repo.all() |> Enum.map(& &1.title) |> Enum.sort() == ["one", "three", "two"]
    end

    test "a same-table union_all: the parent's limit and offset cover the whole result", %{
      instance: i
    } do
      branch = from(a in Article, where: a.id >= 2)
      query = from(a in Article, where: a.id <= 2) |> union_all(^branch) |> limit(3) |> offset(1)
      scoped = scoped!(query, user(1), i, columns: [:id])

      # user 1 sees 1..3: [1, 2] ++ [2, 3], then OFFSET 1 LIMIT 3 over the union.
      assert scoped |> Repo.all() |> length() == 3
      assert sql(scoped) =~ ~r/UNION ALL \(SELECT .*"public"."articles".*\) LIMIT 3 OFFSET 1$/
    end

    test "each union branch carries its own permission cap", %{instance: i} do
      branch = from(a in Article, where: a.id >= 3, limit: 10)
      query = from(a in Article, where: a.id <= 3) |> union_all(^branch) |> limit(10)
      scoped = scoped!(query, HasuraFixture.session!("capped"), i)

      assert sql(scoped) =~ ~r/UNION ALL \(SELECT .* LIMIT \$\d+\) LIMIT \$\d+$/
      assert {_sql, params} = SQL.to_sql(:all, Repo, scoped)
      assert Enum.count(params, &(&1 == 2)) == 2
      assert scoped |> Repo.all() |> length() == 2
    end

    test "union branches over another physical table are rejected", %{instance: i} do
      query = union_all(from(u in "users"), ^from(u in "users", prefix: "audit"))

      assert Authzura.scope(query, user(1), instance: i) ==
               {:error, {:unsupported_query, :combination_tables}}
    end
  end

  # A task reading as user `id` through the parent's sandbox connection.
  defp read_as(id, instance, parent) do
    Task.async(fn ->
      Sandbox.allow(Repo, parent, self())
      {id, Article |> scoped!(user(id), instance, columns: [:id, :author_id]) |> Repo.all()}
    end)
  end

  describe "sessions" do
    test "concurrent sessions on one template each see their own rows", %{instance: i} do
      parent = self()

      results = 1..20 |> Enum.map(&read_as(rem(&1, 2) + 1, i, parent)) |> Task.await_many()

      for {id, rows} <- results, do: assert(rows != [] and Enum.all?(rows, &(&1.author_id == id)))
    end
  end

  describe "public API" do
    test "permission/3, allowed_columns/3 and validate_columns/4", %{instance: i} do
      assert {:ok, %Permission{role: "user", table: @articles, columns: columns}} =
               Authzura.permission(user(1), Article, instance: i)

      assert Enum.sort(columns) == Enum.sort(@article_columns)
      assert Authzura.allowed_columns(user(1), "users", instance: i) == {:ok, ["id", "email"]}

      assert Authzura.permission(HasuraFixture.session!("nobody"), Article, instance: i) ==
               {:error, :forbidden}

      assert Authzura.validate_columns(user(1), Article, [:id, :title], instance: i) == :ok

      assert Authzura.validate_columns(user(1), Article, [:id, :internal_notes], instance: i) ==
               {:error, {:forbidden_columns, ["internal_notes"]}}
    end

    test "permission/3 is introspection and ignores root_fields", %{instance: i} do
      assert {:ok, %Permission{root_fields: []}} =
               Authzura.permission(HasuraFixture.session!("noroot"), Article, instance: i)

      assert Authzura.allowed_columns(HasuraFixture.session!("noroot"), Article, instance: i) ==
               {:ok, ["id"]}
    end

    test "scope!/3 raises Authzura.Error", %{instance: i} do
      assert %Query{} = Authzura.scope!(Article, user(1), instance: i)

      assert_raise Error, ~r/:forbidden/, fn ->
        Authzura.scope!(Article, HasuraFixture.session!("nobody"), instance: i)
      end
    end

    test "an instance that is not running is not ready" do
      assert Authzura.scope(Article, user(1), instance: Module.concat(__MODULE__, Missing)) ==
               {:error, :not_ready}
    end

    test "preloads are executor-only", %{instance: i} do
      assert Authzura.scope(Article, user(1), instance: i, preload: [:author]) ==
               {:error, {:unsupported_query, :preload_requires_execute}}
    end
  end

  describe "telemetry" do
    test "scope emits granted and denied stops", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [[:authzura, :scope, :stop]], instance: i)

      Authzura.scope(Article, HasuraFixture.session!("nobody"), instance: i)

      assert_receive {:telemetry, [:authzura, :scope, :stop],
                      %{result: :denied, reason_class: :forbidden, role: "nobody"}}

      Authzura.scope(Article, user(1), instance: i)
      assert_receive {:telemetry, [:authzura, :scope, :stop], %{result: :granted, role: "user"}}
    end
  end
end

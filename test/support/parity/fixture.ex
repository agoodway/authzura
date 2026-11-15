defmodule Authzura.Parity.Fixture do
  @moduledoc """
  The parity database: schema, seed rows and the Hasura metadata applied to
  the real Hasura.

    * `migrate!/1` runs the fixture migrations of `priv/test_migrations`,
      every one except `create_hdb_catalog`: real Hasura owns
      `hdb_catalog`.
    * `seed!/1` truncates the fixture tables (never the catalog) and commits
      the rows below.
    * `metadata/0` is the fixture's relationships
      (`Authzura.FilterFixture.relationship_tables/0` plus a reverse object
      relationship and an organization's users) with one select permission
      per parity role. Each role isolates one rule, so a test names the rule
      it checks by its role.
  """

  alias Authzura.{FilterFixture, FixtureSchema, HasuraFixture}
  alias Ecto.Migrator

  @migrations "priv/test_migrations"
  @hasura_owned "create_hdb_catalog"
  @migration_namespace Authzura.Test.Repo.Migrations

  @organizations {"public", "organizations"}
  @users {"public", "users"}
  @profiles {"public", "user_profiles"}
  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @memberships {"public", "org_memberships"}
  @notes {"public", "membership_notes"}
  @order {"public", "Order"}
  @kinds {"public", "key_kinds"}
  @view {"public", "published_articles"}
  @audit_users {"audit", "users"}
  @events {"audit", "article_events"}

  @tracked FixtureSchema.tracked_refs()

  # "line item" is not a GraphQL name; Hasura exposes it as `line_item`.
  @graphql_names %{@order => %{"line item" => "line_item"}}

  @seeds [
    "insert into public.organizations values (1, 'one'), (2, 'two')",
    """
    insert into public.users (id, org_id, manager_id, email, role, is_admin, salary) values
      (1, 1, null, 'a@x.com', 'editor', false, 1000.50),
      (2, 1, 1, 'b@x.com', 'viewer', false, null),
      (3, 2, null, 'C@X.com', 'admin', true, 2500)
    """,
    "insert into public.user_profiles values (1, 'bio one'), (3, null)",
    """
    insert into public.articles
      (id, org_id, author_id, editor_id, status, is_published, title, body, internal_notes,
       assignees, external_ref, published_at)
    values
      (1, 1, 1, null, 'draft', false, 'Alpha', null, null, '{"1": true}',
       '0b6f1f8e-4a39-4c1e-9d2a-1a2b3c4d5e6f', null),
      (2, 1, 1, 2, 'published', true, 'beta', 'b', 'x', '{"2": true, "3": true}',
       null, '2024-03-01 10:00:00.5+00'),
      (3, 1, 2, null, 'review', false, 'Gamma', 'g', 'y', '{}', null, null),
      (4, 2, 3, 3, 'published', true, 'delta', null, null, '{"1": true, "3": [1, 2.5]}',
       '7d0e0a3c-6b0f-4e55-8a77-000000000004', '2025-01-02 03:04:05+00')
    """,
    """
    insert into public.comments values
      (1, 1, 1, 'a'), (2, 1, 2, 'b'), (3, 2, 1, 'b'), (4, 4, 3, 'c'), (5, 2, 2, 'd'), (6, 2, 3, 'e')
    """,
    "insert into public.org_memberships values (1, 1, 5), (1, 2, 7)",
    "insert into public.membership_notes values (1, 1, 1, 'n1'), (2, 1, 2, 'n2'), (3, null, null, 'orphan')",
    ~s|insert into public."Order" ("Id", "line item") values (1, 'widget'), (2, 'gadget'), (3, null)|,
    """
    insert into public.key_kinds (id, code, rank, grade, score, meta, ratio) values
      (1, 'a', 1, 'A', 1.5, null, 0.25),
      (2, 'b', 2, null, 2.25, '{}', null),
      (3, 'a,b', 3, 'B', null, 'null', 1.5),
      (4, '"q"', 4, null, -3.75, null, null),
      (5, 'abcdefghijklmnop', 5, 'C', 0.1, '{"k": [1]}', 0.5)
    """,
    "insert into audit.users values (1, 'audited one'), (5, 'audited')",
    "insert into audit.article_events values (1, 1, 'edit'), (2, 1, 'view'), (3, 4, 'edit')"
  ]

  @user_id "X-Hasura-User-Id"
  @all_columns "*"
  @article_columns ["id", "title", "author_id", "is_published"]

  @tables %{
    organizations: @organizations,
    users: @users,
    profiles: @profiles,
    articles: @articles,
    comments: @comments,
    memberships: @memberships,
    notes: @notes,
    order: @order,
    kinds: @kinds,
    view: @view,
    audit_users: @audit_users,
    events: @events
  }

  @doc """
  The `{schema, name}` of a fixture table by its short name: `:articles`,
  `:users`, `:comments`, `:kinds` (`key_kinds`), `:notes`
  (`membership_notes`), `:memberships`, `:profiles` (`user_profiles`),
  `:organizations`, `:order` (`"Order"`), `:view` (`published_articles`),
  `:audit_users` or `:events` (`audit.article_events`).
  """
  @spec table(atom()) :: {String.t(), String.t()}
  def table(name), do: Map.fetch!(@tables, name)

  @doc "Every table the metadata tracks."
  @spec tracked() :: [{String.t(), String.t()}]
  def tracked, do: @tracked

  @doc """
  The columns of `table` whose GraphQL name differs from their database
  name (the metadata's `column_config` custom names), as
  `%{column => graphql_name}`; `%{}` for most tables.
  """
  @spec graphql_names({String.t(), String.t()}) :: %{String.t() => String.t()}
  def graphql_names(table), do: Map.get(@graphql_names, table, %{})

  @doc "The article columns most article roles may select."
  @spec article_columns() :: [String.t()]
  def article_columns, do: @article_columns

  @doc "Runs every fixture migration except the Hasura-owned catalog one."
  @spec migrate!(module()) :: [integer()]
  def migrate!(repo) do
    path = Application.app_dir(:authzura, @migrations)

    pending =
      for {:down, version, name} <- Migrator.migrations(repo, [path]),
          name != @hasura_owned,
          do: {version, migration_module(path, version, name)}

    Migrator.run(repo, pending, :up, all: true, log: false)
  end

  @doc "Replaces every fixture row with the parity seed rows, committed."
  @spec seed!(module()) :: :ok
  def seed!(repo) do
    :ok = FixtureSchema.truncate(repo, hasura_catalog: false)
    Enum.each(@seeds, &repo.query!/1)
  end

  @doc """
  The metadata (format v3) applied to Hasura and read back by Authzura,
  plus `extra` `{table, permission}` entries (see `json_filter_permission/0`).
  """
  @spec metadata([{{String.t(), String.t()}, map()}]) :: map()
  def metadata(extra \\ []) do
    relationships = Map.new(FilterFixture.relationship_tables(), &{&1.table, &1})
    permissions = Enum.group_by(permissions() ++ extra, &elem(&1, 0), &elem(&1, 1))

    @tracked
    |> Enum.map(fn ref ->
      relationships
      |> Map.get(ref, %{table: ref})
      |> add_relationships(ref)
      |> Map.put(:select_permissions, Map.get(permissions, ref, []))
      |> configure(ref)
    end)
    |> HasuraFixture.metadata()
    |> put_in(["sources", Access.at(0), "configuration"], %{
      "connection_info" => %{"database_url" => %{"from_env" => "HASURA_GRAPHQL_DATABASE_URL"}}
    })
  end

  @doc """
  `_is_null` on a `json` column: Hasura v2.51.6 rejects it as inconsistent
  metadata ("JSON column can not be part of boolean expression"), and
  Authzura denies it at load with a `:deny` diagnostic. Kept out of
  `metadata/0` so Hasura accepts the rest.
  """
  @spec json_filter_permission() :: {{String.t(), String.t()}, map()}
  def json_filter_permission,
    do: perm(@kinds, "op_json_null", ["id"], %{"meta" => %{"_is_null" => true}})

  # A migration's module is loaded when this VM already ran it on the test
  # repo; compiling its file again would redefine it.
  defp migration_module(path, version, name) do
    module = Module.concat(@migration_namespace, Macro.camelize(name))
    module |> Code.ensure_loaded?() |> compiled(module, "#{path}/#{version}_#{name}.exs")
  end

  defp compiled(true = _loaded?, module, _file), do: module

  defp compiled(false, _module, file) do
    [{module, _bytecode}] = Code.compile_file(file)
    module
  end

  defp add_relationships(entry, @users) do
    profile = %{
      name: "profile",
      using: %{foreign_key_constraint_on: %{table: @profiles, columns: ["user_id"]}}
    }

    Map.update(entry, :object_relationships, [profile], &(&1 ++ [profile]))
  end

  defp add_relationships(entry, @organizations) do
    users = %{
      name: "users",
      using: %{foreign_key_constraint_on: %{table: @users, column: "org_id"}}
    }

    Map.put(entry, :array_relationships, [users])
  end

  defp add_relationships(entry, _ref), do: entry

  defp configure(entry, ref) when is_map_key(@graphql_names, ref) do
    config = Map.new(@graphql_names[ref], fn {column, name} -> {column, %{custom_name: name}} end)
    Map.put(entry, :configuration, %{column_config: config})
  end

  defp configure(entry, _ref), do: entry

  defp permissions do
    everyone() ++
      row_filters() ++
      empty_forms() ++
      null_handling() ++
      relationships() ++
      exists() ++
      operators() ++
      session_variables() ++ columns_and_limits() ++ root_fields()
  end

  defp perm(table, role, columns, filter, extra \\ %{}),
    do: {table, %{role: role, permission: Map.merge(%{columns: columns, filter: filter}, extra)}}

  defp articles(role, filter), do: perm(@articles, role, @article_columns, filter)

  defp everyone, do: Enum.map(@tracked, &perm(&1, "everyone", @all_columns, %{}))

  defp row_filters do
    [
      articles("author", %{"author_id" => %{"_eq" => @user_id}}),
      perm(@comments, "author", ["id", "article_id", "body"], %{
        "author_id" => %{"_eq" => @user_id}
      }),
      perm(@users, "author", ["id", "email"], %{}),
      articles("published", %{"is_published" => true}),
      articles("reviewer", %{"status" => %{"_in" => ["review", "published"]}}),
      articles("author_or_published", %{
        "$or" => [%{"author_id" => "X-HASURA-USER-ID"}, %{"is_published" => %{"_eq" => true}}]
      })
    ]
  end

  defp empty_forms do
    [
      articles("in_empty", %{"id" => %{"_in" => []}}),
      articles("nin_empty", %{"id" => %{"_nin" => []}}),
      articles("not_in_empty", %{"_not" => %{"id" => %{"_in" => []}}}),
      articles("or_empty", %{"_or" => []}),
      articles("and_empty", %{"_and" => []}),
      articles("not_empty", %{"_not" => %{}})
    ]
  end

  defp null_handling do
    [
      articles("editor_eq_me", %{"editor_id" => %{"_eq" => @user_id}}),
      articles("editor_neq_me", %{"editor_id" => %{"_neq" => @user_id}}),
      articles("editor_eq_null", %{"editor_id" => %{"_eq" => nil}}),
      articles("notes_neq_literal", %{"internal_notes" => %{"_neq" => "x"}}),
      articles("notes_not_eq", %{"_not" => %{"internal_notes" => %{"_eq" => "x"}}}),
      articles("editor_is_null", %{"editor_id" => %{"_is_null" => true}}),
      articles("editor_not_null", %{"editor_id" => %{"_is_null" => false}})
    ]
  end

  defp relationships do
    [
      articles("rel_object", %{"author" => %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}}),
      perm(@users, "rel_array", ["id"], %{"articles" => %{"is_published" => %{"_eq" => true}}}),
      perm(@comments, "rel_3hop", ["id"], %{
        "article" => %{"author" => %{"org" => %{"name" => %{"_eq" => "one"}}}}
      }),
      perm(@users, "rel_same_row", ["id"], %{
        "articles" => %{
          "_and" => [%{"is_published" => %{"_eq" => true}}, %{"status" => %{"_eq" => "draft"}}]
        }
      }),
      perm(@users, "rel_siblings", ["id"], %{
        "_and" => [
          %{"articles" => %{"is_published" => %{"_eq" => true}}},
          %{"articles" => %{"status" => %{"_eq" => "draft"}}}
        ]
      }),
      articles("rel_exists", %{"comments" => %{}}),
      articles("rel_negated", %{"_not" => %{"comments" => %{}}}),
      perm(@notes, "rel_composite", ["id", "note"], %{
        "membership" => %{"level" => %{"_gte" => 6}}
      }),
      perm(@users, "rel_self", ["id"], %{"manager" => %{"role" => %{"_eq" => "editor"}}}),
      perm(@comments, "rel_no_target_perm", ["id"], %{
        "article" => %{"internal_notes" => %{"_eq" => "x"}}
      }),
      articles("rel_manual", %{"events" => %{"kind" => %{"_eq" => "edit"}}}),
      perm(@view, "rel_view", ["id", "title"], %{"author" => %{"role" => %{"_eq" => "admin"}}}),
      perm(@users, "rel_reverse_object", ["id"], %{
        "profile" => %{"bio" => %{"_is_null" => false}}
      })
    ]
  end

  defp exists do
    audit_me = %{
      "_exists" => %{
        "_table" => %{"schema" => "audit", "name" => "users"},
        "_where" => %{"id" => %{"_eq" => @user_id}}
      }
    }

    [
      articles("exists_uncorrelated", %{
        "_exists" => %{
          "_table" => %{"schema" => "public", "name" => "users"},
          "_where" => %{"is_admin" => %{"_eq" => true}}
        }
      }),
      articles("exists_none", %{
        "_exists" => %{
          "_table" => %{"schema" => "public", "name" => "users"},
          "_where" => %{"id" => %{"_eq" => 999}}
        }
      }),
      articles("exists_same_table", %{
        "_exists" => %{
          "_table" => %{"schema" => "public", "name" => "articles"},
          "_where" => %{
            "_and" => [
              %{"author_id" => %{"_eq" => @user_id}},
              %{"status" => %{"_eq" => "review"}}
            ]
          }
        }
      }),
      articles("exists_or", %{"_or" => [%{"id" => %{"_eq" => 1}}, audit_me]}),
      articles("exists_not", %{"_not" => audit_me}),
      perm(@audit_users, "audit_only", ["id", "note"], %{"id" => %{"_eq" => @user_id}})
    ]
  end

  defp operators do
    text_operators() ++ jsonb_operators() ++ typed_operators()
  end

  defp text_operators do
    [
      {"op_like", "_like", "%ta"},
      {"op_nlike", "_nlike", "%ta"},
      {"op_ilike", "_ilike", "a%"},
      {"op_nilike", "_nilike", "a%"},
      {"op_similar", "_similar", "(A|b)%"},
      {"op_nsimilar", "_nsimilar", "(A|b)%"},
      {"op_regex", "_regex", "^[A-Z]"},
      {"op_nregex", "_nregex", "^[A-Z]"},
      {"op_iregex", "_iregex", "^g"},
      {"op_niregex", "_niregex", "^g"}
    ]
    |> Enum.map(fn {role, operator, pattern} ->
      articles(role, %{"title" => %{operator => pattern}})
    end)
  end

  defp jsonb_operators do
    [
      {"op_contains", "_contains", %{"1" => true}},
      {"op_contained_in", "_contained_in", %{"1" => true, "2" => true, "3" => true}},
      {"op_has_key", "$has_key", "2"},
      {"op_has_key_session", "_has_key", @user_id},
      {"op_has_keys_any", "_has_keys_any", ["2", "9"]},
      {"op_has_keys_all", "_has_keys_all", ["1", "3"]}
    ]
    |> Enum.map(fn {role, operator, value} ->
      articles(role, %{"assignees" => %{operator => value}})
    end)
  end

  defp typed_operators do
    [
      perm(@kinds, "op_cmp", ["id"], %{"rank" => %{"_gt" => 1, "_lte" => 4}}),
      perm(@kinds, "op_neq", ["id"], %{"rank" => %{"_neq" => 2}}),
      perm(@kinds, "op_range", ["id"], %{
        "_and" => [%{"rank" => %{"_gte" => 2}}, %{"rank" => %{"_lt" => 5}}]
      }),
      perm(@kinds, "op_in", ["id"], %{"code" => %{"$in" => ["a", "b"]}}),
      perm(@kinds, "op_nin", ["id"], %{"code" => %{"_nin" => ["a"]}}),
      perm(@kinds, "op_float", ["id"], %{"score" => %{"_gt" => 1}}),
      perm(@kinds, "op_real", ["id"], %{"ratio" => %{"_lte" => 0.5}}),
      perm(@kinds, "op_char", ["id"], %{"grade" => %{"_eq" => "A"}}),
      perm(@users, "op_citext", ["id"], %{"email" => %{"_eq" => "c@x.com"}}),
      perm(@users, "op_numeric", ["id"], %{"salary" => %{"_gte" => 1000}}),
      perm(@users, "op_bool", ["id"], %{"is_admin" => %{"_eq" => "X-Hasura-Is-Admin"}}),
      articles("op_uuid", %{"external_ref" => %{"_eq" => "X-Hasura-Ref"}}),
      articles("op_timestamptz", %{"published_at" => %{"_gt" => "X-Hasura-Since"}}),
      articles("op_enum", %{"status" => %{"_eq" => "review"}})
    ]
  end

  defp session_variables do
    [
      articles("sv_array", %{"id" => %{"_in" => "X-Hasura-Article-Ids"}}),
      perm(@kinds, "sv_codes", ["id", "code"], %{"code" => %{"_in" => "X-Hasura-Codes"}}),
      perm(@kinds, "sv_long", ["id", "code"], %{"code" => %{"_eq" => "X-Hasura-Code"}})
    ]
  end

  defp columns_and_limits do
    [
      perm(@articles, "cols", ["id", "title", "is_published", "status"], %{
        "internal_notes" => %{"_is_null" => false}
      }),
      perm(@articles, "lim", ["id", "title"], %{}, %{limit: 2}),
      perm(@articles, "lim_rel", @all_columns, %{}),
      perm(@comments, "lim_rel", @all_columns, %{}, %{limit: 1})
    ]
  end

  defp root_fields do
    [
      perm(@articles, "rf_none", ["id"], %{}, %{query_root_fields: []}),
      perm(@articles, "rf_pk", ["id"], %{}, %{query_root_fields: ["select_by_pk"]}),
      perm(@users, "rf_rel", @all_columns, %{}),
      perm(@articles, "rf_rel", ["id", "title"], %{}, %{query_root_fields: []})
    ]
  end
end

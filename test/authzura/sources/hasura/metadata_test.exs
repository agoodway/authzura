defmodule Authzura.Sources.Hasura.MetadataTest do
  use Authzura.DataCase, async: true

  alias Authzura.Adapters.Postgres
  alias Authzura.HasuraFixture
  alias Authzura.Model.{Diagnostic, Permission}
  alias Authzura.Sources.Hasura.Metadata

  @articles {"public", "articles"}
  @users {"public", "users"}
  @comments {"public", "comments"}

  setup do
    {:ok, tables, fks} = Postgres.introspect(Repo, [@articles, @users, @comments])
    %{tables: tables, fks: fks}
  end

  defp grant(role, permission), do: %{role: role, permission: permission}

  defp load(entries, context, opts \\ []) do
    metadata = HasuraFixture.metadata(entries, opts)
    source = Keyword.get(opts, :source, "default")

    {tables, rel_diagnostics} =
      Metadata.resolve_relationships(metadata, source, context.tables, context.fks)

    {permissions, diagnostics} = Metadata.translate(metadata, source, tables, Postgres)
    {permissions, rel_diagnostics ++ diagnostics}
  end

  defp find(permissions, role, table \\ @articles, operation \\ :select) do
    Enum.find(permissions, &(&1.role == role and &1.table == table and &1.operation == operation))
  end

  defp denied_reasons(%Permission{status: {:denied, diagnostics}}),
    do: Enum.map(diagnostics, & &1.reason)

  describe "sources" do
    test "tracked tables come from the named source" do
      metadata =
        HasuraFixture.metadata([%{table: @articles}],
          source: "main",
          sources: [%{name: "default", kind: "postgres", tables: [%{table: @users}]}]
        )

      assert {:ok, [@articles]} = Metadata.tracked_tables(metadata, "main")
      assert {:ok, [@users]} = Metadata.tracked_tables(metadata, "default")
      assert {:error, :source_not_found} = Metadata.tracked_tables(metadata, "nope")
      assert {:error, :source_not_found} = Metadata.tracked_tables(%{}, "default")
      assert {:error, :source_not_found} = Metadata.tracked_tables(nil, "default")
    end

    test "a bare table name is in the public schema" do
      metadata = %{"sources" => [%{"name" => "default", "tables" => [%{"table" => "users"}]}]}
      assert {:ok, [@users]} = Metadata.tracked_tables(metadata, "default")
    end

    test "translation reads only the named source", context do
      entries = [
        %{table: @articles, select_permissions: [grant("user", %{columns: "*", filter: %{}})]}
      ]

      assert {[%Permission{}], []} = load(entries, context, source: "main")
      metadata = HasuraFixture.metadata(entries, source: "main")
      assert {[], []} = Metadata.translate(metadata, "default", context.tables, Postgres)
    end
  end

  describe "select permissions" do
    test "a full permission translates", context do
      permission = %{
        columns: ["id", "title"],
        filter: %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}},
        limit: 10,
        allow_aggregations: true,
        query_root_fields: ["select", "select_by_pk"],
        subscription_root_fields: []
      }

      {permissions, []} =
        load([%{table: @articles, select_permissions: [grant("user", permission)]}], context)

      assert %Permission{
               role: "user",
               table: @articles,
               operation: :select,
               columns: ["id", "title"],
               filter: {:compare, "author_id", :eq, {:session, "x-hasura-user-id"}},
               limit: 10,
               allow_aggregations: true,
               root_fields: [:select, :select_by_pk],
               status: :ok
             } = find(permissions, "user")
    end

    test "a missing filter is denied", context do
      {permissions, diagnostics} =
        load([%{table: @articles, select_permissions: [grant("user", %{columns: "*"})]}], context)

      assert [:missing_filter] = denied_reasons(find(permissions, "user"))

      assert [
               %Diagnostic{
                 severity: :deny,
                 role: "user",
                 table: @articles,
                 operation: :select,
                 reason: :missing_filter
               }
             ] =
               diagnostics
    end

    test "a negative or non-integer limit is denied", context do
      {permissions, _diagnostics} =
        load(
          [
            %{
              table: @articles,
              select_permissions: [
                grant("a", %{columns: "*", filter: %{}, limit: -1}),
                grant("b", %{columns: "*", filter: %{}, limit: "5"}),
                grant("c", %{columns: "*", filter: %{}, limit: 0})
              ]
            }
          ],
          context
        )

      assert [{:invalid_limit, -1}] = denied_reasons(find(permissions, "a"))
      assert [{:invalid_limit, "5"}] = denied_reasons(find(permissions, "b"))
      assert %Permission{status: :ok, limit: 0} = find(permissions, "c")
    end

    test "query_root_fields: missing is :all, [] stays []", context do
      {permissions, []} =
        load(
          [
            %{
              table: @articles,
              select_permissions: [
                grant("a", %{columns: "*", filter: %{}}),
                grant("b", %{columns: "*", filter: %{}, query_root_fields: []})
              ]
            }
          ],
          context
        )

      assert %Permission{root_fields: :all, status: :ok} = find(permissions, "a")
      assert %Permission{root_fields: [], status: :ok} = find(permissions, "b")
    end

    test "an unknown root field is denied", context do
      {permissions, _diagnostics} =
        load(
          [
            %{
              table: @articles,
              select_permissions: [
                grant("a", %{columns: "*", filter: %{}, query_root_fields: ["nope"]})
              ]
            }
          ],
          context
        )

      assert [{:invalid_root_field, "nope"}] = denied_reasons(find(permissions, "a"))
    end

    test "a computed_fields grant is ignored with a warning; the rest is enforced", context do
      {permissions, diagnostics} =
        load(
          [
            %{
              table: @articles,
              computed_fields: [
                %{name: "word_count", definition: %{function: %{schema: "public", name: "wc"}}}
              ],
              select_permissions: [
                grant("a", %{
                  columns: ["id", "title"],
                  filter: %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}},
                  limit: 5,
                  computed_fields: ["word_count"]
                }),
                grant("b", %{columns: "*", filter: %{}, computed_fields: []}),
                grant("c", %{columns: "*", filter: %{}, computed_fields: "word_count"})
              ]
            }
          ],
          context
        )

      assert %Permission{status: :ok, columns: ["id", "title"], limit: 5, filter: filter} =
               find(permissions, "a")

      assert filter == {:compare, "org_id", :eq, {:session, "x-hasura-org-id"}}

      assert [
               %Diagnostic{
                 severity: :warning,
                 reason: {:unsupported, :computed_fields},
                 path: ["computed_fields"],
                 role: "a",
                 table: @articles,
                 operation: :select
               }
             ] = Enum.filter(diagnostics, &(&1.reason == {:unsupported, :computed_fields}))

      assert %Permission{status: :ok} = find(permissions, "b")
      assert [{:invalid_computed_fields, "word_count"}] = denied_reasons(find(permissions, "c"))
    end

    test "a computed field is never exposed, even when granted", context do
      {permissions, _diagnostics} =
        load(
          [
            %{
              table: @articles,
              computed_fields: [
                %{name: "word_count", definition: %{function: %{schema: "public", name: "wc"}}}
              ],
              select_permissions: [
                grant("a", %{columns: "*", filter: %{}, computed_fields: ["word_count"]})
              ]
            }
          ],
          context
        )

      assert %Permission{status: :ok, columns: columns} = find(permissions, "a")
      refute "word_count" in columns
      assert columns == context.tables[@articles].columns |> Map.keys() |> Enum.sort()
    end

    test "columns: \"*\" expands to every introspected column, sorted", context do
      {permissions, []} =
        load(
          [%{table: @articles, select_permissions: [grant("a", %{columns: "*", filter: %{}})]}],
          context
        )

      assert %Permission{columns: columns} = find(permissions, "a")
      assert columns == context.tables[@articles].columns |> Map.keys() |> Enum.sort()
    end

    test "an unknown column is denied", context do
      {permissions, _diagnostics} =
        load(
          [
            %{
              table: @articles,
              select_permissions: [grant("a", %{columns: ["id", "nope"], filter: %{}})]
            }
          ],
          context
        )

      assert [{:unknown_column, "nope"}] = denied_reasons(find(permissions, "a"))
    end

    test "filter parse errors deny with the filter path", context do
      {permissions, diagnostics} =
        load(
          [
            %{
              table: @articles,
              select_permissions: [
                grant("a", %{columns: "*", filter: %{"title" => %{"_foo" => 1}}})
              ]
            }
          ],
          context
        )

      assert [{:unknown_operator, "_foo"}] = denied_reasons(find(permissions, "a"))
      assert [%Diagnostic{path: ["filter", "title", "_foo"]}] = diagnostics
    end

    test "a filter using a denied relationship is denied", context do
      entries = [
        %{
          table: @articles,
          object_relationships: [%{name: "bogus", using: %{foreign_key_constraint_on: "title"}}],
          select_permissions: [grant("a", %{columns: "*", filter: %{"bogus" => %{}}})]
        }
      ]

      {permissions, diagnostics} = load(entries, context)
      assert [{:unknown_field, "bogus"}] = denied_reasons(find(permissions, "a"))

      assert Enum.any?(
               diagnostics,
               &(&1.reason == :no_foreign_key and &1.path == ["object_relationships", "bogus"])
             )

      assert Enum.any?(diagnostics, &(&1.reason == {:unknown_field, "bogus"} and &1.role == "a"))
    end

    test "a filter through a resolved relationship translates", context do
      entries = [
        %{
          table: @articles,
          object_relationships: [
            %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
          ],
          select_permissions: [
            grant("a", %{columns: "*", filter: %{"author" => %{"id" => "X-Hasura-User-Id"}}})
          ]
        },
        %{table: @users}
      ]

      {permissions, []} = load(entries, context)

      assert %Permission{
               status: :ok,
               filter:
                 {:relationship, "author", {:compare, "id", :eq, {:session, "x-hasura-user-id"}}}
             } =
               find(permissions, "a")
    end

    test "computed fields and remote relationships in a filter are denied", context do
      entries = [
        %{
          table: @articles,
          computed_fields: [
            %{name: "word_count", definition: %{function: %{schema: "public", name: "wc"}}}
          ],
          remote_relationships: [%{name: "crm", definition: %{to_source: %{source: "other"}}}],
          select_permissions: [
            grant("a", %{columns: "*", filter: %{"word_count" => %{"_gt" => 1}}}),
            grant("b", %{columns: "*", filter: %{"crm" => %{}}})
          ]
        }
      ]

      {permissions, _diagnostics} = load(entries, context)
      assert [{:unsupported, :computed_field}] = denied_reasons(find(permissions, "a"))
      assert [{:unsupported, :remote_relationship}] = denied_reasons(find(permissions, "b"))
    end

    test "a table missing from the database denies its permissions", context do
      entries = [
        %{
          table: {"public", "gone"},
          select_permissions: [grant("a", %{columns: "*", filter: %{}})]
        }
      ]

      {permissions, _diagnostics} = load(entries, context)

      assert [{:unknown_table, {"public", "gone"}}] =
               denied_reasons(find(permissions, "a", {"public", "gone"}))
    end

    test "a role with two select permissions on one table is denied", context do
      entries = [
        %{
          table: @articles,
          select_permissions: [
            grant("a", %{columns: "*", filter: %{}}),
            grant("a", %{columns: ["id"], filter: %{}})
          ]
        }
      ]

      {permissions, _diagnostics} = load(entries, context)

      assert [%Permission{status: {:denied, [%Diagnostic{reason: :duplicate_permission}]}}] =
               permissions
    end

    test "a table tracked twice denies every permission on it", context do
      entry = %{table: @articles, select_permissions: [grant("a", %{columns: "*", filter: %{}})]}
      {permissions, _diagnostics} = load([entry, entry], context)

      assert [%Permission{status: {:denied, [%Diagnostic{reason: :duplicate_table}]}}] =
               Enum.uniq(permissions)
    end

    test "malformed permissions are denied, never raise", context do
      entries = [
        %{
          table: @articles,
          select_permissions: [
            %{role: "a", permission: 5},
            %{role: "b"},
            %{role: "c", permission: %{columns: 5, filter: %{}}},
            %{role: "d", permission: %{columns: "*", filter: %{}, allow_aggregations: "yes"}},
            %{role: 5, permission: %{}},
            7
          ]
        }
      ]

      {permissions, diagnostics} = load(entries, context)

      for role <- ~w(a b c d) do
        assert %Permission{status: {:denied, [_ | _]}} = find(permissions, role)
      end

      assert Enum.all?(permissions, &match?(%Permission{status: {:denied, _}}, &1))
      assert Enum.any?(diagnostics, &(&1.reason == :invalid_permission and &1.role == nil))
    end
  end

  describe "write permissions" do
    test "filter, check, set, columns and backend_only are parsed and stored", context do
      entries = [
        %{
          table: @articles,
          insert_permissions: [
            %{
              role: "user",
              permission: %{
                check: %{"author_id" => "X-Hasura-User-Id"},
                set: %{"org_id" => "x-hasura-org-id", "status" => "draft"},
                columns: ["title", "body"],
                backend_only: true
              }
            }
          ],
          update_permissions: [
            %{
              role: "user",
              permission: %{
                filter: %{"author_id" => "X-Hasura-User-Id"},
                check: %{},
                columns: "*",
                backend_only: false
              }
            }
          ],
          delete_permissions: [%{role: "user", permission: %{filter: %{"id" => 1}}}]
        }
      ]

      {permissions, []} = load(entries, context)

      assert %Permission{
               status: :ok,
               check: {:compare, "author_id", :eq, {:session, "x-hasura-user-id"}},
               presets: %{
                 "org_id" => {:session, "x-hasura-org-id"},
                 "status" => {:literal, "draft"}
               },
               columns: ["title", "body"],
               backend_only: true
             } = find(permissions, "user", @articles, :insert)

      assert %Permission{
               status: :ok,
               filter: {:compare, "author_id", :eq, _},
               check: {:and, []},
               backend_only: false
             } =
               find(permissions, "user", @articles, :update)

      assert %Permission{status: :ok, filter: {:compare, "id", :eq, {:literal, 1}}} =
               find(permissions, "user", @articles, :delete)
    end

    test "a write failure is a warning and never touches the select permission", context do
      entries = [
        %{
          table: @articles,
          select_permissions: [grant("user", %{columns: "*", filter: %{}})],
          insert_permissions: [
            %{
              role: "user",
              permission: %{
                check: %{"nope" => 1},
                set: %{"id" => "abc"},
                columns: ["zzz"],
                backend_only: 3
              }
            }
          ],
          update_permissions: [%{role: "user", permission: %{columns: "*"}}]
        }
      ]

      {permissions, diagnostics} = load(entries, context)
      assert %Permission{status: :ok} = find(permissions, "user")

      assert %Permission{status: {:denied, [_ | _]}} =
               find(permissions, "user", @articles, :insert)

      assert %Permission{status: {:denied, [_ | _]}} =
               find(permissions, "user", @articles, :update)

      assert diagnostics != []
      assert Enum.all?(diagnostics, &(&1.severity == :warning))

      reasons = Enum.map(diagnostics, & &1.reason)
      assert {:unknown_field, "nope"} in reasons
      assert {:invalid_literal, {:invalid_value, "int8"}} in reasons
      assert {:unknown_column, "zzz"} in reasons
      assert {:invalid_backend_only, 3} in reasons
      assert :missing_filter in reasons
    end
  end

  describe "inherited roles" do
    test "each inherited role is denied and gets no permission", context do
      entries = [
        %{
          table: @articles,
          select_permissions: [
            grant("user", %{columns: "*", filter: %{}}),
            grant("combo", %{columns: "*", filter: %{}})
          ]
        }
      ]

      {permissions, diagnostics} =
        load(entries, context,
          inherited_roles: [
            %{role_name: "combo", role_set: ["user", "editor"]},
            %{role_name: "other", role_set: ["user"]}
          ]
        )

      assert [%Permission{role: "user"}] = permissions

      assert [
               %Diagnostic{
                 severity: :deny,
                 role: "combo",
                 reason: {:unsupported, :inherited_role}
               },
               %Diagnostic{
                 severity: :deny,
                 role: "other",
                 reason: {:unsupported, :inherited_role}
               }
             ] = diagnostics
    end
  end
end

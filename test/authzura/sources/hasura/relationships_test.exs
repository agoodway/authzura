defmodule Authzura.Sources.Hasura.RelationshipsTest do
  use Authzura.DataCase, async: true

  alias Authzura.Adapters.Postgres
  alias Authzura.HasuraFixture
  alias Authzura.Model.{Column, Diagnostic, Relationship, Table}
  alias Authzura.Sources.Hasura.Metadata

  @articles {"public", "articles"}
  @users {"public", "users"}
  @notes {"public", "membership_notes"}
  @view {"public", "published_articles"}

  @refs [
    @articles,
    @users,
    @notes,
    @view,
    {"public", "organizations"},
    {"public", "user_profiles"},
    {"public", "comments"},
    {"public", "org_memberships"},
    {"audit", "article_events"},
    {"audit", "users"}
  ]

  setup do
    {:ok, tables, fks} = Postgres.introspect(Repo, @refs)
    %{tables: tables, fks: fks}
  end

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}},
          %{name: "editor", using: %{foreign_key_constraint_on: ["editor_id"]}},
          %{name: "bogus", using: %{foreign_key_constraint_on: "title"}},
          %{
            name: "nowhere",
            using: %{
              manual_configuration: %{
                remote_table: {"public", "nope"},
                column_mapping: %{id: "id"}
              }
            }
          },
          %{
            name: "bad_column",
            using: %{manual_configuration: %{remote_table: @users, column_mapping: %{id: "nope"}}}
          },
          %{name: "weird", using: %{something: true}}
        ],
        array_relationships: [
          %{
            name: "comments",
            using: %{
              foreign_key_constraint_on: %{table: {"public", "comments"}, column: "article_id"}
            }
          },
          %{
            name: "events",
            using: %{
              manual_configuration: %{
                remote_table: {"audit", "article_events"},
                column_mapping: %{id: "article_id"}
              }
            }
          }
        ]
      },
      %{
        table: @users,
        object_relationships: [
          %{name: "organization", using: %{foreign_key_constraint_on: "org_id"}},
          %{
            name: "profile",
            using: %{
              foreign_key_constraint_on: %{
                table: {"public", "user_profiles"},
                columns: ["user_id"]
              }
            }
          }
        ],
        array_relationships: [
          %{
            name: "articles",
            using: %{foreign_key_constraint_on: %{table: @articles, columns: ["author_id"]}}
          },
          %{
            name: "id",
            using: %{foreign_key_constraint_on: %{table: @articles, column: "editor_id"}}
          }
        ]
      },
      %{
        table: @notes,
        object_relationships: [
          %{name: "membership", using: %{foreign_key_constraint_on: ["user_id", "org_id"]}}
        ]
      },
      %{
        table: @view,
        object_relationships: [
          %{
            name: "author",
            using: %{
              manual_configuration: %{remote_table: @users, column_mapping: %{author_id: "id"}}
            }
          }
        ],
        array_relationships: [
          %{
            name: "events",
            using: %{
              manual_configuration: %{
                remote_table: {"audit", "article_events"},
                column_mapping: %{id: "article_id"}
              }
            }
          }
        ]
      }
    ])
  end

  defp resolve(%{tables: tables, fks: fks}),
    do: Metadata.resolve_relationships(metadata(), "default", tables, fks)

  defp rel(tables, ref, name), do: tables[ref].relationships[name]

  defp denial(diagnostics, ref, name) do
    Enum.find(diagnostics, &(&1.table == ref and List.last(&1.path) == name))
  end

  test "FK on the local table, string and list forms", context do
    {tables, _diagnostics} = resolve(context)

    assert %Relationship{kind: :object, target: @users, mapping: [{"author_id", "id"}]} =
             rel(tables, @articles, "author")

    assert %Relationship{kind: :object, target: @users, mapping: [{"editor_id", "id"}]} =
             rel(tables, @articles, "editor")

    assert %Relationship{
             kind: :object,
             target: {"public", "organizations"},
             mapping: [{"org_id", "id"}]
           } =
             rel(tables, @users, "organization")
  end

  test "FK on the remote table: array and reverse object relationships", context do
    {tables, _diagnostics} = resolve(context)

    assert %Relationship{kind: :array, target: @articles, mapping: [{"id", "author_id"}]} =
             rel(tables, @users, "articles")

    assert %Relationship{
             kind: :object,
             target: {"public", "user_profiles"},
             mapping: [{"id", "user_id"}]
           } =
             rel(tables, @users, "profile")

    assert %Relationship{
             kind: :array,
             target: {"public", "comments"},
             mapping: [{"id", "article_id"}]
           } =
             rel(tables, @articles, "comments")
  end

  test "composite FK maps every pair in constraint order", context do
    {tables, _diagnostics} = resolve(context)

    assert %Relationship{
             kind: :object,
             target: {"public", "org_memberships"},
             mapping: [{"org_id", "org_id"}, {"user_id", "user_id"}]
           } = rel(tables, @notes, "membership")
  end

  test "manual configuration across schemas", context do
    {tables, _diagnostics} = resolve(context)

    assert %Relationship{
             kind: :array,
             target: {"audit", "article_events"},
             mapping: [{"id", "article_id"}]
           } =
             rel(tables, @articles, "events")
  end

  test "a view gets manual relationships", context do
    {tables, _diagnostics} = resolve(context)

    assert %Relationship{kind: :object, target: @users, mapping: [{"author_id", "id"}]} =
             rel(tables, @view, "author")

    assert %Relationship{kind: :array, target: {"audit", "article_events"}} =
             rel(tables, @view, "events")
  end

  test "unresolvable relationships are omitted and denied", context do
    {tables, diagnostics} = resolve(context)

    for {name, reason} <- [
          {"bogus", :no_foreign_key},
          {"nowhere", {:unknown_table, {"public", "nope"}}},
          {"bad_column", {:unknown_column, @users, "nope"}},
          {"weird", :invalid_relationship}
        ] do
      refute Map.has_key?(tables[@articles].relationships, name)

      assert %Diagnostic{
               severity: :deny,
               table: @articles,
               path: ["object_relationships", ^name],
               reason: ^reason
             } =
               denial(diagnostics, @articles, name)
    end
  end

  test "an array relationship using the local-FK form is denied", context do
    metadata =
      HasuraFixture.metadata([
        %{
          table: @articles,
          array_relationships: [
            %{name: "writers", using: %{foreign_key_constraint_on: "author_id"}},
            %{name: "editors", using: %{foreign_key_constraint_on: ["editor_id"]}}
          ]
        }
      ])

    {tables, diagnostics} =
      Metadata.resolve_relationships(metadata, "default", context.tables, context.fks)

    assert tables[@articles].relationships == %{}

    assert [
             %Diagnostic{
               severity: :deny,
               path: ["array_relationships", "writers"],
               reason: :invalid_relationship
             },
             %Diagnostic{
               severity: :deny,
               path: ["array_relationships", "editors"],
               reason: :invalid_relationship
             }
           ] = diagnostics
  end

  test "a relationship named like a column is denied", context do
    {tables, diagnostics} = resolve(context)
    refute Map.has_key?(tables[@users].relationships, "id")

    assert %Diagnostic{severity: :deny, reason: :conflicting_field} =
             denial(diagnostics, @users, "id")
  end

  test "a relationship declared twice is denied" do
    {tables, fks} = synthetic()

    metadata =
      HasuraFixture.metadata([
        %{
          table: {"public", "a"},
          object_relationships: [%{name: "b", using: %{foreign_key_constraint_on: ["c1"]}}],
          array_relationships: [
            %{
              name: "b",
              using: %{foreign_key_constraint_on: %{table: {"public", "b"}, column: "c1"}}
            }
          ]
        }
      ])

    {tables, diagnostics} = Metadata.resolve_relationships(metadata, "default", tables, fks)
    assert tables[{"public", "a"}].relationships == %{}

    assert [
             %Diagnostic{reason: :duplicate_relationship},
             %Diagnostic{reason: :duplicate_relationship}
           ] = diagnostics
  end

  test "several matching FKs are ambiguous and denied" do
    {tables, fks} = synthetic()

    ambiguous = [
      %{table: {"public", "a"}, columns: ["c1"], ref_table: {"public", "c"}, ref_columns: ["c1"]}
      | fks
    ]

    metadata =
      HasuraFixture.metadata([
        %{
          table: {"public", "a"},
          object_relationships: [%{name: "x", using: %{foreign_key_constraint_on: "c1"}}]
        }
      ])

    {tables, diagnostics} = Metadata.resolve_relationships(metadata, "default", tables, ambiguous)
    assert tables[{"public", "a"}].relationships == %{}
    assert [%Diagnostic{severity: :deny, reason: :ambiguous_foreign_key}] = diagnostics
  end

  test "more than 8 column pairs is denied" do
    {tables, fks} = synthetic()

    metadata =
      HasuraFixture.metadata([
        %{
          table: {"public", "a"},
          object_relationships: [
            %{name: "wide", using: %{foreign_key_constraint_on: Enum.map(1..9, &"c#{&1}")}},
            %{name: "eight", using: %{foreign_key_constraint_on: Enum.map(1..8, &"c#{&1}")}}
          ]
        }
      ])

    {tables, diagnostics} = Metadata.resolve_relationships(metadata, "default", tables, fks)
    assert [%Diagnostic{severity: :deny, reason: {:too_many_column_pairs, 9}}] = diagnostics
    assert %Relationship{mapping: mapping} = tables[{"public", "a"}].relationships["eight"]
    assert mapping == Enum.map(1..8, &{"c#{&1}", "c#{&1}"})
  end

  test "malformed metadata never raises", %{tables: tables, fks: fks} do
    for metadata <- [
          nil,
          %{"sources" => 5},
          %{"sources" => [%{"name" => "default", "tables" => [5, %{"table" => 5}]}]},
          %{
            "sources" => [
              %{
                "name" => "default",
                "tables" => [
                  %{
                    "table" => %{"schema" => "public", "name" => "users"},
                    "object_relationships" => [5, %{"name" => 5}]
                  }
                ]
              }
            ]
          }
        ] do
      assert {%{}, diagnostics} = Metadata.resolve_relationships(metadata, "default", tables, fks)
      assert Enum.all?(diagnostics, &(&1.severity == :deny))
    end
  end

  defp synthetic do
    columns = Enum.map(1..9, &"c#{&1}")
    a = table("a", columns)
    b = table("b", columns)
    c = table("c", columns)

    fks = [
      %{table: {"public", "a"}, columns: ["c1"], ref_table: {"public", "b"}, ref_columns: ["c1"]},
      %{
        table: {"public", "a"},
        columns: columns,
        ref_table: {"public", "b"},
        ref_columns: columns
      },
      %{
        table: {"public", "a"},
        columns: Enum.take(columns, 8),
        ref_table: {"public", "b"},
        ref_columns: Enum.take(columns, 8)
      }
    ]

    {%{{"public", "a"} => a, {"public", "b"} => b, {"public", "c"} => c}, fks}
  end

  defp table(name, columns) do
    columns =
      Map.new(
        columns,
        &{&1, %Column{name: &1, pg_type: "int8", base_kind: :bigint, ecto_type: :integer}}
      )

    %Table{schema: "public", name: name, columns: columns}
  end
end

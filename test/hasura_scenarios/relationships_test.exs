defmodule Authzura.HasuraScenarios.RelationshipsTest do
  @moduledoc """
  Relationships ported from Hasura v2.51.6. Paths are relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  alias Authzura.Test.HasuraSchemas.BoolexpAuthor

  # lib/api-tests/src/Test/Regression/MultiColumnObjectRelationshipsSpec.hs
  describe "Regression/MultiColumnObjectRelationshipsSpec.hs" do
    @quote {"hasura_multi_column", "quote"}

    setup %{test: test} do
      mapping = %{character_first_name: "first_name", character_last_name: "last_name"}

      %{
        instance:
          start!(test, [
            %{table: {"hasura_multi_column", "character"}},
            %{
              table: @quote,
              object_relationships: [
                %{
                  name: "by",
                  using: %{
                    manual_configuration: %{
                      remote_table: {"hasura_multi_column", "character"},
                      column_mapping: mapping
                    }
                  }
                }
              ]
            }
          ])
      }
    end

    test "select quotes by characters", %{instance: i} do
      assert all(table(@quote), i, "admin", %{},
               columns: ["quote"],
               preload: %{"by" => %{"columns" => ["first_name", "last_name"]}}
             ) ==
               {:ok,
                [
                  %{
                    "quote" => "The heart is an arrow. It demands aim to land true.",
                    "by" => %{"first_name" => "Inej", "last_name" => "Ghafa"}
                  },
                  %{
                    "quote" => "Im a business man. No more, no less.",
                    "by" => %{"first_name" => "Kaz", "last_name" => "Brekker"}
                  }
                ]}
    end
  end

  # lib/api-tests/src/Test/Regression/ObjectRelationshipsLimit7936Spec.hs
  describe "Regression/ObjectRelationshipsLimit7936Spec.hs" do
    @limited_article {"hasura_object_limit", "article"}

    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{table: {"hasura_object_limit", "author"}},
            %{
              table: @limited_article,
              object_relationships: [
                %{
                  name: "author",
                  using: %{
                    manual_configuration: %{
                      remote_table: {"hasura_object_limit", "author"},
                      column_mapping: %{author_name: "name"}
                    }
                  }
                }
              ]
            }
          ])
      }
    end

    # Two authors are named "Author 1", so article 1's object relationship
    # matches two rows. Hasura returns one of them (either is accepted).
    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): an object relationship matching more than " <>
             "one row is {:unsupported_query, {:object_cardinality, \"author\"}}, " <>
             "never an arbitrary row"
    test "an object relationship matching two rows gives one of them", %{instance: i} do
      preload = %{"author" => %{"columns" => ["id"]}}
      by_id = where(table(@limited_article), [a], field(a, :id) == 1)

      assert {:ok, [%{"id" => 1, "author" => %{"id" => first}}]} =
               all(by_id, i, "admin", %{}, columns: ["id"], preload: preload)

      assert first in [1, 3]

      assert {:ok, [%{"id" => 1, "author" => %{"id" => one}}, %{"id" => 2, "author" => two}]} =
               all(limit(table(@limited_article), 2), i, "admin", %{},
                 columns: ["id"],
                 preload: preload
               )

      assert one in [1, 3]
      assert two == %{"id" => 2}
    end
  end

  # lib/api-tests/src/Test/Auth/Authorization/DisableRootFields/SelectPermission/RelationshipSpec.hs
  describe "DisableRootFields/SelectPermission/RelationshipSpec.hs" do
    @rf_author {"hasura_root_fields", "author"}
    @rf_article {"hasura_root_fields", "article"}

    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{
              table: @rf_author,
              array_relationships: [
                %{
                  name: "articles_by_id_to_author_id",
                  using: %{
                    foreign_key_constraint_on: %{table: @rf_article, column: "author_id"}
                  }
                }
              ],
              select_permissions: [
                %{
                  role: "user",
                  permission: %{
                    columns: "*",
                    filter: %{
                      "articles_by_id_to_author_id" => %{
                        "author_id" => %{"_eq" => "X-Hasura-User-Id"}
                      }
                    },
                    allow_aggregations: true,
                    query_root_fields: ["select", "select_by_pk", "select_aggregate"],
                    subscription_root_fields: ["select_stream"]
                  }
                }
              ]
            },
            %{
              table: @rf_article,
              select_permissions: [
                %{
                  role: "user",
                  permission: %{
                    columns: "*",
                    filter: %{},
                    query_root_fields: [],
                    subscription_root_fields: []
                  }
                }
              ]
            }
          ])
      }
    end

    @headers %{"X-Hasura-User-Id" => "1"}

    test "the author list is accessible, with articles through the relationship", %{
      instance: i
    } do
      preload = %{
        "articles_by_id_to_author_id" => %{
          "columns" => ["title"],
          "order_by" => [%{"id" => "asc"}]
        }
      }

      assert all(table(@rf_author), i, "user", @headers, columns: ["id"], preload: preload) ==
               {:ok,
                [
                  %{
                    "id" => 1,
                    "articles_by_id_to_author_id" => [
                      %{"title" => "Article 1"},
                      %{"title" => "Article 3"}
                    ]
                  }
                ]}
    end

    test "the article list root field is disabled", %{instance: i} do
      assert all(table(@rf_article), i, "user", @headers, columns: ["id"]) ==
               {:error, :root_field_disabled}
    end
  end

  # lib/api-tests/src/Test/Regression/LongIdentifiers3796Spec.hs
  describe "Regression/LongIdentifiers3796Spec.hs" do
    @regular {"hasura_long_identifiers",
              "regular_table_with_a_long_name_to_test_rename_identifiers"}
    @long {"hasura_long_identifiers",
           "i_need_a_table_with_a_long_name_to_test_rename_identifiers"}
    @relationship "i_need_a_table_with_a_long_name_to_test_rename_identifierss_by_id_to_regular_id"
    @long_column "i_need_a_column_with_a_long_name_to_test_rename_identifiers"
    @other_column "i_need_a_column_with_a_long_name_but_is_different"

    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{
              table: @regular,
              array_relationships: [
                %{
                  name: @relationship,
                  using: %{foreign_key_constraint_on: %{table: @long, column: "regular_id"}}
                }
              ]
            },
            %{table: @long}
          ])
      }
    end

    test "select a long column via an array relationship", %{instance: i} do
      preload = %{
        @relationship => %{
          "columns" => [@long_column, @other_column],
          "order_by" => [%{@long_column => "asc"}, %{@other_column => "asc"}]
        }
      }

      assert all(table(@regular), i, "admin", %{}, columns: ["id"], preload: preload) ==
               {:ok,
                [
                  %{"id" => 1, @relationship => [%{@long_column => 1, @other_column => 1}]},
                  %{"id" => 2, @relationship => [%{@long_column => 2, @other_column => 2}]}
                ]}
    end
  end

  # tests-py/queries/graphql_query/boolexp/basic/select_author_article_where_permissions.yaml
  # (https://github.com/hasura/graphql-engine/issues/6931)
  describe "tests-py boolexp/basic/select_author_article_where_permissions.yaml" do
    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{
              table: {"hasura_boolexp", "author"},
              array_relationships: [
                %{
                  name: "articles",
                  using: %{
                    foreign_key_constraint_on: %{
                      table: {"hasura_boolexp", "article"},
                      column: "author_id"
                    }
                  }
                }
              ],
              select_permissions: [
                %{role: "user", permission: %{columns: ["id", "name"], filter: %{}}}
              ]
            },
            %{
              table: {"hasura_boolexp", "article"},
              select_permissions: [
                %{
                  role: "user",
                  permission: %{
                    columns: ["author_id", "content", "id", "title"],
                    filter: %{"is_published" => %{"_eq" => true}}
                  }
                }
              ]
            }
          ])
      }
    end

    defp authors_with_articles(instance, role),
      do:
        all_input(BoolexpAuthor, instance, role, %{}, %{
          "columns" => ["name"],
          "filter" => %{"articles" => %{}},
          "order_by" => [%{"id" => "asc"}]
        })

    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended: relationships are rejected in input; Hasura " <>
             "applies them with the target's permission). The empty form {articles: {}} " <>
             "is :relationship_in_input, like every relationship-shaped key"
    test "as admin, every author with an article", %{instance: i} do
      assert authors_with_articles(i, "admin") ==
               {:ok, [%{name: "Author 1"}, %{name: "Author 2"}, %{name: "Author 3"}]}
    end

    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended: relationships are rejected in input; Hasura " <>
             "applies them with the target's permission). The empty form {articles: {}} " <>
             "is :relationship_in_input, like every relationship-shaped key"
    test "as user, the relationship applies article's own permission", %{instance: i} do
      assert authors_with_articles(i, "user") ==
               {:ok, [%{name: "Author 1"}, %{name: "Author 3"}]}
    end

    # What Authzura does instead, for every role: the empty form reads as a
    # relationship whether or not one exists, so it reveals no name.
    test "the empty form {articles: {}} is relationship_in_input", %{instance: i} do
      for role <- ["admin", "user"] do
        assert authors_with_articles(i, role) ==
                 {:error, {:invalid_input, [{["articles"], :relationship_in_input}]}},
               role
      end
    end
  end
end

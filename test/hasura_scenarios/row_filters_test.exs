defmodule Authzura.HasuraScenarios.RowFiltersTest do
  @moduledoc """
  Row filters ported from Hasura v2.51.6. Paths are relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  alias Authzura.Test.HasuraSchemas.PermissionsArticle

  # lib/api-tests/src/Test/Schema/DataValidations/Permissions/SelectSpec.hs
  describe "Schema/DataValidations/Permissions/SelectSpec.hs" do
    @spec_article {"hasura_select_spec", "article"}

    setup %{test: test} do
      permissions = [
        %{
          role: "author",
          permission: %{columns: "*", filter: %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}}
        },
        %{
          role: "user",
          permission: %{columns: "*", filter: %{"state" => %{"_eq" => "Published"}}}
        },
        %{
          role: "editor",
          permission: %{
            columns: "*",
            filter: %{"state" => %{"_in" => ["InReview", "Published"]}}
          }
        }
      ]

      %{
        instance:
          start!(test, [
            %{table: {"hasura_select_spec", "author"}},
            %{
              table: @spec_article,
              object_relationships: [
                %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
              ],
              select_permissions: permissions
            }
          ])
      }
    end

    test "authors can't select another author's articles", %{instance: i} do
      assert all(table(@spec_article), i, "author", %{"X-Hasura-User-Id" => "0"},
               columns: ["id", "author_id"]
             ) == {:ok, []}
    end

    test "authors can select their own articles", %{instance: i} do
      assert all(table(@spec_article), i, "author", %{"X-Hasura-User-Id" => "1"},
               columns: ["id", "author_id"]
             ) == {:ok, [%{"id" => 1, "author_id" => 1}]}
    end

    test "the user role can select published articles only", %{instance: i} do
      assert all(table(@spec_article), i, "user", %{"X-Hasura-User-Id" => "2"},
               columns: ["title", "content", "author_id"]
             ) ==
               {:ok,
                [
                  %{
                    "author_id" => 2,
                    "content" => "Sample article content 2",
                    "title" => "Article 2"
                  }
                ]}
    end

    test "the editor role can select in-review and published articles only", %{instance: i} do
      assert all(table(@spec_article), i, "editor", %{},
               columns: ["title", "content", "author_id"]
             ) ==
               {:ok,
                [
                  %{
                    "author_id" => 1,
                    "content" => "Sample article content 1",
                    "title" => "Article 1"
                  },
                  %{
                    "author_id" => 2,
                    "content" => "Sample article content 2",
                    "title" => "Article 2"
                  }
                ]}
    end
  end

  # tests-py/queries/graphql_query/permissions/setup.yaml, with
  # anonymous_can_only_get_published_articles.yaml and
  # user_select_query_unpublished_articles.yaml
  describe "tests-py permissions: article and author" do
    @author {"hasura_permissions", "author"}
    @perm_article {"hasura_permissions", "article"}
    @article_columns ["id", "title", "content", "is_published"]
    @author_preload %{"author" => %{"columns" => ["id", "name"]}}

    setup %{test: test} do
      %{instance: start!(test, permissions_tables())}
    end

    test "anonymous: an input filter for unpublished articles finds none", %{instance: i} do
      assert all_input(PermissionsArticle, i, "anonymous", %{}, %{
               "filter" => %{"is_published" => %{"_eq" => false}}
             }) == {:ok, []}
    end

    test "anonymous: only published articles, each with its author", %{instance: i} do
      assert all(table(@perm_article), i, "anonymous", %{},
               columns: @article_columns,
               preload: @author_preload
             ) ==
               {:ok,
                [
                  article(2, true, %{"id" => 1, "name" => "Author 1"}),
                  article(3, true, %{"id" => 2, "name" => "Author 2"})
                ]}
    end

    test "user: an input filter finds only its own unpublished article, with its author",
         %{instance: i} do
      assert all_input(PermissionsArticle, i, "user", %{"X-Hasura-User-Id" => "1"}, %{
               "columns" => @article_columns,
               "filter" => %{"is_published" => %{"_eq" => false}},
               "preload" => @author_preload
             }) ==
               {:ok,
                [
                  %{
                    :id => 1,
                    :title => "Article 1",
                    :content => "Sample article content 1",
                    :is_published => false,
                    "author" => %{"id" => 1, "name" => "Author 1"}
                  }
                ]}
    end

    # Not a separate Hasura test file: the rows the setup.yaml permissions
    # (`$or` with the mixed-case `X-HASURA-USER-ID`) give every query above.
    test "user: $or with a mixed-case session name in the metadata", %{instance: i} do
      assert all(table(@perm_article), i, "user", %{"X-Hasura-User-Id" => "1"},
               columns: @article_columns,
               preload: @author_preload
             ) ==
               {:ok,
                [
                  article(1, false, %{"id" => 1, "name" => "Author 1"}),
                  article(2, true, %{"id" => 1, "name" => "Author 1"}),
                  article(3, true, %{"id" => 2, "name" => "Author 2"})
                ]}
    end

    # The author part of select_articles_without_required_headers.yaml's
    # anonymous case: authors with at least one published article.
    test "anonymous: an array relationship filter on author", %{instance: i} do
      assert all(table(@author), i, "anonymous", %{}, columns: ["id", "name"]) ==
               {:ok, [%{"id" => 1, "name" => "Author 1"}, %{"id" => 2, "name" => "Author 2"}]}
    end

    defp article(id, published?, author),
      do: %{
        "id" => id,
        "title" => "Article #{id}",
        "content" => "Sample article content #{id}",
        "is_published" => published?,
        "author" => author
      }
  end

  # tests-py/queries/graphql_query/boolexp/basic/query_account_permission_{success,fail}.yaml
  describe "tests-py boolexp/basic: _exists on account" do
    @account {"hasura_boolexp", "account"}

    setup %{test: test} do
      filter = %{
        "_exists" => %{
          "_table" => %{"schema" => "hasura_boolexp", "name" => "user"},
          "_where" => %{"id" => "X-Hasura-User-Id", "is_admin" => true}
        }
      }

      %{
        instance:
          start!(test, [
            %{table: {"hasura_boolexp", "user"}},
            %{
              table: @account,
              select_permissions: [
                %{role: "user", permission: %{columns: ["id", "account_no"], filter: filter}}
              ]
            }
          ])
      }
    end

    test "a user who is an admin sees every account", %{instance: i} do
      assert all(table(@account), i, "user", %{"X-Hasura-User-Id" => "2"}) ==
               {:ok, [%{"id" => 1, "account_no" => 1}, %{"id" => 2, "account_no" => 2}]}
    end

    test "a user who is not an admin sees none", %{instance: i} do
      assert all(table(@account), i, "user", %{"X-Hasura-User-Id" => "1"}) == {:ok, []}
    end
  end

  # lib/api-tests/src/Test/Regression/RootExistElementAliasing9457Spec.hs
  describe "Regression/RootExistElementAliasing9457Spec.hs" do
    # test-role-2 is denied at load (see the skipped test), which logs a warning.
    @describetag :capture_log
    @user {"hasura_root_exists", "user"}
    @org_stuff {"hasura_root_exists", "org_stuff"}

    setup %{test: test} do
      own_table = %{
        "_exists" => %{
          "_table" => %{"schema" => "hasura_root_exists", "name" => "user"},
          "_where" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}}
        }
      }

      member_of_same_group = %{
        "_and" => [
          %{"public" => %{"_eq" => true}},
          %{
            "_not" => %{
              "_exists" => %{
                "_table" => %{"schema" => "hasura_root_exists", "name" => "org_stuff"},
                "_where" => %{
                  "_and" => [
                    %{
                      "organization_by_organization_id_to_id" => %{
                        "organization_members_by_id_to_organization_id" => %{
                          "user_id" => %{"_eq" => "X-Hasura-User-Id"}
                        }
                      }
                    },
                    %{"group" => %{"_ceq" => ["$", "group"]}}
                  ]
                }
              }
            }
          }
        ]
      }

      %{
        instance:
          start!(test, [
            %{
              table: @user,
              select_permissions: [
                %{role: "test-role-1", permission: %{columns: "*", filter: own_table}}
              ]
            },
            %{
              table: {"hasura_root_exists", "organization"},
              array_relationships: [
                %{
                  name: "organization_members_by_id_to_organization_id",
                  using: %{
                    foreign_key_constraint_on: %{
                      table: {"hasura_root_exists", "organization_member"},
                      column: "organization_id"
                    }
                  }
                }
              ]
            },
            %{table: {"hasura_root_exists", "organization_member"}},
            %{
              table: @org_stuff,
              object_relationships: [
                %{
                  name: "organization_by_organization_id_to_id",
                  using: %{foreign_key_constraint_on: "organization_id"}
                }
              ],
              select_permissions: [
                %{role: "test-role-2", permission: %{columns: "*", filter: member_of_same_group}}
              ]
            }
          ])
      }
    end

    test "an _exists on the root's own table with a session variable", %{instance: i} do
      names = fn id ->
        all(table(@user), i, "test-role-1", %{"X-Hasura-User-Id" => id}, columns: ["name"])
      end

      assert names.("1") ==
               {:ok,
                [
                  %{"name" => "Alice"},
                  %{"name" => "Bob"},
                  %{"name" => "Charlie"},
                  %{"name" => "Dave"}
                ]}

      assert names.("10") == {:ok, []}
    end

    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): _ceq with the root reference $ is a column " <>
             "comparison operator, unsupported in stage one, so the permission is denied"
    test "_not _exists on the root's table, correlated through _ceq [$, group]", %{instance: i} do
      assert all(
               table(@org_stuff, [:organization_id]),
               i,
               "test-role-2",
               %{
                 "X-Hasura-User-Id" => "1"
               },
               columns: ["data"]
             ) ==
               {:ok, [%{"data" => "Second data"}, %{"data" => "Third data"}]}
    end
  end

  # tests-py/queries/graphql_query/boolexp/basic/self_referential_relationships.yaml and
  # select_article_author_{is_published_and_registered,not_published_or_not_registered}.yaml.
  # Hasura runs these as user `where` arguments as admin; the same bool_exp
  # compiles here as each role's permission filter, because Authzura's input
  # path rejects relationships (see relationships_test.exs, issue 6931).
  describe "tests-py boolexp/basic: relationships in a bool_exp" do
    @message {"hasura_boolexp", "message"}
    @boolexp_article {"hasura_boolexp", "article"}

    setup %{test: test} do
      hello = %{"_ilike" => "%hello%"}

      %{
        instance:
          start!(test, [
            %{
              table: @message,
              object_relationships: [
                %{name: "parent", using: %{foreign_key_constraint_on: "parent_id"}}
              ],
              array_relationships: [
                %{
                  name: "children",
                  using: %{foreign_key_constraint_on: %{table: @message, column: "parent_id"}}
                }
              ],
              select_permissions: [
                %{
                  role: "m1",
                  permission: %{
                    columns: ["id"],
                    filter: %{
                      "_or" => [
                        %{"content" => hello},
                        %{"children" => %{"content" => hello}}
                      ]
                    }
                  }
                },
                %{
                  role: "level1",
                  permission: %{
                    columns: ["id"],
                    filter: %{"parent" => %{"parent_id" => %{"_is_null" => true}}}
                  }
                }
              ]
            },
            %{table: {"hasura_boolexp", "author"}},
            %{
              table: @boolexp_article,
              object_relationships: [
                %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
              ],
              select_permissions: [
                %{
                  role: "published_and_registered",
                  permission: %{
                    columns: ["id"],
                    filter: %{
                      "_and" => [
                        %{"is_published" => %{"_eq" => true}},
                        %{"author" => %{"is_registered" => %{"_eq" => true}}}
                      ]
                    }
                  }
                },
                %{
                  role: "not_published_or_not_registered",
                  permission: %{
                    columns: ["id"],
                    filter: %{
                      "_or" => [
                        %{"is_published" => %{"_eq" => false}},
                        %{"author" => %{"is_registered" => %{"_eq" => false}}}
                      ]
                    }
                  }
                }
              ]
            }
          ])
      }
    end

    defp ids(ref, instance, role) do
      {:ok, rows} = all(table(ref), instance, role)
      Enum.map(rows, & &1["id"])
    end

    test "self-referential array and object relationships", %{instance: i} do
      assert ids(@message, i, "m1") == [1, 4, 6]
      assert ids(@message, i, "level1") == [2, 3, 5, 6]
    end

    test "an object relationship under _and and _or", %{instance: i} do
      assert ids(@boolexp_article, i, "published_and_registered") == [2]
      assert ids(@boolexp_article, i, "not_published_or_not_registered") == [1, 3, 4]
    end
  end
end

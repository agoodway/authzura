defmodule Authzura.HasuraScenarios.SessionVariablesTest do
  @moduledoc """
  Session variables ported from Hasura v2.51.6. Paths are relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  # tests-py/queries/graphql_query/permissions/in_and_nin.yaml
  describe "tests-py permissions/in_and_nin.yaml" do
    @artist {"hasura_permissions", "Artist"}

    setup %{test: test} do
      permission = fn role, filter ->
        %{role: role, permission: %{columns: "*", filter: %{"name" => filter}}}
      end

      %{
        instance:
          start!(test, [
            %{
              table: @artist,
              select_permissions: [
                permission.("free_user_in", %{"_in" => "X-Hasura-Free-Artists"}),
                permission.("free_user_nin", %{"_nin" => "X-Hasura-Premium-Artists"})
              ]
            }
          ])
      }
    end

    defp names(instance, role, headers) do
      {:ok, rows} = all(table(@artist, [:name]), instance, role, headers, columns: ["name"])
      Enum.map(rows, & &1["name"])
    end

    test "_in an array session variable, and an empty one", %{instance: i} do
      assert names(i, "free_user_in", %{"X-Hasura-free-artists" => "{Camilla,DSP}"}) ==
               ["Camilla", "DSP"]

      assert names(i, "free_user_in", %{"X-Hasura-free-artists" => "{}"}) == []
    end

    test "_nin an array session variable, and an empty one", %{instance: i} do
      assert names(i, "free_user_nin", %{"X-Hasura-premium-artists" => "{Akon}"}) ==
               ["Camilla", "DSP"]

      assert names(i, "free_user_nin", %{"X-Hasura-premium-artists" => "{}"}) ==
               ["Akon", "Camilla", "DSP"]
    end
  end

  # lib/api-tests/src/Test/Databases/Postgres/DataValidation/PermissionSpec.hs
  describe "Databases/Postgres/DataValidation/PermissionSpec.hs" do
    @allowed {"hasura_array_permission", "author"}

    setup %{test: test} do
      filter = %{"id" => %{"_in" => "X-Hasura-Allowed-Ids"}}

      %{
        instance:
          start!(test, [
            %{
              table: @allowed,
              select_permissions: [%{role: "user", permission: %{columns: "*", filter: filter}}]
            }
          ])
      }
    end

    test "non-matching X-Hasura-Allowed-Ids return no data", %{instance: i} do
      assert all(table(@allowed), i, "user", %{"X-Hasura-Allowed-Ids" => "{}"}) == {:ok, []}
    end

    test "matching X-Hasura-Allowed-Ids return data", %{instance: i} do
      assert all(table(@allowed), i, "user", %{"X-Hasura-Allowed-Ids" => "{1,2,3}"}) ==
               {:ok, [%{"id" => 1, "name" => "Author 1"}, %{"id" => 2, "name" => "Author 2"}]}
    end
  end

  # lib/api-tests/src/Test/Regression/DoNotTruncateSessionVariables8158Spec.hs
  describe "Regression/DoNotTruncateSessionVariables8158Spec.hs" do
    @untruncated {"hasura_untruncated", "author"}

    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{
              table: @untruncated,
              select_permissions: [
                %{
                  role: "user",
                  permission: %{columns: "*", filter: %{"uuid" => "X-Hasura-User-Id"}}
                }
              ]
            }
          ])
      }
    end

    test "session variable strings are not truncated to 30 characters", %{instance: i} do
      headers = %{"X-Hasura-User-Id" => "36a6257b-08bb-45ef-a5cf-c1b7a7997087"}

      assert all(table(@untruncated, [:uuid]), i, "user", headers) ==
               {:ok, [%{"name" => "Author 1", "uuid" => "36a6257b-08bb-45ef-a5cf-c1b7a7997087"}]}
    end
  end

  # tests-py/queries/graphql_query/permissions/artist_select_query_Track{,_fail}.yaml
  describe "tests-py permissions: Track by its Artist" do
    @track {"hasura_permissions", "Track"}

    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{table: {"hasura_permissions", "Artist"}},
            %{
              table: @track,
              object_relationships: [
                %{name: "Artist", using: %{foreign_key_constraint_on: "artist_id"}}
              ],
              select_permissions: [
                %{
                  role: "Artist",
                  permission: %{
                    columns: "*",
                    filter: %{"Artist" => %{"id" => "X-Hasura-Artist-Id"}},
                    allow_aggregations: true
                  }
                }
              ]
            }
          ])
      }
    end

    test "an artist can only select their tracks", %{instance: i} do
      assert all(table(@track), i, "Artist", %{"X-Hasura-Artist-Id" => "2"},
               columns: ["id", "name"]
             ) == {:ok, [%{"id" => 3, "name" => "Happy"}]}
    end

    test "without the header the read fails: missing session variable", %{instance: i} do
      assert all(table(@track), i, "Artist", %{}, columns: ["id", "name"]) ==
               {:error, {:missing_session_variable, "x-hasura-artist-id"}}
    end
  end

  # tests-py/queries/graphql_query/permissions/select_articles_without_required_headers.yaml
  describe "tests-py permissions/select_articles_without_required_headers.yaml" do
    @author {"hasura_permissions", "author"}
    @articles_preload %{"articles" => %{"columns" => ["title", "content", "is_published"]}}

    setup %{test: test} do
      %{instance: start!(test, permissions_tables())}
    end

    test "a preload whose target permission needs a missing header fails", %{instance: i} do
      assert all(table(@author), i, "critic", %{},
               columns: ["name"],
               preload: @articles_preload
             ) == {:error, {:missing_session_variable, "x-hasura-critic-id"}}
    end

    test "a role whose permissions need no header reads the same tree", %{instance: i} do
      assert all(table(@author), i, "anonymous", %{},
               columns: ["name"],
               preload: @articles_preload
             ) ==
               {:ok,
                [
                  %{"name" => "Author 1", "articles" => [article(2)]},
                  %{"name" => "Author 2", "articles" => [article(3)]}
                ]}
    end

    defp article(id),
      do: %{
        "title" => "Article #{id}",
        "content" => "Sample article content #{id}",
        "is_published" => true
      }
  end
end

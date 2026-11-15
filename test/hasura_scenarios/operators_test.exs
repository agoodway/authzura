defmodule Authzura.HasuraScenarios.OperatorsTest do
  @moduledoc """
  Operators ported from Hasura v2.51.6. Paths are relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  alias Authzura.Test.HasuraSchemas.{LiteralTable, SqlIdentifier, UuidTest}

  # tests-py/queries/graphql_query/permissions/setup.yaml (jsonb_table, Artist)
  describe "tests-py permissions: jsonb and _iregex" do
    @jsonb {"hasura_permissions", "jsonb_table"}
    @artist {"hasura_permissions", "Artist"}
    @hasura_row %{"id" => 1, "jsonb_col" => %{"name" => "Hasura", "age" => 7}}

    setup %{test: test} do
      jsonb = fn role, filter ->
        %{
          role: role,
          permission: %{columns: ["id", "jsonb_col"], filter: %{"jsonb_col" => filter}}
        }
      end

      %{
        instance:
          start!(test, [
            %{
              table: @jsonb,
              select_permissions: [
                jsonb.("user1", %{"$has_key" => "age"}),
                jsonb.("user2", %{"$has_key" => "X-Hasura-Has-Key"}),
                jsonb.("user4", %{"$has_keys_any" => "X-Hasura-Json-Keys"}),
                jsonb.("user5", %{"$has_keys_all" => "X-Hasura-Json-Required-Keys"})
              ]
            },
            %{
              table: @artist,
              select_permissions: [
                %{
                  role: "user_iregex",
                  permission: %{
                    columns: "*",
                    filter: %{"name" => %{"_iregex" => "X-Hasura-IRegex-Artists"}}
                  }
                }
              ]
            }
          ])
      }
    end

    # user_can_query_jsonb_values_filter.yaml
    test "$has_key with a literal key", %{instance: i} do
      assert all(table(@jsonb), i, "user1") == {:ok, [@hasura_row]}
    end

    # user_can_query_jsonb_values_filter_session_vars.yaml
    test "$has_key with a session variable", %{instance: i} do
      assert all(table(@jsonb), i, "user2", %{"X-Hasura-Has-Key" => "age"}) ==
               {:ok, [@hasura_row]}
    end

    # jsonb_has_any.yaml
    test "$has_keys_any with an array session variable", %{instance: i} do
      assert all(table(@jsonb), i, "user4", %{"X-Hasura-Json-keys" => "{age}"}) ==
               {:ok, [@hasura_row]}

      assert all(table(@jsonb), i, "user4", %{"X-Hasura-Json-keys" => "{}"}) == {:ok, []}
    end

    # jsonb_has_all.yaml. Its second case sends a different header and expects
    # no rows; upstream disables the test (test_graphql_queries.py), so only
    # the first case is ported.
    test "$has_keys_all with an array session variable", %{instance: i} do
      assert all(table(@jsonb), i, "user5", %{"X-Hasura-Json-required-keys" => "{name,age}"}) ==
               {:ok, [@hasura_row]}
    end

    # iregex.yaml
    test "_iregex with a session variable", %{instance: i} do
      assert all(
               table(@artist, [:name]),
               i,
               "user_iregex",
               %{
                 "X-Hasura-iregex-artists" => "(.*ak)|(.*lla)"
               },
               columns: ["name"]
             ) == {:ok, [%{"name" => "Akon"}, %{"name" => "Camilla"}]}
    end
  end

  # tests-py/queries/graphql_query/permissions/user_query_auction.yaml
  describe "tests-py permissions: auction" do
    # The permission is denied at load (see the skipped test), which logs a warning.
    @describetag :capture_log

    @auction {"hasura_permissions", "auction"}

    setup %{test: test} do
      permission = %{
        columns: ["id", "bid_price"],
        filter: %{"bid_price" => %{"$cgt" => "price"}}
      }

      %{
        instance:
          start!(test, [
            %{table: @auction, select_permissions: [%{role: "user", permission: permission}]}
          ])
      }
    end

    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): $cgt is a column comparison operator, " <>
             "unsupported in stage one, so the permission is denied"
    test "$cgt compares two columns", %{instance: i} do
      query = @auction |> table([:bid_price]) |> limit(1)

      assert all(query, i, "user") == {:ok, [%{"id" => 4, "bid_price" => 260}]}
    end
  end

  # Hasura runs these as admin `where` arguments; here they are the admin
  # role's input filters.
  describe "input filters" do
    setup %{test: test} do
      %{
        instance:
          start!(test, [
            %{table: {"hasura_boolexp", "uuid_test"}},
            %{table: {"hasura_boolexp", "table_with_sql_identifier"}},
            %{table: {"hasura_array_literal", "table"}}
          ])
      }
    end

    defp rows(root, instance, filter),
      do:
        all_input(root, instance, "admin", %{}, %{
          "filter" => filter,
          "order_by" => [%{"id" => "asc"}]
        })

    # tests-py/queries/graphql_query/boolexp/basic/select_uuid_test_in_uuid_col_postgres.yaml
    test "_in on a uuid column", %{instance: i} do
      filter = %{
        "uuid_col" => %{
          "_in" => [
            "28d6d683-1317-49f7-b1cf-7d195242e4e5",
            "28d6d683-1317-49f7-b1cf-7d195242e4e6",
            "28d6d683-1317-49f7-b1cf-7d195242e4e8"
          ]
        }
      }

      assert rows(UuidTest, i, filter) ==
               {:ok,
                [
                  %{id: 1, uuid_col: "28d6d683-1317-49f7-b1cf-7d195242e4e5"},
                  %{id: 2, uuid_col: "28d6d683-1317-49f7-b1cf-7d195242e4e6"}
                ]}
    end

    # tests-py/queries/graphql_query/boolexp/basic/in_sql_identifier_array.yaml
    # information_schema.sql_identifier is a domain over `name`, which
    # compares as text.
    test "_nin on an information_schema.sql_identifier column", %{instance: i} do
      assert rows(SqlIdentifier, i, %{"sql_id" => %{"_nin" => ["one", "three"]}}) ==
               {:ok, [%{id: 3, sql_id: "two"}, %{id: 5, sql_id: "four"}, %{id: 7, sql_id: "two"}]}
    end

    # Not a Hasura case: the rest of the text operators on the same column.
    test "_eq, _gt, _like and _in on a name-based column", %{instance: i} do
      four = {:ok, [%{id: 5, sql_id: "four"}]}

      assert rows(SqlIdentifier, i, %{"sql_id" => %{"_eq" => "four"}}) == four
      assert rows(SqlIdentifier, i, %{"sql_id" => %{"_like" => "f%"}}) == four
      assert rows(SqlIdentifier, i, %{"sql_id" => %{"_in" => ["four", "nope"]}}) == four
      assert {:ok, [_ | _]} = rows(SqlIdentifier, i, %{"sql_id" => %{"_gt" => "one"}})
    end

    # lib/api-tests/src/Test/Regression/ArrayLiteralTextEncodingSpec.hs
    test "_in and _nin elements with commas, quotes, backslashes and empty strings",
         %{instance: i} do
      assert rows(LiteralTable, i, %{"str" => %{"_in" => ["a,b", "c"]}}) ==
               {:ok, [%{id: 1, str: "a,b"}, %{id: 8, str: "c"}]}

      assert rows(LiteralTable, i, %{"str" => %{"_nin" => ["a,", "", ",", "\"", "שלום"]}}) ==
               {:ok,
                [
                  %{id: 1, str: "a,b"},
                  %{id: 5, str: "\\"},
                  %{id: 7, str: "&"},
                  %{id: 8, str: "c"}
                ]}
    end
  end
end

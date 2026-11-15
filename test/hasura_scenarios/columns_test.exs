defmodule Authzura.HasuraScenarios.ColumnsTest do
  @moduledoc """
  Column permissions ported from Hasura v2.51.6's
  `tests-py/queries/graphql_query/permissions/` (paths relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server).
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  @author {"hasura_permissions", "author"}
  @article {"hasura_permissions", "article"}

  setup %{test: test} do
    %{instance: start!(test, permissions_tables())}
  end

  # user_cannot_access_remarks_col.yaml
  describe "user_cannot_access_remarks_col.yaml" do
    test "the user role cannot read remarks_internal", %{instance: i} do
      assert all(table(@author), i, "user", %{"X-Hasura-User-Id" => "1"},
               columns: ["id", "name", "remarks_internal"]
             ) == {:error, {:forbidden_columns, ["remarks_internal"]}}
    end

    test "the admin role can", %{instance: i} do
      assert all(table(@author), i, "admin", %{}, columns: ["id", "name", "remarks_internal"]) ==
               {:ok,
                for(
                  id <- 1..3,
                  do: %{
                    "id" => id,
                    "name" => "Author #{id}",
                    "remarks_internal" => "remark #{id}"
                  }
                )}
    end
  end

  # setup.yaml: the user role's article filter reads author_id, which is not
  # one of its columns.
  describe "a filter on a column the role cannot select" do
    test "still filters, and the column stays hidden", %{instance: i} do
      headers = %{"X-Hasura-User-Id" => "1"}

      assert {:ok, rows} = all(table(@article), i, "user", headers)
      assert Enum.map(rows, & &1["id"]) == [1, 2, 3]
      assert Enum.all?(rows, &(Map.keys(&1) == ["content", "id", "is_published", "title"]))

      assert all(table(@article), i, "user", headers, columns: ["id", "author_id"]) ==
               {:error, {:forbidden_columns, ["author_id"]}}
    end
  end
end

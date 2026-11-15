defmodule Authzura.HasuraScenarios.SearchTest do
  @moduledoc """
  The pattern operators of
  `tests-py/queries/graphql_query/boolexp/search/` (paths relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server). Hasura runs
  each as an admin `where`; here each is the admin role's input filter on
  the same rows. A role with a permission shows the same filter ANDed with
  the permission, and a role without one is denied.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  alias Authzura.Test.HasuraSchemas.{City, Project}

  @city_columns ["name", "country"]

  setup %{test: test} do
    usa = %{"country" => %{"_eq" => "USA"}}

    %{
      instance:
        start!(test, [
          %{
            table: {"hasura_search", "city"},
            select_permissions: [
              %{role: "usa_only", permission: %{columns: "*", filter: usa}}
            ]
          },
          %{table: {"hasura_search", "project"}}
        ])
    }
  end

  defp cities(instance, filter, role \\ "admin"),
    do:
      all_input(City, instance, role, %{}, %{
        "columns" => @city_columns,
        "filter" => %{"name" => filter},
        "order_by" => [%{"id" => "asc"}]
      })

  @durham %{name: "Durham", country: "USA"}
  @york %{name: "New York", country: "USA"}
  @fram %{name: "Framlingham", country: "UK"}
  @orleans %{name: "New Orleans", country: "USA"}

  # select_city_where_like.yaml
  test "_like: names ending with ham", %{instance: i} do
    assert cities(i, %{"_like" => "%ham"}) == {:ok, [@durham, @fram]}
  end

  # select_city_where_nlike.yaml
  test "_nlike: names not ending with ham", %{instance: i} do
    assert cities(i, %{"_nlike" => "%ham"}) == {:ok, [@york, @orleans]}
  end

  # select_city_where_ilike_postgres.yaml
  test "_ilike: names starting with new, any case", %{instance: i} do
    assert cities(i, %{"_ilike" => "new %"}) == {:ok, [@york, @orleans]}
  end

  # select_city_where_nilike_postgres.yaml
  test "_nilike: names not starting with new", %{instance: i} do
    assert cities(i, %{"_nilike" => "new %"}) == {:ok, [@durham, @fram]}
  end

  # select_city_where_similar_postgres.yaml
  test "_similar: names ending with gham", %{instance: i} do
    assert cities(i, %{"_similar" => "_*gham"}) == {:ok, [@fram]}
  end

  # select_city_where_not_similar_postgres.yaml
  test "_nsimilar: names not ending with ham", %{instance: i} do
    assert cities(i, %{"_nsimilar" => "_*ham"}) == {:ok, [@york, @orleans]}
  end

  # select_city_where_regex_postgres.yaml
  test "_regex: names ending with gham", %{instance: i} do
    assert cities(i, %{"_regex" => ".*gham"}) == {:ok, [@fram]}
  end

  # select_city_where_nregex_postgres.yaml
  test "_nregex is case-sensitive: no name matches new.*", %{instance: i} do
    assert cities(i, %{"_nregex" => "new.*"}) == {:ok, [@durham, @york, @fram, @orleans]}
  end

  # select_city_where_iregex_postgres.yaml
  test "_iregex: names starting with fram, any case", %{instance: i} do
    assert cities(i, %{"_iregex" => "fram.*"}) == {:ok, [@fram]}
  end

  # select_city_where_niregex_postgres.yaml
  test "_niregex: names not starting with new", %{instance: i} do
    assert cities(i, %{"_niregex" => "new.*"}) == {:ok, [@durham, @fram]}
  end

  # select_project_where_ilike_postgres.yaml (issue 6217): a char(3) column.
  # Hasura sends no order_by, so the two rows are compared as a set.
  test "_ilike on a character column", %{instance: i} do
    assert {:ok, rows} =
             all_input(Project, i, "admin", %{}, %{"filter" => %{"id" => %{"_ilike" => "b%"}}})

    assert rows |> Enum.map(& &1.id) |> Enum.sort() == ["BCD", "bcd"]
  end

  # Negative controls: the permission's filter still applies to the same
  # pattern, and a role with no permission on the table is denied.
  test "a role's permission is ANDed with the pattern filter", %{instance: i} do
    assert cities(i, %{"_like" => "%ham"}, "usa_only") == {:ok, [@durham]}
    assert cities(i, %{"_niregex" => "new.*"}, "usa_only") == {:ok, [@durham]}
  end

  test "a role without a permission is denied", %{instance: i} do
    assert cities(i, %{"_like" => "%ham"}, "nobody") == {:error, :forbidden}
  end
end

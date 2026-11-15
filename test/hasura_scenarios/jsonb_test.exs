defmodule Authzura.HasuraScenarios.JsonbTest do
  @moduledoc """
  The jsonb operators of `tests-py/queries/graphql_query/boolexp/jsonb/`
  (paths relative to
  https://github.com/hasura/graphql-engine/tree/v2.51.6/server). Hasura runs
  each as an admin `where`; here each is the admin role's input filter on
  the same rows. A permission that filters on the same operator shows the
  denied and the empty outcomes.
  """

  use Authzura.CommittedCase

  import Authzura.HasuraScenarios

  alias Authzura.Test.HasuraSchemas.{JsonbArticle, JsonbProduct}

  @article {"hasura_jsonb", "article"}
  @article_columns ["id", "title", "content", "tags"]
  @author_preload %{"author" => %{"columns" => ["id", "name"]}}

  setup %{test: test} do
    %{
      instance:
        start!(test, [
          %{table: {"hasura_jsonb", "author"}},
          %{
            table: @article,
            object_relationships: [
              %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
            ],
            select_permissions: [
              %{
                role: "has_no_such_tag",
                permission: %{columns: "*", filter: %{"tags" => %{"_contains" => "missing"}}}
              }
            ]
          },
          %{table: {"hasura_jsonb", "product"}}
        ])
    }
  end

  defp articles(instance, filter, role \\ "admin"),
    do:
      all_input(
        JsonbArticle,
        instance,
        role,
        %{},
        %{
          "columns" => @article_columns,
          "filter" => %{"tags" => filter},
          "order_by" => [%{"id" => "asc"}]
        },
        preload: @author_preload
      )

  defp article(id, tags, author_id) do
    %{
      :id => id,
      :title => "Article #{id}",
      :content => "Sample article content #{id}",
      :tags => tags,
      "author" => %{"id" => author_id, "name" => "Author #{author_id}"}
    }
  end

  defp products(instance, filter) do
    all_input(JsonbProduct, instance, "admin", %{}, %{
      "columns" => ["id", "name", "category", "spec"],
      "filter" => %{"spec" => filter},
      "order_by" => [%{"id" => "asc"}]
    })
  end

  @specs %{
    1 => %{
      "Operating System" => "os1",
      "RAM" => "8GB",
      "Disk" => "128GB",
      "Weight" => "1.2Kg",
      "Processor" => "processor1"
    },
    2 => %{
      "OS" => "os2",
      "RAM" => "16GB",
      "Disk" => "128GB",
      "Weight" => "1.2Kg",
      "Processor" => "processor2",
      "Touchscreen" => true
    },
    3 => %{
      "Operating System Type" => "osType1",
      "RAM" => "3GB",
      "Weight" => "200g",
      "Processor" => "processor2",
      "Network type" => "4G",
      "SIM type" => "DualSim",
      "Sensors" => "Accelerometer sensor, E-compass, Proximity sensor",
      "Touchscreen" => true
    }
  }

  defp product(id, name, category),
    do: %{id: id, name: name, category: category, spec: Map.fetch!(@specs, id)}

  # select_article_author_jsonb_contains_latest.yaml
  test "_contains a string element, with the author", %{instance: i} do
    assert articles(i, %{"_contains" => "latest"}) ==
             {:ok,
              [
                article(2, ["bestseller", "latest"], 1),
                article(3, ["latest"], 2)
              ]}
  end

  # select_article_author_jsonb_contained_in_latest.yaml
  test "_contained_in [latest], with the author", %{instance: i} do
    assert articles(i, %{"_contained_in" => ["latest"]}) ==
             {:ok, [article(3, ["latest"], 2)]}
  end

  # select_article_author_jsonb_contained_in_bestseller_latest.yaml
  test "_contained_in [bestseller, latest], with the author", %{instance: i} do
    assert articles(i, %{"_contained_in" => ["bestseller", "latest"]}) ==
             {:ok,
              [
                article(2, ["bestseller", "latest"], 1),
                article(3, ["latest"], 2)
              ]}
  end

  # select_product_jsonb_has_key_sim_type.yaml
  test "_has_key with a key that has a space", %{instance: i} do
    assert products(i, %{"_has_key" => "SIM type"}) == {:ok, [product(3, "mobile1", "Mobile")]}
  end

  # select_product_jsonb_has_keys_all_ram_touchscreen.yaml
  test "_has_keys_all", %{instance: i} do
    assert products(i, %{"_has_keys_all" => ["Touchscreen", "RAM"]}) ==
             {:ok, [product(2, "laptop2", "Laptop"), product(3, "mobile1", "Mobile")]}
  end

  # select_product_jsonb_has_keys_any_os_operating_system.yaml
  test "_has_keys_any", %{instance: i} do
    assert products(i, %{"_has_keys_any" => ["OS", "Operating System"]}) ==
             {:ok, [product(1, "laptop1", "Laptop"), product(2, "laptop2", "Laptop")]}
  end

  # Negative controls: an operand nothing matches gives no rows, a row with a
  # NULL jsonb value never matches, and a permission on the same operator
  # that matches nothing gives no rows for a role.
  test "an operand nothing matches gives no rows", %{instance: i} do
    assert products(i, %{"_has_key" => "no such key"}) == {:ok, []}
    assert products(i, %{"_has_keys_all" => ["RAM", "no such key"]}) == {:ok, []}
    assert articles(i, %{"_contained_in" => ["nothing"]}) == {:ok, []}
  end

  test "an article without tags matches no jsonb operator", %{instance: i} do
    assert {:ok, rows} = articles(i, %{"_contains" => "bestseller"})
    assert Enum.map(rows, & &1.id) == [2]
  end

  test "a role whose permission matches nothing, and a role without one", %{instance: i} do
    for {role, expected} <- [{"has_no_such_tag", {:ok, []}}, {"nobody", {:error, :forbidden}}] do
      input = %{"columns" => ["id"], "filter" => %{"tags" => %{"_contains" => "latest"}}}
      assert all_input(JsonbArticle, i, role, %{}, input) == expected, role
    end
  end
end

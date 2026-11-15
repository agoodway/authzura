defmodule Authzura.HasuraScenarios do
  @moduledoc """
  Helpers for `test/hasura_scenarios`, which port Hasura v2.51.6's own
  select-permission tests.

  The ported fixtures live in their own Postgres schemas, built and seeded
  once by the `create_hasura_scenario_schemas` test migration. The tests
  only read them, so each test just starts an instance on its metadata and
  reads through Authzura's public API.

  Hasura's admin role (a request without `X-Hasura-Role`) is the instance's
  opt-in `admin_role`, `"admin"`.
  """

  import Ecto.Query, only: [from: 2]

  alias Authzura.{HasuraFixture, Session}
  alias Authzura.Test.Repo
  alias Ecto.{Query, Queryable}

  @article_columns ["id", "title", "content", "is_published"]

  @doc "Starts an instance named `name` on `tables`, with `\"admin\"` as its admin role."
  @spec start!(atom(), [map()]) :: atom()
  def start!(name, tables) when is_list(tables),
    do:
      HasuraFixture.start_instance!(name, Repo, HasuraFixture.metadata(tables),
        admin_role: "admin"
      )

  @doc "A schemaless query on `{schema, table}`, ordered by `order` (default `[:id]`)."
  @spec table({String.t(), String.t()}, [atom()]) :: Query.t()
  def table({schema, name}, order \\ [:id]),
    do: from(t in name, prefix: ^schema, order_by: ^order)

  @doc "A session for `role` carrying Hasura-style `headers` (any casing)."
  @spec session(String.t(), map()) :: Session.t()
  def session(role, headers \\ %{}), do: HasuraFixture.session!(role, headers)

  @doc "Runs `Authzura.all/3` on `instance` for `role` with `headers`."
  @spec all(Queryable.t(), atom(), String.t(), map(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def all(queryable, instance, role, headers \\ %{}, opts \\ []),
    do: Authzura.all(queryable, session(role, headers), [instance: instance] ++ opts)

  @doc """
  The `author` and `article` tables of
  `tests-py/queries/graphql_query/permissions/setup.yaml`, with their
  relationships and select permissions.
  """
  @spec permissions_tables() :: [map()]
  def permissions_tables do
    [
      %{
        table: {"hasura_permissions", "author"},
        array_relationships: [
          %{
            name: "articles",
            using: %{
              foreign_key_constraint_on: %{
                table: {"hasura_permissions", "article"},
                column: "author_id"
              }
            }
          }
        ],
        select_permissions: [
          %{
            role: "user",
            permission: %{
              columns: ["id", "name", "is_registered"],
              filter: %{
                "_or" => [
                  %{"id" => "X-HASURA-USER-ID"},
                  %{"articles" => %{"is_published" => %{"_eq" => true}}}
                ]
              },
              limit: 10
            }
          },
          %{
            role: "anonymous",
            permission: %{
              columns: ["id", "name"],
              filter: %{"articles" => %{"is_published" => %{"_eq" => true}}}
            }
          },
          %{role: "critic", permission: %{columns: ["name"], filter: %{}}}
        ]
      },
      %{
        table: {"hasura_permissions", "article"},
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: [
          %{
            role: "user",
            permission: %{
              columns: @article_columns,
              filter: %{
                "$or" => [%{"author_id" => "X-HASURA-USER-ID"}, %{"is_published" => true}]
              }
            }
          },
          %{
            role: "anonymous",
            permission: %{columns: @article_columns, filter: %{"is_published" => true}}
          },
          %{
            role: "critic",
            permission: %{
              columns: ["title", "content", "is_published"],
              filter: %{"id" => %{"_eq" => "X-Hasura-Critic-Id"}}
            }
          }
        ]
      }
    ]
  end

  @doc """
  Runs `Authzura.all_input/4` on `instance` for `role` with `headers`; `opts`
  (for example `preload:`) are passed on.
  """
  @spec all_input(Queryable.t(), atom(), String.t(), map(), map(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def all_input(queryable, instance, role, headers, input, opts \\ []),
    do: Authzura.all_input(queryable, session(role, headers), input, [instance: instance] ++ opts)
end

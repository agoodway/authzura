defmodule Authzura.FilterFixture do
  @moduledoc """
  Builds compiler inputs from the fixture database: introspected tables with
  the relationships below resolved, permission filters parsed with
  `Authzura.Sources.Hasura.BoolExp`, sessions, and compiler contexts.
  """

  import Ecto.Query, only: [from: 2, where: 2]

  alias Authzura.Adapters.Postgres
  alias Authzura.{AST, Compiler, FixtureSchema, HasuraFixture, Session}
  alias Authzura.Compiler.Aliases
  alias Authzura.Sources.Hasura.{BoolExp, Metadata}
  alias Ecto.Query

  @users {"public", "users"}
  @articles {"public", "articles"}
  @comments {"public", "comments"}

  @doc "Introspects the fixture tables and resolves the fixture relationships."
  @spec tables(module()) :: map()
  def tables(repo) do
    {:ok, tables, fks} = Postgres.introspect(repo, FixtureSchema.tracked_refs())
    {tables, []} = Metadata.resolve_relationships(metadata(), "default", tables, fks)
    tables
  end

  @doc "Parses a permission filter against `ref`."
  @spec parse(map(), {String.t(), String.t()}, map()) ::
          {:ok, AST.t()} | {:error, [{BoolExp.path(), BoolExp.reason()}]}
  def parse(tables, ref, json),
    do:
      BoolExp.parse(json, :permission, %{
        table: tables[ref],
        tables: tables,
        adapter: Postgres,
        limits: Metadata.permission_limits()
      })

  @doc "Parses a permission filter against `ref`, raising on parse errors."
  @spec parse!(map(), {String.t(), String.t()}, map()) :: AST.t()
  def parse!(tables, ref, json) do
    {:ok, ast} = parse(tables, ref, json)
    ast
  end

  @doc "A session for role `user` carrying `vars`."
  @spec session(map()) :: Session.t()
  def session(vars \\ %{}), do: HasuraFixture.session!("user", vars)

  @doc "A root compiler context for `ref`."
  @spec ctx(map(), {String.t(), String.t()}, Session.t() | :validate, keyword()) :: map()
  def ctx(tables, ref, session, opts \\ []),
    do:
      Compiler.root_ctx(
        tables[ref],
        tables,
        session,
        Postgres,
        Keyword.get(opts, :mode, :permission)
      )

  @doc "Compiles `json` (a Hasura filter) on `ref` and returns the dynamic."
  @spec compile(map(), {String.t(), String.t()}, map(), Session.t()) ::
          {:ok, Query.dynamic_expr()} | {:error, term()}
  def compile(tables, ref, json, session),
    do: tables |> parse!(ref, json) |> Compiler.compile(ctx(tables, ref, session))

  @doc "The root query on `ref`, aliased as the root binding, selecting `pk`."
  @spec root({String.t(), String.t()}, String.t()) :: Query.t()
  def root({schema, name}, pk \\ "id"),
    do: from(t in name, prefix: ^schema, as: ^Aliases.at(0), select: field(t, ^pk))

  @doc "The root query on `ref` filtered by `dynamic`."
  @spec scoped({String.t(), String.t()}, Query.dynamic_expr(), String.t()) ::
          Query.t()
  def scoped(ref, dynamic, pk \\ "id"), do: ref |> root(pk) |> where(^dynamic)

  defp metadata, do: HasuraFixture.metadata(relationship_tables())

  @doc """
  The fixture's tracked tables and their relationships, without permissions,
  as `Authzura.HasuraFixture.metadata/2` table entries.
  """
  @spec relationship_tables() :: [map()]
  def relationship_tables do
    [
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}},
          %{name: "editor", using: %{foreign_key_constraint_on: "editor_id"}}
        ],
        array_relationships: [
          %{
            name: "comments",
            using: %{foreign_key_constraint_on: %{table: @comments, column: "article_id"}}
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
          %{name: "org", using: %{foreign_key_constraint_on: "org_id"}},
          %{name: "manager", using: %{foreign_key_constraint_on: "manager_id"}}
        ],
        array_relationships: [
          %{
            name: "articles",
            using: %{foreign_key_constraint_on: %{table: @articles, column: "author_id"}}
          }
        ]
      },
      %{
        table: @comments,
        object_relationships: [
          %{name: "article", using: %{foreign_key_constraint_on: "article_id"}}
        ]
      },
      %{
        table: {"public", "membership_notes"},
        object_relationships: [
          %{name: "membership", using: %{foreign_key_constraint_on: ["org_id", "user_id"]}}
        ]
      },
      %{
        table: {"public", "published_articles"},
        object_relationships: [
          %{
            name: "author",
            using: %{
              manual_configuration: %{remote_table: @users, column_mapping: %{author_id: "id"}}
            }
          }
        ]
      }
    ]
  end
end

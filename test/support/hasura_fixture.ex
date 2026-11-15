defmodule Authzura.HasuraFixture do
  @moduledoc """
  Builds Hasura v2 (format v3) metadata documents for tests.

  Table entries are written as Elixir maps with atom or string keys; every
  key is stringified, and every `{schema, name}` tuple becomes Hasura's
  `%{"schema" => schema, "name" => name}` table object. Everything else is
  passed through, so entries read like the JSON Hasura stores.

      HasuraFixture.metadata([
        %{
          table: {"public", "articles"},
          select_permissions: [%{role: "user", permission: %{columns: "*", filter: %{}}}]
        }
      ])

  For sandboxed tests, `snapshot!/2` builds the snapshot the Hasura source
  would load, in the test process (no transaction), and `start_instance!/4`
  serves it from an instance backed by `Authzura.TestSource`, so the Store
  validates it but never touches the database.
  """

  import ExUnit.Callbacks, only: [start_supervised!: 1]

  alias Authzura.Adapters.Postgres
  alias Authzura.Model.Snapshot
  alias Authzura.{Session, TestSource}
  alias Authzura.Sources.Hasura
  alias Authzura.Sources.Hasura.Metadata

  @doc """
  Returns a metadata map with one source holding `tables`.

  Options:

    * `:source` - the source name (default `"default"`)
    * `:inherited_roles` - top-level `inherited_roles` entries
    * `:sources` - extra source maps appended after the built one
  """
  @spec metadata([map()], keyword()) :: map()
  def metadata(tables, opts \\ []) when is_list(tables) and is_list(opts) do
    source = %{
      "name" => Keyword.get(opts, :source, "default"),
      "kind" => "postgres",
      "tables" => Enum.map(tables, &json/1),
      "configuration" => %{"connection_info" => %{"database_url" => %{"from_env" => "PG_URL"}}}
    }

    %{"version" => 3, "sources" => [source | Enum.map(Keyword.get(opts, :sources, []), &json/1)]}
    |> put_inherited(Keyword.get(opts, :inherited_roles))
  end

  @doc """
  A `select_permissions` entry list granting `role` the `columns` (or `"*"`)
  under `filter` (default: all rows).
  """
  @spec select_permissions(String.t(), [String.t()] | String.t(), map()) :: [map()]
  def select_permissions(role, columns, filter \\ %{}),
    do: [%{role: role, permission: %{columns: columns, filter: filter}}]

  @doc "A manual object relationship entry."
  @spec object_relationship(String.t(), {String.t(), String.t()}, map()) :: map()
  def object_relationship(name, remote_table, column_mapping),
    do: manual_relationship(name, remote_table, column_mapping)

  @doc "A manual array relationship entry."
  @spec array_relationship(String.t(), {String.t(), String.t()}, map()) :: map()
  def array_relationship(name, remote_table, column_mapping),
    do: manual_relationship(name, remote_table, column_mapping)

  @doc "A relationship inferred from a local or remote foreign key."
  @spec fk_relationship(String.t(), String.t() | [String.t()] | map()) :: map()
  def fk_relationship(name, constraint),
    do: %{name: name, using: %{foreign_key_constraint_on: constraint}}

  defp manual_relationship(name, remote_table, column_mapping),
    do: %{
      name: name,
      using: %{
        manual_configuration: %{remote_table: remote_table, column_mapping: column_mapping}
      }
    }

  @doc """
  Replaces the single `hdb_catalog.hdb_metadata` row with `metadata` at
  `resource_version`. Test fixture only: the library never writes the catalog.
  """
  @spec put_metadata!(module(), map(), integer()) :: :ok
  def put_metadata!(repo, metadata, resource_version \\ 1) when is_map(metadata) do
    repo.query!("DELETE FROM hdb_catalog.hdb_metadata")

    repo.query!(
      "INSERT INTO hdb_catalog.hdb_metadata (id, metadata, resource_version) VALUES (1, $1, $2)",
      [metadata, resource_version]
    )

    :ok
  end

  @doc """
  Introspects `metadata`'s `"default"` source and assembles the snapshot with
  the same builder `Authzura.Sources.Hasura.load/1` uses, but in the calling
  process and outside any transaction, so it works inside the SQL sandbox.
  Like the source's, the snapshot is unvalidated: the Store validates it.
  """
  @spec snapshot!(module(), map()) :: Snapshot.t()
  def snapshot!(repo, metadata) when is_map(metadata) do
    {:ok, refs} = Metadata.tracked_tables(metadata, "default")
    {:ok, tables, fks} = Postgres.introspect(repo, refs)
    Hasura.build_snapshot(metadata, "default", tables, fks, Postgres, "fixture")
  end

  @doc """
  Starts an instance named `name` serving `snapshot!(repo, metadata)` and
  returns `name` once its first generation is published. `opts` are extra
  instance options, such as `admin_role:`.
  """
  @spec start_instance!(atom(), module(), map(), keyword()) :: atom()
  def start_instance!(name, repo, metadata, opts \\ []) do
    {name, _agent} = start_instance_with_source!(name, repo, metadata, opts)
    name
  end

  @doc """
  Like `start_instance!/4`, but also returns the `Authzura.TestSource`
  agent, so a test can serve another snapshot later:
  `TestSource.put(agent, snapshot: snapshot!(repo, m), version: v)` then
  `Authzura.reload(name)`.
  """
  @spec start_instance_with_source!(atom(), module(), map(), keyword()) :: {atom(), pid()}
  def start_instance_with_source!(name, repo, metadata, opts \\ []) do
    agent =
      start_supervised!(
        Supervisor.child_spec(
          {TestSource, snapshot: snapshot!(repo, metadata), version: "fixture"},
          id: {TestSource, name}
        )
      )

    source = {TestSource, agent: agent}

    start_supervised!(
      {Authzura,
       Keyword.merge(
         [name: name, repo: repo, source: source, poll_interval: nil, max_staleness: :infinity],
         opts
       )}
    )

    :ok = Authzura.reload(name)
    {name, agent}
  end

  @doc "A session for `role` carrying the `x-hasura-*` `vars`."
  @spec session!(String.t(), map()) :: Session.t()
  def session!(role, vars \\ %{}) when is_binary(role) and is_map(vars) do
    {:ok, session} = Session.new(Map.put(vars, "x-hasura-role", role), [])
    session
  end

  defp put_inherited(metadata, nil), do: metadata
  defp put_inherited(metadata, roles), do: Map.put(metadata, "inherited_roles", json(roles))

  defp json({schema, name}) when is_binary(schema) and is_binary(name),
    do: %{"schema" => schema, "name" => name}

  defp json(map) when is_map(map),
    do: Map.new(map, fn {key, value} -> {key(key), json(value)} end)

  defp json(list) when is_list(list), do: Enum.map(list, &json/1)
  defp json(value), do: value

  defp key(key) when is_atom(key), do: Atom.to_string(key)
  defp key(key) when is_binary(key), do: key
end

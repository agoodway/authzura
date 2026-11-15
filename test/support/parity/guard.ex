defmodule Authzura.Parity.Guard do
  @moduledoc """
  Refuses to run the parity suite's destructive setup against the wrong
  target.

  The suite migrates the database, truncates its fixture tables
  (`TRUNCATE ... CASCADE`) and replaces Hasura's whole metadata. Neither
  URL has a default (`localhost:5432` and `localhost:8080` may well be
  another application's): `db_url/0` and `Authzura.Parity.Hasura.url/0`
  raise when `AUTHZURA_PARITY_DB_URL` or `AUTHZURA_PARITY_HASURA_URL` is
  unset, before anything is contacted. Then both targets are checked:

    * `database/2` - the database named in the URL must be exactly
      `authzura_parity`
    * `metadata/3` - Hasura's current metadata must look like the fixture's
      own (or a fresh Hasura's):
      - exactly one source, `default`, whose connection is
        `from_env: HASURA_GRAPHQL_DATABASE_URL`, the one the fixture
        metadata uses, so replacing the metadata cannot move the source to
        another database
      - tracking nothing but fixture tables, with no event triggers and no
        functions, native queries or logical models
      - no actions, remote schemas, cron triggers, query collections, REST
        endpoints or inherited roles: the fixture has none, so any of them
        means another application's Hasura
    * `source_database/3` - the database that environment variable
      actually reaches (asked through `run_sql`, since the metadata cannot
      tell) must be the parity URL's. Only database names are compared:
      the host is each side's own view of the server (a compose service
      name for Hasura, `localhost` for the suite).

  Setting `AUTHZURA_PARITY_CONFIRM_DESTRUCTIVE=1` (`confirmed?/0`) skips
  every check, for a deliberately chosen target with another name.

  `check!/2` runs them all against the live targets; every suite that
  writes to them (`Authzura.ParityCase`, the randomized differential and
  its replay) calls it before touching anything.
  """

  alias Authzura.Parity.Hasura

  @database "authzura_parity"
  @source "default"
  @connection %{"from_env" => "HASURA_GRAPHQL_DATABASE_URL"}

  # Lists the fixture never has, with the tag each entry is refused under:
  # top-level ones, and ones of the `default` source.
  @foreign_lists [
    {"actions", :action},
    {"remote_schemas", :remote_schema},
    {"cron_triggers", :cron_trigger},
    {"query_collections", :query_collection},
    {"rest_endpoints", :rest_endpoint},
    {"inherited_roles", :inherited_role}
  ]

  @foreign_source_lists [
    {"functions", :function},
    {"native_queries", :native_query},
    {"logical_models", :logical_model}
  ]

  @typedoc "Why a metadata document is refused, one entry per finding."
  @type refusal ::
          {:source, String.t()}
          | {:missing_source, String.t()}
          | {:source_connection, String.t()}
          | {String.t(), String.t()}
          | {atom(), term()}
          | {:event_trigger, {String.t(), String.t()}, String.t()}
          | {:source_database, String.t(), String.t()}

  @doc "The parity database URL, `AUTHZURA_PARITY_DB_URL`; raises when unset."
  @spec db_url() :: String.t()
  def db_url, do: env!("AUTHZURA_PARITY_DB_URL")

  @doc """
  The value of the environment variable `name`; raises with how to set it
  when it is unset or empty. The parity targets have no defaults.
  """
  @spec env!(String.t()) :: String.t()
  def env!(name) do
    case System.get_env(name) do
      value when value not in [nil, ""] ->
        value

      _unset ->
        raise ArgumentError,
              "#{name} is not set: the parity and differential suites have no default " <>
                "target. Export AUTHZURA_PARITY_DB_URL and AUTHZURA_PARITY_HASURA_URL " <>
                "(see the Security guide's \"Running parity tests\")"
    end
  end

  @doc """
  Waits for Hasura, then checks `db_url`, Hasura's current metadata
  against `fixture_tables` and the database Hasura's `default` source
  reaches (each skipped when `confirmed?/0`). Raises on any refusal.
  """
  @spec check!(String.t(), [{String.t(), String.t()}]) :: :ok
  def check!(db_url, fixture_tables) do
    confirmed? = confirmed?()

    :ok = Hasura.await_healthy()
    :ok = database(db_url, confirmed?)
    {:ok, current} = Hasura.export_metadata()
    :ok = metadata(current, fixture_tables, confirmed?)
    :ok = live_source_database(db_url, confirmed?)
  end

  # The metadata check requires the `default` source and its connection
  # from Hasura's environment, which only Hasura can resolve: ask it which
  # database that reaches.
  defp live_source_database(_db_url, true = _confirmed?), do: :ok

  defp live_source_database(db_url, false) do
    {:ok, database} = Hasura.source_database(@source)
    source_database(database, db_url, false)
  end

  @doc "Whether `AUTHZURA_PARITY_CONFIRM_DESTRUCTIVE=1` is set."
  @spec confirmed?() :: boolean()
  def confirmed?, do: System.get_env("AUTHZURA_PARITY_CONFIRM_DESTRUCTIVE") == "1"

  @doc "`:ok` when `url` names the `authzura_parity` database, or when `confirmed?`."
  @spec database(String.t(), boolean()) :: :ok | {:error, {:refused_database, String.t() | nil}}
  def database(_url, true), do: :ok

  def database(url, false) when is_binary(url) do
    case URI.parse(url) do
      %URI{path: "/" <> @database} -> :ok
      %URI{path: path} -> {:error, {:refused_database, path}}
    end
  end

  @doc """
  `:ok` when `metadata` (Hasura's exported metadata) passes the checks in
  the moduledoc against `fixture_tables`, or when `confirmed?`.
  """
  @spec metadata(map(), [{String.t(), String.t()}], boolean()) ::
          :ok | {:error, {:refused_metadata, [refusal()]}}
  def metadata(_metadata, _fixture_tables, true), do: :ok

  def metadata(%{} = metadata, fixture_tables, false) do
    sources = Map.get(metadata, "sources", [])

    (default_source(sources) ++
       Enum.flat_map(sources, &foreign_source(&1, MapSet.new(fixture_tables))) ++
       Enum.flat_map(@foreign_lists, &foreign_list(metadata, &1)))
    |> verdict()
  end

  @doc """
  `:ok` when `database`, the one Hasura's `default` source is connected to,
  is the database of `db_url`, or when `confirmed?`.
  """
  @spec source_database(String.t(), String.t(), boolean()) ::
          :ok | {:error, {:refused_metadata, [refusal()]}}
  def source_database(_database, _db_url, true), do: :ok

  def source_database(database, db_url, false) when is_binary(database) and is_binary(db_url) do
    case URI.parse(db_url) do
      %URI{path: "/" <> ^database} -> :ok
      %URI{} -> verdict([{:source_database, @source, database}])
    end
  end

  defp default_source(sources),
    do: sources |> Enum.any?(&match?(%{"name" => @source}, &1)) |> missing_source()

  defp missing_source(true = _present?), do: []
  defp missing_source(false), do: [{:missing_source, @source}]

  defp foreign_source(%{"name" => @source} = source, fixture) do
    tables = Map.get(source, "tables", [])

    connection(source) ++
      Enum.reject(Enum.map(tables, &table_ref/1), &MapSet.member?(fixture, &1)) ++
      Enum.flat_map(tables, &event_triggers/1) ++
      Enum.flat_map(@foreign_source_lists, &foreign_list(source, &1))
  end

  defp foreign_source(%{"name" => name}, _fixture), do: [{:source, name}]

  # The connection itself is never echoed: a literal URL holds a password.
  defp connection(source) do
    case get_in(source, ["configuration", "connection_info", "database_url"]) do
      @connection -> []
      _other -> [{:source_connection, @source}]
    end
  end

  defp event_triggers(%{"event_triggers" => [_ | _] = triggers} = entry),
    do: Enum.map(triggers, &{:event_trigger, table_ref(entry), Map.get(&1, "name")})

  defp event_triggers(_entry), do: []

  defp foreign_list(%{} = container, {key, tag}),
    do: container |> Map.get(key, []) |> Enum.map(&{tag, entry_name(&1)})

  # Entries name themselves under different keys.
  defp entry_name(%{"name" => name}), do: name
  defp entry_name(%{"role_name" => name}), do: name
  defp entry_name(%{"root_field_name" => name}), do: name
  defp entry_name(%{"function" => function}), do: table_ref(%{"table" => function})
  defp entry_name(_entry), do: nil

  defp table_ref(%{"table" => %{"name" => name} = table}),
    do: {Map.get(table, "schema", "public"), name}

  defp table_ref(%{"table" => name}), do: {"public", name}

  defp verdict([]), do: :ok
  defp verdict(foreign), do: {:error, {:refused_metadata, foreign}}
end

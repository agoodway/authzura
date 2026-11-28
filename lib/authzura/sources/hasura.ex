defmodule Authzura.Sources.Hasura do
  @moduledoc """
  Loads select permissions and function execute grants from Hasura v2 metadata in `hdb_catalog`.

  The catalog is only ever read. Options:

    * `:repo` - the repo holding `hdb_catalog.hdb_metadata` (default under an instance: its repo)
    * `:source_name` - the Hasura source (default `"default"`)
    * `:max_retries` - retries when the source changes during a load (default 3)

  The instance sets `:data_repo` (the repo holding the data tables) to its
  own `:repo` and `:adapter` to its own `:adapter`, overwriting any value
  given here.

  Only `postgres` sources are supported; any other `kind` fails the load with
  a `:deny` diagnostic naming it.

  `load/1` returns the translated snapshot; like every source's, it is
  validated by the Store (`Authzura.Validator`) before it is published.

  ## Coherence

  The snapshot's version is `{{resource_version, digest}, fingerprint}`,
  where `digest` is the `md5` of the metadata document, computed in SQL: a
  document replaced without moving `resource_version` (a restore, a
  blue/green switch, a manual edit) is a new version too. When both repos
  are the same, one `REPEATABLE READ, READ ONLY` transaction reads the
  metadata and introspects, so the pair is consistent. When they differ, the
  metadata and the data are read in separate such transactions, and the full
  version is re-read outside both. If it changed, the load retries up to
  `:max_retries` times and then fails with `{:error, :unstable_source}`.
  """

  @behaviour Authzura.Source

  alias Authzura.Adapters.Postgres
  alias Authzura.AST
  alias Authzura.Model.{Diagnostic, Snapshot}
  alias Authzura.Sources.Hasura.{BoolExp, Metadata}

  @metadata_sql "SELECT metadata::jsonb, resource_version, md5(metadata::text) FROM hdb_catalog.hdb_metadata ORDER BY resource_version DESC LIMIT 1"

  @version_sql """
  WITH m AS (
    SELECT metadata::jsonb AS md, resource_version, md5(metadata::text) AS digest
    FROM hdb_catalog.hdb_metadata
    ORDER BY resource_version DESC
    LIMIT 1
  ), src AS (
    SELECT e.s
    FROM m,
         jsonb_array_elements(CASE WHEN jsonb_typeof(m.md -> 'sources') = 'array'
                                   THEN m.md -> 'sources' ELSE '[]'::jsonb END)
           WITH ORDINALITY AS e(s, n)
    WHERE jsonb_typeof(e.s) = 'object' AND e.s -> 'name' = to_jsonb($1::text)
    ORDER BY e.n
    LIMIT 1
  ), refs AS (
    SELECT sch, nm, min(n) AS pos
    FROM (
      SELECT t.n,
             CASE WHEN jsonb_typeof(t.tb) = 'string' THEN 'public'
                  ELSE coalesce(t.tb ->> 'schema', 'public') END AS sch,
             CASE WHEN jsonb_typeof(t.tb) = 'string' THEN t.tb #>> '{}'
                  ELSE t.tb ->> 'name' END AS nm
      FROM src,
           jsonb_array_elements(CASE WHEN jsonb_typeof(src.s -> 'tables') = 'array'
                                     THEN src.s -> 'tables' ELSE '[]'::jsonb END)
             WITH ORDINALITY AS x(t0, n),
           LATERAL (SELECT x.n, x.t0 -> 'table' AS tb) t
      WHERE jsonb_typeof(x.t0) = 'object'
        AND (jsonb_typeof(t.tb) = 'string'
             OR (jsonb_typeof(t.tb) = 'object'
                 AND jsonb_typeof(t.tb -> 'name') = 'string'
                 AND coalesce(jsonb_typeof(t.tb -> 'schema'), 'string') = 'string'))
    ) r
    GROUP BY sch, nm
  )
  SELECT m.resource_version,
         m.digest,
         EXISTS (SELECT 1 FROM src),
         coalesce((SELECT s -> 'kind' FROM src), '"postgres"'::jsonb),
         coalesce((SELECT array_agg(sch ORDER BY pos) FROM refs), '{}'::text[]),
         coalesce((SELECT array_agg(nm ORDER BY pos) FROM refs), '{}'::text[])
  FROM m
  """

  @resource_version_sql "SELECT resource_version, md5(metadata::text) FROM hdb_catalog.hdb_metadata ORDER BY resource_version DESC LIMIT 1"

  @isolation "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"

  @typedoc "`resource_version` and the `md5` of the metadata document."
  @type metadata_version :: {integer(), String.t()}

  @typedoc "A snapshot version: the metadata's version and the tables' fingerprint."
  @type version :: {metadata_version(), binary()}

  @typep config :: %{
           repo: module(),
           data_repo: module(),
           source_name: String.t(),
           adapter: module(),
           max_retries: non_neg_integer(),
           before_verify: (non_neg_integer() -> term()) | nil
         }

  @doc "Loads a coherent snapshot. See the moduledoc."
  @impl true
  @spec load(keyword()) :: {:ok, Snapshot.t()} | {:error, term()}
  def load(opts), do: opts |> config() |> attempt(0)

  @doc "Reads `{{resource_version, digest}, fingerprint}` outside any transaction, with no cache."
  @spec version(keyword()) :: {:ok, version()} | {:error, term()}
  def version(opts), do: opts |> config() |> current_version()

  @doc """
  Reads `{{resource_version, digest}, fingerprint}` outside any
  transaction, like `version/1`, and returns the cache for the next call.

  The tracked tables (what the fingerprint covers) change only with the
  metadata. So the cache is `{{resource_version, digest}, kind, tables}`:
  while the pair is unchanged, a poll reads only it and the fingerprint,
  never parsing the metadata document. The fingerprint is
  computed on every call, since it is what detects DDL. Errors return no
  cache.
  """
  @impl true
  @spec version(keyword(), cache) :: {:ok, version(), cache} | {:error, term()}
        when cache: {metadata_version(), term(), [{String.t(), String.t()}]} | nil
  def version(opts, cache), do: opts |> config() |> cached_version(cache)

  @doc "Parses an input filter with `BoolExp.parse/3` in `:input` mode."
  @impl true
  @spec parse_input(map(), map()) :: {:ok, AST.t()} | {:error, [{[String.t()], term()}]}
  def parse_input(json, ctx), do: BoolExp.parse(json, :input, ctx)

  @spec config(keyword()) :: config()
  defp config(opts) do
    repo = Keyword.fetch!(opts, :repo)

    %{
      repo: repo,
      data_repo: Keyword.get(opts, :data_repo, repo),
      source_name: Keyword.get(opts, :source_name, "default"),
      adapter: Keyword.get(opts, :adapter, Postgres),
      max_retries: Keyword.get(opts, :max_retries, 3),
      before_verify: Keyword.get(opts, :before_verify)
    }
  end

  # Loading.

  defp attempt(%{max_retries: max} = cfg, retry) when retry <= max do
    with {:ok, loaded} <- read(cfg),
         :ok <- verify(cfg, loaded, retry) do
      {:ok, snapshot(cfg, loaded)}
    else
      :changed -> attempt(cfg, retry + 1)
      {:error, _reason} = error -> error
    end
  end

  defp attempt(_cfg, _retry), do: {:error, :unstable_source}

  defp read(%{repo: repo, data_repo: repo} = cfg) do
    repo
    |> read_only(fn ->
      with {:ok, metadata} <- read_metadata(repo), do: read_data(cfg, metadata)
    end)
    |> with_metadata()
  end

  defp read(%{repo: repo, data_repo: data_repo} = cfg) do
    with {:ok, metadata} <- read_only(repo, fn -> read_metadata(repo) end) do
      data_repo
      |> read_only(fn -> read_data(cfg, metadata) end)
      |> with_metadata()
    end
  end

  # Pairs what the data read returned with the metadata it was read for.
  defp with_metadata({:ok, {metadata, data}}), do: {:ok, Map.put(data, :metadata, metadata)}
  defp with_metadata({:error, _reason} = error), do: error

  # A single transaction is coherent by itself; separate repos need a re-read.
  defp verify(%{repo: repo, data_repo: repo}, _loaded, _retry), do: :ok

  defp verify(
         %{before_verify: hook} = cfg,
         %{metadata: {_json, resource_version}, fingerprint: fingerprint},
         retry
       ) do
    run_hook(hook, retry)

    case current_version(cfg) do
      {:ok, {^resource_version, ^fingerprint}} -> :ok
      {:ok, _other} -> :changed
      {:error, _reason} = error -> error
    end
  end

  defp run_hook(nil, _retry), do: :ok
  defp run_hook(hook, retry), do: hook.(retry)

  defp read_data(%{data_repo: data_repo, adapter: adapter, source_name: name}, {json, version}) do
    with {:ok, refs} <- tracked_tables(json, name),
         {:ok, tables, fks} <- adapter.introspect(data_repo, refs),
         {:ok, fingerprint} <- adapter.fingerprint(data_repo, refs) do
      {:ok, {{json, version}, %{tables: tables, fks: fks, fingerprint: fingerprint}}}
    end
  end

  defp tracked_tables(json, name) do
    with {:ok, kind} <- Metadata.source_kind(json, name),
         :ok <- ensure_postgres(kind, name) do
      Metadata.tracked_tables(json, name)
    end
  end

  defp ensure_postgres("postgres", _name), do: :ok

  defp ensure_postgres(kind, name),
    do: {:error, {:unsupported_source_kind, kind, [unsupported_kind(name, kind)]}}

  defp unsupported_kind(name, kind),
    do: %Diagnostic{severity: :deny, path: [name], reason: {:unsupported_source_kind, kind}}

  defp snapshot(%{source_name: name, adapter: adapter}, %{
         metadata: {json, resource_version},
         tables: tables,
         fks: fks,
         fingerprint: fingerprint
       }),
       do: build_snapshot(json, name, tables, fks, adapter, {resource_version, fingerprint})

  @doc false
  # The snapshot assembly shared by `load/1` and the sandboxed test fixture:
  # relationship, permission and function-grant translation over
  # already-introspected tables. Validation is the Store's job (`Authzura.Validator`).
  @spec build_snapshot(term(), String.t(), Metadata.tables(), [map()], module(), term()) ::
          Snapshot.t()
  def build_snapshot(json, source_name, tables, fks, adapter, version) do
    {tables, relationship_diagnostics} =
      Metadata.resolve_relationships(json, source_name, tables, fks)

    {permissions, diagnostics} = Metadata.translate(json, source_name, tables, adapter)
    {functions, function_diagnostics} = Metadata.translate_functions(json, source_name)

    %Snapshot{
      version: version,
      tables: tables,
      permissions: Map.new(permissions, &{{&1.role, &1.table, &1.operation}, &1}),
      functions: functions,
      diagnostics: relationship_diagnostics ++ diagnostics ++ function_diagnostics
    }
  end

  # Version.

  defp current_version(cfg) do
    with {:ok, version, _cache} <- cached_version(cfg, nil), do: {:ok, version}
  end

  defp cached_version(%{data_repo: data_repo, adapter: adapter, source_name: name} = cfg, cache) do
    with {:ok, {resource_version, kind, refs} = source} <- version_source(cfg, cache),
         :ok <- ensure_postgres(kind, name),
         {:ok, fingerprint} <- adapter.fingerprint(data_repo, refs) do
      {:ok, {resource_version, fingerprint}, source}
    end
  end

  # A cache for the current resource_version is reused; anything else reads
  # the tracked tables again.
  defp version_source(%{repo: repo, source_name: name}, nil), do: read_version_source(repo, name)

  defp version_source(%{repo: repo, source_name: name}, {cached, _kind, _refs} = cache) do
    case read_resource_version(repo) do
      {:ok, ^cached} -> {:ok, cache}
      {:ok, _other} -> read_version_source(repo, name)
      {:error, _reason} = error -> error
    end
  end

  defp read_resource_version(repo),
    do:
      query_row(repo, @resource_version_sql, [], fn [resource_version, digest] ->
        {:ok, {resource_version, digest}}
      end)

  # Reads only what the version needs, one statement, with the tracked tables
  # extracted in SQL. It must mirror BoolExp.table_ref/1: a bare string is a
  # table in "public", and a missing schema defaults to "public".
  defp read_version_source(repo, source_name),
    do: query_row(repo, @version_sql, [source_name], &version_source_row/1)

  defp version_source_row([resource_version, digest, true, kind, schemas, names]),
    do: {:ok, {{resource_version, digest}, kind, Enum.zip(schemas, names)}}

  defp version_source_row([_resource_version, _digest, false | _rest]),
    do: {:error, :source_not_found}

  # Reads.

  defp read_metadata(repo),
    do:
      query_row(repo, @metadata_sql, [], fn [json, resource_version, digest] ->
        {:ok, {json, {resource_version, digest}}}
      end)

  # One catalog row decoded by `decode`; no row means no metadata.
  defp query_row(repo, sql, params, decode) do
    case repo.query(sql, params) do
      {:ok, %{rows: [row]}} -> decode.(row)
      {:ok, %{rows: []}} -> {:error, :no_metadata}
      {:error, _reason} = error -> error
    end
  end

  defp read_only(repo, fun) do
    repo.transaction(fn ->
      with {:ok, _result} <- repo.query(@isolation),
           {:ok, value} <- fun.() do
        value
      else
        {:error, reason} -> repo.rollback(reason)
      end
    end)
  end
end

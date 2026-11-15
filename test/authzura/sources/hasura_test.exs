defmodule Authzura.Sources.HasuraTest do
  use Authzura.CommittedCase

  alias Authzura.Adapters.Postgres
  alias Authzura.{HasuraFixture, TelemetryHelper}
  alias Authzura.Model.{Diagnostic, Snapshot}
  alias Authzura.Sources.Hasura
  alias Authzura.Sources.Hasura.Metadata

  @articles %{
    table: {"public", "articles"},
    select_permissions: [%{role: "user", permission: %{columns: "*", filter: %{}}}]
  }

  defp put(tables, version \\ 1, opts \\ []) do
    HasuraFixture.put_metadata!(Repo, HasuraFixture.metadata(tables, opts), version)
  end

  defp put_source(tables, key, value) do
    metadata = put_in(HasuraFixture.metadata(tables), ["sources", Access.at(0), key], value)
    HasuraFixture.put_metadata!(Repo, metadata)
  end

  test "loads a snapshot with ok permissions and a version" do
    put([@articles], 7)

    assert {:ok, %Snapshot{version: {{7, _digest}, fingerprint}} = snapshot} =
             Hasura.load(repo: Repo)

    assert is_binary(fingerprint)
    assert %{status: :ok} = snapshot.permissions[{"user", {"public", "articles"}, :select}]
    assert is_map_key(snapshot.tables, {"public", "articles"})
  end

  test "a tracked table missing from Postgres is denied with a diagnostic" do
    put([@articles, %{@articles | table: {"public", "ghosts"}}])

    assert {:ok, snapshot} = Hasura.load(repo: Repo)

    assert {:denied, [_ | _]} =
             snapshot.permissions[{"user", {"public", "ghosts"}, :select}].status

    assert Enum.any?(
             snapshot.diagnostics,
             &(&1.severity == :deny and &1.table == {"public", "ghosts"})
           )
  end

  test "version/1 follows resource_version" do
    put([@articles], 1)
    assert {:ok, {{1, _digest}, fingerprint}} = Hasura.version(repo: Repo)

    put([@articles], 2)
    assert {:ok, {{2, _digest}, ^fingerprint}} = Hasura.version(repo: Repo)
  end

  test "version/1 changes when the metadata is replaced at the same resource_version" do
    put([@articles], 5)
    assert {:ok, {{5, digest}, fingerprint}} = Hasura.version(repo: Repo)

    put([%{@articles | select_permissions: []}], 5)
    assert {:ok, {{5, other}, ^fingerprint}} = Hasura.version(repo: Repo)
    assert other != digest
  end

  describe "version/2 with a cache" do
    @repo_query [:authzura, :test, :repo, :query]
    @comments %{@articles | table: {"public", "comments"}}

    setup %{test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
    end

    defp version_queries, do: TelemetryHelper.received_queries(@repo_query)

    defp parses_metadata?(queries), do: Enum.any?(queries, &(&1 =~ "metadata::jsonb"))

    test "an unchanged resource_version reuses the tracked tables" do
      put([@articles], 1)

      assert {:ok, {{1, _digest}, fingerprint} = version, cache} =
               Hasura.version([repo: Repo], nil)

      assert {:ok, version} == Hasura.version(repo: Repo)
      assert parses_metadata?(version_queries())

      assert {:ok, {{1, _digest}, ^fingerprint}, ^cache} = Hasura.version([repo: Repo], cache)
      refute parses_metadata?(version_queries())
    end

    test "a new resource_version re-reads them" do
      put([@articles], 1)
      {:ok, {{1, _digest}, before}, cache} = Hasura.version([repo: Repo], nil)
      version_queries()

      put([@articles, @comments], 2)
      assert {:ok, {{2, _digest}, fingerprint}, cache} = Hasura.version([repo: Repo], cache)
      assert parses_metadata?(version_queries())
      assert fingerprint != before
      assert {:ok, {{2, _digest}, ^fingerprint}} = Hasura.version(repo: Repo)

      assert {:ok, {{2, _digest}, ^fingerprint}, ^cache} = Hasura.version([repo: Repo], cache)
    end

    test "DDL still changes the version while the tables are cached" do
      put([@articles], 3)
      {:ok, {{3, _digest}, before}, cache} = Hasura.version([repo: Repo], nil)

      Repo.query!("ALTER TABLE public.articles ADD COLUMN cached_drift int")

      on_exit(fn ->
        Repo.query!("ALTER TABLE public.articles DROP COLUMN IF EXISTS cached_drift")
      end)

      assert {:ok, {{3, _digest}, after_ddl}, _cache} = Hasura.version([repo: Repo], cache)
      assert after_ddl != before
    end

    test "errors are not cached" do
      put([@articles], 1)
      {:ok, _version, cache} = Hasura.version([repo: Repo], nil)

      assert {:error, :source_not_found} =
               Hasura.version([repo: Repo, source_name: "other"], nil)

      Repo.query!("DELETE FROM hdb_catalog.hdb_metadata")
      assert {:error, :no_metadata} = Hasura.version([repo: Repo], cache)
    end
  end

  test "a missing hdb_catalog is an error" do
    put([@articles])
    Repo.query!("ALTER SCHEMA hdb_catalog RENAME TO hdb_catalog_hidden")
    on_exit(fn -> Repo.query!("ALTER SCHEMA hdb_catalog_hidden RENAME TO hdb_catalog") end)

    assert {:error, _} = Hasura.load(repo: Repo)
    assert {:error, _} = Hasura.version(repo: Repo)
  end

  test "an empty catalog is an error" do
    Repo.query!("DELETE FROM hdb_catalog.hdb_metadata")
    assert {:error, :no_metadata} = Hasura.load(repo: Repo)
  end

  test "an unknown source is an error" do
    put([@articles])
    assert {:error, :source_not_found} = Hasura.load(repo: Repo, source_name: "other")
  end

  test "a non-postgres source fails with a deny diagnostic naming the kind" do
    metadata = HasuraFixture.metadata([@articles])
    metadata = put_in(metadata, ["sources", Access.at(0), "kind"], "mssql")
    HasuraFixture.put_metadata!(Repo, metadata)

    assert {:error,
            {:unsupported_source_kind, "mssql", [%Diagnostic{severity: :deny} = diagnostic]}} =
             Hasura.load(repo: Repo)

    assert diagnostic.reason == {:unsupported_source_kind, "mssql"}
  end

  test "version/1 changes with DDL while resource_version is unchanged" do
    put([@articles], 3)
    {:ok, {{3, _digest}, before}} = Hasura.version(repo: Repo)

    Repo.query!("ALTER TABLE public.articles ADD COLUMN ver_drift int")
    on_exit(fn -> Repo.query!("ALTER TABLE public.articles DROP COLUMN IF EXISTS ver_drift") end)

    assert {:ok, {{3, _digest}, after_ddl}} = Hasura.version(repo: Repo)
    assert after_ddl != before
  end

  test "a source without a kind loads as postgres" do
    metadata = HasuraFixture.metadata([@articles])
    metadata = update_in(metadata, ["sources", Access.at(0)], &Map.delete(&1, "kind"))
    HasuraFixture.put_metadata!(Repo, metadata)

    assert {:ok, snapshot} = Hasura.load(repo: Repo)
    assert %{status: :ok} = snapshot.permissions[{"user", {"public", "articles"}, :select}]
    assert {:ok, snapshot.version} == Hasura.version(repo: Repo)
  end

  test "an explicit null kind is denied" do
    put_source([@articles], "kind", nil)

    assert {:error, {:unsupported_source_kind, nil, [%Diagnostic{severity: :deny}]}} =
             Hasura.load(repo: Repo)

    assert {:error, {:unsupported_source_kind, nil, _}} = Hasura.version(repo: Repo)
  end

  test "version/1 on a non-postgres source returns the unsupported-kind error" do
    put_source([@articles], "kind", "mssql")

    assert {:error, {:unsupported_source_kind, "mssql", [%Diagnostic{severity: :deny}]}} =
             Hasura.version(repo: Repo)
  end

  test "version/1 on an unknown source is an error" do
    put([@articles])
    assert {:error, :source_not_found} = Hasura.version(repo: Repo, source_name: "other")
  end

  test "version/1 matches the snapshot for every table entry shape" do
    metadata =
      HasuraFixture.metadata([
        @articles,
        %{table: "organizations"},
        %{table: %{name: "users"}},
        %{table: %{schema: "audit", name: "users"}},
        %{table: %{schema: "audit", name: "users"}},
        %{table: %{schema: nil, name: "comments"}},
        %{table: 5},
        %{no_table: true}
      ])

    HasuraFixture.put_metadata!(Repo, metadata, 4)
    {:ok, refs} = Metadata.tracked_tables(metadata, "default")
    {:ok, fingerprint} = Postgres.fingerprint(Repo, refs)

    assert {:ok, %Snapshot{version: {{4, _digest}, ^fingerprint}}} = Hasura.load(repo: Repo)
    assert {:ok, {{4, _digest}, ^fingerprint}} = Hasura.version(repo: Repo)
  end

  test "load/1 inside an open transaction returns an error" do
    put([@articles])

    Repo.transaction(fn ->
      Repo.query!("SELECT 1")
      send(self(), {:result, Hasura.load(repo: Repo)})
    end)

    assert_received {:result, {:error, _}}
  end

  test "same-repo load/1 runs in one REPEATABLE READ, READ ONLY transaction" do
    put([@articles])

    TelemetryHelper.forward!("load-tx-#{inspect(self())}", [[:authzura, :test, :repo, :query]],
      caller_only: true
    )

    assert {:ok, _snapshot} = Hasura.load(repo: Repo)
    queries = drain()

    assert ["begin", "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY" | rest] =
             queries

    assert List.last(queries) == "commit"
    assert Enum.count(queries, &(&1 in ["begin", "commit"])) == 2
    assert [_, _, _ | _] = rest
  end

  test "parse_input/2 parses in input mode" do
    put([@articles])
    {:ok, snapshot} = Hasura.load(repo: Repo)
    table = snapshot.tables[{"public", "articles"}]

    ctx = %{
      table: table,
      tables: snapshot.tables,
      adapter: Postgres,
      limits: %{binding_depth: 15, syntactic_depth: 8, nodes: 100}
    }

    assert {:ok, {:compare, "id", :eq, {:literal, 1}}} =
             Hasura.parse_input(%{"id" => %{"_eq" => 1}}, ctx)
  end

  defp drain(acc \\ []) do
    receive do
      {:telemetry, _event, %{query: query}} -> drain([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

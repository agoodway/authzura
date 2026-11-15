defmodule Authzura.Parity.GuardTest do
  @moduledoc """
  The parity suite's destructive-target guards. Pure checks, so they run in
  the default suite without Hasura.
  """

  use ExUnit.Case, async: true

  alias Authzura.Parity.{Fixture, Guard}

  @fixture Fixture.tracked()
  @db_url "postgres://postgres:postgres@localhost:55432/authzura_parity"
  @from_env %{"from_env" => "HASURA_GRAPHQL_DATABASE_URL"}

  defp source(name, tables, extra \\ %{}, database_url \\ @from_env),
    do:
      Map.merge(
        %{
          "name" => name,
          "kind" => "postgres",
          "tables" => Enum.map(tables, &table/1),
          "configuration" => %{"connection_info" => %{"database_url" => database_url}}
        },
        extra
      )

  defp table(%{"table" => _table} = entry), do: entry
  defp table(table), do: %{"table" => table}

  defp default(tables \\ [], extra \\ %{}), do: source("default", tables, extra)

  defp metadata(metadata), do: Guard.metadata(metadata, @fixture, false)

  describe "database/2" do
    test "accepts only the authzura_parity database" do
      assert :ok = Guard.database("postgres://u:p@localhost:55432/authzura_parity", false)

      for url <- [
            "postgres://u:p@localhost:5432/app_dev",
            "postgres://u:p@localhost:5432/authzura_parity_copy",
            "postgres://u:p@localhost:5432/",
            "postgres://u:p@localhost:5432"
          ] do
        assert {:error, {:refused_database, _path}} = Guard.database(url, false)
      end
    end

    test "confirmation overrides it" do
      assert :ok = Guard.database("postgres://u:p@localhost:5432/app_dev", true)
    end
  end

  describe "metadata/3" do
    test "accepts a fresh Hasura and the fixture's own metadata" do
      assert :ok = metadata(%{"version" => 3, "sources" => [default()]})

      tables = [%{"schema" => "public", "name" => "articles"}, "users"]
      assert :ok = metadata(%{"sources" => [default(tables)]})

      empty = Map.new(~w(actions remote_schemas cron_triggers inherited_roles), &{&1, []})
      empty_lists = %{"functions" => [], "native_queries" => [], "logical_models" => []}
      assert :ok = metadata(Map.put(empty, "sources", [default([], empty_lists)]))

      assert :ok = metadata(%{"sources" => [Fixture.metadata() |> Map.fetch!("sources") |> hd()]})
    end

    test "refuses another source, no default source, or a table outside the fixture" do
      assert {:error, {:refused_metadata, [source: "crm"]}} =
               metadata(%{"sources" => [default(), source("crm", [])]})

      assert {:error, {:refused_metadata, [missing_source: "default"]}} =
               metadata(%{"version" => 3})

      foreign = %{"sources" => [default([%{"schema" => "public", "name" => "invoices"}])]}
      assert {:error, {:refused_metadata, [{"public", "invoices"}]}} = metadata(foreign)
    end

    test "refuses top-level lists the fixture never has" do
      assert {:error, {:refused_metadata, refused}} =
               metadata(%{
                 "sources" => [default()],
                 "actions" => [%{"name" => "login"}],
                 "remote_schemas" => [%{"name" => "countries"}],
                 "cron_triggers" => [%{"name" => "nightly"}],
                 "query_collections" => [%{"name" => "allowed-queries"}],
                 "rest_endpoints" => [%{"name" => "get_user"}],
                 "inherited_roles" => [%{"role_name" => "staff"}]
               })

      assert refused == [
               action: "login",
               remote_schema: "countries",
               cron_trigger: "nightly",
               query_collection: "allowed-queries",
               rest_endpoint: "get_user",
               inherited_role: "staff"
             ]
    end

    test "refuses functions, native queries and logical models of the source" do
      lists = %{
        "functions" => [%{"function" => %{"schema" => "public", "name" => "search"}}],
        "native_queries" => [%{"root_field_name" => "report"}],
        "logical_models" => [%{"name" => "report_row"}]
      }

      assert metadata(%{"sources" => [default([], lists)]}) ==
               {:error,
                {:refused_metadata,
                 [
                   function: {"public", "search"},
                   native_query: "report",
                   logical_model: "report_row"
                 ]}}
    end

    test "refuses event triggers, even on a fixture table" do
      articles = %{"schema" => "public", "name" => "articles"}
      entry = %{"table" => articles, "event_triggers" => [%{"name" => "on_insert"}]}

      assert metadata(%{"sources" => [default([entry])]}) ==
               {:error,
                {:refused_metadata, [{:event_trigger, {"public", "articles"}, "on_insert"}]}}
    end

    # Replacing the metadata keeps the fixture's `from_env` connection, so
    # any other connection could move the source to another database.
    test "refuses any connection but the fixture's from_env one, without echoing it" do
      for url <- [
            "postgres://u:secret@postgres:5432/authzura_parity",
            %{"from_env" => "APP_DATABASE_URL"},
            %{"connection_parameters" => %{"database" => "authzura_parity"}}
          ] do
        assert metadata(%{"sources" => [source("default", [], %{}, url)]}) ==
                 {:error, {:refused_metadata, [source_connection: "default"]}},
               inspect(url)
      end
    end

    test "confirmation overrides it" do
      other = %{"sources" => [source("crm", [])], "actions" => [%{"name" => "login"}]}
      assert :ok = Guard.metadata(other, @fixture, true)
    end
  end

  describe "source_database/3" do
    test "accepts only the parity URL's database" do
      assert :ok = Guard.source_database("authzura_parity", @db_url, false)

      assert Guard.source_database("app_dev", @db_url, false) ==
               {:error, {:refused_metadata, [{:source_database, "default", "app_dev"}]}}

      assert :ok = Guard.source_database("app_dev", @db_url, true)
    end
  end
end

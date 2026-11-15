defmodule Authzura.Bench.ReportTest do
  use ExUnit.Case, async: true

  alias Authzura.Bench.Report

  @moduletag :tmp_dir

  @sentinel "ZQX_sentinel_7f3a"

  test "the report and results never contain session values or SQL", %{tmp_dir: dir} do
    results = results_with(session: @sentinel, sql: "select '#{@sentinel}'", plan_expr: @sentinel)

    assert :ok = Report.write!(results, dir: dir)

    written = File.read!(Path.join(dir, "REPORT.md")) <> File.read!(Path.join(dir, "small.json"))
    refute written =~ @sentinel
    assert written =~ "flat-tenant"
    assert written =~ "articles_org_id_index"
  end

  test "the report has the header, one row per scenario, fairness and known gaps", %{
    tmp_dir: dir
  } do
    :ok = Report.write!(results_with([]), dir: dir)
    report = File.read!(Path.join(dir, "REPORT.md"))

    assert report =~ "small"
    assert report =~ "v2.51.6"
    assert report =~ "`hasura/graphql-engine:v2.51.6 (derived)`"
    assert report =~ "20261114"
    assert report =~ ~r/\| flat-tenant \| 1\.10 \(0\.02\) \|/
    assert report =~ ~r/\| page-1000 \| aborted: verdict_mismatch/
    assert report =~ "## Fairness"
    assert report =~ "one request at a time"
    assert report =~ "## Known gaps"
  end

  test "a second mode and an --only run merge into the same results", %{tmp_dir: dir} do
    :ok = Report.write!(results_with([]), dir: dir)
    :ok = Report.write!(%{results_with([]) | mode: :read_only_connection}, dir: dir)
    :ok = Report.write!(%{results_with([]) | mode: :input_index_pushdown}, dir: dir)
    only = %{results_with([]) | scenarios: [hd(results_with([]).scenarios)]}
    :ok = Report.write!(only, dir: dir)

    %{"modes" => modes} = dir |> Path.join("small.json") |> File.read!() |> Jason.decode!()

    assert modes |> Map.keys() |> Enum.sort() ==
             ["default", "input_index_pushdown", "read_only_connection"]

    assert [_flat, _page] = modes["default"]["scenarios"]
    assert File.read!(Path.join(dir, "REPORT.md")) =~ "input_index_pushdown"
  end

  defp results_with(opts) do
    secret = Keyword.get(opts, :session, "17")
    sql = Keyword.get(opts, :sql, "SELECT 1")
    expr = Keyword.get(opts, :plan_expr, "(org_id = 3)")

    %{
      scale: :small,
      mode: :default,
      seed: 20_261_114,
      date: ~D[2026-11-14],
      versions: %{postgres: "18.1", hasura: "v2.51.6"},
      scenarios: [
        %{
          id: "flat-tenant",
          preload_levels: 0,
          auth: {:jwt, %{"x-hasura-user-id" => secret}, "tenant"},
          session: %{"x-hasura-user-id" => secret},
          sql: sql,
          status: :measured,
          db_time: %{ratio: 1.1, cv: 0.02, verdict: :pass, hasura_ms: 1.0, authzura_ms: 1.1},
          statements: %{
            hasura: %{counts: %{data: 1.0}, db_ms: 1.0, queries: [sql]},
            authzura: %{counts: %{data: 1.0, transaction_control: 3.0}, db_ms: 1.1}
          },
          plans: %{
            hasura: [plan(expr, sql)],
            authzura: [plan(expr, sql)]
          },
          targets: %{
            db_time: :pass,
            data_statements: :pass,
            transaction_control: :not_applicable,
            indexes: :pass,
            buffers: :pass
          },
          verdict: :pass
        },
        %{
          id: "page-1000",
          preload_levels: 0,
          status: {:aborted, {:verdict, {:mismatch, "row #{secret} differs: #{sql}"}}}
        }
      ]
    }
  end

  defp plan(expr, sql),
    do: %{
      table_scans: [{"articles", :index, "articles_org_id_index"}],
      shared_buffers: 12,
      filter: expr,
      sql: sql
    }
end

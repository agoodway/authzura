defmodule Authzura.Bench.Report do
  @moduledoc """
  Writes the benchmark's results: `bench/results/<scale>.json` and
  `bench/REPORT.md`. Test harness only.

  Nothing measured goes out as is. `sanitize/1` copies only whitelisted
  fields into plain maps: ids, numbers, verdicts, scan kinds, and table and
  index names. An aborted scenario's reason becomes its class (an atom's
  name, such as `verdict_mismatch`), never its message. Session values, SQL
  text, bind values and plan expressions have no field to land in, and
  `REPORT.md` is rendered from the sanitized results files only.

  Each `<scale>.json` holds one entry per mode. Writing a mode replaces its
  scenarios by id and keeps the others, so the modes and an `--only`
  rerun accumulate in the same file.
  """

  alias Authzura.Bench.{Measure, Scenarios}

  @scales ["small", "large"]
  @modes ["default", "read_only_connection", "input_index_pushdown"]
  @targets ~w(db_time data_statements transaction_control indexes buffers)a
  @images %{postgres: "postgres", hasura: "hasura/graphql-engine"}

  @doc """
  Writes `results` (`%{scale, mode, seed, date, versions, scenarios}`).

  Options: `:dir` writes both files to that directory instead of `bench/`
  and `bench/results/`.
  """
  @spec write!(map(), keyword()) :: :ok
  def write!(%{scale: scale} = results, opts \\ []) do
    {report_dir, results_dir} = dirs(opts)
    File.mkdir_p!(results_dir)
    path = Path.join(results_dir, "#{scale}.json")

    document = path |> read_results() |> merge(sanitize(results))
    File.write!(path, Jason.encode_to_iodata!(document, pretty: true))

    documents =
      for scale <- @scales,
          file = Path.join(results_dir, "#{scale}.json"),
          File.exists?(file),
          do: read_results(file)

    File.mkdir_p!(report_dir)
    File.write!(Path.join(report_dir, "REPORT.md"), render(documents))
  end

  @doc """
  The JSON-safe, value-free form of `results`: one results document with
  the run's mode as its only entry.
  """
  @spec sanitize(map()) :: map()
  def sanitize(%{scale: scale, mode: mode, seed: seed, date: date, versions: versions} = results) do
    %{
      "scale" => to_string(scale),
      "seed" => seed,
      "images" => images(versions),
      "modes" => %{
        to_string(mode) => %{
          "date" => Date.to_iso8601(date),
          "scenarios" => Enum.map(results.scenarios, &scenario/1)
        }
      }
    }
  end

  defp dirs(opts) do
    case Keyword.fetch(opts, :dir) do
      {:ok, dir} -> {dir, dir}
      :error -> {"bench", Path.join("bench", "results")}
    end
  end

  defp read_results(path) do
    case File.read(path) do
      {:ok, json} -> Jason.decode!(json)
      {:error, :enoent} -> %{}
    end
  end

  defp merge(existing, %{"modes" => new_modes} = new) do
    modes =
      Map.merge(Map.get(existing, "modes", %{}), new_modes, fn _mode, old, latest ->
        %{latest | "scenarios" => merge_scenarios(old["scenarios"], latest["scenarios"])}
      end)

    Map.put(new, "modes", modes)
  end

  defp merge_scenarios(old, latest) do
    by_id = Map.new(old ++ latest, &{&1["id"], &1})
    order = Scenarios.ids()

    by_id
    |> Map.values()
    |> Enum.sort_by(&(Enum.find_index(order, fn id -> id == &1["id"] end) || length(order)))
  end

  # The image tags come from the environment (`Authzura.Bench.Env.image/1`);
  # without them they are derived from the server versions and say so.
  defp images(%{postgres: postgres, hasura: hasura} = versions) do
    [major | _] = String.split(postgres, ".")

    %{
      "postgres" => image(versions[:postgres_image], "#{@images.postgres}:#{major}"),
      "postgres_version" => postgres,
      "hasura" => image(versions[:hasura_image], "#{@images.hasura}:#{hasura}"),
      "hasura_version" => hasura
    }
  end

  defp image(nil, derived), do: "#{derived} (derived)"
  defp image(tag, _derived) when is_binary(tag), do: tag

  defp scenario(%{
         status: :measured,
         id: id,
         preload_levels: levels,
         db_time: db_time,
         statements: statements,
         plans: plans,
         targets: targets,
         verdict: verdict
       }) do
    %{
      "id" => id,
      "preload_levels" => levels,
      "status" => "measured",
      "db_time" => %{
        "ratio" => db_time.ratio,
        "cv" => db_time.cv,
        "hasura_ms" => db_time.hasura_ms,
        "authzura_ms" => db_time.authzura_ms
      },
      "statements" => %{
        "hasura" => statement_counts(statements.hasura),
        "authzura" => statement_counts(statements.authzura)
      },
      "plans" => %{
        "hasura" => Enum.map(plans.hasura, &plan/1),
        "authzura" => Enum.map(plans.authzura, &plan/1)
      },
      "buffer_ratio" => Measure.buffer_ratio(plans),
      "targets" =>
        Map.new(@targets, &{Atom.to_string(&1), Atom.to_string(Map.fetch!(targets, &1))}),
      "verdict" => Atom.to_string(verdict)
    }
  end

  defp scenario(%{id: id, preload_levels: levels, status: {:aborted, reason}}),
    do: %{
      "id" => id,
      "preload_levels" => levels,
      "status" => "aborted",
      "reason" => reason_class(reason)
    }

  defp statement_counts(%{counts: counts, db_ms: db_ms}),
    do: %{
      "data" => Map.get(counts, :data, 0.0),
      "transaction_control" => Map.get(counts, :transaction_control, 0.0),
      "setup" => Map.get(counts, :setup, 0.0),
      "db_ms" => db_ms
    }

  defp plan(%{table_scans: scans, shared_buffers: buffers}),
    do: %{
      "table_scans" =>
        for({table, kind, index} <- scans, do: [table, Atom.to_string(kind), index]),
      "shared_buffers" => buffers
    }

  # The class of a gate reason, never its payload.
  defp reason_class(reason) when is_atom(reason), do: Atom.to_string(reason)

  defp reason_class({tag, inner}) when is_atom(tag) and is_tuple(inner),
    do: "#{tag}_#{reason_class(inner)}"

  defp reason_class({tag, inner}) when is_atom(tag) and is_atom(inner), do: "#{tag}_#{inner}"

  defp reason_class(reason) when is_tuple(reason) and is_atom(elem(reason, 0)),
    do: Atom.to_string(elem(reason, 0))

  defp reason_class(_reason), do: "other"

  ## Rendering, from sanitized documents only

  defp render(documents) do
    Enum.join(
      [
        """
        # Benchmark report

        Generated by `mix authzura.bench` (test harness only; see `bench/README.md`).
        Each scenario runs the same read on both engines after the parity gate.
        Ratios are Authzura over Hasura. Targets: DB time ≤ 1.25×, data
        statements exactly `1 + L`, an index wherever Hasura uses one on that
        table, shared buffers ≤ 1.5×; in `read_only_connection` mode, no
        transaction-control statement for reads without preloads (`L = 0`).
        """
        | Enum.flat_map(documents, &render_document/1)
      ] ++ [fairness(), known_gaps(documents)],
      "\n"
    )
  end

  defp render_document(%{"scale" => scale, "seed" => seed, "images" => images, "modes" => modes}) do
    for mode <- @modes, %{"date" => date, "scenarios" => scenarios} <- [Map.get(modes, mode)] do
      """
      ## #{scale} / #{mode}

      Date #{date} · scale `#{scale}` · mode `#{mode}` · seed #{seed} ·
      `#{images["postgres"]}` (#{images["postgres_version"]}) ·
      `#{images["hasura"]}` (#{images["hasura_version"]})

      | Scenario | DB ratio (CV) | DB ms H / A | Data H / A (target) | Txn ctl H / A | Setup A | Index | Buffers | Verdict |
      |---|---|---|---|---|---|---|---|---|
      #{Enum.map_join(scenarios, "\n", &row/1)}

      Plan shape (`EXPLAIN (ANALYZE, BUFFERS)`, scans in plan order; shared buffers hit + read):

      | Scenario | Hasura scans | Authzura scans | Buffers H / A |
      |---|---|---|---|
      #{scenarios |> Enum.filter(&(&1["status"] == "measured")) |> Enum.map_join("\n", &plan_row/1)}
      """
    end
  end

  defp row(%{"status" => "aborted", "id" => id, "reason" => reason}),
    do: "| #{id} | aborted: #{reason} | | | | | | | aborted |"

  defp row(%{"id" => id, "preload_levels" => levels} = scenario) do
    %{"db_time" => db, "statements" => %{"hasura" => h, "authzura" => a}, "targets" => t} =
      scenario

    cells = [
      id,
      "#{fixed(db["ratio"])} (#{fixed(db["cv"])})",
      "#{fixed(db["hasura_ms"], 3)} / #{fixed(db["authzura_ms"], 3)}",
      "#{count(h["data"])} / #{count(a["data"])} (#{1 + levels})",
      "#{count(h["transaction_control"])} / #{count(a["transaction_control"])}#{txn_note(t)}",
      count(a["setup"]),
      t["indexes"],
      "#{ratio(scenario["buffer_ratio"])} #{t["buffers"]}",
      verdict(scenario)
    ]

    "| " <> Enum.join(cells, " | ") <> " |"
  end

  defp plan_row(%{"id" => id, "plans" => %{"hasura" => h, "authzura" => a}}),
    do: "| #{id} | #{scans(h)} | #{scans(a)} | #{buffers(h)} / #{buffers(a)} |"

  defp scans(plans) do
    plans
    |> Enum.with_index(1)
    |> Enum.map_join("; ", fn {%{"table_scans" => scans}, i} ->
      "#{i}: " <> Enum.map_join(scans, ", ", &scan/1)
    end)
  end

  defp scan([table, "seq", nil]), do: "#{table} seq"
  defp scan([table, kind, index]), do: "#{table} #{kind} `#{index}`"

  defp buffers(plans), do: Enum.sum_by(plans, & &1["shared_buffers"])

  defp txn_note(%{"transaction_control" => "not_applicable"}), do: ""
  defp txn_note(%{"transaction_control" => verdict}), do: " #{verdict}"

  defp verdict(%{"verdict" => "pass"}), do: "pass"

  defp verdict(%{"verdict" => verdict, "targets" => targets}) do
    "#{verdict} (#{failing(targets)})"
  end

  defp fairness do
    """
    ## Fairness

    Hasura's figures include its HTTP, GraphQL and in-database JSON work
    (`json_agg`, `row_to_json`), which an Ecto caller does in Elixir instead.
    Only database work is compared: `pg_stat_statements` planning plus
    execution time and statement counts for the `authzura_bench` database,
    with each engine measured alone after a `pg_stat_statements_reset()`.
    Planning time is counted on both sides. Hasura's `hdb_catalog` work and
    the statistics and type-catalog reads are excluded. Transaction control
    includes `BEGIN`, `COMMIT`, `SET TRANSACTION` and savepoints, but
    `pg_stat_statements` records Authzura's named (cached) `SET TRANSACTION`
    only on its first use per connection, so after warm-up its count and
    time are missing (it still runs on every read); setup is
    `set_config`, `SET LOCAL`, `current_setting` and Authzura's pattern
    pre-check. Plans come from one `EXPLAIN (ANALYZE, BUFFERS)` per data
    statement after the timed runs. Authzura's statements are explained as
    the steady state runs them: prepared, executed five times, then
    explained as `EXECUTE`, so a statement Postgres switched to a generic
    plan shows that plan. Hasura's come from `/v1/graphql/explain`, which
    inlines the values Hasura would otherwise bind, so they are custom
    plans. The timed figures are those of the plans each engine actually
    ran.
    Pools: Authzura reads through Ecto pools of 10 connections (both bench
    repos); the bench Hasura keeps its default of up to 50 connections per
    source. Each engine is sent one request at a time, after 6 warm-up
    requests per connection of its pool, so every connection is past
    Postgres's switch to generic plans; the DB-time CV is that of the paired
    per-repetition ratios.
    Only database work is compared, so "less DB time" is not "faster":
    Authzura's Ecto decoding and preload stitching and every round trip
    (four or more per Authzura read) are outside these figures, while
    Hasura's JSON building happens in SQL and is inside them.
    """
  end

  defp known_gaps(documents) do
    gaps =
      for %{"scale" => scale, "modes" => modes} <- documents,
          mode <- @modes,
          %{"scenarios" => scenarios} <- [Map.get(modes, mode)],
          %{"id" => id} = scenario <- scenarios,
          gap = gap(scenario),
          do: "- `#{id}` (#{scale}, #{mode}): #{gap}"

    """
    ## Known gaps

    Every failing, inconclusive or aborted target, triaged in `bench/TRIAGE.md`.
    `transaction_control` is not applicable to preload scenarios: they keep
    their `REPEATABLE READ, READ ONLY` transaction by design.

    #{if gaps == [], do: "None.", else: Enum.join(gaps, "\n")}
    """
  end

  defp gap(%{"status" => "aborted", "reason" => reason}), do: "aborted (#{reason})"
  defp gap(%{"verdict" => "pass"}), do: nil

  defp gap(%{"targets" => targets}), do: failing(targets)

  defp failing(targets) do
    targets
    |> Enum.filter(fn {_name, value} -> value in ["fail", "inconclusive"] end)
    |> Enum.map(fn {name, value} -> "#{name} #{value}" end)
    |> Enum.sort()
    |> Enum.join(", ")
  end

  defp fixed(value, decimals \\ 2), do: :erlang.float_to_binary(value / 1, decimals: decimals)

  defp ratio(nil), do: "n/a"
  defp ratio(value), do: fixed(value) <> "×"

  defp count(value) when value == trunc(value), do: Integer.to_string(trunc(value))
  defp count(value), do: fixed(value)
end

defmodule Mix.Tasks.Authzura.Bench.Micro do
  @shortdoc "Micro-benchmarks Authzura's in-process overhead (test harness only)"

  @moduledoc """
  Benchee micro-benchmarks of Authzura's own work (scope build, filter
  compile, input parse, preload-tree validation, overhead over the
  database), against a committed baseline. On demand only, never in CI.

      MIX_ENV=bench mix authzura.bench.micro [--record | --check]

  Needs the seeded `small` dataset (`mix authzura.bench.seed --scale small`)
  and `AUTHZURA_BENCH_DB_URL`; it does not use Hasura.

    * no flag: runs and prints the jobs
    * `--record`: also writes `bench/baselines/micro.json` (numbers and the
      environment: OTP, Elixir minor, OS family and architecture, CPU model,
      schedulers; times are whole ns)
    * `--check`: compares with that baseline and exits non-zero when a job
      regressed, meaning all 3 of its runs are more than 20% slower than the
      baseline median. A baseline from another environment (the warning names
      the differing keys), a malformed one, or none, only warns: a different
      machine's numbers prove nothing. Jobs in the baseline but not the run,
      or the reverse, are warned about. The two `overhead` jobs are
      report-only: printed and recorded, never gating.

  See `Authzura.Bench.Micro` for the jobs.
  """

  use Mix.Task

  alias Authzura.Bench
  alias Authzura.Bench.Micro

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: [record: :boolean, check: :boolean])

    if opts[:record] && opts[:check], do: Mix.raise("use --record or --check, not both")

    Mix.Task.run("app.start")
    {:ok, _pid} = Supervisor.start_link(Bench.children(), strategy: :one_for_one)
    await_ready!()

    result = Micro.run()
    print(result)

    cond do
      opts[:record] -> record(result)
      opts[:check] -> check(result)
      true -> :ok
    end
  end

  defp await_ready!(attempts \\ 50)
  defp await_ready!(0), do: Mix.raise("the bench instance never became ready")

  defp await_ready!(attempts) do
    if Authzura.status(Bench.instance()).ready? do
      :ok
    else
      Process.sleep(100)
      await_ready!(attempts - 1)
    end
  end

  defp print(%{env: env, jobs: jobs}) do
    info("env #{inspect(env)}")

    for {name, %{median_ns: median, runs: runs}} <- Enum.sort(jobs) do
      label = if Micro.report_only?(name), do: " (report-only)", else: ""

      info(
        "#{String.pad_trailing(name <> label, 44)} median #{format(median)}  runs #{Enum.map_join(runs, ", ", &format/1)}"
      )
    end
  end

  defp format(ns) when ns >= 1_000_000, do: "#{Float.round(ns / 1_000_000, 2)}ms"
  defp format(ns) when ns >= 1_000, do: "#{Float.round(ns / 1_000, 2)}us"
  defp format(ns), do: "#{Float.round(ns / 1, 1)}ns"

  defp record(result) do
    path = Micro.baseline_path()
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, Micro.encode(result))
    info("baseline written to #{path}")
  end

  defp check(result) do
    path = Micro.baseline_path()

    case Micro.read_baseline() do
      nil -> skip("no usable baseline at #{path} (missing or malformed)")
      baseline -> compare(result, baseline, path)
    end
  end

  defp compare(result, baseline, path) do
    drift = Micro.job_drift(result, baseline)

    if drift.missing != [],
      do: warn("jobs in the baseline but not run: #{Enum.join(drift.missing, ", ")}")

    if drift.extra != [],
      do: warn("jobs run but not in the baseline: #{Enum.join(drift.extra, ", ")}")

    case Micro.regressions(result, baseline) do
      {:ok, []} ->
        info("no regressions against #{path}")

      {:ok, jobs} ->
        Mix.raise("regressed against #{path}: #{Enum.join(jobs, ", ")}")

      {:skipped, :env_mismatch} ->
        skip(
          "environment differs from the baseline's (#{Enum.join(Micro.env_diff(result, baseline), ", ")})"
        )
    end
  end

  defp skip(reason), do: warn("check skipped: #{reason}; record a baseline here with --record")

  defp info(message), do: Mix.shell().info(message)
  defp warn(message), do: Mix.shell().error("warning: " <> message)
end

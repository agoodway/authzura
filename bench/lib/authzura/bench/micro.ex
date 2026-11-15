defmodule Authzura.Bench.Micro do
  @moduledoc """
  Micro-benchmarks of Authzura's in-process overhead, with a committed
  baseline. Test harness only; run on demand, never in CI.

  Jobs (the benchmark's `small` dataset, the bench instance):

    * `scope-flat-tenant` and `scope-rel-filter-3hop`: `Authzura.scope/3` on
      those scenarios' roles (permission lookup and filter compile)
    * `input-filter`: `Authzura.scope_input/4` on the `input-filter` request
      (input parse, validation and compile; its filter has no pattern, so no
      statement runs)
    * `preload-nested-3`: `Authzura.Preload.Tree.validate/5` on that
      scenario's tree
    * `overhead` and `overhead-preload-nested-3`: `[:authzura, :execute]`
      minus the summed `[:authzura, :query]` durations of one real read of
      `flat-tenant` and `preload-nested-3`: the time outside Authzura's own
      statements. `BEGIN` and `COMMIT` have no query span, so it includes
      their round trips and the pool checkout as well as the library's
      work, and it depends on the environment (network, host, container)

  Every job runs exactly 3 times (the regression rule needs all 3 runs; there
  is no option to change it). The benchmark jobs go through Benchee, each run
  reporting its median; `overhead` is sampled from the telemetry spans,
  because Benchee can only time a whole function (`:samples` reads per run).
  A job's `median_ns` is the median of its run medians, in whole ns.

  The two `overhead` jobs are **report-only**: they are run, printed and
  recorded, but never gate. They include pool checkout and the database's
  own jitter, and swing far more than 20% between runs.

  The baseline (`bench/baselines/micro.json`) holds numbers and the
  environment only (OTP, Elixir minor, OS family and architecture, CPU model,
  schedulers): no value, session or SQL. A regression is a gating job whose
  runs *all* exceed the baseline median by more than the tolerance; a
  baseline from another environment, a malformed one, or none, is skipped.
  """

  alias Authzura.Bench
  alias Authzura.Bench.{Scenarios, Stats}
  alias Authzura.Parity.Runner
  alias Authzura.Preload.Tree
  alias Authzura.{Store, Util}

  @type env :: %{
          otp: String.t(),
          elixir: String.t(),
          os: String.t(),
          cpu_model: String.t(),
          schedulers: pos_integer()
        }
  @type job :: %{median_ns: integer(), runs: [integer()]}
  @type result :: %{env: env(), jobs: %{String.t() => job()}}

  @baseline_path "bench/baselines/micro.json"
  @runs 3
  @report_only ~w(overhead overhead-preload-nested-3)
  @samples 200
  @warmup_samples 20
  @tolerance 0.20
  @env_keys ~w(otp elixir os cpu_model schedulers)a

  @doc "Where the committed baseline lives, relative to the project root."
  @spec baseline_path() :: String.t()
  def baseline_path, do: @baseline_path

  @doc """
  Runs every job #{@runs} times. Options: `:time` and `:warmup` (Benchee
  seconds, default 1 and 0.5) and `:samples` (overhead reads per run,
  default #{@samples}). The bench instance must be started
  (`Authzura.Bench.children/0`) and the `small` dataset seeded.
  """
  @spec run(keyword()) :: result()
  def run(opts \\ []) do
    instance = Bench.instance()
    fixtures = fixtures(instance)

    benchmarks = for _run <- 1..@runs, do: benchee(benchmark_jobs(fixtures), opts)

    overheads =
      Map.new(overhead_jobs(fixtures), fn {name, read} ->
        {name, for(_run <- 1..@runs, do: overhead(read, Keyword.get(opts, :samples, @samples)))}
      end)

    jobs(benchmarks, overheads)
  end

  defp jobs(benchmarks, overheads) do
    sampled = Enum.flat_map(overheads, fn {name, runs} -> Enum.map(runs, &{name, &1}) end)

    by_name =
      benchmarks
      |> Enum.flat_map(& &1)
      |> Enum.concat(sampled)
      |> Enum.group_by(fn {name, _ns} -> name end, fn {_name, ns} -> round(ns) end)

    %{env: env(), jobs: Map.new(by_name, fn {name, runs} -> {name, job(runs)} end)}
  end

  defp job(runs), do: %{median_ns: runs |> Stats.median() |> round(), runs: runs}

  @doc "The environment a baseline is only valid for."
  @spec env() :: env()
  def env do
    %{
      otp: to_string(:erlang.system_info(:otp_release)),
      elixir: elixir_minor(),
      os: os(),
      cpu_model: cpu_model(),
      schedulers: System.schedulers_online()
    }
  end

  defp elixir_minor do
    %Version{major: major, minor: minor} = Version.parse!(System.version())
    "#{major}.#{minor}"
  end

  # The OS family and the CPU architecture; not the kernel version.
  defp os do
    {family, name} = :os.type()
    [arch | _rest] = "#{:erlang.system_info(:system_architecture)}" |> String.split("-")
    "#{family}-#{name}-#{arch}"
  end

  defp cpu_model do
    case :os.type() do
      {:unix, :darwin} -> command("sysctl", ~w(-n machdep.cpu.brand_string))
      _other -> linux_cpu_model()
    end
  end

  defp linux_cpu_model do
    with {:ok, text} <- File.read("/proc/cpuinfo"),
         [_, model] <- Regex.run(~r/^model name\s*:\s*(.+)$/m, text) do
      String.trim(model)
    else
      _unknown -> "unknown"
    end
  end

  defp command(program, args) do
    case System.cmd(program, args, stderr_to_stdout: true) do
      {output, 0} -> String.trim(output)
      _failure -> "unknown"
    end
  rescue
    ErlangError -> "unknown"
  end

  @doc """
  Which gating jobs of `current` regressed against `baseline`: those whose
  runs all exceed `baseline_median * (1 + tolerance)`. Report-only jobs
  (`report_only?/1`) never count. `{:skipped, :env_mismatch}` when the
  baseline was recorded in another environment (`env_diff/2` names the
  keys). A missing or malformed baseline never gets here: `read_baseline/1`
  returns `nil` for it, and the check is skipped before comparing.
  """
  @spec regressions(result(), result(), float()) ::
          {:ok, [String.t()]} | {:skipped, :env_mismatch}
  def regressions(current, baseline, tolerance \\ @tolerance)

  def regressions(%{env: env, jobs: jobs}, %{env: baseline_env, jobs: baseline_jobs}, tolerance) do
    if env == baseline_env do
      {:ok, regressed(jobs, baseline_jobs, tolerance)}
    else
      {:skipped, :env_mismatch}
    end
  end

  defp regressed(jobs, baseline_jobs, tolerance) do
    jobs
    |> Enum.reject(fn {name, _job} -> report_only?(name) end)
    |> Enum.filter(fn {name, %{runs: runs}} ->
      case baseline_jobs do
        %{^name => %{median_ns: base}} -> Enum.all?(runs, &(&1 > base * (1 + tolerance)))
        _unrecorded -> false
      end
    end)
    |> Enum.map(fn {name, _job} -> name end)
    |> Enum.sort()
  end

  @doc "Whether job `name` is reported and recorded but never gates."
  @spec report_only?(String.t()) :: boolean()
  def report_only?(name), do: name in @report_only

  @doc "The environment keys on which `current` and `baseline` differ."
  @spec env_diff(result(), result()) :: [atom()]
  def env_diff(%{env: env}, %{env: baseline_env}),
    do: Enum.filter(@env_keys, &(env[&1] != baseline_env[&1]))

  @doc "The jobs only in the baseline (`:missing`) and only in the run (`:extra`)."
  @spec job_drift(result(), result()) :: %{missing: [String.t()], extra: [String.t()]}
  def job_drift(%{jobs: jobs}, %{jobs: baseline_jobs}) do
    %{
      missing: baseline_jobs |> Map.keys() |> Enum.reject(&is_map_key(jobs, &1)) |> Enum.sort(),
      extra: jobs |> Map.keys() |> Enum.reject(&is_map_key(baseline_jobs, &1)) |> Enum.sort()
    }
  end

  @doc "The baseline file's JSON for `result`: environment and numbers only."
  @spec encode(result()) :: String.t()
  def encode(%{env: env, jobs: jobs}) do
    Jason.encode!(%{"env" => env, "jobs" => jobs}, pretty: true) <> "\n"
  end

  @doc "The result a baseline file's JSON holds; `nil` when it is not one. Never raises."
  @spec decode(String.t()) :: result() | nil
  def decode(json) do
    with {:ok, %{"env" => env, "jobs" => jobs}} <- Jason.decode(json),
         {:ok, env} <- decode_env(env),
         {:ok, jobs} <- decode_jobs(jobs) do
      %{env: env, jobs: jobs}
    else
      _invalid -> nil
    end
  end

  defp decode_env(%{
         "otp" => otp,
         "elixir" => elixir,
         "os" => os,
         "cpu_model" => cpu_model,
         "schedulers" => schedulers
       })
       when is_binary(otp) and is_binary(elixir) and is_binary(os) and is_binary(cpu_model) and
              is_integer(schedulers),
       do:
         {:ok, %{otp: otp, elixir: elixir, os: os, cpu_model: cpu_model, schedulers: schedulers}}

  defp decode_env(_env), do: :error

  defp decode_jobs(jobs) when is_map(jobs) do
    with {:ok, decoded} <- jobs |> Map.to_list() |> Util.map_ok(&decode_named_job/1),
         do: {:ok, Map.new(decoded)}
  end

  defp decode_jobs(_jobs), do: :error

  defp decode_named_job({name, job}) do
    with {:ok, job} <- decode_job(job), do: {:ok, {name, job}}
  end

  defp decode_job(%{"median_ns" => median, "runs" => runs})
       when is_number(median) and is_list(runs) do
    case Enum.reject(runs, &is_number/1) do
      [] -> {:ok, %{median_ns: median, runs: runs}}
      _malformed -> :error
    end
  end

  defp decode_job(_job), do: :error

  @doc "Reads the committed baseline; `nil` when missing or unreadable."
  @spec read_baseline(String.t()) :: result() | nil
  def read_baseline(path \\ @baseline_path) do
    case File.read(path) do
      {:ok, json} -> decode(json)
      {:error, _reason} -> nil
    end
  end

  # What every job needs, built once: sessions, queries, the generation.
  defp fixtures(instance) do
    scenarios = Map.new(Scenarios.all(), &{&1.id, &1})
    {:ok, generation} = Store.current(instance)

    %{
      instance: instance,
      generation: generation,
      scenarios: scenarios,
      sessions: Map.new(scenarios, fn {id, %{auth: auth}} -> {id, session!(auth)} end)
    }
  end

  defp session!(auth) do
    {:ok, session} = Runner.session(auth)
    session
  end

  defp benchmark_jobs(%{instance: instance, generation: generation} = fixtures) do
    flat = fixtures.scenarios["flat-tenant"]
    deep = fixtures.scenarios["rel-filter-3hop"]
    input = fixtures.scenarios["input-filter"]
    nested = fixtures.scenarios["preload-nested-3"]
    options = &[instance: instance, columns: &1.read.columns]

    %{
      "scope-flat-tenant" => fn ->
        {:ok, _query} =
          Authzura.scope(Runner.query(flat.read), fixtures.sessions[flat.id], options.(flat))
      end,
      "scope-rel-filter-3hop" => fn ->
        {:ok, _query} =
          Authzura.scope(Runner.query(deep.read), fixtures.sessions[deep.id], options.(deep))
      end,
      "input-filter" => fn ->
        {:ok, _query} =
          Authzura.scope_input(
            elem(input.read.table, 1),
            fixtures.sessions[input.id],
            Runner.input(input.read),
            instance: instance
          )
      end,
      "preload-nested-3" => fn ->
        {:ok, _nodes} =
          Tree.validate(
            Runner.preload(nested.read.relationships),
            nested.read.table,
            fixtures.sessions[nested.id],
            generation,
            %{depth: 3, nodes: 8}
          )
      end
    }
  end

  defp overhead_jobs(fixtures) do
    %{
      "overhead" => scenario_run(fixtures, "flat-tenant"),
      "overhead-preload-nested-3" => scenario_run(fixtures, "preload-nested-3")
    }
  end

  defp scenario_run(fixtures, id) do
    %{read: read} = fixtures.scenarios[id]
    session = fixtures.sessions[id]
    instance = fixtures.instance

    fn ->
      {:ok, _rows} =
        Authzura.all(Runner.query(read), session,
          instance: instance,
          columns: read.columns,
          preload: Runner.preload(read.relationships)
        )
    end
  end

  # One Benchee run of every job: its median (ns) per job name.
  defp benchee(jobs, opts) do
    suite =
      Benchee.run(jobs,
        time: Keyword.get(opts, :time, 1),
        warmup: Keyword.get(opts, :warmup, 0.5),
        memory_time: 0,
        formatters: [],
        print: [benchmarking: false, configuration: false, fast_warning: false]
      )

    Map.new(suite.scenarios, fn scenario ->
      {scenario.name, scenario.run_time_data.statistics.median}
    end)
  end

  # The median of `samples` reads' `[:authzura, :execute]` duration minus the
  # summed `[:authzura, :query]` durations, in ns.
  defp overhead(run, samples) do
    handler = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach_many(
        handler,
        [[:authzura, :execute, :stop], [:authzura, :query, :stop]],
        &__MODULE__.forward/4,
        self()
      )

    try do
      Enum.each(1..@warmup_samples, fn _ -> sample(run) end)
      1..samples |> Enum.map(fn _ -> sample(run) end) |> Stats.median()
    after
      :telemetry.detach(handler)
    end
  end

  defp sample(run) do
    flush()
    run.()
    {executes, queries} = collect([], [])
    Enum.sum(executes) - Enum.sum(queries)
  end

  defp collect(executes, queries) do
    receive do
      {:span, :execute, ns} -> collect([ns | executes], queries)
      {:span, :query, ns} -> collect(executes, [ns | queries])
    after
      0 -> {executes, queries}
    end
  end

  defp flush do
    receive do
      {:span, _event, _ns} -> flush()
    after
      0 -> :ok
    end
  end

  @doc false
  @spec forward([atom()], map(), map(), pid()) :: :ok
  def forward([:authzura, event, :stop], %{duration: duration}, _metadata, pid) do
    send(pid, {:span, event, System.convert_time_unit(duration, :native, :nanosecond)})
    :ok
  end
end

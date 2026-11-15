defmodule Mix.Tasks.Authzura.Bench do
  @shortdoc "Benchmarks Authzura against Hasura on the bench database (test harness only)"

  @moduledoc """
  Measures every benchmark scenario on both engines and writes
  `bench/results/<scale>.json` and `bench/REPORT.md`.

      MIX_ENV=bench mix authzura.bench [--scale small|large]
        [--mode default|read_only_connection|input_index_pushdown] [--only id,id] [--check]
        [--requests N] [--warmup N] [--no-compose]

  In order:

    1. seeds the database (`mix authzura.bench.seed`) when its row counts
       are not those of `--scale` (default `small`); `--no-compose` is
       passed on
    2. starts the bench instance of `--mode` (default `default`; see
       `Authzura.Bench`) and runs the parity gate (`Authzura.Bench.Gate`):
       a scenario that fails it is aborted by id and not measured
    3. measures each remaining scenario (`Authzura.Bench.Measure`):
       statements and DB time over 5 alternating repetitions of
       `--requests` requests per engine (default 200), each after
       `--warmup` warm-up requests (default 6 per connection of the
       engine's pool), then plans
    4. writes the results (`Authzura.Bench.Report`)

  `--only` takes scenario ids. With `--check`, the task fails when a target
  fails or a scenario is aborted; an inconclusive DB time is listed but
  does not fail. `--requests` and `--warmup` must be positive integers. The image tags in
  the report come from `AUTHZURA_BENCH_POSTGRES_IMAGE` and
  `AUTHZURA_BENCH_HASURA_IMAGE` when set (else they are derived from the
  server versions and labelled so). The server must have
  `pg_stat_statements.track_planning` and `.track_utility` on. The targets come from `AUTHZURA_BENCH_DB_URL`,
  `AUTHZURA_BENCH_HASURA_URL` and `AUTHZURA_BENCH_ADMIN_SECRET`; none has a
  default (see `bench/README.md`).
  """

  use Mix.Task

  alias Authzura.Bench
  alias Authzura.Bench.{Dataset, Env, Gate, Hasura, Measure, Repo, Report, Scenarios}

  @switches [
    scale: :string,
    mode: :string,
    only: :string,
    check: :boolean,
    requests: :integer,
    warmup: :integer,
    no_compose: :boolean
  ]
  @scales %{"small" => :small, "large" => :large}
  @modes %{
    "default" => :default,
    "read_only_connection" => :read_only_connection,
    "input_index_pushdown" => :input_index_pushdown
  }
  @mode_usage "--mode default|read_only_connection|input_index_pushdown"

  @impl Mix.Task
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: @switches)
    scale_name = Keyword.get(opts, :scale, "small")
    scale = pick!(@scales, scale_name, "--scale small|large")

    mode = pick!(@modes, Keyword.get(opts, :mode, "default"), @mode_usage)

    scenarios = scenarios!(opts[:only])
    requests = requests!(Keyword.get(opts, :requests, 200))
    measure_opts = [mode: mode, requests: requests] ++ warmup!(opts[:warmup])

    Mix.Task.run("app.start")
    seed_if_needed!(scale, scale_name, opts)
    {:ok, _supervisor} = Supervisor.start_link(Bench.children(mode), strategy: :one_for_one)
    :ok = Authzura.reload(Bench.instance(mode))
    :ok = Measure.ensure_tracking!()

    {passed, aborted} = Gate.check(scenarios, instance: Bench.instance(mode))
    measured = Enum.map(passed, &measure(&1, measure_opts))

    results = %{
      scale: scale,
      mode: mode,
      seed: Dataset.default_seed(),
      date: Date.utc_today(),
      versions: versions(),
      scenarios: ordered(scenarios, measured, aborted)
    }

    :ok = Report.write!(results)
    Mix.shell().info("wrote bench/REPORT.md and bench/results/#{scale}.json")
    if opts[:check], do: check!(results)
  end

  defp pick!(choices, name, usage) do
    case Map.fetch(choices, name) do
      {:ok, value} -> value
      :error -> Mix.raise("expected #{usage}")
    end
  end

  defp requests!(requests) when is_integer(requests) and requests > 0, do: requests
  defp requests!(_requests), do: Mix.raise("--requests must be a positive integer")

  defp warmup!(nil), do: []
  defp warmup!(warmup) when is_integer(warmup) and warmup > 0, do: [warmup: warmup]
  defp warmup!(_warmup), do: Mix.raise("--warmup must be a positive integer")

  defp scenarios!(nil), do: Scenarios.all()

  defp scenarios!(only) do
    ids = String.split(only, ",", trim: true)

    case ids -- Scenarios.ids() do
      [] -> Enum.filter(Scenarios.all(), &(&1.id in ids))
      unknown -> Mix.raise("unknown scenario ids: #{Enum.join(unknown, ", ")}")
    end
  end

  # The seed task starts its own repo, so this check stops the repo again.
  defp seed_if_needed!(scale, scale_name, opts) do
    {:ok, _pid} = Repo.start_link()
    seeded? = seeded?(scale)
    :ok = Repo.stop()
    seed(seeded?, scale_name, opts)
  end

  defp seed(true, _scale_name, _opts), do: :ok

  defp seed(false, scale_name, opts) do
    Mix.shell().info("seeding #{scale_name}")
    no_compose = if opts[:no_compose], do: ["--no-compose"], else: []
    Mix.Task.run("authzura.bench.seed", ["--scale", scale_name | no_compose])
    :ok = Repo.stop()
  end

  defp seeded?(scale) do
    expected =
      Map.new(Dataset.sizes(scale), fn {table, count} -> {Atom.to_string(table), count} end)

    Dataset.counts(Repo) == expected
  rescue
    _not_ready in [Postgrex.Error, DBConnection.ConnectionError] -> false
  end

  defp measure(%{id: id} = scenario, opts) do
    Mix.shell().info("measuring #{id}")
    Measure.measure(scenario, opts)
  end

  defp ordered(scenarios, measured, aborted) do
    by_id = Map.new(measured, &{&1.id, &1})
    reasons = Map.new(aborted)

    for %{id: id, preload_levels: levels} <- scenarios do
      Map.get_lazy(by_id, id, fn ->
        %{id: id, preload_levels: levels, status: {:aborted, Map.fetch!(reasons, id)}}
      end)
    end
  end

  defp versions do
    %{rows: [[postgres]]} = Repo.query!("SHOW server_version")
    {:ok, hasura} = Hasura.version()
    [postgres | _] = String.split(postgres, " ")

    %{
      postgres: postgres,
      hasura: hasura,
      postgres_image: Env.image(:postgres),
      hasura_image: Env.image(:hasura)
    }
  end

  defp check!(%{scenarios: scenarios}) do
    failing =
      for %{id: id} = scenario <- scenarios, failing?(scenario), do: id

    if failing != [], do: Mix.raise("benchmark targets failed: #{Enum.join(failing, ", ")}")
  end

  defp failing?(%{status: {:aborted, _reason}}), do: true
  defp failing?(%{verdict: :fail}), do: true
  defp failing?(_scenario), do: false
end

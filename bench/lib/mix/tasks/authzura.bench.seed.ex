defmodule Mix.Tasks.Authzura.Bench.Seed do
  @shortdoc "Seeds the benchmark database and its Hasura (test harness only)"

  @moduledoc """
  Prepares the benchmark: the `authzura_bench` database, its seeded
  dataset, and the bench Hasura with the bench permissions.

      MIX_ENV=bench mix authzura.bench.seed --scale small|large [--seed N] [--no-compose]

  In order:

    1. creates the database and `CREATE EXTENSION pg_stat_statements` (the
       server must preload it: `docker-compose.yml` does)
    2. runs the fixture migrations and `priv/bench_migrations`
    3. runs `docker compose --profile bench up -d --wait hasura_bench`
       (skipped with `--no-compose`, for a Hasura you started yourself)
    4. checks the Hasura is the bench one (its source reaches
       `authzura_bench`, and it tracks nothing but the bench tables), loads
       the dataset (`Authzura.Bench.Dataset.load!/3`, in one transaction),
       and runs `VACUUM (ANALYZE)`
    5. replaces the Hasura's metadata with `Authzura.Bench.Metadata.build/0`

  It prints the table sizes and the dataset checksum. The targets come from
  `AUTHZURA_BENCH_DB_URL`, `AUTHZURA_BENCH_HASURA_URL` and
  `AUTHZURA_BENCH_ADMIN_SECRET`; none has a default (see `bench/README.md`).
  Re-running replaces the data and the metadata.
  """

  use Mix.Task

  alias Authzura.Bench.{Dataset, Env, Hasura, Metadata, Repo}
  alias Authzura.Parity.{Fixture, Guard}
  alias Ecto.Adapters.Postgres
  alias Ecto.Migrator

  @scales %{"small" => :small, "large" => :large}
  @bench_migrations "priv/bench_migrations"
  @extension "pg_stat_statements"

  @impl Mix.Task
  def run(args) do
    {opts, _rest} =
      OptionParser.parse!(args, strict: [scale: :string, seed: :integer, no_compose: :boolean])

    scale = scale!(opts[:scale])
    seed = Keyword.get(opts, :seed, Dataset.default_seed())

    Mix.Task.run("app.start")
    _ = Postgres.storage_up(Repo.config())
    {:ok, _pid} = Repo.start_link()

    prepare_database!()
    compose(opts[:no_compose])
    check_hasura!()
    load!(scale, seed)
    replace_metadata!()
  end

  defp compose(true), do: :ok
  defp compose(_start), do: start_hasura!()

  defp scale!(name) when is_map_key(@scales, name), do: Map.fetch!(@scales, name)

  defp scale!(_name), do: Mix.raise("--scale small|large is required")

  defp prepare_database! do
    Repo.query!("CREATE EXTENSION IF NOT EXISTS #{@extension}")
    %{rows: [[libraries]]} = Repo.query!("SHOW shared_preload_libraries")

    if not String.contains?(libraries, @extension),
      do: Mix.raise("the server must preload #{@extension} (shared_preload_libraries)")

    Fixture.migrate!(Repo)

    Migrator.run(Repo, Application.app_dir(:authzura, @bench_migrations), :up,
      all: true,
      log: false
    )
  end

  defp start_hasura! do
    args = ~w(compose --profile bench up -d --wait hasura_bench)

    case System.cmd("docker", args, into: IO.stream(), stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {_output, status} -> Mix.raise("docker #{Enum.join(args, " ")} exited #{status}")
    end
  end

  # The destructive steps follow only when this Hasura is the bench one.
  defp check_hasura! do
    :ok = Hasura.await_healthy()
    {:ok, current} = Hasura.export_metadata()
    {:ok, database} = Hasura.source_database("default")

    with :ok <- Guard.metadata(current, Metadata.tables(), false),
         :ok <- Guard.source_database(database, Env.db_url!(), false) do
      :ok
    else
      {:error, refusal} -> Mix.raise("refusing the bench Hasura: #{inspect(refusal)}")
    end
  end

  defp load!(scale, seed) do
    Dataset.load!(Repo, scale, seed)
    Repo.query!("VACUUM (ANALYZE)", [], timeout: :infinity)

    Mix.shell().info("scale #{scale}, seed #{seed}")
    Mix.shell().info("rows     #{inspect(Dataset.counts(Repo))}")
    Mix.shell().info("checksum #{inspect(Dataset.checksum(Repo))}")
  end

  defp replace_metadata! do
    case Hasura.replace_metadata(Metadata.build()) do
      :ok -> Mix.shell().info("bench metadata applied")
      {:error, reason} -> Mix.raise("replace_metadata failed: #{inspect(reason)}")
    end
  end
end

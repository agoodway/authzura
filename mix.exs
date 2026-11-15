defmodule Authzura.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/agoodway/authzura"

  def project do
    [
      app: :authzura,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      test_load_filters: [&test_file?/1],
      test_ignore_filters: [
        ~r{^test/pgrest_examples/},
        ~r{^test/parity/reviewed_divergences\.exs$}
      ],
      aliases: aliases(),
      test_coverage: [tool: ExCoveralls],

      # Hex
      description: description(),
      package: package(),

      # Dialyzer
      dialyzer: [plt_add_apps: [:mix, :ex_unit]],

      # Docs
      name: "Authzura",
      source_url: @source_url,
      docs: docs()
    ]
  end

  def cli do
    [
      preferred_envs: [
        quality: :test,
        coveralls: :test,
        "coveralls.html": :test,
        "coveralls.json": :test,
        "coveralls.lcov": :test,
        "authzura.bench": :bench,
        "authzura.bench.seed": :bench,
        "authzura.bench.micro": :bench
      ]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(env) when env in [:test, :bench], do: ["lib", "test/support", "bench/lib"]
  defp elixirc_paths(_), do: ["lib"]

  # The PgRest examples run only with the optional local PgRest checkout.
  defp pgrest?, do: File.exists?(Path.expand("../pgrest/mix.exs", __DIR__))

  defp test_file?("test/pgrest_examples/" <> _ = path), do: pgrest?() and test_exs?(path)
  defp test_file?(path), do: test_exs?(path)

  defp test_exs?(path), do: String.ends_with?(path, "_test.exs")

  defp deps do
    [
      # Core
      {:ecto, "~> 3.13"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, "~> 0.19 or ~> 1.0"},
      {:jason, "~> 1.4"},
      {:telemetry, "~> 1.0"},
      {:nimble_options, "~> 1.0"},

      # Optional
      {:jose, "~> 1.11", optional: true},

      # Dev/Test
      {:req, "~> 0.5", only: [:test, :bench]},
      {:excoveralls, "~> 0.18.5", only: :test},
      {:stream_data, "~> 1.1", only: [:test, :bench]},
      {:benchee, "~> 1.5", only: [:test, :bench]},
      {:ex_doc, "~> 0.40.4", only: :dev, runtime: false},
      {:credo, "~> 1.7.19", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4.9", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.23.0", only: [:dev, :test], runtime: false},
      {:ex_slop, "~> 0.4.5", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.19.0", only: [:dev, :test], runtime: false},
      {:ex_dna, "~> 1.5.4", only: [:dev, :test], runtime: false}
    ] ++ pgrest_deps()
  end

  # Optional local checkout of github.com/agoodway/pgrest; switch to a github
  # ref once released.
  defp pgrest_deps do
    if pgrest?(), do: [{:pgrest, path: "../pgrest", only: :test}], else: []
  end

  defp aliases do
    [
      test: [
        "ecto.create --quiet -r Authzura.Test.Repo",
        "ecto.migrate --quiet -r Authzura.Test.Repo --migrations-path priv/test_migrations",
        "test"
      ],
      # Run to check the quality of your code
      quality: [
        "compile --warnings-as-errors",
        "deps.unlock --unused",
        "format --check-formatted",
        "sobelow --config",
        "ex_dna",
        "doctor",
        "credo --strict",
        "dialyzer"
      ]
    ]
  end

  defp description do
    "Enforces Hasura v2 select permissions on Ecto reads."
  end

  defp package do
    [
      maintainers: ["Chase Pursley"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url, "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"},
      files: ~w(lib mix.exs README.md CHANGELOG.md usage-rules.md LICENSE .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "docs/guides/configuration.md",
        "docs/guides/querying.md",
        "docs/guides/security.md",
        "docs/guides/compatibility.md",
        "CHANGELOG.md"
      ],
      groups_for_extras: [
        Guides: ~r{docs/guides/}
      ],
      groups_for_modules: [
        "Entry points": [
          Authzura,
          Authzura.Options,
          Authzura.Session,
          Authzura.JWT,
          Authzura.Input,
          Authzura.Get,
          Authzura.Preload.Tree
        ],
        Errors: [Authzura.Error],
        Telemetry: [Authzura.Telemetry],
        Behaviours: [Authzura.Source, Authzura.Adapter],
        "Model structs": ~r/^Authzura\.Model\./,
        "Sources and adapters": [
          Authzura.Sources.Hasura,
          Authzura.Adapters.Postgres,
          Authzura.Adapters.Postgres.Citext
        ],
        "Mix tasks": [Mix.Tasks.Authzura.Check],
        "Internals (implementation reference)": ~r/^Authzura\./
      ],
      source_ref: "v#{@version}"
    ]
  end
end

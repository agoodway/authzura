import Config

port = String.to_integer(System.get_env("AUTHZURA_TEST_PORT", "5432"))
database = System.get_env("AUTHZURA_TEST_DATABASE", "authzura_test")

repo_opts = [
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: port,
  database: database,
  pool: Ecto.Adapters.SQL.Sandbox,
  # Every async DataCase test holds a sandbox connection, and ExUnit runs
  # `2 * schedulers` cases at once, so the pool matches that concurrency.
  pool_size: System.schedulers_online() * 2
]

config :authzura, Authzura.Test.Repo, repo_opts
config :authzura, Authzura.Test.OtherRepo, repo_opts

config :authzura, ecto_repos: [Authzura.Test.Repo]

# Per-call test hooks (`isolation:`, `between_levels:`); never in production.
config :authzura, :test_hooks, true

config :logger, level: :warning

# Logs queries at a level the test logger prints; `Authzura.Test.LogRepo`.
config :authzura,
       Authzura.Test.LogRepo,
       repo_opts |> Keyword.delete(:pool) |> Keyword.put(:log, :warning)

# A repo whose types module decodes `cube`; `Authzura.Test.CubeRepo`.
config :authzura,
       Authzura.Test.CubeRepo,
       repo_opts |> Keyword.delete(:pool) |> Keyword.put(:types, Authzura.Test.CubeTypes)

# `Authzura.Test.SingleConnectionRepo`: one connection, started by its test.
config :authzura,
       Authzura.Test.SingleConnectionRepo,
       repo_opts
       |> Keyword.delete(:pool)
       |> Keyword.merge(types: Authzura.Test.CubeTypes, pool_size: 1)

import Config

# The benchmark database comes from AUTHZURA_BENCH_DB_URL at start-up (see
# Authzura.Bench.Repo); there is deliberately no default target.
config :authzura, ecto_repos: [Authzura.Bench.Repo]
config :authzura, Authzura.Bench.Repo, log: false, pool_size: 10

config :logger, level: :warning

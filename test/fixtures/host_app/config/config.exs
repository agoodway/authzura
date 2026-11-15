import Config

config :host, ecto_repos: [Host.Repo]

config :host, Host.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: String.to_integer(System.get_env("AUTHZURA_TEST_PORT", "5432")),
  database: System.get_env("AUTHZURA_TEST_DATABASE", "authzura_test")

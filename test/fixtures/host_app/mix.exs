defmodule Host.MixProject do
  use Mix.Project

  # A minimal host application for `test/mix/tasks/authzura_check_host_test.exs`.
  # It shares Authzura's fetched deps and lockfile, and builds into its own
  # directory under `_build` (outside `test/`, which `mix format` walks).
  def project do
    [
      app: :host,
      version: "0.0.0",
      elixir: "~> 1.19",
      build_path: "../../../_build/host_app",
      deps_path: "../../../deps",
      lockfile: "../../../mix.lock",
      deps: [{:authzura, path: "../../.."}]
    ]
  end

  def application, do: [extra_applications: [:logger]]
end

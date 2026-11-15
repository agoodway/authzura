defmodule Authzura.CommittedCase do
  @moduledoc """
  Unsandboxed case (`async: false`) for tests that execute through Authzura's
  executors.

  Both test repos switch to `:auto` mode, so any Store, task or second
  connection gets a real, committed connection. Cleanup truncates every
  fixture table in `on_exit`, which runs in a fresh process with its own
  auto-mode connection, and then restores `:manual` mode. ExUnit runs every
  async module before the sync ones, so this cannot affect `DataCase` tests.
  """

  use ExUnit.CaseTemplate

  alias Authzura.FixtureSchema
  alias Authzura.Test.{OtherRepo, Repo}
  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      import Ecto.Query

      alias Authzura.Test.{OtherRepo, Repo}
    end
  end

  setup do
    Sandbox.mode(Repo, :auto)
    Sandbox.mode(OtherRepo, :auto)

    on_exit(fn ->
      try do
        FixtureSchema.truncate(Repo)
      after
        Sandbox.mode(Repo, :manual)
        Sandbox.mode(OtherRepo, :manual)
      end
    end)

    :ok
  end
end

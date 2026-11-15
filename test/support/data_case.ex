defmodule Authzura.DataCase do
  @moduledoc """
  Sandboxed, async-safe case for tests that build or inspect queries.

  Tests that execute through Authzura's executors use `Authzura.CommittedCase`
  instead, because the sandbox's wrapping transaction breaks
  `SET TRANSACTION`.
  """

  use ExUnit.CaseTemplate

  alias Authzura.Test.Repo
  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      import Ecto.Query

      alias Authzura.Test.Repo
    end
  end

  setup tags do
    owner = Sandbox.start_owner!(Repo, shared: not tags[:async])
    on_exit(fn -> Sandbox.stop_owner(owner) end)
    :ok
  end
end

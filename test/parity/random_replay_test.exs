defmodule Authzura.Parity.RandomReplayTest do
  @moduledoc """
  Replays every saved differential failure in `test/parity/cases/random/`
  (`Authzura.Gen.Save`) against a real Hasura v2.51.6, as part of the
  opt-in parity suite (`mix test --only hasura_parity`).

  Saved cases were found on `Authzura.Test.Seed`'s rows with their batch's
  permissions, so this module does not use `Authzura.ParityCase`: its own
  setup checks the targets, commits the same seed rows, and each case
  applies its own permissions (`Authzura.Parity.Fixture.metadata/1`
  through `Authzura.Gen.metadata/1`) before it runs. A case passes when it
  now matches Hasura or is a reviewed divergence.
  """

  use ExUnit.Case, async: false

  alias Authzura.Gen.Save
  alias Authzura.Parity.Differential

  @moduletag :hasura_parity

  @instance Module.concat(__MODULE__, Instance)
  @cases Path.wildcard(Path.join(Save.dir(), "*.json"))

  for path <- @cases, do: @external_resource(path)

  setup_all do
    start_supervised!(Differential.repo!())
    :ok = Differential.seed!()
    start_supervised!(Differential.instance(@instance))
    :ok
  end

  for path <- @cases do
    @path path
    test "saved case #{Path.basename(path, ".json")}" do
      payload = Save.load!(@path)
      c = Differential.case_of(payload)
      tables = Differential.load!(@instance, payload.permissions, Path.basename(@path))
      outcome = Differential.run(c, payload.permissions, @instance, tables)

      assert Differential.pass?(outcome.verdict),
             "#{@path}: #{inspect(outcome.verdict)}\n  hasura: #{inspect(outcome.hasura)}\n" <>
               "  authzura: #{inspect(outcome.authzura)}"
    end
  end
end

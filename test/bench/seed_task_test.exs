defmodule Authzura.Bench.SeedTaskTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Authzura.Bench.Seed

  describe "authzura.bench.seed --db-only" do
    test "never contacts Hasura: only the database steps are selected" do
      assert Seed.steps(db_only: true) == [:prepare_database, :load]
      assert :check_hasura in Seed.steps([])
      assert :start_hasura in Seed.steps([])
      refute :start_hasura in Seed.steps(no_compose: true)
    end
  end
end

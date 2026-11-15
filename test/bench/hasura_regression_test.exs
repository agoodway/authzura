defmodule Authzura.Bench.HasuraRegressionTest do
  # The bench regressions that compare with Hasura, so they need the seeded
  # :small database and its bench Hasura (`AUTHZURA_BENCH_*`, see
  # bench/README.md): mix test --only bench test/bench/hasura_regression_test.exs
  use ExUnit.Case, async: false

  alias Authzura.Bench
  alias Authzura.Bench.{Gate, Measure, Scenarios}

  @moduletag :bench

  setup_all do
    Enum.each(Bench.children(), &start_supervised!/1)
    :ok = Authzura.reload(Bench.instance())
    :ok
  end

  test "the broad scenarios pass the gate" do
    broad =
      Enum.map(~w(input-rel-broad-limit input-col-broad-limit), &Scenarios.fetch!/1)

    assert {^broad, []} = Gate.check(broad)
  end

  # The relationship permission compiles as a join on the input execute path;
  # the CASE fence re-checks the chain without a second EXISTS evaluation.
  test "input-rel-permission buffers are at most 1.5x Hasura's" do
    scenario = Scenarios.fetch!("input-rel-permission")

    plans = %{
      hasura: Measure.plans(:hasura, scenario),
      authzura: Measure.plans(:authzura, scenario)
    }

    ratio = Measure.buffer_ratio(plans)

    assert is_float(ratio), "Hasura read no buffer"
    assert ratio <= 1.5, "buffers are #{Float.round(ratio, 2)}x Hasura's"
  end
end

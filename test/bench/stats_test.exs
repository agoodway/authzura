defmodule Authzura.Bench.StatsTest do
  use ExUnit.Case, async: true

  alias Authzura.Bench.Stats

  doctest Stats

  test "cv/1 divides by n - 1" do
    # Population SD of [1, 1, 1, 1, 1.4] is 0.16 (CV 0.148); sample SD is 0.179.
    assert_in_delta Stats.cv([1.0, 1.0, 1.0, 1.0, 1.4]), 0.1656, 0.0001
    assert Stats.cv([5.0]) == 0.0
    assert Stats.cv([0.0, 0.0]) == 0.0
  end
end

defmodule Authzura.LiftVacuityTest do
  @moduledoc "Pure counterexamples and boundaries for the join-lift coverage guards."

  use ExUnit.Case, async: true

  import StreamData, only: [member_of: 1, map: 2]

  alias Authzura.Gen
  alias Authzura.Test.Vacuity

  @observation %{
    rel_permission?: true,
    lifted: 1,
    incomplete?: false,
    fallback?: false,
    nullable_chain?: true
  }

  test "an empty stream fails every lift guard" do
    assert [_, _, _] = Vacuity.lift_failures([])
  end

  test "a degenerate stream without relationship permissions fails every lift guard" do
    assert [_, _, _] = failures(rel_permission?: false)
  end

  test "a degenerate stream without executed lifts fails the lifted guard" do
    assert [failure] = failures(lifted: 0)
    assert failure =~ "lifted"
    assert failure =~ "20 %"
  end

  test "a degenerate stream without incomplete lifts or fallbacks fails their guard" do
    assert [failure] = failures(incomplete?: false, fallback?: false)
    assert failure =~ "incomplete or fallback"
    assert failure =~ "10 %"
  end

  test "a degenerate stream without nullable chains fails their guard" do
    assert [failure] = failures(nullable_chain?: false)
    assert failure =~ "nullable chain"
  end

  test "the floors are inclusive and only relationship permissions enter the denominator" do
    plain = %{@observation | rel_permission?: false, lifted: 0, fallback?: false}
    fallback = %{@observation | lifted: 0, fallback?: true, nullable_chain?: false}
    lifted = %{@observation | fallback?: false, nullable_chain?: false}
    neither = %{fallback | fallback?: false}
    nullable = %{lifted | nullable_chain?: true}
    log = [nullable, lifted, fallback | List.duplicate(neither, 7)]

    assert Vacuity.lift_failures(log ++ List.duplicate(plain, 90)) == []
    incomplete = %{fallback | lifted: 1, incomplete?: true, fallback?: false}

    assert Vacuity.lift_failures([nullable, lifted, incomplete | List.duplicate(neither, 7)]) ==
             []

    assert [_failure] = Vacuity.lift_failures([nullable, neither | tl(tl(log))])

    assert [_failure] =
             Vacuity.lift_failures([nullable, lifted, neither | List.duplicate(neither, 7)])

    no_nullable = Enum.map(log, &%{&1 | nullable_chain?: false})
    assert ["nullable chain: no cases"] = Vacuity.lift_failures([plain | no_nullable])
  end

  test "19 percent lifted and 9 percent fallback are below the unchanged floors" do
    fallback = %{@observation | lifted: 0, fallback?: true, nullable_chain?: false}
    neither = %{fallback | fallback?: false}

    too_few_lifts =
      List.duplicate(@observation, 19) ++
        List.duplicate(fallback, 10) ++ List.duplicate(neither, 71)

    too_few_fallbacks =
      List.duplicate(@observation, 20) ++
        List.duplicate(fallback, 9) ++ List.duplicate(neither, 71)

    assert ["lifted relationship reads: 19/100, below 20 %"] =
             Vacuity.lift_failures(too_few_lifts)

    assert ["incomplete or fallback relationship reads: 9/100, below 10 %"] =
             Vacuity.lift_failures(too_few_fallbacks)
  end

  defp failures(changes) do
    [@observation, %{@observation | lifted: 0, fallback?: true, nullable_chain?: false}]
    |> member_of()
    |> map(&Map.merge(&1, Map.new(changes)))
    |> Gen.take(1, 60)
    |> Vacuity.lift_failures()
  end
end

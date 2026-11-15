defmodule Authzura.Parity.RandomDifferentialTest do
  @moduledoc """
  Randomized differential testing against a real Hasura v2.51.6 (on
  demand: `mix test --only hasura_differential`; see the Security guide's
  "Running parity tests").

  One test per batch. Batch `i` draws its permissions with seed
  `AUTHZURA_PROP_SEED + i` (`Authzura.Gen.batch/2`) and spends its share
  of `AUTHZURA_DIFF_RUNS` (default 300, over `AUTHZURA_DIFF_BATCHES`,
  default 1): the random stream with request seed ExUnit's `--seed`, then
  one forced case per denial class. Each case runs on both engines
  (`Authzura.Parity.Runner`, with HS256 JWTs) and is classified by
  `Authzura.Parity.Verdict`.

  A failing verdict is shrunk, saved under `test/parity/cases/random/`
  (`Authzura.Gen.Save`) and reported with the command that replays it. A
  leak fails with `"LEAK"` first and stops the run: later batches fail at
  once. Per batch, guard (a) is checked after loading, and guards (b)-(e)
  plus the reviewed-divergence share (at most 5 %) after the cases.

  `AUTHZURA_DIFF_PUSHDOWN=1` starts the instance with
  `input_index_pushdown: true` (default off); the verdict is unchanged.
  """

  use ExUnit.Case, async: false

  alias Authzura.{Gen, Telemetry}
  alias Authzura.Gen.Save
  alias Authzura.Parity.Differential
  alias Authzura.Parity.Runner
  alias Authzura.Test.Vacuity

  @moduletag :hasura_differential
  @moduletag timeout: :infinity

  @instance Module.concat(__MODULE__, Instance)
  @leak {__MODULE__, :leak}
  @divergence_share 0.05
  @batches Gen.env_integer("AUTHZURA_DIFF_BATCHES", 1)

  setup_all do
    start_supervised!(Differential.repo!())
    :ok = Differential.seed!()
    start_supervised!(Differential.instance(@instance))
    :persistent_term.erase(@leak)
    :ok
  end

  for i <- 1..@batches do
    test "batch #{i} matches Hasura", context do
      run_batch(unquote(i), context)
    end
  end

  defp run_batch(i, context) do
    if earlier = :persistent_term.get(@leak, nil),
      do: flunk("LEAK found in batch #{earlier}; the run stopped")

    batch = Gen.batch(i)
    tables = Differential.load!(@instance, batch, "batch #{i}")
    {:ok, log} = Agent.start_link(fn -> [] end)
    seed = request_seed()

    property = fn c ->
      outcome = Differential.run(c, batch, @instance, tables)

      observation =
        Vacuity.observe(c, outcome.authzura, &Runner.authzura(&1.read, &1.auth, @instance))

      Agent.update(log, &[{observation, Map.put(outcome, :case, c)} | &1])
      if Differential.pass?(outcome.verdict), do: {:ok, nil}, else: {:error, {c, outcome}}
    end

    check!(i, context, batch, Gen.request(batch), random_runs(), seed, property)

    for mutation <- Gen.sweep(),
        do: check!(i, context, batch, Gen.request(batch, mutation: mutation), 1, seed, property)

    entries = log |> Agent.get(&Enum.reverse/1)
    Agent.stop(log)
    report(i, entries)

    {random, _sweep} = Enum.split(entries, random_runs())
    observations = Enum.map(entries, &elem(&1, 0))

    failures =
      Vacuity.failures(Enum.map(random, &elem(&1, 0))) ++
        Vacuity.denial_failures(observations) ++ divergence_failures(entries)

    assert failures == [], "batch #{i} (request seed #{seed}): #{Enum.join(failures, "; ")}"
  end

  defp check!(i, context, batch, generator, runs, seed, property) do
    case StreamData.check_all(generator, [initial_seed: {0, 0, seed}, max_runs: runs], property) do
      {:ok, _} -> :ok
      {:error, failure} -> fail!(i, context, batch, seed, failure)
    end
  end

  defp fail!(i, context, batch, seed, %{
         original_failure: {_c, original},
         shrunk_failure: {c, shrunk}
       }) do
    leak? = Enum.any?([original, shrunk], &match?({:leak, _}, &1.verdict))
    if leak?, do: :persistent_term.put(@leak, i)

    {class, message} = shrunk.verdict
    reason = "#{class}: #{message}"

    path = save(c, batch, reason, %{batch: Gen.seed() + i, request: seed})

    flunk("""
    #{if leak?, do: "LEAK. ", else: ""}batch #{i} (batch seed #{Gen.seed() + i}, request seed #{seed}): #{reason}
      original: #{inspect(original.verdict)}
      read: #{inspect(c.read)}
      auth: #{inspect(c.auth)}
      hasura: #{inspect(shrunk.hasura, limit: 30)}
      authzura: #{inspect(shrunk.authzura, limit: 30)}
      twin: #{inspect(shrunk.twin, limit: 30)}
      saved: #{path}
    replay with:
      #{replay(context)}
    """)
  end

  # A saved case under the same id with another payload, or any failure to
  # write it (a `File.Error`, say), must not hide the failure (a leak above
  # all): the message still leads with it.
  defp save(c, batch, reason, seeds) do
    c
    |> Differential.payload(batch)
    |> Save.write!(reason, seeds, tags: c.tags)
  rescue
    error -> "not saved (#{Exception.message(error)})"
  end

  defp replay(context) do
    "AUTHZURA_PROP_SEED=#{Gen.seed()} AUTHZURA_DIFF_BATCHES=#{@batches} " <>
      "AUTHZURA_DIFF_RUNS=#{runs()} mix test --only hasura_differential " <>
      "#{Path.relative_to_cwd(context.file)} --seed #{request_seed()}"
  end

  # Verdict tallies, twin checks, and each Hasura error code with the
  # Authzura reasons it met and one of its messages.
  defp report(i, entries) do
    outcomes = Enum.map(entries, &elem(&1, 1))
    tally = outcomes |> Enum.map(&verdict_class(&1.verdict)) |> Enum.frequencies()
    twins = Enum.count(outcomes, &(&1.twin != nil))

    errors =
      for %{hasura: {:error, code, message}, authzura: authzura} <- outcomes,
          reduce: %{} do
        acc ->
          Map.update(acc, code, {MapSet.new([reason_shape(authzura)]), message}, fn {shapes, m} ->
            {MapSet.put(shapes, reason_shape(authzura)), m}
          end)
      end

    IO.puts("""

    batch #{i} (seed #{Gen.seed() + i}): #{length(entries)} cases, #{inspect(tally)}, #{twins} twin checks
    #{Enum.map_join(errors, "\n", fn {code, {shapes, message}} -> "  #{code} #{inspect(MapSet.to_list(shapes))}: #{message}" end)}
    #{Enum.map_join(reviewed(outcomes), "\n", &"  #{&1}")}\
    """)
  end

  defp reviewed(outcomes) do
    for %{verdict: {:reviewed_divergence, id}, authzura: {:error, reason}, case: c} <- outcomes,
        do:
          "#{id}: #{inspect(reason)} on #{inspect(c.read.table)}, session #{inspect(Gen.variables(c))}"
  end

  defp verdict_class(:match), do: :match
  defp verdict_class({:reviewed_divergence, id}), do: {:reviewed_divergence, id}
  defp verdict_class({class, _detail}), do: class

  defp reason_shape({:error, reason}), do: Telemetry.reason_class(reason)
  defp reason_shape({:ok, _rows}), do: :granted

  defp divergence_failures(entries) do
    reviewed = Enum.count(entries, &match?({_o, %{verdict: {:reviewed_divergence, _id}}}, &1))

    if entries != [] and reviewed / length(entries) > @divergence_share,
      do: ["reviewed divergences #{reviewed}/#{length(entries)}, above 5 %"],
      else: []
  end

  defp request_seed, do: ExUnit.configuration()[:seed]

  defp runs, do: Gen.env_integer("AUTHZURA_DIFF_RUNS", 300)

  # The sweep is part of each batch's share of the runs.
  defp random_runs, do: max(div(runs(), @batches) - length(Gen.sweep()), 1)
end

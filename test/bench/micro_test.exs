defmodule Authzura.Bench.MicroTest do
  use ExUnit.Case, async: true

  alias Authzura.Bench.Micro

  @env %{otp: "28", elixir: "1.19.0", os: "unix-darwin-arm", cpu_model: "M", schedulers: 8}

  defp result(runs, env \\ @env),
    do: %{env: env, jobs: %{"scope" => %{median_ns: hd(runs), runs: runs}}}

  defp baseline, do: result([100, 100, 100])

  test "a job regresses only when all 3 runs exceed tolerance" do
    assert {:ok, ["scope"]} = Micro.regressions(result([121, 130, 125]), baseline())
    assert {:ok, []} = Micro.regressions(result([121, 130, 119]), baseline())
    assert {:ok, []} = Micro.regressions(result([120, 130, 125]), baseline())
    assert {:ok, []} = Micro.regressions(result([50, 60, 70]), baseline())
    assert {:ok, ["scope"]} = Micro.regressions(result([105, 106, 107]), baseline(), 0.01)
  end

  test "a baseline from a different env is skipped, never a failure" do
    slow = result([500, 500, 500])
    other = result([100, 100, 100], %{@env | schedulers: 4})
    assert {:skipped, :env_mismatch} = Micro.regressions(slow, other)
  end

  test "the baseline file carries env and no values or SQL" do
    json = Micro.encode(baseline())
    decoded = Jason.decode!(json)

    assert Map.keys(decoded) |> Enum.sort() == ["env", "jobs"]
    assert Map.keys(decoded["env"]) |> Enum.sort() == ~w(cpu_model elixir os otp schedulers)
    assert %{"scope" => %{"median_ns" => 100, "runs" => [100, 100, 100]}} = decoded["jobs"]

    refute json =~ ~r/select|where|x-hasura|from "/i
    assert Micro.decode(json) == baseline()
    assert Micro.decode("not json") == nil
    assert Micro.read_baseline("/nonexistent/micro.json") == nil
  end

  test "report-only jobs never gate, even at 500%" do
    jobs = %{"overhead" => %{median_ns: 500, runs: [500, 500, 500]}}
    base = %{env: @env, jobs: %{"overhead" => %{median_ns: 100, runs: [100, 100, 100]}}}

    assert Micro.report_only?("overhead")
    assert Micro.report_only?("overhead-preload-nested-3")
    refute Micro.report_only?("scope-flat-tenant")
    assert {:ok, []} = Micro.regressions(%{env: @env, jobs: jobs}, base)
  end

  test "decode never raises on a malformed baseline" do
    env = Map.new(@env, fn {k, v} -> {Atom.to_string(k), v} end)

    for jobs <- [
          %{"a" => 1},
          %{"a" => %{"median_ns" => "x", "runs" => []}},
          [1],
          nil,
          %{"a" => %{"median_ns" => 1, "runs" => ["x"]}}
        ] do
      assert Micro.decode(Jason.encode!(%{"env" => env, "jobs" => jobs})) == nil
    end

    bad_env = Map.put(env, "schedulers", "8")
    assert Micro.decode(Jason.encode!(%{"env" => bad_env, "jobs" => %{}})) == nil
    assert Micro.decode("[]") == nil
  end

  test "env_diff names the differing keys and job_drift the unmatched jobs" do
    other = %{baseline() | env: %{@env | schedulers: 4, otp: "27"}}
    assert Micro.env_diff(baseline(), other) == [:otp, :schedulers]

    run = %{env: @env, jobs: %{"new" => %{median_ns: 1, runs: [1, 1, 1]}}}
    assert Micro.job_drift(run, baseline()) == %{missing: ["scope"], extra: ["new"]}
  end

  test "the committed baseline, when present, decodes with whole-ns numbers" do
    case Micro.read_baseline() do
      nil ->
        :ok

      %{jobs: jobs} ->
        assert Map.has_key?(jobs, "overhead")

        assert Enum.all?(jobs, fn {_n, %{median_ns: m, runs: r}} ->
                 is_integer(m) and Enum.all?(r, &is_integer/1)
               end)
    end
  end
end

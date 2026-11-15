defmodule Authzura.TestSource do
  @moduledoc """
  An Agent-controlled `Authzura.Source` for Store tests.

  Start one per test with `start_supervised!({TestSource, opts})` and pass
  `source: {TestSource, agent: agent}` to the instance. Every field can be
  changed later with `put/2`:

    * `:version` - what `version/2` returns as `{:ok, version, cache}`,
      passing the cache through (default `"A"`)
    * `:version_error` - when set, `version/2` returns `{:error, reason}`
    * `:version_reply` - when set, `version/2` returns it verbatim, even if
      malformed (`{:ok, version}` gets the cache added)
    * `:load` - `:ok` or `{:error, reason}` for `load/1` (default `:ok`);
      `{:throw, value}` or `{:raise, message}` make it throw or raise
    * `:snapshot` - the snapshot `load/1` returns, with its `version` set to
      the current `:version`; or a function of the 1-based load count that
      builds the snapshot itself
    * `:gate` - a pid; when set, `load/1` sends it
      `{Authzura.TestSource, :loading, loader_pid}` and waits for `:release`.
      The load's outcome is read after the release
    * `:input` - the AST `parse_input/2` returns. When `nil` (the default),
      `parse_input/2` delegates to `Authzura.Sources.Hasura.parse_input/2`
  """

  @behaviour Authzura.Source

  use Agent

  alias Authzura.AST
  alias Authzura.Model.Snapshot
  alias Authzura.Sources.Hasura

  @defaults %{
    version: "A",
    version_error: nil,
    version_reply: nil,
    load: :ok,
    snapshot: %Snapshot{version: nil},
    gate: nil,
    input: nil,
    loads: 0
  }

  @doc "Starts the agent holding the source's behaviour."
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts), do: Agent.start_link(fn -> Map.merge(@defaults, Map.new(opts)) end)

  @doc "Changes the source's behaviour for later calls."
  @spec put(pid(), keyword()) :: :ok
  def put(agent, changes), do: Agent.update(agent, &Map.merge(&1, Map.new(changes)))

  @doc "Returns how many times `load/1` has started."
  @spec loads(pid()) :: non_neg_integer()
  def loads(agent), do: Agent.get(agent, & &1.loads)

  @impl true
  @spec load(keyword()) :: {:ok, Snapshot.t()} | {:error, term()}
  def load(opts) do
    agent = Keyword.fetch!(opts, :agent)

    %{gate: gate, loads: n} =
      Agent.get_and_update(agent, fn %{loads: loads} = state ->
        next = %{state | loads: loads + 1}
        {next, next}
      end)

    wait(gate)
    agent |> Agent.get(& &1) |> result(n)
  end

  @impl true
  @spec version(keyword(), term()) :: {:ok, term(), term()} | {:error, term()} | term()
  def version(opts, cache) do
    opts
    |> Keyword.fetch!(:agent)
    |> Agent.get(& &1)
    |> reported_version()
    |> with_cache(cache)
  end

  @impl true
  @spec parse_input(map(), map()) :: {:ok, AST.t()} | {:error, [{[String.t()], term()}]}
  def parse_input(json, %{source_opts: opts} = ctx) do
    case opts |> Keyword.fetch!(:agent) |> Agent.get(& &1.input) do
      nil -> Hasura.parse_input(json, Map.delete(ctx, :source_opts))
      ast -> {:ok, ast}
    end
  end

  defp wait(nil), do: :ok

  defp wait(pid) do
    send(pid, {__MODULE__, :loading, self()})

    receive do
      :release -> :ok
    end
  end

  # The outcome is read after the gate opens, so a test can change it while
  # the load waits. `n` is this load's own count.
  defp result(%{load: {:error, _reason} = error}, _n), do: error
  defp result(%{load: {:throw, value}}, _n), do: throw(value)
  defp result(%{load: {:raise, message}}, _n), do: raise(message)
  defp result(%{load: :ok, snapshot: build}, n) when is_function(build, 1), do: {:ok, build.(n)}

  defp result(%{load: :ok, snapshot: snapshot, version: version}, _n),
    do: {:ok, %{snapshot | version: version}}

  defp with_cache({:ok, version}, cache), do: {:ok, version, cache}
  defp with_cache(reply, _cache), do: reply

  defp reported_version(%{version_reply: reply}) when reply != nil, do: reply
  defp reported_version(%{version_error: nil, version: version}), do: {:ok, version}
  defp reported_version(%{version_error: reason}), do: {:error, reason}
end

defmodule Authzura.TelemetryHelper do
  @moduledoc """
  Forwards telemetry events to the test process as
  `{:telemetry, event, metadata}` messages.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  alias Authzura.Bench.Measure

  @doc """
  Attaches `handler_id` to `events` and detaches it in `on_exit`.

  Options narrow what is forwarded, because other async tests emit the same
  events:

    * `:instance` - only events whose metadata carries this `:instance`
    * `:caller_only` - only events emitted from the calling process
  """
  @spec forward!(term(), [[atom()]], keyword()) :: :ok
  def forward!(handler_id, events, opts \\ []) when is_list(events) and is_list(opts) do
    config = %{
      parent: self(),
      instance: Keyword.get(opts, :instance),
      caller_only?: Keyword.get(opts, :caller_only, false)
    }

    :ok = :telemetry.attach_many(handler_id, events, &__MODULE__.handle/4, config)
    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  @doc """
  Returns every forwarded `{event, metadata}` already in the mailbox, in
  order, removing those messages.
  """
  @spec drain() :: [{[atom()], map()}]
  def drain do
    receive do
      {:telemetry, event, meta} -> [{event, meta} | drain()]
    after
      0 -> []
    end
  end

  @doc """
  Returns the `:query` of every forwarded `event` already in the mailbox, in
  order, removing those messages.
  """
  @spec received_queries([atom()]) :: [String.t()]
  def received_queries(event) when is_list(event) do
    receive do
      {:telemetry, ^event, %{query: query}} -> [query | received_queries(event)]
    after
      0 -> []
    end
  end

  @doc """
  Runs a read and returns its result with captured `{sql, params}` statements
  for `event`. Requires `forward!/3` first. Old messages are drained; transaction
  control and table-free input checks are excluded.
  """
  @spec capture_statements([atom()], (-> term())) :: {term(), [{String.t(), list()}]}
  def capture_statements(event, read) when is_list(event) and is_function(read, 0) do
    drain()
    result = read.()

    statements =
      for {^event, %{query: sql, params: params}} <- drain(),
          Measure.classify(sql) == :data,
          do: {sql, params}

    {result, statements}
  end

  @doc false
  def handle(event, _measurements, meta, %{parent: parent} = config) do
    if forward?(meta, config), do: send(parent, {:telemetry, event, meta})
  end

  defp forward?(meta, %{instance: instance, caller_only?: caller_only?, parent: parent}),
    do: instance_match?(meta, instance) and (not caller_only? or self() == parent)

  defp instance_match?(_meta, nil), do: true
  defp instance_match?(%{instance: instance}, instance), do: true
  defp instance_match?(_meta, _instance), do: false
end

defmodule Authzura.Store do
  @moduledoc """
  The per-instance process that loads, publishes and polls generations.

  ## Reading

  `current/1` reads the published `Authzura.Store.Generation` straight from
  `:persistent_term`, without calling the process. It is `:not_ready` when
  nothing is published, when the publishing process is dead (a Store killed
  with `:kill` never runs `terminate/2`), or when the generation's
  incarnation is not the one its owner registered. It is
  `:stale_permissions` when the generation was last confirmed current more
  than `max_staleness` ago.

  ## Loading

  Loads run inside the Store, so they are serialized. Each load takes the
  next `seq`, and a generation is published only when its `seq` is higher
  than the published one. Every snapshot a source loads goes through
  `Authzura.Validator` before it is published, so the deny-by-default
  load checks hold for any `Authzura.Source`. A failed first load retries
  with backoff; a failed later load keeps the active generation and its
  freshness. A poll that observes a version whose load keeps failing
  retries it with the same exponential backoff (from 1 s, doubling up to
  30 s) instead of at every poll; a new observed version, a successful
  load or an explicit `Authzura.reload/1` starts over.

  ## Freshness

  A poll that observes the active version renews freshness. Any other
  version (compared only for equality) reloads. A version error or a failed
  reload renews nothing, so the generation eventually goes stale.

  Freshness is stamped with the time a check *started*: the poll's version
  read, or the load itself. A load that takes longer than `max_staleness`
  therefore publishes a generation that is already stale. That is safe, since
  reads fail closed until the next poll confirms it.

  ## Status

  `status/1` and `diagnostics/1` never call the process either, so they
  answer while a load is running. They read the published generation and a
  small `{incarnation, observed_version, last_error}` term under
  `{Authzura.Store, instance, :status}`. `last_error` is a bounded error
  *kind* (see `t:error_kind/0`), never the raw reason, because raw database
  errors differ on every attempt (connection ids, queue times, pids). The
  term is rewritten only when the observed version or the error kind changes,
  so neither a routine poll nor a long outage rewrites it on every poll, and
  polling never triggers a `:persistent_term` global GC per poll. Full reasons
  go to the log (once per change of kind for version checks, on every failed
  load); the `:stop` telemetry metadata of loads carries only `error_class`.
  """

  use GenServer

  alias Authzura.Model.{Diagnostic, Permission, Snapshot}
  alias Authzura.{Options, Telemetry, Validator}
  alias Authzura.Store.Generation

  require Logger

  @read_only_slot 2

  @typedoc "The reasons `current/1` refuses a read."
  @type unavailable :: :not_ready | :stale_permissions

  @typedoc "What `status/1` reports."
  @type status :: %{
          ready?: boolean(),
          fresh?: boolean(),
          seq: non_neg_integer(),
          active_version: term(),
          observed_version: term(),
          last_confirmed_current_at: integer() | nil,
          last_error: error_kind() | nil,
          diagnostics_count: non_neg_integer()
        }

  @typedoc """
  A bounded summary of a failure reason: `{:exception, module}`,
  `{:exit, tag}`, the module of a struct reason (such as `Postgrex.Error`),
  a bare atom, the atom tag of a tagged tuple, or `:other`.
  """
  @type error_kind :: {:exception, module()} | {:exit, atom()} | atom()

  @doc "Starts the Store for validated instance options, registered under their `:name`."
  @spec start_link(Options.instance()) :: GenServer.on_start()
  def start_link(%{name: name} = config), do: GenServer.start_link(__MODULE__, config, name: name)

  @doc "Returns the instance's current generation if it is live and fresh."
  @spec current(atom()) :: {:ok, Generation.t()} | {:error, unavailable()}
  def current(instance) do
    with {:ok, generation} <- live(instance), do: fresh(generation)
  end

  @doc false
  @spec poll(atom()) :: :ok
  def poll(instance), do: GenServer.call(instance, :poll, :infinity)

  @doc "Loads and publishes a new generation, confirming its freshness."
  @spec reload(atom()) :: :ok | {:error, term()}
  def reload(instance), do: GenServer.call(instance, :reload, :infinity)

  @doc """
  Reports readiness, versions and freshness without calling the process.

  `ready?` means a live generation is published; `fresh?` means `current/1`
  would also accept it. `last_error` is the kind of the latest load or poll
  failure (`t:error_kind/0`), and
  is cleared by the next successful poll or load.
  """
  @spec status(atom()) :: status()
  def status(instance) do
    instance
    |> live()
    |> report()
    |> Map.merge(observations(instance))
  end

  @doc "Returns the published snapshot's diagnostics without calling the process."
  @spec diagnostics(atom()) :: {:ok, [Diagnostic.t()]} | {:error, :not_ready}
  def diagnostics(instance) do
    with {:ok, %Generation{snapshot: %Snapshot{diagnostics: diagnostics}}} <- live(instance),
         do: {:ok, diagnostics}
  end

  # Reading.

  defp key(instance), do: {__MODULE__, instance}
  defp incarnation_key(instance), do: {__MODULE__, instance, :incarnation}
  defp status_key(instance), do: {__MODULE__, instance, :status}

  # Published and owned by the live incarnation, freshness aside.
  defp live(instance) do
    with {:ok, generation} <- published(instance),
         :ok <- owned(generation),
         do: {:ok, generation}
  end

  defp published(instance) do
    case :persistent_term.get(key(instance), nil) do
      %Generation{} = generation -> {:ok, generation}
      nil -> {:error, :not_ready}
    end
  end

  defp owned(%Generation{instance: instance, owner: owner, incarnation: incarnation}) do
    case registered(instance) do
      {:ok, {^owner, ^incarnation}} -> :ok
      _other -> {:error, :not_ready}
    end
  end

  # The incarnation registered by a Store that is still alive.
  defp registered(instance) do
    with {owner, _incarnation} = registration <-
           :persistent_term.get(incarnation_key(instance), nil),
         true <- Process.alive?(owner) do
      {:ok, registration}
    else
      _other -> :error
    end
  end

  # Only the live incarnation's observations count; a dead one's are hidden.
  defp observations(instance) do
    with {:ok, {_owner, incarnation}} <- registered(instance),
         {^incarnation, observed, error} <- :persistent_term.get(status_key(instance), nil) do
      %{observed_version: observed, last_error: error}
    else
      _other -> %{observed_version: nil, last_error: nil}
    end
  end

  defp fresh(%Generation{config: %{max_staleness: :infinity}} = generation), do: {:ok, generation}

  defp fresh(
         %Generation{config: %{max_staleness: max, clock: clock}, freshness: ref} = generation
       ) do
    within(now(clock) - :atomics.get(ref, 1) <= max, generation)
  end

  defp within(true, generation), do: {:ok, generation}
  defp within(false, _generation), do: {:error, :stale_permissions}

  defp now(clock), do: clock.(:millisecond)

  # Lifecycle.

  @impl true
  def init(%{name: instance, backoff: backoff} = config) do
    Process.flag(:trap_exit, true)
    # Startup invalidation: whatever a previous incarnation left behind is
    # never served again.
    :persistent_term.erase(key(instance))
    :persistent_term.erase(status_key(instance))
    incarnation = make_ref()
    :persistent_term.put(incarnation_key(instance), {self(), incarnation})

    state = %{
      config: config,
      instance: instance,
      incarnation: incarnation,
      seq: 0,
      active: nil,
      observed_version: nil,
      version_cache: nil,
      last_error: nil,
      backoff: backoff(backoff),
      retry: nil
    }

    {:ok, state, {:continue, :load}}
  end

  # Every step that may load hibernates afterwards: a load builds the
  # snapshot on this process's heap before publishing it, and the state
  # keeps only the active generation's `seq`, `version` and `freshness`, so
  # hibernating (a full collection) frees the built copy.
  @impl true
  def handle_continue(:load, state), do: {:noreply, startup_load(state), :hibernate}

  @impl true
  def handle_info(:load, %{active: nil} = state),
    do: {:noreply, startup_load(state), :hibernate}

  def handle_info(:load, state), do: {:noreply, state}

  def handle_info(:poll, state) do
    {_result, state} = poll_once(state)
    schedule_poll(state)
    {:noreply, state, :hibernate}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def handle_call(:poll, _from, state) do
    {_result, state} = poll_once(state)
    {:reply, :ok, state, :hibernate}
  end

  # An explicit reload always loads, and its outcome restarts any backoff.
  def handle_call(:reload, _from, state) do
    {result, state} = load(state)
    {:reply, result, %{state | retry: nil}, :hibernate}
  end

  # A brutal kill or a shutdown timeout skips this, leaving the keys until the
  # next Store with this name starts and erases them in `init/1`. Until then
  # reads stay `:not_ready`, because the owner is no longer alive.
  @impl true
  def terminate(_reason, %{instance: instance}) do
    :persistent_term.erase(key(instance))
    :persistent_term.erase(incarnation_key(instance))
    :persistent_term.erase(status_key(instance))
    :ok
  end

  # Loading.

  defp backoff({initial, max}), do: %{initial: initial, max: max, delay: initial}
  defp backoff(delay), do: backoff({delay, delay})

  # Only the startup path schedules retries, so there is one retry chain.
  defp startup_load(state) do
    case load(state) do
      {:ok, state} ->
        state

      {{:error, _reason}, %{backoff: %{delay: delay, max: ceiling} = backoff} = state} ->
        Process.send_after(self(), :load, delay)
        %{state | backoff: %{backoff | delay: (delay * 2) |> max(1) |> min(ceiling)}}
    end
  end

  defp load(
         %{config: %{clock: clock}, seq: seq, instance: instance, observed_version: observed} =
           state
       ) do
    state = %{state | seq: seq + 1}
    started_at = now(clock)

    case run_load(state) do
      {:ok, %Snapshot{} = snapshot} ->
        {:ok, publish(state, snapshot, started_at)}

      other ->
        reason = failure(other, :invalid_load_result)

        Logger.warning(
          "Authzura instance #{inspect(instance)} failed to load permissions: " <>
            inspect(error_kind(reason))
        )

        {{:error, reason}, remember(state, observed, error_kind(reason))}
    end
  end

  defp failure({:error, reason}, _malformed), do: reason
  defp failure(other, malformed), do: {malformed, other}

  defp run_load(%{config: config, instance: instance, seq: seq} = state) do
    {source, opts} = source(config)
    meta = %{instance: instance, seq: seq}

    load = fn -> checked_load(state, source, opts) end
    guarded(fn -> Telemetry.span(load_event(state), meta, load) end)
  end

  defp checked_load(%{config: %{adapter: adapter}} = state, source, opts) do
    with :ok <- verify_read_only(state),
         {:ok, %Snapshot{} = snapshot} <- source.load(opts) do
      {:ok, Validator.validate(snapshot, adapter)}
    end
  end

  defp load_event(%{active: nil}), do: :load
  defp load_event(_state), do: :reload

  defp check_version(%{config: config, version_cache: cache}) do
    {source, opts} = source(config)
    guarded(fn -> source.version(opts, cache) end)
  end

  # `read_only: :connection` trusts the repo's connections to be read-only,
  # so every load and poll checks they still are. A failed check turns the
  # active generation's read-only slot off (`Generation.connection_read_only?/1`)
  # until the next successful load: reads then build plans that take the
  # `SET TRANSACTION READ ONLY` path again. A failed check also fails a
  # load, so nothing is ever first published unverified.
  defp verify_read_only(
         %{config: %{read_only: :connection, adapter: adapter, repo: repo}, active: active} =
           state
       ) do
    result = guarded(fn -> adapter.verify_read_only(repo) end)
    active |> mark(result) |> log_read_only(state, result)
    result
  end

  defp verify_read_only(%{}), do: :ok

  # A failed check turns the active generation's slot off for good: each
  # check samples one pooled connection, so a later passing check proves
  # nothing about the one that failed. Only a successful load publishes a
  # generation whose slot is on again. Returns whether this check turned it
  # off (with no active generation, the failed load itself is logged).
  defp mark(nil, _result), do: false
  defp mark(%{}, :ok), do: false
  defp mark(%{freshness: ref}, _error), do: :atomics.exchange(ref, @read_only_slot, 0) == 1

  defp log_read_only(false = _turned_off?, _state, _result), do: :ok

  defp log_read_only(true, %{instance: instance}, error) do
    Logger.warning(
      "Authzura instance #{inspect(instance)} found its repo's connections not read-only " <>
        "(read_only: :connection); reads use SET TRANSACTION READ ONLY until a check passes: " <>
        inspect(error_kind(error))
    )
  end

  # The instance repo is the data repo; the source's repo defaults to it.
  defp source(%{source: {source, opts}, repo: repo, adapter: adapter}) do
    {source,
     opts |> Keyword.merge(data_repo: repo, adapter: adapter) |> Keyword.put_new(:repo, repo)}
  end

  # A raising, throwing or exiting source is a failed load, never a crashed Store.
  defp guarded(fun) do
    fun.()
  rescue
    exception -> {:error, {:exception, exception}}
  catch
    :exit, reason -> {:error, {:exit, reason}}
    :throw, value -> {:error, {:throw, value}}
  end

  # Publication.

  defp publish(
         %{instance: instance, incarnation: incarnation, seq: seq, config: config} = state,
         %Snapshot{version: version} = snapshot,
         confirmed_at
       ) do
    # Slot 1: last confirmed current; slot 2: connections verified
    # read-only (a load with `read_only: :connection` has just verified them).
    freshness = :atomics.new(2, signed: true)
    :atomics.put(freshness, 1, confirmed_at)
    :atomics.put(freshness, @read_only_slot, 1)

    generation = %Generation{
      instance: instance,
      owner: self(),
      incarnation: incarnation,
      seq: seq,
      version: version,
      snapshot: snapshot,
      templates: templates(snapshot),
      admin: admin(snapshot, config),
      config: config,
      freshness: freshness
    }

    put(state, generation)
  end

  defp put(%{active: %{seq: active}} = state, %Generation{seq: seq}) when seq <= active,
    do: state

  # The state keeps only what polling and ordering need, never the
  # generation itself (see `handle_continue/2`).
  defp put(
         %{instance: instance, backoff: %{initial: initial} = backoff} = state,
         %Generation{seq: seq, version: version, freshness: freshness} = generation
       ) do
    :persistent_term.put(key(instance), generation)
    log_diagnostics(generation)
    became_ready(state)

    active = %{seq: seq, version: version, freshness: freshness}

    %{state | active: active, backoff: %{backoff | delay: initial}}
    |> remember(version, nil)
  end

  defp became_ready(%{active: nil} = state), do: schedule_poll(state)
  defp became_ready(_state), do: :ok

  defp templates(%Snapshot{permissions: permissions}) do
    for {{role, table, :select}, %Permission{status: :ok, filter: filter} = permission} <-
          permissions,
        into: %{},
        do: {{role, table}, {Permission.indexed(permission), filter}}
  end

  defp admin(%Snapshot{tables: tables}, %{admin_role: role}) when is_binary(role) do
    Map.new(tables, fn {ref, table} ->
      %Permission{filter: filter} = permission = Permission.admin(role, table)
      {ref, {permission, filter}}
    end)
  end

  defp admin(%Snapshot{}, %{}), do: %{}

  defp log_diagnostics(%Generation{snapshot: %Snapshot{diagnostics: []}}), do: :ok

  defp log_diagnostics(%Generation{
         instance: instance,
         snapshot: %Snapshot{diagnostics: [_ | _] = diagnostics}
       }) do
    Logger.warning(
      "Authzura instance #{inspect(instance)} loaded with #{length(diagnostics)} diagnostic(s); see Authzura.diagnostics/1"
    )
  end

  # Polling.

  defp schedule_poll(%{config: %{poll_interval: nil}}), do: :ok

  defp schedule_poll(%{config: %{poll_interval: interval}}),
    do: Process.send_after(self(), :poll, interval)

  defp poll_once(%{active: nil} = state), do: load(state)

  defp poll_once(
         %{
           active: %{version: version, freshness: freshness},
           config: %{clock: clock},
           last_error: last_error,
           observed_version: observed_version
         } = state
       ) do
    checked_at = now(clock)
    _verified = verify_read_only(state)

    case check_version(state) do
      {:ok, ^version, cache} ->
        :atomics.put(freshness, 1, checked_at)
        {:ok, remember(%{state | version_cache: cache}, version, nil)}

      {:ok, observed, cache} ->
        %{state | version_cache: cache} |> remember(observed, last_error) |> reload(checked_at)

      other ->
        reason = failure(other, :invalid_version_result)
        kind = error_kind(reason)
        log_version_failure(state, kind, reason)
        {{:error, reason}, remember(state, observed_version, kind)}
    end
  end

  # A version whose load failed is retried only once its backoff delay has
  # passed. The poll renews nothing meanwhile, so reads still go stale.
  defp reload(%{observed_version: observed, retry: %{version: observed, at: at}} = state, now)
       when now < at,
       do: {{:error, :reload_backoff}, state}

  defp reload(state, now) do
    case load(state) do
      {:ok, state} -> {:ok, %{state | retry: nil}}
      {error, state} -> {error, retry_later(state, now)}
    end
  end

  defp retry_later(
         %{
           observed_version: observed,
           retry: %{version: observed, delay: delay},
           backoff: %{max: ceiling}
         } = state,
         now
       ),
       do: retry_at(state, now, min(delay * 2, ceiling))

  defp retry_later(%{backoff: %{initial: initial, max: ceiling}} = state, now),
    do: retry_at(state, now, min(initial, ceiling))

  defp retry_at(%{observed_version: observed} = state, now, delay),
    do: %{state | retry: %{version: observed, at: now + delay, delay: delay}}

  defp log_version_failure(%{last_error: kind}, kind, _reason), do: :ok

  defp log_version_failure(%{instance: instance}, kind, _reason) do
    Logger.warning(
      "Authzura instance #{inspect(instance)} failed to check the permission version: #{inspect(kind)}"
    )
  end

  # Status.

  # Rewrites the status term only when its value changes. `kind` is already
  # bounded by `error_kind/1`, so a flapping raw reason can't force a write.
  defp remember(%{observed_version: observed, last_error: kind} = state, observed, kind),
    do: state

  defp remember(%{instance: instance, incarnation: incarnation} = state, observed, kind) do
    :persistent_term.put(status_key(instance), {incarnation, observed, kind})
    %{state | observed_version: observed, last_error: kind}
  end

  @doc """
  Summarizes a failure reason as a bounded `t:error_kind/0`, safe to print or
  keep: it never carries hosts, ports or other raw detail.
  """
  @spec error_kind(term()) :: error_kind()
  def error_kind({:exception, %module{}}), do: {:exception, module}
  def error_kind({:exit, reason}), do: {:exit, Telemetry.reason_class(reason)}
  def error_kind(reason), do: Telemetry.reason_class(reason)

  defp report({:error, _not_ready}) do
    %{
      ready?: false,
      fresh?: false,
      seq: 0,
      active_version: nil,
      last_confirmed_current_at: nil,
      diagnostics_count: 0
    }
  end

  defp report(
         {:ok,
          %Generation{
            seq: seq,
            version: version,
            freshness: freshness,
            snapshot: %Snapshot{diagnostics: diagnostics}
          } = generation}
       ) do
    %{
      ready?: true,
      fresh?: match?({:ok, _generation}, fresh(generation)),
      seq: seq,
      active_version: version,
      last_confirmed_current_at: :atomics.get(freshness, 1),
      diagnostics_count: length(diagnostics)
    }
  end
end

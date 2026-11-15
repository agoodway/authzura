defmodule Authzura.Telemetry do
  @moduledoc """
  Telemetry span helpers.

  Every event is prefixed with `:authzura` and emitted as a span: `:start`,
  then `:stop` or `:exception`, with the same events, measurements and
  `telemetry_span_context` as `:telemetry.span/3`.

  **Measurements.** `:start` carries `system_time` and `monotonic_time`;
  `:stop` and `:exception` carry `duration` and `monotonic_time` (native
  time units). Everything else, including `:rows`, is metadata.

  **Metadata is bounded by design.** It carries names (instance, role,
  table, relationship), categories, counts and the class of a reason or
  exception: never a session value, a literal, a SQL parameter, SQL text or
  an exception message. For detail, read the call's return value and
  `Authzura.status/1`.

    * `[:authzura, :load | :reload]` (Store): `:instance` and `:seq`; `:stop`
      adds `:result` (`:ok` or `:error`) and, on failure, `:error_class`.
    * `[:authzura, :scope]` and `[:authzura, :execute]`: `:instance` and
      `:role` (`:execute` also `:mode`; `Authzura.filter_rows/3` emits the
      scope span with `mode: :filter_rows`); `:stop` adds `result: :granted`, or
      `result: :denied` with `:reason_class`.
    * `[:authzura, :input]`: `:instance` and `:role`; `:stop` adds
      `:result`, and `:table` on success or `:reason_class` on failure.
    * `[:authzura, :query]`: one per statement a read issues (`BEGIN` and
      `COMMIT`, savepoints and Store polls are excluded), with `:instance`,
      `:category` (`:transaction_control`, `:setup` or `:data`), `:stage`
      (`:root` or `:preload`) and `:table`; `:stop` adds `:rows`. The pattern
      pre-check of an input filter is a `:setup` statement; a pattern
      Postgres refuses is an ordinary outcome, so its `:stop` carries
      `result: :rejected` instead of `:rows`. `:exception` is reserved for
      unexpected failures.
    * `[:authzura, :preload]`: one per preload node that has parents, with
      `:instance`, `:relationship`, `:depth` and `:parents`; `:stop` adds
      `:rows`.

  `:exception` adds `:kind` and `:exception_class` (the exception module,
  `:throw` or `:exit`); the exception is re-raised unchanged.
  """

  alias Postgrex.Result

  @type classify(result) :: (result -> map())

  @doc false
  # Runs `fun` inside a `[:authzura, event]` span.
  #
  # `:stop` metadata adds `result: :ok` for an `{:ok, _}` or `:ok` result,
  # `result: :error, error_class: class` for `{:error, reason}`, and
  # `result: :error` otherwise.
  @spec span(atom(), map(), (-> result)) :: result when result: term()
  def span(event, metadata, fun), do: span(event, metadata, fun, &outcome/1)

  @doc false
  # An access decision span: `:stop` adds `result: :granted` for `{:ok, _}`,
  # and `result: :denied, reason_class: class` for `{:error, reason}`.
  @spec access_span(
          atom(),
          map(),
          (-> {:ok, term()} | {:ok, term(), term()} | {:error, term()})
        ) :: {:ok, term()} | {:ok, term(), term()} | {:error, term()}
  def access_span(event, metadata, fun), do: span(event, metadata, fun, &decision/1)

  @doc false
  # A span whose `:stop` metadata is the start metadata merged with
  # `classify.(result)`. On an exception the metadata adds only `:kind` and
  # `:exception_class`, and the exception is re-raised with its stacktrace.
  @spec span(atom(), map(), (-> result), classify(result)) :: result when result: term()
  def span(event, metadata, fun, classify)
      when is_atom(event) and is_map(metadata) and is_function(fun, 0) and
             is_function(classify, 1) do
    name = [:authzura, event]
    context = make_ref()
    metadata = Map.put(metadata, :telemetry_span_context, context)
    start = System.monotonic_time()

    :telemetry.execute(
      name ++ [:start],
      %{system_time: System.system_time(), monotonic_time: start},
      metadata
    )

    try do
      fun.()
    catch
      kind, reason ->
        stacktrace = __STACKTRACE__
        stop(name ++ [:exception], start, Map.merge(metadata, raised(kind, reason)))
        :erlang.raise(kind, reason, stacktrace)
    else
      result ->
        stop(name ++ [:stop], start, Map.merge(metadata, classify.(result)))
        result
    end
  end

  @doc false
  # One SQL statement inside a `[:authzura, :query]` span. `metadata`
  # (`:instance`, `:table`, when known) is merged into the span's. `:stop`
  # adds `rows`, or `result: :rejected` when `fun` returns `:rejected`.
  @spec query(:transaction_control | :setup | :data, :root | :preload, map(), (-> result)) ::
          result
        when result: term()
  def query(category, stage, metadata, fun) when is_map(metadata),
    do: span(:query, Map.merge(metadata, %{category: category, stage: stage}), fun, &statement/1)

  defp statement(:rejected), do: %{result: :rejected}
  defp statement(result), do: %{rows: rows(result)}

  @doc """
  The class of a failure reason: the atom itself, the module of a struct,
  the first element of a tuple that starts with an atom, and `:other` for
  anything else. It never carries the reason's values.

      iex> Authzura.Telemetry.reason_class({:forbidden_columns, ["salary"]})
      :forbidden_columns
      iex> Authzura.Telemetry.reason_class(:forbidden)
      :forbidden
      iex> Authzura.Telemetry.reason_class("text")
      :other
  """
  @spec reason_class(term()) :: atom()
  def reason_class(reason) when is_atom(reason), do: reason
  def reason_class(%module{}), do: module
  def reason_class(reason) when is_tuple(reason) and tuple_size(reason) > 0, do: tag(reason)
  def reason_class(_reason), do: :other

  defp tag(tuple) when is_atom(elem(tuple, 0)), do: elem(tuple, 0)
  defp tag(_tuple), do: :other

  @doc """
  Counts the rows of a result: a list, `{:ok, rows}`, or a
  `%Postgrex.Result{}`; `nil` for anything else.

      iex> Authzura.Telemetry.rows({:ok, [%{}, %{}]})
      2
      iex> Authzura.Telemetry.rows(:error)
      nil
  """
  @spec rows(term()) :: non_neg_integer() | nil
  def rows(rows) when is_list(rows), do: length(rows)
  def rows({:ok, rows}) when is_list(rows), do: length(rows)
  def rows(%Result{num_rows: count}) when is_integer(count), do: count
  def rows(_other), do: nil

  defp stop(event, start, metadata) do
    now = System.monotonic_time()
    :telemetry.execute(event, %{duration: now - start, monotonic_time: now}, metadata)
  end

  defp raised(:error, reason) do
    %{__struct__: module} = Exception.normalize(:error, reason)
    %{kind: :error, exception_class: module}
  end

  defp raised(kind, _reason), do: %{kind: kind, exception_class: kind}

  defp outcome(:ok), do: %{result: :ok}
  defp outcome({:ok, _value}), do: %{result: :ok}
  defp outcome({:error, reason}), do: %{result: :error, error_class: reason_class(reason)}
  defp outcome(_other), do: %{result: :error}

  defp decision({:ok, _value}), do: %{result: :granted}
  defp decision({:ok, _value, _extra}), do: %{result: :granted}
  defp decision({:error, reason}), do: %{result: :denied, reason_class: reason_class(reason)}
end

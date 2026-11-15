defmodule Authzura.Bench.Gate do
  @moduledoc """
  The response-parity gate: nothing is measured for a scenario that has not
  passed it. Test harness only.

  `check/2` runs each scenario once on Hasura and once on Authzura, as the
  scenario's JWT, and passes it only when all of these hold. The first that
  fails is the scenario's reason:

    1. the instance has no `admin_role` (`:admin_role_configured`)
    2. Hasura's body carries no `errors` (`{:hasura_error, code}`)
    3. `Authzura.Parity.Verdict.classify/3` is `:match`
       (`{:verdict, verdict}`)
    4. both engines return at least one row (`:empty_response`), and at
       least one row at every preload level (`{:empty_level, path}`, the
       path of relationship names): a level with no rows would measure no
       preload work
    5. with the read's `where`, `limit`, `offset` and relationships
       stripped, the role sees strictly between 0 and all of the root
       table's rows (`:permission_filters_nothing`, or
       `:permission_hides_everything`): a permission that filters nothing
       would measure a plain table scan, one that filters everything an
       empty read

  Returns `{passed_scenarios, [{id, reason}]}`.

  Options: `:instance` (default `Authzura.Bench.instance/0`) and `:run`
  (`(scenario -> %{hasura:, authzura:})`, default runs both engines; a
  test plants a difference with it).
  """

  import Ecto.Query, only: [from: 2]

  alias Authzura.Bench
  alias Authzura.Bench.{Hasura, Repo, Scenarios}
  alias Authzura.Parity.{Read, Runner, Verdict}
  alias Authzura.Store

  @type reason ::
          :admin_role_configured
          | {:hasura_error, String.t()}
          | {:verdict, term()}
          | :empty_response
          | {:empty_level, [String.t()]}
          | :permission_filters_nothing
          | :permission_hides_everything

  @doc "Checks `scenarios`; see the moduledoc."
  @spec check([Scenarios.scenario()], keyword()) ::
          {[Scenarios.scenario()], [{String.t(), reason()}]}
  def check(scenarios, opts \\ []) do
    instance = Keyword.get(opts, :instance, Bench.instance())
    run = Keyword.get(opts, :run, &run(&1, instance))
    {:ok, %{snapshot: %{tables: tables}, config: config}} = Store.current(instance)

    {passed, failed} =
      Enum.reduce(scenarios, {[], []}, fn %{id: id} = scenario, {passed, failed} ->
        case verify(scenario, config, tables, instance, run) do
          :ok -> {[scenario | passed], failed}
          {:error, reason} -> {passed, [{id, reason} | failed]}
        end
      end)

    {Enum.reverse(passed), Enum.reverse(failed)}
  end

  @doc "Runs `scenario`'s read on both engines."
  @spec run(Scenarios.scenario(), atom()) :: %{hasura: Hasura.result(), authzura: term()}
  def run(%{read: %Read{table: table} = read, auth: auth}, instance) do
    {graphql, variables} = Runner.graphql(read)

    %{
      hasura: Hasura.query(graphql, variables, Read.root_field(table), auth),
      authzura: Runner.authzura(read, auth, instance)
    }
  end

  defp verify(scenario, config, tables, instance, run) do
    with :ok <- no_admin_role(config),
         %{hasura: hasura, authzura: authzura} <- run.(scenario),
         :ok <- no_hasura_error(hasura),
         context = Verdict.context(scenario.read, tables, divergences: []),
         :ok <- match(context, hasura, authzura),
         :ok <- not_empty(context, hasura, authzura) do
      restricts(scenario, tables, instance)
    end
  end

  defp no_admin_role(%{admin_role: nil}), do: :ok
  defp no_admin_role(_config), do: {:error, :admin_role_configured}

  defp no_hasura_error({:error, code}), do: {:error, {:hasura_error, code}}
  defp no_hasura_error({:ok, _rows}), do: :ok

  defp match(context, hasura, authzura) do
    case Verdict.classify(context, hasura, authzura) do
      :match -> :ok
      verdict -> {:error, {:verdict, verdict}}
    end
  end

  defp not_empty(%Verdict{levels: levels}, {:ok, [_ | _] = hasura}, {:ok, [_ | _] = authzura}) do
    levels
    |> Map.keys()
    |> Enum.sort()
    |> Enum.find(&empty_level?(&1, hasura, authzura))
    |> level_found()
  end

  defp not_empty(_context, _hasura, _authzura), do: {:error, :empty_response}

  defp level_found(nil), do: :ok
  defp level_found(path), do: {:error, {:empty_level, path}}

  defp empty_level?(path, hasura, authzura),
    do: rows_at(hasura, path) == [] or rows_at(authzura, path) == []

  # The rows at `path` below `rows`: an object is one row, `nil` none.
  defp rows_at(rows, []), do: rows

  defp rows_at(rows, [name | rest]),
    do: rows |> Enum.flat_map(&List.wrap(Map.get(&1, name))) |> rows_at(rest)

  # The role's visible rows of the root table, read through Authzura with
  # nothing the request adds: no where, limit, offset or relationship.
  defp restricts(%{read: %Read{table: {schema, name} = ref}, auth: auth}, tables, instance) do
    %{primary_key: key} = Map.fetch!(tables, ref)
    {:ok, session} = Runner.session(auth)

    {:ok, visible} =
      Authzura.all(from(t in name, prefix: ^schema), session, instance: instance, columns: key)

    total = Repo.aggregate(from(t in name, prefix: ^schema), :count)
    bounded(length(visible), total)
  end

  defp bounded(0, _total), do: {:error, :permission_hides_everything}
  defp bounded(visible, total) when visible < total, do: :ok
  defp bounded(_visible, _total), do: {:error, :permission_filters_nothing}
end

defmodule Authzura.ParityCase do
  @moduledoc """
  The opt-in Hasura v2.51.6 parity suite's case (`@moduletag :hasura_parity`,
  `async: false`; excluded from the default run by `test_helper.exs`).

  Run it with `mix test --only hasura_parity` against
  `docker compose --profile parity up -d` (see the Security guide's
  "Running parity tests"). **Setup is destructive** for its targets: it
  migrates and truncates the database and replaces Hasura's metadata.
  `setup_all`:

    1. waits up to 60 seconds for Hasura's `GET /healthz`
       (`AUTHZURA_PARITY_HASURA_URL`, required: there is no default)
    2. refuses a database not named `authzura_parity`
       (`AUTHZURA_PARITY_DB_URL`, required: there is no default) and a
       Hasura whose metadata holds anything the fixture does not (another
       source or connection, foreign tables, event triggers, actions and
       the like) or whose `default` source reaches another database
       (`Authzura.Parity.Guard`;
       `AUTHZURA_PARITY_CONFIRM_DESTRUCTIVE=1` overrides them all)
    3. starts `Authzura.Test.ParityRepo`, migrates the fixture schema and
       commits the seed rows (`Authzura.Parity.Fixture`)
    4. applies the fixture metadata with Hasura's `replace_metadata`, so
       Hasura writes `hdb_catalog` itself
    5. starts the Authzura instance `#{inspect(__MODULE__)}.Instance` on
       `ParityRepo` with the stock `Authzura.Sources.Hasura` source

  Tests call `assert_parity/2` with an `Authzura.Parity.Read` and an
  authentication (`t:Authzura.Parity.Hasura.auth/0`). It runs the read on
  both sides (`Authzura.Parity.Runner`), checks sampled relationships, and
  asserts that the complete values, normalized by declared column type,
  are equal or that the errors are equivalent (`Authzura.Parity.Compare`).
  """

  use ExUnit.CaseTemplate

  import ExUnit.Assertions

  alias Authzura.Parity.{Compare, Fixture, Guard, Hasura, Read, Runner}
  alias Authzura.Store
  alias Authzura.Test.ParityRepo

  @instance Module.concat(__MODULE__, Instance)

  using do
    quote do
      import Authzura.ParityCase,
        only: [assert_parity: 2, impersonate: 1, impersonate: 2, ids: 1, instance: 0, tables: 0]

      alias Authzura.Parity.{Fixture, Read}

      @moduletag :hasura_parity
    end
  end

  setup_all do
    db_url = Guard.db_url()
    :ok = Guard.check!(db_url, Fixture.tracked())

    start_supervised!({ParityRepo, url: db_url, pool_size: 2, log: false})
    Fixture.migrate!(ParityRepo)
    :ok = Fixture.seed!(ParityRepo)
    :ok = Hasura.replace_metadata(Fixture.metadata())

    start_supervised!(
      {Authzura,
       name: @instance,
       repo: ParityRepo,
       source: {Authzura.Sources.Hasura, []},
       poll_interval: nil,
       max_staleness: :infinity}
    )

    :ok = Authzura.reload(@instance)
    :ok
  end

  @doc "The suite's Authzura instance."
  @spec instance() :: atom()
  def instance, do: @instance

  @doc "The introspected tables of the instance's active snapshot."
  @spec tables() :: Compare.tables()
  def tables do
    {:ok, %{snapshot: %{tables: tables}}} = Store.current(@instance)
    tables
  end

  @doc "Admin-secret impersonation of `role` with `vars` (permission-semantics cases only)."
  @spec impersonate(String.t(), map()) :: Hasura.auth()
  def impersonate(role, vars \\ %{}), do: {:admin_impersonate, role, vars}

  @doc """
  Runs `read` through Hasura and Authzura as `auth` and asserts parity.

  Returns `{:ok, rows}` with Hasura's raw rows, or `{:error, code, reason}`
  with both errors, so a test can also pin what parity was reached on.
  """
  @spec assert_parity(Read.t(), Hasura.auth()) ::
          {:ok, [map()]} | {:error, String.t(), term()}
  def assert_parity(%Read{} = read, auth) do
    read |> Runner.run(auth, @instance) |> compare(read, tables())
  end

  @doc "The `\"id\"` of each row, in order."
  @spec ids([map()]) :: [term()]
  def ids(rows), do: Enum.map(rows, &Map.fetch!(&1, "id"))

  defp compare(%{hasura: {:ok, expected}, authzura: {:ok, actual}}, read, tables) do
    for {side, rows} <- [hasura: expected, authzura: actual] do
      with {:error, strays} <- Compare.check_samples(rows, read, tables, &Runner.members/1),
           do: flunk("#{side} returned sampled rows outside their parent: #{inspect(strays)}")
    end

    assert Compare.normalize(actual, read, tables) == Compare.normalize(expected, read, tables)
    {:ok, expected}
  end

  defp compare(%{hasura: {:error, code}, authzura: {:error, reason}}, _read, _tables) do
    assert Compare.equivalent?(code, reason),
           "Hasura failed with #{inspect(code)}, Authzura with #{inspect(reason)}"

    {:error, code, reason}
  end

  defp compare(%{hasura: hasura, authzura: authzura}, _read, _tables),
    do: flunk("Hasura returned #{inspect(hasura)}, Authzura #{inspect(authzura)}")
end

defmodule Authzura.Parity.Differential do
  @moduledoc """
  What the randomized differential suite and its replay share: the
  destructive setup (behind `Authzura.Parity.Guard.check!/2`), serving a
  batch's metadata to both engines, and running one generated case on
  both with its verdict (`Authzura.Parity.Verdict`).

  Setup migrates `authzura_parity`, commits `Authzura.Test.Seed`'s rows
  and starts an Authzura instance on the stock `Authzura.Sources.Hasura`
  source, which reads the `hdb_catalog` Hasura itself writes through
  `replace_metadata`. The instance's `admin_role` is `Authzura.Gen`'s
  `"gen_admin"`, used only by the vacuity guards' Authzura-side oracle;
  Hasura never sees it.
  """

  import ExUnit.Assertions

  alias Authzura.{Gen, Store}
  alias Authzura.Gen.Catalog
  alias Authzura.Parity.{Fixture, Guard, Hasura, Runner, Verdict}
  alias Authzura.Test.{ParityRepo, Seed}

  @type outcome :: %{
          verdict: Verdict.verdict(),
          hasura: Verdict.hasura(),
          authzura: {:ok, [map()]} | {:error, term()},
          twin: Verdict.hasura() | nil
        }

  @doc """
  Checks both targets (`Authzura.Parity.Guard.check!/2`, raising on a
  refusal) and returns the child spec of `ParityRepo` on the parity
  database.
  """
  @spec repo!() :: {module(), keyword()}
  def repo! do
    db_url = Guard.db_url()
    :ok = Guard.check!(db_url, Fixture.tracked())
    {ParityRepo, url: db_url, pool_size: 2, log: false}
  end

  @doc "Migrates the parity database and commits the seed rows (`ParityRepo` running)."
  @spec seed!() :: :ok
  def seed! do
    Fixture.migrate!(ParityRepo)
    Seed.insert!(ParityRepo)
  end

  @doc """
  The child spec of the Authzura instance `instance` on `ParityRepo`. With
  `AUTHZURA_DIFF_PUSHDOWN=1` it runs with `input_index_pushdown: true`.
  """
  @spec instance(atom()) :: {module(), keyword()}
  def instance(instance),
    do:
      {Authzura,
       name: instance,
       repo: ParityRepo,
       source: {Authzura.Sources.Hasura, []},
       admin_role: Gen.admin_role(),
       poll_interval: nil,
       max_staleness: :infinity,
       input_index_pushdown: System.get_env("AUTHZURA_DIFF_PUSHDOWN") == "1"}

  @doc """
  Applies `batch`'s permissions to Hasura (`replace_metadata`), reloads
  `instance` and checks guard (a): no `:deny` diagnostic for a generated
  role. Warnings are printed. Returns the instance's tables.
  """
  @spec load!(atom(), Gen.batch(), String.t()) :: map()
  def load!(instance, batch, label) do
    :ok = Hasura.replace_metadata(Gen.metadata(batch))
    :ok = Authzura.reload(instance)

    {:ok, diagnostics} = Authzura.diagnostics(instance)
    generated = Enum.filter(diagnostics, &generated_role?(&1.role))
    {denied, warnings} = Enum.split_with(generated, &(&1.severity == :deny))
    if warnings != [], do: IO.puts("#{label}: #{length(warnings)} warning diagnostic(s)")
    assert denied == [], "#{label}: guard (a), deny diagnostics: #{inspect(denied)}"

    {:ok, %{snapshot: %{tables: tables}}} = Store.current(instance)
    tables
  end

  @doc "Runs case `c` of `batch` on both engines and classifies the results."
  @spec run(Gen.case_t(), Gen.batch(), atom(), map()) :: outcome()
  def run(c, batch, instance, tables) do
    %{hasura: hasura, authzura: authzura} =
      Runner.run(c.read, c.auth, instance, messages: true)

    ctx = Verdict.for_case(c, batch, tables)
    twin = twin(ctx)
    ctx = if twin, do: Verdict.put_twin(ctx, twin), else: ctx

    %{
      verdict: Verdict.classify(ctx, hasura, authzura),
      hasura: hasura,
      authzura: authzura,
      twin: twin
    }
  end

  defp twin(ctx) do
    case Verdict.twin(ctx) do
      nil -> nil
      twin -> Runner.hasura(twin.read, twin.auth, messages: true)
    end
  end

  @doc "Whether `verdict` passes: a match or a reviewed divergence."
  @spec pass?(Verdict.verdict()) :: boolean()
  def pass?(:match), do: true
  def pass?({:reviewed_divergence, _id}), do: true
  def pass?(_verdict), do: false

  @doc """
  The `Authzura.Gen.Save` payload of case `c` of `batch`: the permissions
  of its role, twin and allowed roles, and the relationships its levels
  use.
  """
  @spec payload(Gen.case_t(), Gen.batch()) :: Authzura.Gen.Save.payload()
  def payload(c, batch) do
    roles = Enum.reject([c.role, c.twin | c.allowed_roles], &is_nil/1)

    relationships =
      for {[_ | _] = path, kind, table, parent, _read} <- Gen.levels(c.read) do
        {_kind, _target, mapping} = Catalog.relationship(parent, List.last(path))
        %{path: path, kind: kind, table: table, mapping: mapping}
      end

    %{
      read: c.read,
      auth: c.auth,
      permissions: Map.take(batch, roles),
      relationships: relationships
    }
  end

  @doc """
  The generated case a saved payload describes: its role is the requested
  role (else the token's default role), its twin `"<role>_twin"` when the
  payload holds that role's permissions.
  """
  @spec case_of(Authzura.Gen.Save.payload()) :: Gen.case_t()
  def case_of(
        %{read: read, auth: {:jwt, claims, requested} = auth, permissions: permissions} = payload
      ) do
    session = Map.fetch!(claims, "https://hasura.io/jwt/claims")
    role = requested || Map.fetch!(session, "x-hasura-default-role")
    twin = "#{role}_twin"

    %{
      id: "saved",
      role: role,
      read: read,
      auth: auth,
      allowed_roles: Map.fetch!(session, "x-hasura-allowed-roles"),
      denial: nil,
      twin: if(Map.has_key?(permissions, twin), do: twin),
      tags: Map.get(payload, :tags, []),
      input_tags: []
    }
  end

  defp generated_role?("gen_" <> _rest), do: true
  defp generated_role?(_role), do: false
end

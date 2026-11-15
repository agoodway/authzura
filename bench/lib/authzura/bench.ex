defmodule Authzura.Bench do
  @moduledoc """
  What the benchmark's pieces share: the Authzura instance that serves the
  bench permissions, in each mode. Test harness only.

  The instance reads the `hdb_catalog` the bench Hasura wrote through
  `replace_metadata` with the stock `Authzura.Sources.Hasura` source, and
  has **no** `admin_role`: every scenario is measured under a real role's
  permissions.

  Three modes:

    * `:default` - `Authzura.Bench.Repo` and the default
      `read_only: :transaction`
    * `:read_only_connection` - `Authzura.Bench.ReadOnlyRepo`, whose
      connections are read-only by themselves, and `read_only: :connection`.
      That option needs a `poll_interval` and a finite `max_staleness`; both
      are an hour, so no poll falls inside a measurement window
    * `:input_index_pushdown` - the `:default` repo and transaction setup
      with `input_index_pushdown: true`
  """

  alias Authzura.Bench.{ReadOnlyRepo, Repo}
  alias Authzura.Sources.Hasura

  @type mode :: :default | :read_only_connection | :input_index_pushdown

  @modes %{
    default: %{
      instance: Authzura.Bench.Instance,
      repo: Repo,
      options: [poll_interval: nil, max_staleness: :infinity]
    },
    read_only_connection: %{
      instance: Authzura.Bench.ReadOnlyInstance,
      repo: ReadOnlyRepo,
      options: [read_only: :connection, poll_interval: 3_600_000, max_staleness: 3_600_000]
    },
    input_index_pushdown: %{
      instance: Authzura.Bench.PushdownInstance,
      repo: Repo,
      options: [poll_interval: nil, max_staleness: :infinity, input_index_pushdown: true]
    }
  }

  @doc "The modes, in the order the report lists them."
  @spec modes() :: [mode()]
  def modes, do: [:default, :read_only_connection, :input_index_pushdown]

  @doc "The instance name of `mode`."
  @spec instance(mode()) :: atom()
  def instance(mode \\ :default), do: fetch!(mode).instance

  @doc "The repo `mode`'s instance reads through."
  @spec repo(mode()) :: module()
  def repo(mode \\ :default), do: fetch!(mode).repo

  @doc "The Ecto telemetry event of `mode`'s repo: one per statement it runs."
  @spec query_event(mode()) :: [atom()]
  def query_event(mode \\ :default), do: repo(mode).config()[:telemetry_prefix] ++ [:query]

  @doc """
  The child specs a process that benchmarks in `mode` needs: the repo (the
  gate and the measurements always use it), `mode`'s own repo, and its
  instance.
  """
  @spec children(mode()) :: [Supervisor.child_spec() | {module(), keyword()}]
  def children(mode \\ :default) do
    %{instance: instance, repo: repo, options: options} = fetch!(mode)

    Enum.uniq([Repo, repo]) ++
      [
        {Authzura, [name: instance, repo: repo, source: {Hasura, []}] ++ options}
      ]
  end

  defp fetch!(mode), do: Map.fetch!(@modes, mode)
end

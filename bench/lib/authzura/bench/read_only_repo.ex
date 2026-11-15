defmodule Authzura.Bench.ReadOnlyRepo do
  @moduledoc """
  The benchmark's read-only repo, on the `authzura_bench` database: every
  pool connection runs `SET default_transaction_read_only = on` when it
  connects, as a replica's or a role setting's would be. It serves the
  `read_only: :connection` mode. Test harness only.

  Its telemetry prefix is `[:authzura, :bench, :read_only_repo]`, and
  statement logging is off.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres

  alias Authzura.Bench.Env

  @impl Ecto.Repo
  def init(_type, config) do
    {:ok,
     Keyword.merge(config,
       url: Env.db_url!(),
       log: false,
       after_connect: {Postgrex, :query!, ["SET default_transaction_read_only = on", []]}
     )}
  end
end

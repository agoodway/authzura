defmodule Authzura.Bench.Repo do
  @moduledoc """
  The benchmark's repo, on the `authzura_bench` database. Test harness only.

  The URL comes from `AUTHZURA_BENCH_DB_URL` when the repo starts
  (`Authzura.Bench.Env.db_url!/0`), so the default test run never touches
  it. Statement logging is off.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres

  alias Authzura.Bench.Env

  @impl Ecto.Repo
  def init(_type, config) do
    {:ok, config |> Keyword.put(:url, Env.db_url!()) |> Keyword.put(:log, false)}
  end
end

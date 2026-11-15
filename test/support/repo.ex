defmodule Authzura.Test.Repo do
  @moduledoc false
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres
end

defmodule Authzura.Test.OtherRepo do
  @moduledoc false
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres
end

defmodule Authzura.Test.ParityRepo do
  @moduledoc """
  The opt-in parity suite's repo, on the database a real Hasura serves.

  It has no `config/test.exs` entry and no sandbox pool:
  `Authzura.ParityCase` starts it with the URL from
  `AUTHZURA_PARITY_DB_URL`, so the default test run never touches it.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres
end

defmodule Authzura.Test.ReadOnlyRepo do
  @moduledoc """
  A repo whose connections are read-only by themselves, as a replica's or a
  role setting's would be.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres

  alias Authzura.Test.Repo

  @doc """
  The options to start it with: the test repo's, a pool of `:pool_size`
  connections that each run `SET default_transaction_read_only = on`, and
  the telemetry prefix `[:authzura, :test, :read_only_repo]`.
  """
  @spec start_options(pos_integer()) :: keyword()
  def start_options(pool_size \\ 1) do
    Keyword.merge(Repo.config(),
      pool: DBConnection.ConnectionPool,
      pool_size: pool_size,
      telemetry_prefix: [:authzura, :test, :read_only_repo],
      after_connect: {Postgrex, :query!, ["SET default_transaction_read_only = on", []]}
    )
  end
end

defmodule Authzura.Test.LogRepo do
  @moduledoc """
  A repo that logs every query at `:warning` (see `config/test.exs`), which
  the test logger prints. It is never started by the test helper, so
  `mix authzura.check` starts it, as it would a host app's repo.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres
end

defmodule Authzura.Test.CubeRepo do
  @moduledoc """
  A repo whose Postgrex types module decodes `cube` (`Authzura.Test.CubeTypes`),
  as an application's would decode PostGIS types. The main test repo does not.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres
end

defmodule Authzura.Test.SingleConnectionRepo do
  @moduledoc """
  Like `Authzura.Test.CubeRepo`, with a pool of one connection: a load that
  holds a transaction leaves no second connection to probe on.
  """
  use Ecto.Repo, otp_app: :authzura, adapter: Ecto.Adapters.Postgres
end

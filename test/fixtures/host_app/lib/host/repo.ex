defmodule Host.Repo do
  use Ecto.Repo, otp_app: :host, adapter: Ecto.Adapters.Postgres
end

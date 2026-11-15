defmodule Authzura.Bench.Env do
  @moduledoc """
  The benchmark's targets, read from the environment. Test harness only.

  Nothing here has a default: the destructive steps (migrate, truncate,
  `replace_metadata`) must never reach `localhost:5432` or `localhost:8080`
  by accident, because those may well be another application.

    * `AUTHZURA_BENCH_DB_URL` - the Postgres URL; its database must be
      `authzura_bench`
    * `AUTHZURA_BENCH_HASURA_URL` - the bench Hasura's base URL
    * `AUTHZURA_BENCH_ADMIN_SECRET` - that Hasura's admin secret

  See `bench/README.md` for the values `docker-compose.yml`'s `bench`
  profile uses.
  """

  @database "authzura_bench"

  @doc "The benchmark database name, `#{@database}`."
  @spec database() :: String.t()
  def database, do: @database

  @doc "The Postgres URL; raises when unset or when it names another database."
  @spec db_url!() :: String.t()
  def db_url! do
    url = get!("AUTHZURA_BENCH_DB_URL")
    :ok = check_database!(url)
    url
  end

  @doc "The bench Hasura's base URL; raises when unset."
  @spec hasura_url!() :: String.t()
  def hasura_url!, do: "AUTHZURA_BENCH_HASURA_URL" |> get!() |> String.trim_trailing("/")

  @doc "The bench Hasura's admin secret; raises when unset."
  @spec admin_secret!() :: String.t()
  def admin_secret!, do: get!("AUTHZURA_BENCH_ADMIN_SECRET")

  @doc """
  The image tag of the bench `:postgres` or `:hasura` container, from the
  optional `AUTHZURA_BENCH_POSTGRES_IMAGE` or `AUTHZURA_BENCH_HASURA_IMAGE`
  (the report labels a tag it had to derive), or `nil`.
  """
  @spec image(:postgres | :hasura) :: String.t() | nil
  def image(:postgres), do: optional("AUTHZURA_BENCH_POSTGRES_IMAGE")
  def image(:hasura), do: optional("AUTHZURA_BENCH_HASURA_IMAGE")

  @doc "`:ok` when `url` names the `#{@database}` database, else raises."
  @spec check_database!(String.t()) :: :ok
  def check_database!(url) when is_binary(url) do
    %URI{path: path} = URI.parse(url)
    check_path!(path)
  end

  @doc "`:ok` when `repo` is connected to the `#{@database}` database, else raises."
  @spec check_connected!(module()) :: :ok
  def check_connected!(repo) when is_atom(repo) do
    %{rows: [[database]]} = repo.query!("SELECT current_database()")
    check_path!("/" <> database)
  end

  defp check_path!("/" <> @database), do: :ok

  defp check_path!(path),
    do: raise(ArgumentError, "refusing database #{inspect(path)}: not /#{@database}")

  defp optional(name) do
    case System.get_env(name) do
      value when value not in [nil, ""] -> value
      _unset -> nil
    end
  end

  defp get!(name) do
    case System.get_env(name) do
      value when value not in [nil, ""] ->
        value

      _unset ->
        raise ArgumentError,
              "#{name} is not set: the benchmark has no default target " <>
                "(see bench/README.md for the values to export)"
    end
  end
end

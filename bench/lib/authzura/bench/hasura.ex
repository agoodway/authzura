defmodule Authzura.Bench.Hasura do
  @moduledoc """
  The bench Hasura (`AUTHZURA_BENCH_HASURA_URL`), through the parity suite's
  client (`Authzura.Parity.Hasura`) with the bench's own target. Test
  harness only.

  Every request goes to `target/0`, never to the parity target, so the
  benchmark cannot reach it. Tokens are signed with
  `Authzura.Parity.Hasura.sign/1`, because the bench Hasura uses the same
  JWT secret. Only `explain/3` and `version/0` are bench-specific.
  """

  alias Authzura.Bench.Env
  alias Authzura.Parity.Hasura, as: Client
  alias Req.Response

  @namespace "https://hasura.io/jwt/claims"
  @request_timeout 60_000

  @typedoc "A Hasura GraphQL result: the root field's rows, or the first error's code."
  @type result :: Client.result()

  @doc "The bench Hasura as a `t:Authzura.Parity.Hasura.target/0`, with a 60 s timeout."
  @spec target() :: Client.target()
  def target,
    do: %{url: Env.hasura_url!(), admin_secret: Env.admin_secret!(), timeout: @request_timeout}

  @doc "Polls `GET /healthz` until it answers 200, for at most 60 seconds."
  @spec await_healthy() :: :ok | {:error, :hasura_unavailable}
  def await_healthy, do: Client.await_healthy(target())

  @doc "Hasura's current metadata (`export_metadata`)."
  @spec export_metadata() :: {:ok, map()} | {:error, term()}
  def export_metadata, do: Client.export_metadata(target())

  @doc "The database Hasura's `source` is connected to."
  @spec source_database(String.t()) :: {:ok, String.t()} | {:error, term()}
  def source_database(source), do: Client.source_database(source, target())

  @doc "Replaces Hasura's whole metadata; inconsistent metadata is an error."
  @spec replace_metadata(map()) :: :ok | {:error, term()}
  def replace_metadata(metadata), do: Client.replace_metadata(metadata, target())

  @doc """
  Runs `graphql` as `auth` and returns the rows of `root_field`, or the
  first error's `extensions.code`. A `200` that carries `errors` is an
  error here, as it is for Hasura clients.
  """
  @spec query(String.t(), map(), String.t(), Client.auth()) :: result()
  def query(graphql, variables, root_field, auth),
    do: Client.query(graphql, variables, root_field, auth, target())

  @doc """
  The SQL Hasura generates for `graphql` as the JWT's role and session
  (`POST /v1/graphql/explain`, with the admin secret): one statement per
  root field. The text carries session values; keep it in memory only.
  """
  @spec explain(String.t(), map(), Client.auth()) :: {:ok, [String.t()]} | {:error, term()}
  def explain(graphql, variables, {:jwt, claims, requested_role}) do
    user =
      claims
      |> Map.fetch!(@namespace)
      |> Map.drop(["x-hasura-allowed-roles", "x-hasura-default-role"])
      |> Map.put("x-hasura-role", requested_role)

    body = %{query: %{query: graphql, variables: variables}, user: user}
    target = target()

    case Client.post(target, "/v1/graphql/explain", body, Client.admin_headers(target)) do
      {:ok, %Response{status: 200, body: [_ | _] = fields}} ->
        {:ok, Enum.map(fields, &Map.fetch!(&1, "sql"))}

      {:ok, %Response{status: status}} ->
        {:error, {:status, status}}

      {:error, _reason} = error ->
        error
    end
  end

  @doc "The bench Hasura's version (`GET /v1/version`), such as `\"v2.51.6\"`."
  @spec version() :: {:ok, String.t()} | {:error, term()}
  def version do
    case Req.get(Env.hasura_url!() <> "/v1/version", retry: false) do
      {:ok, %Response{status: 200, body: %{"version" => version}}} -> {:ok, version}
      other -> {:error, other}
    end
  end
end

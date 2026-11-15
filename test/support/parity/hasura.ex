defmodule Authzura.Parity.Hasura do
  @moduledoc """
  A minimal HTTP client, over `Req` (a test-only dependency), for the real
  Hasura v2 the parity suite runs against. Requests never retry and time
  out after 30 seconds.

  The endpoint and secrets come from the environment. The endpoint has no
  default (`url/0` raises when it is unset); the secrets default to
  `docker-compose.yml`'s `parity` profile:

    * `AUTHZURA_PARITY_HASURA_URL` - required, e.g. `http://localhost:8080`
    * `AUTHZURA_PARITY_ADMIN_SECRET` - default `parity`
    * `AUTHZURA_PARITY_JWT_KEY` - the HS256 key of
      `HASURA_GRAPHQL_JWT_SECRET`, default
      `authzura-parity-test-key-0123456789abcdef`

  GraphQL requests authenticate in one of these ways (`t:auth/0`):

    * `{:admin_impersonate, role, vars}` - the admin secret plus
      `x-hasura-role` and the session variables as headers. Hasura applies
      the role's permissions without resolving roles, so this is only for
      permission-semantics cases.
    * `{:jwt, claims, requested_role}` - an HS256 token signed with the
      JWT key, plus `x-hasura-role` when `requested_role` is not `nil`, and
      no admin secret. This is the role-resolution path.
    * `{:token, token, requested_role}` - like `:jwt`, with a token the
      test built itself (a bad signature, say).

  `:admin` (the admin secret alone) reads without any permission; the
  runner uses it only to fetch reference rows.

  Every request goes to a `t:target/0`: the parity Hasura by default
  (`parity_target/0`). The benchmark passes its own (`Authzura.Bench.Hasura`),
  so it never reaches the parity target.
  """

  alias Authzura.Parity.Guard
  alias JOSE.{JWK, JWS, JWT}
  alias Req.Response

  @type auth ::
          {:admin_impersonate, String.t(), %{String.t() => String.t()}}
          | {:jwt, map(), String.t() | nil}
          | {:token, String.t(), String.t() | nil}

  @typedoc "Where requests go: the base URL, the admin secret and the request timeout (ms)."
  @type target :: %{url: String.t(), admin_secret: String.t(), timeout: pos_integer()}

  @typedoc "Rows of the root field, or the first error's `extensions.code`."
  @type result :: {:ok, [map()]} | {:error, String.t()}

  @typedoc """
  `request/4`'s raw result: the rows and the whole body, or the first
  error's code and message and the whole body. A response that carries
  `errors` is an error, even beside `data`.
  """
  @type raw :: {:ok, [map()], map()} | {:error, String.t(), String.t(), map()}

  @health_timeout 60_000
  @health_interval 500
  @request_timeout 30_000

  @doc "The Hasura base URL, `AUTHZURA_PARITY_HASURA_URL`; raises when unset."
  @spec url() :: String.t()
  def url, do: Guard.env!("AUTHZURA_PARITY_HASURA_URL")

  @doc "The parity Hasura: `url/0`, `AUTHZURA_PARITY_ADMIN_SECRET` and a 30 s timeout."
  @spec parity_target() :: target()
  def parity_target,
    do: %{
      url: url(),
      admin_secret: System.get_env("AUTHZURA_PARITY_ADMIN_SECRET", "parity"),
      timeout: @request_timeout
    }

  @doc "The HS256 key Hasura verifies JWTs with."
  @spec jwt_key() :: String.t()
  def jwt_key,
    do: System.get_env("AUTHZURA_PARITY_JWT_KEY", "authzura-parity-test-key-0123456789abcdef")

  @doc """
  Polls `GET /healthz` until it answers 200, for at most 60 seconds.
  Returns `{:error, :hasura_unavailable}` on timeout.
  """
  @spec await_healthy(target()) :: :ok | {:error, :hasura_unavailable}
  def await_healthy(target \\ parity_target()),
    do: await_healthy(target, System.monotonic_time(:millisecond) + @health_timeout)

  @doc "Hasura's current metadata, through `export_metadata`."
  @spec export_metadata(target()) :: {:ok, map()} | {:error, term()}
  def export_metadata(target \\ parity_target()) do
    case metadata_request(target, %{type: "export_metadata", args: %{}}) do
      {:ok, %Response{status: 200, body: metadata}} -> {:ok, metadata}
      other -> {:error, other}
    end
  end

  @doc """
  The database Hasura's source `source` is connected to, from a read-only
  `run_sql` of `SELECT current_database()`.
  """
  @spec source_database(String.t(), target()) :: {:ok, String.t()} | {:error, term()}
  def source_database(source, target \\ parity_target()) when is_binary(source) do
    args = %{source: source, sql: "SELECT current_database()", read_only: true}

    case post(target, "/v2/query", %{type: "run_sql", args: args}, admin_headers(target)) do
      {:ok, %Response{status: 200, body: %{"result" => [_header, [database]]}}} ->
        {:ok, database}

      other ->
        {:error, other}
    end
  end

  @doc """
  Replaces Hasura's whole metadata with `metadata` (format v3) through
  `replace_metadata`. Inconsistent metadata is an error.
  """
  @spec replace_metadata(map(), target()) :: :ok | {:error, term()}
  def replace_metadata(metadata, target \\ parity_target()) when is_map(metadata) do
    args = %{metadata: metadata, allow_inconsistent_metadata: false}

    case metadata_request(target, %{type: "replace_metadata", args: args}) do
      {:ok, %Response{status: 200}} -> :ok
      {:ok, %Response{status: status, body: body}} -> {:error, {status, body}}
      error -> error
    end
  end

  @doc """
  Runs `graphql` (with `variables`) and returns the rows of `root_field`, or
  the first error's `extensions.code`.
  """
  @spec query(String.t(), map(), String.t(), auth() | :admin, target()) :: result()
  def query(graphql, variables, root_field, auth, target \\ parity_target())
      when is_binary(graphql) do
    case request(graphql, variables, root_field, auth, target) do
      {:ok, rows, _body} -> {:ok, rows}
      {:error, code, _message, _body} -> {:error, code}
    end
  end

  @doc """
  Like `query/4`, but keeps the first error's message and the whole body
  (`t:raw/0`).
  """
  @spec request(String.t(), map(), String.t(), auth() | :admin, target()) :: raw()
  def request(graphql, variables, root_field, auth, target \\ parity_target())
      when is_binary(graphql) do
    target
    |> post("/v1/graphql", %{query: graphql, variables: variables}, auth_headers(auth, target))
    |> rows(root_field)
  end

  @doc "POSTs `body` as JSON to `path` on `target`, never retrying."
  @spec post(target(), String.t(), map(), [{String.t(), String.t()}]) ::
          {:ok, Response.t()} | {:error, Exception.t()}
  def post(%{url: url, timeout: timeout}, path, body, headers),
    do:
      Req.post(url <> path, json: body, headers: headers, retry: false, receive_timeout: timeout)

  @doc "The admin-secret header of `target`."
  @spec admin_headers(target()) :: [{String.t(), String.t()}]
  def admin_headers(%{admin_secret: secret}), do: [{"x-hasura-admin-secret", secret}]

  @doc "Signs `claims` as an HS256 JWT with `key` (default `jwt_key/0`)."
  @spec sign(map(), String.t()) :: String.t()
  def sign(claims, key \\ jwt_key()) when is_map(claims) do
    {_jws, token} =
      key |> JWK.from_oct() |> JWT.sign(%{"alg" => "HS256"}, claims) |> JWS.compact()

    token
  end

  # `errors` first: a 200 may carry them beside partial `data`.
  defp rows({:ok, %Response{body: %{"errors" => [first | _]} = body}}, _root_field) do
    %{"extensions" => %{"code" => code}} = first
    {:error, code, Map.get(first, "message", ""), body}
  end

  defp rows({:ok, %Response{status: 200, body: %{"data" => data} = body}}, root_field)
       when is_map_key(data, root_field),
       do: {:ok, Map.fetch!(data, root_field), body}

  defp rows(other, _root_field), do: raise("unexpected Hasura response: #{inspect(other)}")

  defp await_healthy(target, deadline) do
    with {:error, _reason} <- healthz(target),
         true <- System.monotonic_time(:millisecond) < deadline do
      Process.sleep(@health_interval)
      await_healthy(target, deadline)
    else
      :ok -> :ok
      false -> {:error, :hasura_unavailable}
    end
  end

  defp healthz(%{url: url}) do
    case Req.get(url <> "/healthz", retry: false, receive_timeout: 2_000, decode_body: false) do
      {:ok, %Response{status: 200}} -> :ok
      other -> {:error, other}
    end
  end

  defp metadata_request(target, body),
    do: post(target, "/v1/metadata", body, admin_headers(target))

  defp auth_headers(:admin, target), do: admin_headers(target)

  defp auth_headers({:admin_impersonate, role, vars}, target),
    do: admin_headers(target) ++ [{"x-hasura-role", role} | Map.to_list(vars)]

  defp auth_headers({:jwt, claims, requested_role}, target),
    do: auth_headers({:token, sign(claims), requested_role}, target)

  defp auth_headers({:token, token, requested_role}, _target),
    do: [{"authorization", "Bearer " <> token} | role_header(requested_role)]

  defp role_header(nil), do: []
  defp role_header(role), do: [{"x-hasura-role", role}]
end

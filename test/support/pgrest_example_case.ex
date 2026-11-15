defmodule Authzura.PgRestExampleCase do
  @moduledoc """
  Sandboxed case for the PgRest example suite: seeds two organizations,
  starts the Authzura instance and PgRest registry, and serves requests.

  Seed: org 1 has lists 1 (owner 10), 2 (owner 11) and 3 (owner 10); org 2 has
  list 4 (owner 20). Each list has items `id = list * 10 + n`.
  """

  use ExUnit.CaseTemplate

  import Plug.Test, only: [conn: 3]

  alias Authzura.{HasuraFixture, PgRestExample}
  alias Authzura.PgRestExample.{Endpoint, TodoItem, TodoList}
  alias Authzura.Test.Repo
  alias Ecto.Adapters.SQL.Sandbox
  alias PgRest.Registry, as: PgRestRegistry
  alias Plug.Conn

  using do
    quote do
      import Authzura.PgRestExampleCase, only: [get: 3, request: 4, request: 5, request: 6]
    end
  end

  setup do
    owner = Sandbox.start_owner!(Repo, shared: true)
    on_exit(fn -> Sandbox.stop_owner(owner) end)

    seed!()
    instance = HasuraFixture.start_instance!(:todo_authz, Repo, PgRestExample.metadata())
    start_supervised!({PgRestRegistry, modules: [TodoList, TodoItem]})
    {:ok, instance: instance, opts: Endpoint.init(instance: instance, repo: Repo)}
  end

  @doc """
  Runs `GET path` as `role` with `vars` and returns `{status, decoded_body}`.

  `ctx` is the test context holding the endpoint options.
  """
  @spec get(map(), String.t(), {String.t(), map()}) :: {non_neg_integer(), term()}
  def get(ctx, path, identity), do: request(ctx, :get, path, identity)

  @doc "Runs a request with optional headers and body; returns its status and decoded body."
  @spec request(
          map(),
          atom(),
          String.t(),
          {String.t(), map()},
          [{String.t(), String.t()}],
          map() | nil
        ) ::
          {non_neg_integer(), term()}
  def request(%{opts: opts}, method, path, {role, vars}, headers \\ [], body \\ nil) do
    conn =
      method
      |> conn(path, body)
      |> put_headers(headers)
      |> Conn.assign(:hasura_vars, Map.put(vars, "x-hasura-role", role))
      |> Endpoint.call(opts)

    {conn.status, Jason.decode!(conn.resp_body)}
  end

  defp put_headers(conn, headers) do
    Enum.reduce(headers, conn, fn {name, value}, conn ->
      Conn.put_req_header(conn, name, value)
    end)
  end

  defp seed! do
    Repo.query!("INSERT INTO orgs (id, name) VALUES (1, 'acme'), (2, 'globex')")

    Repo.query!("""
    INSERT INTO todo_lists (id, org_id, owner_id, title, assignee_notes) VALUES
      (1, 1, 10, 'groceries', 'secret-1'), (2, 1, 11, 'taxes', 'secret-2'),
      (3, 1, 10, 'garden', 'secret-3'), (4, 2, 20, 'launch', 'secret-4')
    """)

    Repo.query!("""
    INSERT INTO todo_items (id, list_id, body, done)
    SELECT l * 10 + n, l, 'item ' || l || '.' || n, n = 1 FROM generate_series(1, 4) l, generate_series(1, 2) n
    """)
  end
end

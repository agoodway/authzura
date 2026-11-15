defmodule Authzura.PgRestExample do
  @moduledoc """
  A contrived multi-tenant to-do API: PgRest serves it, Authzura decides what
  each role may read.

  The pieces an adopter writes:

    * resources (`TodoList`, `TodoItem`) describing the tables;
    * `Gate`, a `PgRest.Authorization` query callback granting reads;
    * `Endpoint`, the plug that builds the Hasura session from the request and
      forwards to `PgRest.Plug`.

  Resources must set `@schema_prefix` to the instance's `default_prefix`:
  `filter_rows/3` pins the root prefix, and PgRest rejects a hook query that
  changes the base scope's prefix.

  Test-only: nothing in `lib/` depends on PgRest.
  """

  alias Authzura.HasuraFixture

  @doc """
  Hasura metadata for the example: roles `owner`, `member`, `viewer`,
  `capped` (one list), `capped_items` (one item per list), `analyst` (aggregates)
  and `nested_analyst` (aggregates only in embeds).
  """
  @spec metadata() :: map()
  def metadata do
    lists = {"public", "todo_lists"}
    items = {"public", "todo_items"}
    all = ["id", "org_id", "owner_id", "title", "assignee_notes"]
    org = %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}

    HasuraFixture.metadata([
      %{
        table: lists,
        array_relationships: [
          %{
            name: "todo_items",
            using: %{foreign_key_constraint_on: %{table: items, column: "list_id"}}
          }
        ],
        select_permissions: [
          perm("owner", all, %{"owner_id" => %{"_eq" => "X-Hasura-User-Id"}}),
          perm("member", all, org),
          perm("viewer", all -- ["assignee_notes"], org),
          perm("capped", all, org, limit: 1),
          perm("capped_items", all, org),
          perm("analyst", all, org, allow_aggregations: true),
          perm("nested_analyst", all, org,
            allow_aggregations: true,
            query_root_fields: ["select"]
          )
        ]
      },
      %{
        table: items,
        object_relationships: [
          %{name: "todo_list", using: %{foreign_key_constraint_on: "list_id"}}
        ],
        select_permissions: [
          perm("owner", "*", through_list("owner_id", "X-Hasura-User-Id")),
          perm("member", "*", through_list("org_id", "X-Hasura-Org-Id")),
          perm("viewer", "*", through_list("org_id", "X-Hasura-Org-Id")),
          perm("capped_items", "*", through_list("org_id", "X-Hasura-Org-Id"), limit: 1),
          perm("analyst", "*", through_list("org_id", "X-Hasura-Org-Id"),
            allow_aggregations: true
          ),
          perm("nested_analyst", "*", through_list("org_id", "X-Hasura-Org-Id"),
            allow_aggregations: true,
            query_root_fields: ["select"]
          )
        ]
      }
    ])
  end

  defp perm(role, columns, filter, extra \\ []) do
    [%{permission: permission} = entry] =
      HasuraFixture.select_permissions(role, columns, filter)

    %{entry | permission: Enum.into(extra, permission)}
  end

  defp through_list(column, variable), do: %{"todo_list" => %{column => %{"_eq" => variable}}}

  defmodule TodoList do
    @moduledoc false
    use Ecto.Schema
    use PgRest.Resource

    alias Authzura.PgRestExample.TodoItem

    @type t :: %__MODULE__{}

    @schema_prefix "public"
    @primary_key {:id, :integer, autogenerate: false}
    schema "todo_lists" do
      field(:org_id, :integer)
      field(:owner_id, :integer)
      field(:title, :string)
      field(:assignee_notes, :string)
      has_many(:todo_items, TodoItem, foreign_key: :list_id)
    end
  end

  defmodule TodoItem do
    @moduledoc false
    use Ecto.Schema
    use PgRest.Resource

    alias Authzura.PgRestExample.TodoList

    @type t :: %__MODULE__{}

    @schema_prefix "public"
    @primary_key {:id, :integer, autogenerate: false}
    schema "todo_items" do
      field(:body, :string)
      field(:done, :boolean)
      belongs_to(:todo_list, TodoList, foreign_key: :list_id)
    end
  end
end

defmodule Authzura.PgRestExample.Gate do
  @moduledoc """
  Grants reads through Authzura's row filter and permission options.

  PgRest applies the physical column allowlist and per-parent cap at every
  resource path, including aliased and nested embeds. Other operations are
  denied, including execution plans, which can expose bound values.
  """
  @behaviour PgRest.Authorization

  alias Authzura.{Model.Permission, Scope, Session}

  @impl PgRest.Authorization
  def authorize_query(
        _conn,
        _resource,
        :read,
        query,
        %{
          authz: %{instance: instance, session: %Session{} = session}
        } = context
      ) do
    with {:ok, filtered, %Permission{} = permission} <-
           Authzura.filter_rows(query, session, instance: instance) do
      aggregates? = aggregates?(permission, context)

      {:ok, filtered,
       columns: permission.columns,
       limit: permission.limit,
       aggregates: aggregates?,
       count: aggregates?}
    end
  end

  def authorize_query(_conn, _resource, _operation, _query, _context),
    do: {:error, :unsupported}

  defp aggregates?(%Permission{allow_aggregations: false}, _context), do: false
  defp aggregates?(%Permission{allow_aggregations: true}, %{root?: false}), do: true

  defp aggregates?(%Permission{allow_aggregations: true} = permission, _context),
    do: Scope.root_field(permission, :select_aggregate) == :ok
end

defmodule Authzura.PgRestExample.Endpoint do
  @moduledoc """
  Forwards to `PgRest.Plug` with the Hasura session of the request.

  `conn.assigns.hasura_vars` carries the session variables (an upstream plug
  verifies a JWT with `Authzura.JWT` in a real app). A request without a valid
  session reaches the `Gate` with no session and is refused.
  """

  @behaviour Plug

  alias Authzura.PgRestExample.Gate
  alias Authzura.Session
  alias PgRest.Plug, as: PgRestPlug
  alias Plug.Conn

  @impl Plug
  def init(opts) do
    instance = Keyword.fetch!(opts, :instance)

    PgRestPlug.init(
      repo: Keyword.fetch!(opts, :repo),
      authorization: Gate,
      aggregates: true,
      plan_enabled: true,
      anonymous?: fn _conn, %{authz: %{session: session}} -> is_nil(session) end,
      context_builder: fn conn, _opts ->
        %{authz: %{instance: instance, session: session_of(conn)}}
      end
    )
  end

  @impl Plug
  def call(conn, opts), do: PgRestPlug.call(conn, opts)

  defp session_of(%Conn{assigns: assigns}),
    do: assigns |> Map.get(:hasura_vars, %{}) |> Session.new([]) |> unwrap()

  defp unwrap({:ok, %Session{} = session}), do: session
  defp unwrap({:error, _reason}), do: nil
end

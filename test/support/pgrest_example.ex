if Code.ensure_loaded?(PgRest) do
  defmodule Authzura.PgRestExample do
    @moduledoc """
    A contrived multi-tenant to-do API: PgRest serves it, Authzura decides what
    each role may read.

    The pieces an adopter writes:

      * resources (`TodoList`, `TodoItem`) whose `scope/2` and `after_load/2`
        call `Authzura.PgRestExample.Policy`;
      * `Gate`, a `PgRest.Authorization` module, the yes/no check before any SQL;
      * `Endpoint`, the plug that builds the Hasura session from the request and
        forwards to `PgRest.Plug`.

    Test-only: nothing in `lib/` depends on PgRest.
    """

    alias Authzura.HasuraFixture

    @doc """
    Hasura metadata for the example: roles `owner`, `member`, `viewer` and
    `capped` (a member limited to one row, which PgRest cannot express).
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
            perm("capped", all, org, limit: 1)
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
            perm("viewer", "*", through_list("org_id", "X-Hasura-Org-Id"))
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

    defmodule Policy do
      @moduledoc """
      The Authzura half of the integration, shared by every resource.

      PgRest's `scope/2` may only add `where`, `join` and `distinct`, while
      `Authzura.scope/3` also pins the select list and the limit. `scope/2`
      therefore uses `Authzura.filter_rows/3`, which adds only the permission's
      row filter, and `after_load/2` keeps only the permitted columns. PgRest
      cannot deny from `scope/2`, so `filter/2` reports every denial, including
      a permission with a row limit (which `scope/2` cannot express), for the
      `Gate` to refuse before `scope/2` runs.
      """

      alias Authzura.Model.Permission
      alias Authzura.Session
      alias Ecto.{Query, Queryable}

      @typedoc "What `Endpoint` puts into the PgRest context."
      @type authz :: %{instance: atom(), session: Session.t()}

      @typedoc "The PgRest context: the repo plus the Authzura state."
      @type context :: %{required(:authz) => authz(), optional(atom()) => term()}

      @doc "The query with the role's row filter applied, or why the role may not read it."
      @spec filter(Queryable.t(), authz()) :: {:ok, Query.t()} | {:error, term()}
      def filter(queryable, %{instance: instance, session: session}) do
        with {:ok, filtered, permission} <-
               Authzura.filter_rows(queryable, session, instance: instance),
             do: unlimited(filtered, permission)
      end

      # PgRest has no hook for a row limit yet, so a limited permission is refused.
      defp unlimited(%Query{} = query, %Permission{limit: nil}), do: {:ok, query}
      defp unlimited(%Query{}, %Permission{}), do: {:error, :row_limit_unsupported}

      @doc "Applies the role's row filter to `query`. The `Gate` has already accepted it."
      @spec scope(Query.t(), context()) :: Query.t()
      def scope(%Query{} = query, %{authz: authz}) do
        {:ok, filtered} = filter(query, authz)
        filtered
      end

      @doc """
      Keeps the permitted columns of `row` and its embeds, nothing else. Output
      names that are neither (select aliases) are dropped.
      """
      @spec visible(map(), module(), context()) :: map()
      def visible(row, resource, %{authz: %{instance: instance, session: session}}) do
        {:ok, columns} = Authzura.allowed_columns(session, resource, instance: instance)
        embeds = Enum.map(resource.__schema__(:associations), &Atom.to_string/1)
        Map.take(row, columns ++ embeds)
      end
    end

    defmodule TodoList do
      @moduledoc false
      use Ecto.Schema
      use PgRest.Resource, after_load: true

      alias Authzura.PgRestExample.{Policy, TodoItem}

      @type t :: %__MODULE__{}

      @primary_key {:id, :integer, autogenerate: false}
      schema "todo_lists" do
        field(:org_id, :integer)
        field(:owner_id, :integer)
        field(:title, :string)
        field(:assignee_notes, :string)
        has_many(:todo_items, TodoItem, foreign_key: :list_id)
      end

      @impl PgRest.Resource
      def scope(query, context), do: Policy.scope(query, context)

      @impl PgRest.Resource
      def after_load(row, context), do: Policy.visible(row, __MODULE__, context)
    end

    defmodule TodoItem do
      @moduledoc false
      use Ecto.Schema
      use PgRest.Resource

      alias Authzura.PgRestExample.{Policy, TodoList}

      @type t :: %__MODULE__{}

      @primary_key {:id, :integer, autogenerate: false}
      schema "todo_items" do
        field(:body, :string)
        field(:done, :boolean)
        belongs_to(:todo_list, TodoList, foreign_key: :list_id)
      end

      @impl PgRest.Resource
      def scope(query, context), do: Policy.scope(query, context)
    end
  end

  defmodule Authzura.PgRestExample.RequestColumns do
    @moduledoc """
    Every column a read request names, per resource, taken from PgRest's own
    grammar and planner parameter grouping: select items (with aliases, casts,
    JSON paths and aggregates), filters (with `not`, `or` and `and` groups),
    `order` terms and the same for each embed, at any depth.

    `*` names every column of its resource, so for a role with hidden columns it is
    refused at that level: columns must be named explicitly.

    It fails closed: a request PgRest's parser rejects, an embed that is not an
    Ecto association of its parent, or parameters for an embed the select does
    not contain all give `:error`.
    """

    alias Authzura.Util
    alias PgRest.AST.{Aggregate, Condition, Embed, Field, Logic, OrderTerm, SelectField}
    alias PgRest.Grammar.Select
    alias PgRest.Planner.Params
    alias PgRest.Request.QueryString

    @doc "Column names per resource for `query_string`, read against `root`."
    @spec of(String.t(), module()) :: {:ok, [{module(), [String.t()]}]} | :error
    def of(query_string, root) do
      with {:ok, params} <- QueryString.parse(query_string),
           params = for({key, value} <- params, is_binary(value), do: {key, value}),
           {:ok, items} <- select(params),
           {:ok, groups} <- Params.group(params, root.__pgrest_config__().custom_params),
           {:ok, nodes} <- nodes(root, items, []),
           paths = Map.new(nodes, fn {path, resource, _items} -> {path, resource} end),
           :ok <- known_paths(groups, paths),
           :ok <- known_nodes(nodes, groups),
           {:ok, ordered} <- Util.map_ok(order_terms(groups), &order_ref(&1, paths)) do
        {:ok,
         nodes
         |> refs(groups)
         |> Kernel.++(ordered)
         |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
         |> Map.to_list()}
      else
        _failure -> :error
      end
    end

    defp select(params) do
      case Params.last_value(params, "select") do
        nil -> {:ok, [%SelectField{field: :star}]}
        value -> Select.parse(value)
      end
    end

    # `{embed output path, resource, select items}` for the root and every embed.
    defp nodes(resource, items, path) do
      embeds = for %Embed{} = embed <- items, do: embed

      with {:ok, nested} <- Util.map_ok(embeds, &nested(resource, &1, path)) do
        {:ok, [{path, resource, items} | Enum.concat(nested)]}
      end
    end

    defp nested(resource, %Embed{name: name, alias: alias, select: select}, path) do
      with {:ok, related} <- related(resource, name),
           do: nodes(related, select, path ++ [alias || name])
    end

    defp related(resource, name) do
      case Enum.find(resource.__schema__(:associations), &(Atom.to_string(&1) == name)) do
        nil -> :error
        association -> {:ok, resource.__schema__(:association, association).related}
      end
    end

    defp known_paths(groups, paths),
      do: groups |> Map.keys() |> Enum.all?(&is_map_key(paths, &1)) |> known()

    # PgRest's AST is internal and gains node kinds (casts, spreads,
    # aggregates); a node this walker does not know refuses the request
    # rather than naming no column.
    defp known_nodes(nodes, groups) do
      items = for {_path, _resource, items} <- nodes, item <- items, do: item
      conditions = for {_path, %{where: where}} <- groups, condition <- where, do: condition

      known(Enum.all?(items, &known_item?/1) and Enum.all?(conditions, &known_condition?/1))
    end

    defp known_item?(%SelectField{field: :star}), do: true
    defp known_item?(%SelectField{field: %Field{}}), do: true
    defp known_item?(%Aggregate{field: nil}), do: true
    defp known_item?(%Aggregate{field: %Field{}}), do: true
    defp known_item?(%Embed{}), do: true
    defp known_item?(_item), do: false

    defp known_condition?(%Condition{field: %Field{}}), do: true

    defp known_condition?(%Logic{children: children}),
      do: Enum.all?(children, &known_condition?/1)

    defp known_condition?(_condition), do: false

    defp known(true = _all_known?), do: :ok
    defp known(false), do: :error

    defp refs(nodes, groups) do
      for {path, resource, items} <- nodes,
          %{where: where} = Map.get(groups, path, Params.empty_group()),
          name <-
            Enum.flat_map(items, &select_names(&1, resource)) ++
              Enum.flat_map(where, &where_names/1),
          do: {resource, name}
    end

    defp order_terms(groups),
      do: for({path, %{order: terms}} <- groups, term <- terms || [], do: {path, term})

    # `rel(field).asc` orders by a column of the to-one embed `rel`.
    defp order_ref({path, %OrderTerm{field: %Field{name: name}, relation: relation}}, paths) do
      with {:ok, resource} <- Map.fetch(paths, path ++ List.wrap(relation)),
           do: {:ok, {resource, name}}
    end

    # `*` names every column of the resource, spread embeds included: PgRest skips
    # `after_load/2` for spreads, so nothing may rely on it to hide a column.
    defp select_names(%SelectField{field: :star}, resource), do: columns(resource)
    defp select_names(%SelectField{field: %Field{name: name}}, _resource), do: [name]
    defp select_names(%Aggregate{field: %Field{name: name}}, _resource), do: [name]
    defp select_names(_item, _resource), do: []

    defp columns(resource) do
      for field <- resource.__schema__(:fields),
          do: Atom.to_string(resource.__schema__(:field_source, field))
    end

    defp where_names(%Condition{field: %Field{name: name}}), do: [name]
    defp where_names(%Logic{children: children}), do: Enum.flat_map(children, &where_names/1)
  end

  defmodule Authzura.PgRestExample.Gate do
    @moduledoc """
    The yes/no check PgRest runs before any SQL, for the root and every embed.

    A resource passes when `Policy.filter/2` accepts it: the role has a select
    permission, the session carries the variables it needs and the permission
    has no row limit. On the root the gate also reads every column the request
    names, in the root and in every embed (`RequestColumns`), and refuses the
    request when the role may not read one: a filter, `order` or alias on a
    hidden column would otherwise reveal its values.

    Known limitations: the check re-parses the query string with PgRest's own
    grammar, so it follows PgRest's parsing but not its resource resolution
    (an embed must be an Ecto association of its parent, otherwise the request
    is refused); and it sees only reads, the one operation PgRest 0.2 serves.
    """

    @behaviour PgRest.Authorization

    alias Authzura.PgRestExample.{Policy, RequestColumns}
    alias Authzura.{Session, Util}
    alias Plug.Conn

    @impl PgRest.Authorization
    def authorize(conn, resource, :read, %{authz: %{session: %Session{}} = authz}) do
      with {:ok, _query} <- Policy.filter(resource, authz),
           :ok <- check_columns(conn, resource, authz) do
        :ok
      else
        _denied -> {:error, "forbidden"}
      end
    end

    def authorize(_conn, _resource, _operation, _context), do: {:error, "no session"}

    defp check_columns(%Conn{path_info: [table]} = conn, resource, authz),
      do: check_columns(conn, resource, authz, resource.__schema__(:source) == table)

    defp check_columns(_conn, _resource, _authz, false), do: :ok

    defp check_columns(%Conn{query_string: query_string}, resource, authz, true) do
      case RequestColumns.of(query_string, resource) do
        {:ok, referenced} -> Util.first_error(referenced, &denial(&1, authz))
        :error -> :error
      end
    end

    defp denial({resource, columns}, %{instance: instance, session: session}),
      do: Authzura.validate_columns(session, resource, columns, instance: instance)
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
end

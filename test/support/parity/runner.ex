defmodule Authzura.Parity.Runner do
  @moduledoc """
  Runs one `Authzura.Parity.Read` through Hasura GraphQL and through
  Authzura, with the same authentication, and returns both raw results.

  ## Hasura side

  `graphql/1` renders the read as one GraphQL query: the root field with
  `where` as a typed variable (`<root>_bool_exp`), `order_by`, `limit` and
  `offset` as literals, the columns, and every relationship as a nested field with
  its own `order_by`. The result is the root field's rows, or the first
  error's `extensions.code` (see `Authzura.Parity.Hasura.query/4`).
  `run/4` with `messages: true` keeps the error's message as well, as
  `{:error, code, message}` (`Authzura.Parity.Hasura.request/4`).

  A column whose GraphQL name differs from its database name
  (`Authzura.Parity.Fixture.graphql_names/1`, e.g. `"line item"` is
  `line_item`) is renamed in the root's selection, `where` and `order_by`,
  and renamed back in the returned rows, so both sides' rows carry
  database names. No fixture relationship targets such a table, so only
  the root is renamed.

  ## Authzura side

  The session comes from the same authentication: `{:admin_impersonate,
  role, vars}` becomes `Authzura.Session.new/2` on the vars plus
  `x-hasura-role`, and `{:jwt, claims, requested_role}` verifies the same
  signed token with `Authzura.JWT.verify/2`. A read with `where` runs
  through `Authzura.all_input/4` with the JSON request
  (`columns`/`filter`/`order_by`/`limit`/`offset`/`preload`); any other
  through `Authzura.all/3` on a schemaless `from(t in name, prefix: schema)`
  with the order, limit and offset applied and the relationships as `preload:`.

  `members/1` reads a sampled relationship's whole target table through
  Hasura's admin role, for `Authzura.Parity.Compare.check_samples/4`.
  `{:token, token, role}` sends and verifies a token the test built.

  The runner never compares anything; it only produces the two results, so
  a randomized differential driver can reuse it with its own reads.
  """

  import Ecto.Query, only: [from: 2, limit: 2, offset: 2, order_by: 2]

  alias Authzura.{JWT, Session}
  alias Authzura.Parity.{Fixture, Hasura, Read}
  alias Authzura.Test.InternalRead
  alias Ecto.Query

  @type hasura_result :: Hasura.result() | {:error, String.t(), String.t()}
  @type results :: %{hasura: hasura_result(), authzura: {:ok, [map()]} | {:error, term()}}

  @bool_lists ["_and", "_or"]

  @doc """
  Runs `read` on both sides as `auth`, Authzura through `instance`.
  `messages: true` keeps Hasura's error message (see the moduledoc).
  """
  @spec run(Read.t(), Hasura.auth(), atom(), keyword()) :: results()
  def run(%Read{} = read, auth, instance, opts \\ []),
    do: %{hasura: hasura(read, auth, opts), authzura: authzura(read, auth, instance)}

  @doc "Runs `read` through Hasura GraphQL; `opts` as in `run/4`."
  @spec hasura(Read.t(), Hasura.auth() | :admin, keyword()) :: hasura_result()
  def hasura(%Read{table: table} = read, auth, opts \\ []) do
    {graphql, variables} = graphql(read)
    names = Fixture.graphql_names(table)

    graphql
    |> Hasura.request(variables, Read.root_field(table), auth)
    |> hasura_result(names, Keyword.get(opts, :messages, false))
  end

  defp hasura_result({:ok, rows, _body}, names, _messages?),
    do: {:ok, Enum.map(rows, &database_names(&1, names))}

  defp hasura_result({:error, code, message, _body}, _names, true), do: {:error, code, message}
  defp hasura_result({:error, code, _message, _body}, _names, false), do: {:error, code}

  defp database_names(row, names) when map_size(names) == 0, do: row

  defp database_names(row, names) do
    back = Map.new(names, fn {column, name} -> {name, column} end)
    Map.new(row, fn {key, value} -> {Map.get(back, key, key), value} end)
  end

  @doc "Runs `read` through Authzura on `instance`; `opts` reach the input path (`join_lift:`)."
  @spec authzura(Read.t(), Hasura.auth(), atom(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def authzura(%Read{} = read, auth, instance, opts \\ []) do
    with {:ok, session} <- session(auth), do: execute(read, session, instance, opts)
  end

  @doc "The Authzura session for `auth`."
  @spec session(Hasura.auth()) :: {:ok, Session.t()} | {:error, term()}
  def session({:admin_impersonate, role, vars}),
    do: Session.new(Map.put(vars, "x-hasura-role", role), [])

  def session({:jwt, claims, requested_role}),
    do: session({:token, Hasura.sign(claims), requested_role})

  def session({:token, token, requested_role}),
    do: JWT.verify(token, key: Hasura.jwt_key(), requested_role: requested_role)

  @doc """
  Every row of the sampled `read`'s target table with its columns, read
  through Hasura's admin role.
  """
  @spec members(Read.t()) :: [map()]
  def members(%Read{sample: {table, _mapping}, columns: columns}) do
    {:ok, rows} = hasura(Read.new(table, columns: columns), :admin)
    rows
  end

  @doc "The GraphQL query and variables for a root `read`."
  @spec graphql(Read.t()) :: {String.t(), map()}
  def graphql(%Read{table: table} = read) do
    %Read{where: where} = read = rename(read, Fixture.graphql_names(table))
    root = Read.root_field(table)
    {declaration, variables} = where_variable(root, where)
    {"query Parity#{declaration} { #{root}#{arguments(read)} #{selection(read)} }", variables}
  end

  # The root's columns, `where` and `order_by` under their GraphQL names.
  defp rename(read, names) when map_size(names) == 0, do: read

  defp rename(%Read{columns: columns, where: where, order_by: order_by} = read, names) do
    name = &Map.get(names, &1, &1)

    %{
      read
      | columns: Enum.map(columns, name),
        where: rename_where(where, name),
        order_by:
          order_by && Enum.map(order_by, fn {dir, col} -> {dir, name.(Atom.to_string(col))} end)
    }
  end

  defp rename_where(nil, _name), do: nil

  defp rename_where(%{} = where, name) do
    Map.new(where, fn
      {key, list} when key in @bool_lists and is_list(list) ->
        {key, Enum.map(list, &rename_where(&1, name))}

      {"_not", inner} ->
        {"_not", rename_where(inner, name)}

      {key, value} ->
        {name.(key), value}
    end)
  end

  defp where_variable(_root, nil), do: {"", %{}}
  defp where_variable(root, where), do: {"($where: #{root}_bool_exp)", %{"where" => where}}

  # The field arguments, e.g. `(where: $where, order_by: [{id: asc}], limit: 2)`,
  # or "" when the read has none.
  defp arguments(%Read{where: where, order_by: order_by, limit: limit, offset: offset}) do
    [
      where_argument(where),
      order_argument(order_by),
      paging_argument("limit", limit),
      paging_argument("offset", offset)
    ]
    |> List.flatten()
    |> render_arguments()
  end

  defp where_argument(nil), do: []
  defp where_argument(_where), do: "where: $where"

  defp order_argument(nil), do: []
  defp order_argument(order), do: "order_by: #{order_literal(order)}"

  defp paging_argument(_name, nil), do: []
  defp paging_argument(name, n), do: "#{name}: #{n}"

  defp render_arguments([]), do: ""
  defp render_arguments(arguments), do: "(#{Enum.join(arguments, ", ")})"

  defp order_literal(order),
    do:
      "[#{Enum.map_join(order, ", ", fn {direction, column} -> "{#{column}: #{direction}}" end)}]"

  defp selection(%Read{columns: columns, relationships: relationships}) do
    nested =
      Enum.map(relationships, fn {name, read} ->
        name <> arguments(read) <> " " <> selection(read)
      end)

    "{ #{Enum.join(columns ++ nested, " ")} }"
  end

  # Default reads exercise the public entry point and its execute span.
  defp execute(%Read{table: {"public", name}, where: where} = read, session, instance, [])
       when not is_nil(where),
       do: Authzura.all_input(name, session, input(read), instance: instance)

  # Internal comparisons can disable lifting without exposing a public option.
  defp execute(%Read{table: {"public", name}, where: where} = read, session, instance, opts)
       when not is_nil(where),
       do: InternalRead.all_input(name, session, input(read), instance, opts)

  # Non-input reads ignore the internal join_lift option.
  defp execute(
         %Read{columns: columns, relationships: relationships} = read,
         session,
         instance,
         _opts
       ) do
    read
    |> query()
    |> Authzura.all(session,
      instance: instance,
      columns: columns,
      preload: preload(relationships)
    )
  end

  @doc """
  The root query `read` describes for `Authzura.all/3`: its table, sort
  and paging (no columns or preloads, which are options).
  """
  @spec query(Read.t()) :: Query.t()
  def query(%Read{table: {schema, name}, order_by: order_by, limit: limit, offset: offset}) do
    from(t in name, prefix: ^schema)
    |> apply_order(order_by)
    |> apply_limit(limit)
    |> apply_offset(offset)
  end

  defp apply_order(query, nil), do: query
  defp apply_order(query, order), do: order_by(query, ^order)

  defp apply_limit(query, nil), do: query
  defp apply_limit(query, n), do: limit(query, ^n)

  defp apply_offset(query, nil), do: query
  defp apply_offset(query, n), do: offset(query, ^n)

  @doc """
  The Elixir preload tree of `relationships` for `Authzura.all/3`.
  `input/1` builds the same tree in its JSON form (`json_preload/1`);
  keep them in step.
  """
  @spec preload([{String.t(), Read.t()}]) :: keyword() | [{String.t(), keyword()}]
  def preload(relationships) do
    Enum.map(relationships, fn {name, %Read{columns: columns, relationships: nested} = read} ->
      {name, [columns: columns, preload: preload(nested)] ++ order_option(read)}
    end)
  end

  defp order_option(%Read{order_by: nil}), do: []
  defp order_option(%Read{order_by: order}), do: [order_by: order]

  @doc "The `Authzura.all_input/4` request `read` describes, without `nil` keys."
  @spec input(Read.t()) :: map()
  def input(%Read{
        columns: columns,
        where: where,
        order_by: order_by,
        limit: limit,
        offset: offset,
        relationships: relationships
      }) do
    compact(%{
      "columns" => columns,
      "filter" => where,
      "order_by" => json_order(order_by),
      "limit" => limit,
      "offset" => offset,
      "preload" => json_preload(relationships)
    })
  end

  defp json_order(nil), do: nil

  defp json_order(order),
    do: Enum.map(order, fn {direction, column} -> %{"#{column}" => "#{direction}"} end)

  defp json_preload([]), do: nil

  defp json_preload(relationships) do
    Map.new(relationships, fn {name,
                               %Read{columns: columns, order_by: order_by, relationships: nested}} ->
      {name,
       compact(%{
         "columns" => columns,
         "order_by" => json_order(order_by),
         "preload" => json_preload(nested)
       })}
    end)
  end

  defp compact(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)
end

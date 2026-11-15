defmodule Authzura.Get do
  @moduledoc """
  Builds the `Authzura.Plan` for a read by primary key (`Authzura.get/4`).

  `build/5`:

    1. The queryable must be a bare schema, table or query: no `where`,
       `join`, combination, CTE, `limit` or `offset`; otherwise
       `{:unsupported_query, :get_requires_bare_root}`. The key equality is
       the only predicate, so the read is exactly Hasura's `<table>_by_pk`.
    2. Access: the role's permission must exist (`:forbidden`) and expose
       the `select_by_pk` or `select` root field (`:root_field_disabled`).
       A table without a primary key is
       `{:unsupported_query, :no_primary_key}`. Every key column must be one
       the role may select (`{:forbidden_columns, cols}`), as Hasura
       exposes `_by_pk` only then, so a key can never probe a hidden column.
    3. The key: a single value for a one-column key, or a keyword list or
       map naming every key column exactly once and nothing else (field
       atoms for a schema, column names as atoms or strings for a table).
       Any other shape is `{:invalid_input, {:primary_key, :invalid}}`.
    4. Each value is cast against its column like an input literal (with
       the adapter's `c:Authzura.Adapter.cast_value/4`): a value Postgres
       would refuse is `{:invalid_input, [{[column], {:invalid_literal,
       reason}}]}` and `nil` is `{:invalid_input, [{[column],
       :null_operand}]}`, before any SQL runs.
    5. The equality is compiled in `:pinned` mode (`Authzura.Input.compile/3`:
       `:input` semantics, the operator named by its schema, so an operator
       the database owner defines on a column or operand type can never be
       chosen: `OPERATOR(pg_catalog.=)`, or the `citext` extension's own
       schema for a `citext` key, which is refused with
       `{:invalid_literal, {:unsupported_type, "citext"}}` when that schema
       cannot be resolved)
       and added as a plain `where` before `Authzura.Scope.build/4` ANDs in
       the permission (`id = $1 AND permission`), so the primary key index
       applies. It needs no fence behind the permission: it is built by
       Authzura alone from values already cast to each column's own type,
       so it can neither fail nor run long on a row the role cannot see.
       The plan is otherwise the one `Authzura.one/3` builds: the same row
       filter, columns, limit cap and preloads.

  Nothing here creates atoms from the key.
  """

  import Ecto.Query, only: [from: 2, where: 2]

  import Authzura.Util, only: [is_plain_map: 1]

  alias Authzura.{Input, Plan, Scope, Session, Util}
  alias Authzura.Model.{Permission, Table}
  alias Authzura.Store.Generation
  alias Ecto.{Query, Queryable}
  alias Ecto.Query.FromExpr

  @root :authzura_get

  @typedoc "Why a read by primary key is refused; see the moduledoc."
  @type reason ::
          Scope.reason()
          | {:unsupported_query, :get_requires_bare_root | :no_primary_key}
          | {:invalid_input, {:primary_key, :invalid} | [{[String.t()], term()}]}

  @doc """
  Builds the plan reading the row of `queryable` whose primary key is `pk`.
  `opts` are the per-call options, plus `mode` and `max_rows` as for
  `Authzura.Scope.build/4`.
  """
  @spec build(Queryable.t(), Session.t(), term(), Generation.t(), keyword()) ::
          {:ok, Plan.t()} | {:error, reason()}
  def build(queryable, %Session{} = session, pk, %Generation{} = generation, opts) do
    # Access (permission, then root field) is decided before the key is
    # read, so a role that may not read the table learns nothing about its
    # key columns from a malformed key.
    with {:ok, query, binding} <- queryable |> Queryable.to_query() |> bare(),
         {:ok, %Permission{table: ref} = permission} <-
           Scope.permission(query, session, generation, opts),
         :ok <- Scope.root_field(permission, :select_by_pk),
         %{table: table} = ctx = Input.context(generation, ref, session, binding),
         {:ok, keys} <- primary_key(table),
         :ok <- Util.forbidden_columns(Enum.reject(keys, &Permission.allows?(permission, &1))),
         {:ok, values} <- values(pk, keys, Scope.schema(query)),
         {:ok, ast} <- equality(values, ctx),
         {:ok, condition} <- Input.compile(ast, ctx, :pinned),
         {:ok, plan} <-
           query
           |> where(^condition)
           |> Scope.build(session, generation, Keyword.put(opts, :root_field, :select_by_pk)) do
      {:ok, Input.with_comparisons(plan, ast, ctx)}
    end
  end

  # The root.

  defp bare(
         %Query{
           wheres: [],
           joins: [],
           combinations: [],
           with_ctes: nil,
           limit: nil,
           offset: nil,
           from: %FromExpr{as: binding}
         } = query
       ),
       do: {:ok, aliased(query, binding), binding || @root}

  defp bare(%Query{}), do: {:error, {:unsupported_query, :get_requires_bare_root}}

  defp aliased(query, nil), do: from(q in query, as: ^@root)
  defp aliased(query, _binding), do: query

  defp primary_key(%Table{primary_key: []}), do: {:error, {:unsupported_query, :no_primary_key}}
  defp primary_key(%Table{primary_key: keys}), do: {:ok, keys}

  # The key.

  defp values(pk, keys, schema) when is_plain_map(pk), do: keyed(Map.to_list(pk), keys, schema)

  defp values(pk, keys, schema) when is_list(pk),
    do: listed(Keyword.keyword?(pk), pk, keys, schema)

  defp values(pk, [key], _schema), do: {:ok, [{key, pk}]}
  defp values(_pk, _keys, _schema), do: invalid_key()

  defp listed(true, pk, keys, schema), do: keyed(pk, keys, schema)
  defp listed(false, pk, [key], _schema), do: {:ok, [{key, pk}]}
  defp listed(false, _pk, _keys, _schema), do: invalid_key()

  # Every key column exactly once, and nothing else.
  defp keyed(pairs, keys, schema) do
    named = Map.new(pairs, fn {name, value} -> {column(schema, name), value} end)
    distinct? = map_size(named) == length(pairs)

    exact(distinct? and Enum.sort(Map.keys(named)) == Enum.sort(keys), keys, named)
  end

  defp exact(true, keys, named), do: {:ok, Enum.map(keys, &{&1, Map.fetch!(named, &1)})}
  defp exact(false, _keys, _named), do: invalid_key()

  defp column(nil, name) when is_atom(name), do: Atom.to_string(name)
  defp column(schema, name) when is_atom(name), do: Scope.column_for(schema, name)
  defp column(_schema, name) when is_binary(name), do: name
  defp column(_schema, _name), do: nil

  defp invalid_key, do: {:error, {:invalid_input, {:primary_key, :invalid}}}

  # The equality, cast like an input literal.

  defp equality(values, %{table: %Table{columns: columns}, adapter: adapter}) do
    values
    |> Enum.map(fn {name, value} -> compare(name, value, Map.fetch!(columns, name), adapter) end)
    |> Enum.split_with(&match?({:ok, _ast}, &1))
    |> equality()
  end

  defp equality({comparisons, []}), do: {:ok, {:and, Enum.map(comparisons, &elem(&1, 1))}}

  defp equality({_comparisons, errors}),
    do: {:error, {:invalid_input, Enum.map(errors, &elem(&1, 1))}}

  defp compare(name, nil, _column, _adapter), do: {:error, {[name], :null_operand}}

  defp compare(name, value, column, adapter) do
    case adapter.cast_value({:literal, value}, :column, column, :pinned) do
      {:ok, cast} -> {:ok, {:compare, name, :eq, {:literal, cast}}}
      {:error, reason} -> {:error, {[name], {:invalid_literal, reason}}}
    end
  end
end

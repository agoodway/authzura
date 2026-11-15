defmodule Authzura.Sources.Hasura.BoolExp do
  @moduledoc """
  Parses a Hasura v2 boolean expression (`bool_exp`) into an `Authzura.AST`.

  The same grammar serves two modes:

    * `:permission` - a filter or check from metadata. A string whose
      lowercased form starts with `x-hasura-` is a session variable,
      `{:session, name}` with the name lowercased (as is Hasura's legacy
      `REQ_USER_ID`, which means `x-hasura-user-id`).
    * `:input` - an untrusted caller filter. Every value is a literal, an
      explicit `null` operand is rejected, and relationships and `_exists`
      are rejected. So is an unknown key whose value reads as a
      relationship body (an empty object, or one with a key not starting
      with `_` or `$`), as `:relationship_in_input`, so that a caller who
      parses against only the columns it may see learns nothing from a
      name: a relationship, a hidden column and a name that does not exist
      read the same. Pattern operands (`_like`, `_similar`, `_regex` and
      their variants) longer than 1024 bytes are
      `{:invalid_literal, :pattern_too_long}`, a `LIKE`/`ILIKE` pattern
      ending in an unescaped backslash, which Postgres would reject, is
      `{:invalid_literal, :trailing_escape}`, and a regular expression or
      `SIMILAR TO` pattern holding a backreference (an unescaped `\\` and a digit from 1 to 9,
      the one construct that makes Postgres's matcher exponential) is
      `{:invalid_literal, :backreference}`.

  In both modes literals are cast at parse time with the adapter's
  `cast_value/4`, so the AST holds cast values and the compiler never casts
  a literal again.

  ## Grammar

  Follows `Hasura.RQL.IR.BoolExp` and `Hasura.Backends.Postgres.DDL.BoolExp`
  (<https://github.com/hasura/graphql-engine/tree/v2.50.1/server/src-lib/Hasura>):

    * an object is an AND of its keys; one key is just that key and no
      keys is `{:and, []}`
    * `_and`/`$and` and `_or`/`$or` take a list, `_not`/`$not` an object
    * `_exists`/`$exists` takes `%{"_table" => table, "_where" => bool_exp}`
      and is not correlated with the current row
    * a key naming a relationship of the current table parses its value
      against the relationship's target table
    * a key naming a column takes an object of operators (`_eq`, `$in`, ...;
      several are ANDed, none is `{:and, []}`), or a bare value meaning `_eq`

  ## Errors

  Errors never raise. They accumulate, in document order, as `{path, reason}`
  where `path` lists the object keys and list indices (as strings) leading
  to the offending node.

  ## Limits

  Limits count in AST units (see `Authzura.AST`) and are enforced while
  descending, before any deeper input is read. Every node the input would
  produce counts, including invalid ones, so hostile input stops at the node
  limit with `:too_large`, which ends the parse. A node deeper than the
  syntactic or binding depth limit is `:too_deep` and is not descended into.
  """

  import Authzura.Util, only: [is_plain_map: 1]

  alias Authzura.{Adapter, AST}
  alias Authzura.Model.{Column, Relationship, Table}

  @typedoc "Parse mode: metadata (`:permission`) or untrusted caller input (`:input`)."
  @type mode :: :permission | :input

  @typedoc "Object keys and list indices leading to a node."
  @type path :: [String.t()]

  @typedoc "Why a node was rejected."
  @type reason ::
          :invalid_expression
          | :null_operand
          | :relationship_in_input
          | :too_deep
          | :too_large
          | {:unknown_field, String.t()}
          | {:unknown_operator, term()}
          | {:unknown_table, Table.table_ref()}
          | {:unsupported, :column_comparison | :cast | :json_column | unsupported_field()}
          | {:operator_type_mismatch, String.t(), String.t()}
          | {:invalid_literal, term()}

  @typedoc "A field Authzura does not support in filters."
  @type unsupported_field :: :computed_field | :remote_relationship

  @typedoc "AST-unit limits; see the moduledoc."
  @type limits :: %{
          binding_depth: non_neg_integer(),
          syntactic_depth: pos_integer(),
          nodes: pos_integer()
        }

  @typedoc """
  Parser context. `:unsupported` maps a table to the fields (computed fields,
  remote relationships) that exist in metadata but must be denied.
  """
  @type ctx :: %{
          required(:table) => Table.t(),
          required(:tables) => %{Table.table_ref() => Table.t()},
          required(:adapter) => module(),
          required(:limits) => limits(),
          optional(:unsupported) => %{Table.table_ref() => %{String.t() => unsupported_field()}}
        }

  @session_prefix "x-hasura-"
  @legacy_user_id "req_user_id"
  @user_id "x-hasura-user-id"

  @logic for {name, op} <- [and: :and, or: :or, not: :not, exists: :exists],
             prefix <- ["_", "$"],
             into: %{},
             do: {prefix <> Atom.to_string(name), op}

  @operators for op <-
                   ~w(eq neq in nin gt lt gte lte is_null like nlike ilike nilike similar nsimilar
                       regex iregex nregex niregex contains contained_in has_key has_keys_any
                       has_keys_all jsonb_path_exists jsonb_path_match)a,
                 prefix <- ["_", "$"],
                 into: %{"_ne" => :neq, "$ne" => :neq},
                 do: {prefix <> Atom.to_string(op), op}

  @column_comparisons for op <- ~w(ceq cne cneq cgt clt cgte clte),
                          prefix <- ["_", "$"],
                          do: prefix <> op

  @casts ["_cast", "$cast"]

  @like_ops AST.like_ops()
  @pattern_ops AST.pattern_ops()
  # Every operator whose pattern becomes a Postgres regular expression:
  # SIMILAR TO too, where `\"...\"` makes a capturing group.
  @regex_ops [:regex, :iregex, :nregex, :niregex, :similar, :nsimilar]
  # An unescaped backslash (after an even run of them) followed by 1-9.
  @backreference ~r/(?<!\\)(?:\\\\)*\\[1-9]/
  @max_pattern_bytes 1024
  @is_null_keys ["_is_null", "$is_null"]

  @doc """
  Parses `json` against `ctx.table` in `mode`.

      iex> alias Authzura.Model.{Column, Table}
      iex> id = %Column{name: "id", pg_type: "int8", base_kind: :bigint, ecto_type: :integer}
      iex> table = %Table{schema: "public", name: "t", columns: %{"id" => id}}
      iex> ctx = %{table: table, tables: %{{"public", "t"} => table},
      ...>         adapter: Authzura.Adapters.Postgres,
      ...>         limits: %{binding_depth: 15, syntactic_depth: 32, nodes: 1000}}
      iex> Authzura.Sources.Hasura.BoolExp.parse(%{"id" => "X-Hasura-User-Id"}, :permission, ctx)
      {:ok, {:compare, "id", :eq, {:session, "x-hasura-user-id"}}}
      iex> Authzura.Sources.Hasura.BoolExp.parse(%{"id" => %{"_eq" => nil}}, :input, ctx)
      {:error, [{["id", "_eq"], :null_operand}]}
  """
  @spec parse(term(), mode(), ctx()) :: {:ok, AST.t()} | {:error, [{path(), reason()}]}
  def parse(
        json,
        mode,
        %{table: %Table{} = table, tables: tables, adapter: adapter, limits: limits} = ctx
      )
      when mode in [:permission, :input] do
    state = %{
      mode: mode,
      tables: tables,
      adapter: adapter,
      limits: limits,
      unsupported: Map.get(ctx, :unsupported, %{}),
      nodes: 0,
      errors: [],
      halted?: false
    }

    json
    |> expression(%{table: table, rpath: [], depth: 1, binding: 0}, state)
    |> result()
  end

  @doc """
  Tags a Hasura value as a session variable or a literal.

  In `:permission` mode a string whose lowercased form starts with
  `x-hasura-` is `{:session, lowercased}`, and `REQ_USER_ID` (any casing) is
  `{:session, "x-hasura-user-id"}`. Everything else, and every value in
  `:input` mode, is `{:literal, value}`.

      iex> Authzura.Sources.Hasura.BoolExp.value("X-Hasura-Org-Id", :permission)
      {:session, "x-hasura-org-id"}
      iex> Authzura.Sources.Hasura.BoolExp.value("X-Hasura-Org-Id", :input)
      {:literal, "X-Hasura-Org-Id"}
  """
  @spec value(term(), mode()) :: {:session, String.t()} | {:literal, term()}
  def value(raw, :permission) when is_binary(raw), do: raw |> String.downcase() |> session(raw)
  def value(raw, _mode), do: {:literal, raw}

  @doc """
  Turns a metadata value into an `Authzura.AST.value()` for a right side of
  `rhs_kind` against `column`: a session variable (see `value/2`) is kept
  as is, and a literal is cast with `adapter.cast_value/4`.

  Used for comparisons and for write presets (`set`). A literal `nil` for a
  `:column` right side stays `{:literal, nil}`.
  """
  @spec operand(term(), Adapter.rhs_kind(), Column.t(), module()) ::
          {:ok, AST.value()} | {:error, {:invalid_literal, term()}}
  def operand(raw, rhs_kind, %Column{} = column, adapter),
    do: raw |> value(:permission) |> cast(rhs_kind, column, adapter, :permission)

  @doc """
  Parses Hasura's qualified-table JSON: `%{"schema" => s, "name" => n}`
  (schema defaults to `"public"`) or a bare name in the public schema.

      iex> Authzura.Sources.Hasura.BoolExp.table_ref(%{"schema" => "audit", "name" => "users"})
      {:ok, {"audit", "users"}}
      iex> Authzura.Sources.Hasura.BoolExp.table_ref("users")
      {:ok, {"public", "users"}}
      iex> Authzura.Sources.Hasura.BoolExp.table_ref(5)
      :error
  """
  @spec table_ref(term()) :: {:ok, Table.table_ref()} | :error
  def table_ref(%{"name" => name} = table) when is_binary(name),
    do: table |> Map.get("schema", "public") |> qualified(name)

  def table_ref(name) when is_binary(name), do: {:ok, {"public", name}}
  def table_ref(_table), do: :error

  defp qualified(schema, name) when is_binary(schema), do: {:ok, {schema, name}}
  defp qualified(_schema, _name), do: :error

  defp session(@session_prefix <> _rest = name, _raw), do: {:session, name}
  defp session(@legacy_user_id, _raw), do: {:session, @user_id}
  defp session(_folded, raw), do: {:literal, raw}

  defp result({ast, %{errors: []}}), do: {:ok, ast}
  defp result({_ast, %{errors: errors}}), do: {:error, Enum.reverse(errors)}

  # Expressions (objects).

  defp expression(json, at, state)
       when is_plain_map(json) and map_size(json) == 0,
       do: node(at, state, fn _child, state -> {{:and, []}, state} end)

  defp expression(json, at, state)
       when is_plain_map(json) and map_size(json) == 1 do
    [{key, value}] = Map.to_list(json)
    field(key, value, at, state)
  end

  defp expression(json, at, state) when is_plain_map(json) do
    node(at, state, fn child, state ->
      json
      |> collect(state, fn {key, value}, state -> field(key, value, child, state) end)
      |> wrap(:and)
    end)
  end

  defp expression(_json, at, state), do: fail(at, state, :invalid_expression)

  defp field(key, value, at, state) when is_map_key(@logic, key),
    do: logic(Map.fetch!(@logic, key), value, push(at, key), state)

  defp field(key, value, %{table: table} = at, state) when is_binary(key),
    do: key |> lookup(table, state) |> table_field(value, push(at, key), state)

  defp field(_key, _value, at, state), do: fail(at, state, :invalid_expression)

  defp logic(op, list, at, state) when op in [:and, :or] and is_list(list) do
    node(at, state, fn child, state ->
      list
      |> Enum.with_index(fn json, index -> {Integer.to_string(index), json} end)
      |> collect(state, fn {index, json}, state -> expression(json, push(child, index), state) end)
      |> wrap(op)
    end)
  end

  defp logic(:not, json, at, state) when is_plain_map(json),
    do: node(at, state, fn child, state -> json |> expression(child, state) |> wrap(:not) end)

  defp logic(:exists, _json, at, %{mode: :input} = state),
    do: fail(at, state, :relationship_in_input)

  defp logic(:exists, %{"_table" => table, "_where" => where}, at, state) do
    at = bind(at)
    node(at, state, fn child, state -> exists(table_ref(table), where, child, at, state) end)
  end

  defp logic(_op, _json, at, state), do: fail(at, state, :invalid_expression)

  defp exists({:ok, ref}, where, child, at, state),
    do: scoped(ref, where, push(child, "_where"), push(at, "_table"), state, &{:exists, ref, &1})

  defp exists(:error, _where, _child, at, state),
    do: {nil, add_error(state, push(at, "_table"), :invalid_expression)}

  # Fields of the current table: columns, relationships, unsupported fields.

  defp lookup(
         key,
         %Table{schema: schema, name: name, columns: columns, relationships: relationships},
         %{unsupported: unsupported}
       ) do
    with :error <- tagged(:column, columns, key),
         :error <- tagged(:relationship, relationships, key),
         :error <- tagged(:unsupported, Map.get(unsupported, {schema, name}, %{}), key) do
      {:unknown_field, key}
    end
  end

  defp tagged(tag, map, key) do
    case Map.fetch(map, key) do
      {:ok, found} -> {tag, found}
      :error -> :error
    end
  end

  # Hasura v2 rejects any predicate on a `json` (not `jsonb`) column in a
  # permission as inconsistent metadata ("JSON column can not be part of
  # boolean expression"), `_is_null` included, so the permission is denied.
  # Input still allows `_is_null` only.
  defp table_field(
         {:column, %Column{base_kind: :json}},
         _value,
         at,
         %{mode: :permission} = state
       ),
       do: fail(at, state, {:unsupported, :json_column})

  defp table_field({:column, %Column{base_kind: :json} = column}, value, at, state),
    do: value |> null_checks_only?() |> json_field(column, value, at, state)

  defp table_field({:column, column}, ops, at, state) when is_plain_map(ops),
    do: ops |> Map.to_list() |> operators(column, at, state)

  defp table_field({:column, column}, value, at, state),
    do: comparison("_eq", value, column, at, state)

  defp table_field({:relationship, _rel}, _value, at, %{mode: :input} = state),
    do: fail(at, state, :relationship_in_input)

  defp table_field({:relationship, %Relationship{} = rel}, json, at, state) do
    at = bind(at)
    node(at, state, fn child, state -> relationship(rel, json, child, at, state) end)
  end

  defp table_field({:unsupported, kind}, _value, at, state),
    do: fail(at, state, {:unsupported, kind})

  # In input mode an unknown key whose value reads as a relationship body
  # (an empty object, or one with a non-operator key) is refused as a relationship
  # whether or not one exists, so its name reveals nothing.
  defp table_field({:unknown_field, key}, value, at, %{mode: :input} = state),
    do: fail(at, state, unknown_input(key, relationship_body?(value)))

  defp table_field({:unknown_field, key}, _value, at, state),
    do: fail(at, state, {:unknown_field, key})

  defp unknown_input(_key, true), do: :relationship_in_input
  defp unknown_input(key, false), do: {:unknown_field, key}

  # `{}` is a relationship without a condition as much as an empty column
  # condition, so it is read as a relationship too.
  defp relationship_body?(value) when is_plain_map(value) and map_size(value) == 0, do: true

  defp relationship_body?(value) when is_plain_map(value),
    do: Enum.any?(value, fn {key, _value} -> not operator_key?(key) end)

  defp relationship_body?(_value), do: false

  defp operator_key?("_" <> _rest), do: true
  defp operator_key?("$" <> _rest), do: true
  defp operator_key?(_key), do: false

  defp relationship(%Relationship{name: name, target: target}, json, child, at, state),
    do: scoped(target, json, child, at, state, &{:relationship, name, &1})

  # Descends into `json` against the table `ref`; an untracked table is
  # reported at `error_at`.
  defp scoped(ref, json, child, error_at, %{tables: tables} = state, wrap) do
    case Map.fetch(tables, ref) do
      {:ok, table} ->
        {ast, state} = expression(json, %{child | table: table}, state)
        {wrap.(ast), state}

      :error ->
        {nil, add_error(state, error_at, {:unknown_table, ref})}
    end
  end

  defp json_field(true, column, ops, at, state),
    do: ops |> Map.to_list() |> operators(column, at, state)

  defp json_field(false, _column, _value, at, state),
    do: fail(at, state, {:unsupported, :json_column})

  defp null_checks_only?(ops) when is_plain_map(ops) and map_size(ops) > 0,
    do: ops |> Map.keys() |> Enum.all?(&(&1 in @is_null_keys))

  defp null_checks_only?(_value), do: false

  # Operators of one column.

  defp operators([], _column, at, state),
    do: node(at, state, fn _child, state -> {{:and, []}, state} end)

  defp operators([{key, value}], column, at, state),
    do: comparison(key, value, column, push(at, segment(key)), state)

  defp operators(ops, column, at, state) do
    node(at, state, fn child, state ->
      ops
      |> collect(state, fn {key, value}, state ->
        comparison(key, value, column, push(child, segment(key)), state)
      end)
      |> wrap(:and)
    end)
  end

  defp comparison(key, value, column, at, state) do
    node(at, state, fn _child, state ->
      case compare(key, value, column, state) do
        {:ok, ast} -> {ast, state}
        {:error, reason} -> {nil, add_error(state, at, reason)}
      end
    end)
  end

  defp compare(key, value, %Column{name: name} = column, %{adapter: adapter, mode: mode}) do
    with {:ok, op} <- operator(key),
         {:ok, %{lhs: lhs, rhs: rhs}} <- op |> adapter.operator_signature() |> supported(key),
         :ok <- check_lhs(adapter, lhs, column, key),
         {:ok, operand} <- tag(value, rhs, mode),
         {:ok, operand} <- cast(operand, rhs, column, adapter, mode),
         :ok <- pattern(op, operand, mode) do
      {:ok, {:compare, name, op, operand}}
    end
  end

  # Untrusted patterns are bounded, and a LIKE pattern Postgres would reject
  # (a trailing escape) is refused before any SQL runs.
  defp pattern(op, {:literal, value}, :input)
       when op in @pattern_ops and is_binary(value) and byte_size(value) > @max_pattern_bytes,
       do: {:error, {:invalid_literal, :pattern_too_long}}

  defp pattern(op, {:literal, value}, :input) when op in @like_ops and is_binary(value) do
    escapes = byte_size(value) - byte_size(String.trim_trailing(value, "\\"))
    escaped_tail(rem(escapes, 2))
  end

  defp pattern(op, {:literal, value}, :input) when op in @regex_ops and is_binary(value),
    do: @backreference |> Regex.match?(value) |> backreference()

  defp pattern(_op, _operand, _mode), do: :ok

  defp escaped_tail(1), do: {:error, {:invalid_literal, :trailing_escape}}
  defp escaped_tail(0), do: :ok

  defp backreference(true), do: {:error, {:invalid_literal, :backreference}}
  defp backreference(false), do: :ok

  defp operator(key) when is_map_key(@operators, key), do: {:ok, Map.fetch!(@operators, key)}

  defp operator(key) when key in @column_comparisons,
    do: {:error, {:unsupported, :column_comparison}}

  defp operator(key) when key in @casts, do: {:error, {:unsupported, :cast}}
  defp operator(key), do: {:error, {:unknown_operator, key}}

  defp supported({:ok, signature}, _key), do: {:ok, signature}
  defp supported(:unsupported, key), do: {:error, {:unknown_operator, key}}

  defp check_lhs(adapter, lhs, %Column{pg_type: pg_type} = column, key),
    do: lhs |> adapter.lhs_compatible?(column) |> lhs_fits(key, pg_type)

  defp lhs_fits(true, _key, _pg_type), do: :ok
  defp lhs_fits(false, key, pg_type), do: {:error, {:operator_type_mismatch, key, pg_type}}

  defp tag(nil, _rhs, :input), do: {:error, :null_operand}
  # `_is_null` takes a JSON boolean; Hasura never reads a session variable there.
  defp tag(value, :boolean, _mode), do: {:ok, {:literal, value}}
  defp tag(value, _rhs, mode), do: {:ok, value(value, mode)}

  defp cast({:session, _name} = operand, _rhs, _column, _adapter, _mode), do: {:ok, operand}

  defp cast(operand, rhs, column, adapter, mode) do
    case adapter.cast_value(operand, rhs, column, mode) do
      {:ok, value} -> {:ok, {:literal, value}}
      {:error, reason} -> {:error, {:invalid_literal, reason}}
    end
  end

  # Node accounting. Every AST node (or node the input would produce) is
  # counted and depth-checked before its children are read.

  defp node(_at, %{halted?: true} = state, _build), do: {nil, state}

  defp node(
         %{depth: depth, binding: binding} = at,
         %{
           nodes: nodes,
           limits: %{nodes: max_nodes, syntactic_depth: max_depth, binding_depth: max_binding}
         } = state,
         build
       ) do
    count = nodes + 1
    state = %{state | nodes: count}

    cond do
      count > max_nodes ->
        {nil, %{add_error(state, at, :too_large) | halted?: true}}

      depth > max_depth or binding > max_binding ->
        {nil, add_error(state, at, :too_deep)}

      true ->
        build.(%{at | depth: depth + 1}, state)
    end
  end

  defp fail(at, state, reason),
    do: node(at, state, fn _child, state -> {nil, add_error(state, at, reason)} end)

  defp collect(entries, state, parse) do
    {asts, state} =
      Enum.reduce_while(entries, {[], state}, fn entry, {asts, state} ->
        {ast, state} = parse.(entry, state)
        {continue(state), {[ast | asts], state}}
      end)

    {Enum.reverse(asts), state}
  end

  defp continue(%{halted?: true}), do: :halt
  defp continue(_state), do: :cont

  defp wrap({child, state}, :not), do: {{:not, child}, state}
  defp wrap({children, state}, op), do: {{op, children}, state}

  # Paths are strings; a non-string key (possible only in Elixir-built
  # input) is shown inspected.
  defp segment(key) when is_binary(key), do: key
  defp segment(key), do: inspect(key)

  defp push(%{rpath: rpath} = at, segment), do: %{at | rpath: [segment | rpath]}

  defp bind(%{binding: binding} = at), do: %{at | binding: binding + 1}

  defp add_error(%{errors: errors} = state, %{rpath: rpath}, reason),
    do: %{state | errors: [{Enum.reverse(rpath), reason} | errors]}
end

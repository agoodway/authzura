defmodule Authzura.Compiler do
  @moduledoc """
  Compiles a filter `Authzura.AST` plus a session into an Ecto dynamic.

  The dynamic refers to the current table through `as(^binding)`, so the
  caller's root query must carry the root alias (`Aliases.at(0)`). Clause by
  clause:

    * `{:relationship, name, e}` is one `EXISTS` subquery on the target
      table, with its explicit prefix and the next alias from
      `Authzura.Compiler.Aliases`. Its `WHERE` is the mapping equalities
      against `parent_as(^binding)`, ANDed with `e` compiled against the
      target. All conditions in one node hold on the same related row, and
      sibling nodes compile to separate `EXISTS` clauses.
    * `{:exists, {schema, name}, e}` is an `EXISTS` subquery on that table
      with **no** correlation to the current row (Hasura's `_exists`).
    * `{:compare, column, op, value}` binds the value with the adapter's
      `compile_operator/5`. Literals were cast when the filter was parsed and
      are passed through as they are (only their shape is checked); session
      values are cast here with `cast_value/4`. A session value is never
      `NULL`, so `_eq` and `_neq` against one compile as on a non-null
      column (plain `=` and `<>`), which is what Hasura's null-aware form
      evaluates to for a non-null value.
    * `{:and, []}` is `true` and `{:or, []}` is `false`.
    * `lift/3` compiles a root filter with its `_and` chains of object
      relationships onto a strictly unique primary key as inner joins
      instead of `EXISTS`, and gives `compile/2`'s output, unchanged, when
      nothing lifts. `apply_joins/2` adds those joins to the root query.

  Errors are returned, never raised:

    * `{:missing_session_variable, name}` - the session lacks a variable
    * `{:invalid_session_value, name, reason}` - its value does not cast
    * `{:unknown_column, table_ref, column}`, `{:unknown_relationship,
      table_ref, name}`, `{:unknown_table, table_ref}`,
      `{:unsupported_operator, op}`, `{:operator_type_mismatch, op,
      pg_type}`, `{:unsupported_type, pg_type}`, `:too_deep` and
      `:invalid_filter` (a malformed node, operand, relationship or session)
      - the filter itself cannot be compiled. Load-time validation turns
      these into denials, so they are not expected at request time.

  ## Validation mode

  With `session: :validate`, session references are type-checked with the
  adapter's `bindable/2` (the column kind must be bindable for the
  operator's right side) without binding any value, and the comparison
  compiles to `true`. The dynamic is only evidence that the filter compiles;
  it is never executed.
  """

  import Ecto.Query, only: [dynamic: 1, from: 2, join: 5, subquery: 1]

  alias Authzura.{Adapter, AST, Session}
  alias Authzura.Compiler.Aliases
  alias Authzura.Model.{Column, Relationship, Table}
  alias Ecto.Query

  @type ctx :: %{
          table: Table.t(),
          tables: %{Table.table_ref() => Table.t()},
          session: Session.t() | :validate,
          adapter: module(),
          mode: Adapter.mode(),
          binding: atom(),
          depth: non_neg_integer()
        }

  @type reason ::
          {:missing_session_variable, String.t()}
          | {:invalid_session_value, String.t(), term()}
          | {:unknown_column, Table.table_ref(), String.t()}
          | {:unknown_relationship, Table.table_ref(), String.t()}
          | {:unknown_table, Table.table_ref()}
          | {:unsupported_operator, term()}
          | {:operator_type_mismatch, atom(), String.t()}
          | {:unsupported_type, String.t()}
          | :too_deep
          | :invalid_filter

  @type public_reason ::
          :forbidden
          | {:missing_session_variable, String.t()}
          | {:invalid_session_value, String.t(), term()}

  @max_depth Aliases.max_index()

  # The longest `_in` list `pushdown/3` hoists: each hoisted value is a probe
  # that runs on rows the role cannot see, so a long list stays behind the
  # fence only.
  @max_pushdown_list 100

  @doc """
  The context for compiling a filter on `table`, the root of a query: the
  root alias (`Aliases.at(0)`) at binding depth 0.
  """
  @spec root_ctx(
          Table.t(),
          %{Table.table_ref() => Table.t()},
          Session.t() | :validate,
          module(),
          Adapter.mode()
        ) :: ctx()
  def root_ctx(%Table{} = table, tables, session, adapter, mode)
      when mode in [:permission, :input, :pinned] do
    %{
      table: table,
      tables: tables,
      session: session,
      adapter: adapter,
      mode: mode,
      binding: Aliases.at(0),
      depth: 0
    }
  end

  @doc """
  The public form of a request-time compile error: session errors are kept,
  and anything else (never expected after load-time validation) is
  `:forbidden`.

      iex> Authzura.Compiler.public_reason({:missing_session_variable, "x-hasura-user-id"})
      {:missing_session_variable, "x-hasura-user-id"}
      iex> Authzura.Compiler.public_reason(:too_deep)
      :forbidden
  """
  @spec public_reason(reason()) :: public_reason()
  def public_reason({:missing_session_variable, _name} = reason), do: reason
  def public_reason({:invalid_session_value, _name, _detail} = reason), do: reason
  def public_reason(_internal), do: :forbidden

  @doc """
  Compiles `ast` like `compile/2`, returning only public reasons
  (`public_reason/1`).
  """
  @spec compile_public(AST.t(), ctx()) :: {:ok, Query.dynamic_expr()} | {:error, public_reason()}
  def compile_public(ast, ctx),
    do: with({:error, reason} <- compile(ast, ctx), do: {:error, public_reason(reason)})

  @typedoc "An inner join a lift adds: the target, its alias and its `ON` mapping equalities."
  @type join :: %{source: Table.table_ref(), binding: atom(), on: Query.dynamic_expr()}

  @typedoc "A lifted filter: its joins, in the order they must be applied, and its condition."
  @type lifted :: %{joins: [join()], condition: Query.dynamic_expr()}

  # One join under `join_collapse_limit` 8.
  @max_joins 7

  if @max_joins > Aliases.max_index(), do: raise("join limit exceeds the alias pool")

  @doc "The maximum total number of joins permitted on a lifted read."
  @spec max_joins() :: pos_integer()
  def max_joins, do: @max_joins

  @doc """
  Compiles the root filter `ast` like `compile/2`, with its liftable
  relationship nodes as inner joins instead of `EXISTS` subqueries.

  A `{:relationship, name, e}` node lifts when all of these hold:

    1. It is reached through `_and` only: never under `_or` or `_not`, and
       never inside an `EXISTS` that did not lift (an `_exists`, or a
       relationship that did not lift).
    2. It is an `:object` relationship.
    3. Its target is a table with a strictly unique key (`Table.strict_key?/1`),
       and the mapping's remote columns are exactly the whole primary key (a
       temporal key is unique only on all its columns, the range included).
    4. Every mapping pair is certified by the optional adapter callback
       `c:Authzura.Adapter.lossless_join_pair?/2` (absent means no lift).
       Postgres compares without lossy coercion when both columns are in
       the integer family (`Column.integer_kinds/0`), or both have the same
       type of a collation-free kind (`float8`, `numeric`, `uuid`, an enum,
       the timestamp and date types or `boolean`). Domains count as their
       base type. A `float8` against a `bigint` key keeps its `EXISTS` (the
       float `9007199254740992` equals both `9007199254740992` and
       `9007199254740993`), and so do `text`, `varchar`, `bpchar` and
       `citext` pairs, whose equality follows a collation introspection does
       not see.
    5. The statement stays within the limits: at most `budget` and at most #{@max_joins}
       lifted nodes, and every alias within `Aliases.max_index/0`. Over
       either limit nothing in the statement lifts.

  Lifted node `i` (1-based, in tree order) joins its target as
  `Aliases.at(i)`, `ON` the mapping equalities against its parent's alias,
  and contributes `ON AND e'` to the condition, `e'` being `e` compiled
  against the joined alias with its own children lifted by the same rules.
  So the condition re-checks every `ON` equality. If any node requires
  `EXISTS`, the whole filter falls back. Every join has its own alias, so
  siblings on one relationship are two joins. An inner join drops a row whose mapping
  is `NULL` or dangling, as the `EXISTS` does, and the key matches at most
  one target row, so no row repeats.

  **Fallback.** When nothing lifts, `joins` is `[]` and `condition` is
  exactly `compile/2`'s output. A lifted compile that fails also falls back,
  so every error is `compile/2`'s own. `ctx` must be a root context
  (`root_ctx/5`); any other compiles unlifted.

  Lifting is all-or-nothing: if any relationship or `_exists` remains,
  the whole filter uses `compile/2` unchanged.

  The joins must be added to the root query (`apply_joins/2`) before the
  condition is applied, since the condition names their aliases.
  The condition must remain a positive `WHERE` conjunct of that joined
  query. Do not negate it or use it as a standalone per-row boolean.
  The estimate wrapper (see "Relationship fence: estimate wrapper" in
  [benchmark triage](https://github.com/agoodway/authzura/blob/main/bench/TRIAGE.md)) permits exactly one additional use: a complete lift on
  a fenced `all_input/4` read may repeat it as the `WHEN` of the wrapper's
  `CASE`, with every join in that same statement. The `WHEN` re-checks every
  mapping equality and target condition against those joined rows, so true
  implies the original permission. Keep the positive `WHERE` conjunct too;
  the wrapper must preserve `CASE WHEN permission THEN input ELSE false END`.
  """
  @spec lift(AST.t(), ctx(), non_neg_integer()) :: {:ok, lifted()} | {:error, reason()}
  def lift(ast, ctx, 0), do: unlifted(ast, ctx)

  def lift(ast, %{depth: 0} = ctx, budget)
      when is_integer(budget) and budget > 0 do
    with count when count > 0 and count <= budget and count <= @max_joins <-
           liftable(ast, ctx),
         {:ok, condition, %{joins: joins, complete?: true}} <-
           lifted(ast, ctx, %{next: 1, joins: [], complete?: true}) do
      {:ok, %{joins: Enum.reverse(joins), condition: condition}}
    else
      _nothing_lifts -> unlifted(ast, ctx)
    end
  end

  def lift(ast, ctx, _budget), do: unlifted(ast, ctx)

  @doc """
  Lifts `ast` like `lift/3`, returning only public reasons
  (`public_reason/1`).
  """
  @spec lift_public(AST.t(), ctx(), non_neg_integer()) ::
          {:ok, lifted()} | {:error, public_reason()}
  def lift_public(ast, ctx, budget),
    do: with({:error, reason} <- lift(ast, ctx, budget), do: {:error, public_reason(reason)})

  @doc """
  Adds the joins of `lifted` (from `lift/3`) to `query`, in order, as inner
  joins on each target's explicit prefix. Apply them before the condition.
  """
  @spec apply_joins(Query.t(), lifted()) :: Query.t()
  def apply_joins(%Query{} = query, %{joins: joins}),
    do: Enum.reduce(joins, query, &inner_join/2)

  defp inner_join(%{source: {schema, name}, binding: binding, on: on}, query),
    do: join(query, :inner, [], t in ^name, prefix: ^schema, as: ^binding, on: ^on)

  defp unlifted(ast, ctx) do
    with {:ok, condition} <- compile(ast, ctx),
         do: {:ok, %{joins: [], condition: condition}}
  end

  # The number of nodes of `ast` that lift (rules 1 to 4), in tree order.
  defp liftable({:and, children}, ctx) when is_list(children),
    do: Enum.reduce(children, 0, &(liftable(&1, ctx) + &2))

  defp liftable({:relationship, name, child}, ctx) do
    case lift_target(ctx, name) do
      {:ok, _relationship, target} -> 1 + liftable(child, %{ctx | table: target})
      :error -> 0
    end
  end

  defp liftable(_node, _ctx), do: 0

  # Compiles a lifted level, threading the next alias index and the joins
  # (latest first). It walks the tree exactly as `liftable/2` counts it.
  defp lifted({:and, [_ | _] = children}, ctx, acc),
    do: combine(children, acc, &lifted(&1, ctx, &2), &both/2)

  defp lifted({:relationship, name, _child} = node, ctx, acc) do
    ctx |> lift_target(name) |> lift_relationship(node, ctx, acc)
  end

  defp lifted(node, ctx, %{complete?: complete?} = acc) do
    with {:ok, condition, acc} <- compiled(node, ctx, acc),
         do: {:ok, condition, %{acc | complete?: complete? and AST.binding_depth(node) == 0}}
  end

  defp lift_relationship(:error, node, ctx, acc),
    do: compiled(node, ctx, %{acc | complete?: false})

  defp lift_relationship(
         {:ok, %Relationship{target: ref, mapping: mapping}, target},
         {:relationship, _name, child},
         %{binding: parent} = ctx,
         %{next: index, joins: joins} = acc
       ) do
    binding = Aliases.at(index)
    on = correlation(mapping, {:as, parent}, binding)
    lifted_join = %{source: ref, binding: binding, on: on}
    inner = %{ctx | table: target, binding: binding}

    with {:ok, condition, acc} <-
           lifted(child, inner, %{acc | next: index + 1, joins: [lifted_join | joins]}) do
      {:ok, dynamic(^on and ^condition), acc}
    end
  end

  defp compiled(node, ctx, acc),
    do: with({:ok, condition} <- compile(node, ctx), do: {:ok, condition, acc})

  # The relationship `name` of `table` and its target, when rules 2 to 4 hold.
  defp lift_target(
         %{table: %Table{columns: columns} = table, tables: tables, adapter: adapter},
         name
       ) do
    with {:ok, %Relationship{kind: :object, target: ref, mapping: mapping} = rel} <-
           fetch_relationship(table, name),
         {:ok, %Table{kind: :table, primary_key: key, columns: remote_columns} = target} <-
           Table.fetch(tables, ref),
         true <- Table.strict_key?(target),
         true <- whole_key?(mapping, key),
         true <- lossless_mapping?(mapping, columns, remote_columns, adapter) do
      {:ok, rel, target}
    else
      _not_liftable -> :error
    end
  end

  defp whole_key?(mapping, key) do
    remote = Enum.map(mapping, fn {_local, remote} -> remote end)
    Enum.sort(remote) == Enum.sort(key)
  end

  defp lossless_mapping?(mapping, columns, remote_columns, adapter) do
    implements?(adapter, :lossless_join_pair?, 2) and
      Enum.all?(mapping, fn {local, remote} ->
        adapter.lossless_join_pair?(columns[local], remote_columns[remote])
      end)
  end

  @doc """
  Whether `ast`, compiled against `table`, compares any enum column, through
  relationships and `_exists` too. Such a comparison binds labels in the
  enum's type, so it fails when the type or its labels changed since load.
  """
  @spec compares_enum?(AST.t() | nil, Table.t(), %{Table.table_ref() => Table.t()}) ::
          boolean()
  def compares_enum?({group, children}, table, tables)
      when group in [:and, :or] and is_list(children),
      do: Enum.any?(children, &compares_enum?(&1, table, tables))

  def compares_enum?({:not, child}, table, tables), do: compares_enum?(child, table, tables)

  def compares_enum?({:compare, name, _op, _value}, %Table{columns: columns}, _tables),
    do: match?(%{^name => %Column{base_kind: :enum}}, columns)

  def compares_enum?({:relationship, name, child}, %Table{relationships: relationships}, tables) do
    with %{^name => %Relationship{target: ref}} <- relationships,
         {:ok, target} <- Table.fetch(tables, ref) do
      compares_enum?(child, target, tables)
    else
      _missing -> false
    end
  end

  def compares_enum?({:exists, ref, child}, _table, tables) do
    case Table.fetch(tables, ref) do
      {:ok, target} -> compares_enum?(child, target, tables)
      {:error, _unknown} -> false
    end
  end

  def compares_enum?(_ast, _table, _tables), do: false

  @doc """
  The part of an input filter `ast` that `input_index_pushdown` may also run
  outside the input fence: its top-level conjuncts (see `AST.conjuncts/1`)
  that are an `_eq` or `_in` of literals on a column `adapter` allows
  (`c:Authzura.Adapter.index_pushdown?/2`; an `_in` of more than 100 values
  stays fenced), as an `:and` of those comparisons, or `nil` when none is
  (or the adapter lacks the callback). It is a sub-tree of `ast`, so
  compiling it gives the very SQL the fence holds for those comparisons.
  """
  @spec pushdown(AST.t() | nil, Table.t(), module()) :: AST.t() | nil
  def pushdown(ast, %Table{} = table, adapter) do
    with true <- pushdown?(adapter),
         [_ | _] = comparisons <-
           ast |> AST.conjuncts() |> Enum.filter(&hoistable?(&1, table, adapter)) do
      {:and, comparisons}
    else
      _none -> nil
    end
  end

  # `c:Authzura.Adapter.index_pushdown?/2` is optional: no callback, no push-down.
  defp pushdown?(adapter),
    do: implements?(adapter, :index_pushdown?, 2)

  defp hoistable?({:compare, _name, :in, {:literal, values}}, _table, _adapter)
       when length(values) > @max_pushdown_list,
       do: false

  defp hoistable?(
         {:compare, name, op, {:literal, _value}},
         %Table{columns: columns} = table,
         adapter
       )
       when op in [:eq, :in] do
    case columns do
      %{^name => %Column{} = column} -> adapter.index_pushdown?(table, column)
      %{} -> false
    end
  end

  defp hoistable?(_node, _table, _adapter), do: false

  defp implements?(module, name, arity),
    do: Code.ensure_loaded?(module) and function_exported?(module, name, arity)

  defp both(left, right), do: dynamic(^left and ^right)

  @doc """
  Compiles `ast` against `ctx.table`. See the moduledoc.
  """
  @spec compile(AST.t(), ctx()) :: {:ok, Query.dynamic_expr()} | {:error, reason()}
  def compile({:and, []}, _ctx), do: {:ok, dynamic(true)}
  def compile({:or, []}, _ctx), do: {:ok, dynamic(false)}

  def compile({:and, children}, ctx) when is_list(children),
    do: compile_group(children, ctx, &both/2)

  def compile({:or, children}, ctx) when is_list(children),
    do: compile_group(children, ctx, fn left, right -> dynamic(^left or ^right) end)

  def compile({:not, child}, ctx) do
    with {:ok, condition} <- compile(child, ctx), do: {:ok, dynamic(not (^condition))}
  end

  def compile(
        {:compare, name, op, value},
        %{table: %Table{columns: columns} = table, adapter: adapter} = ctx
      ) do
    with {:ok, column} <- fetch(columns, name, {:unknown_column, Table.ref(table), name}),
         {:ok, rhs} <- signature(adapter, op, column),
         {:ok, bound} <- bind(value, rhs, column, ctx) do
      {:ok, comparison(bound, op, column, ctx)}
    end
  end

  def compile({:relationship, name, child}, %{table: table, binding: parent} = ctx) do
    with {:ok, %Relationship{target: ref, mapping: mapping}} <- fetch_relationship(table, name),
         {:ok, %{binding: binding} = inner} <- descend(ctx, ref),
         {:ok, condition} <- compile(child, inner) do
      on = correlation(mapping, {:parent_as, parent}, binding)
      {:ok, exists(inner, dynamic(^on and ^condition))}
    end
  end

  def compile({:exists, ref, child}, ctx) do
    with {:ok, inner} <- descend(ctx, ref),
         {:ok, condition} <- compile(child, inner) do
      {:ok, exists(inner, condition)}
    end
  end

  def compile(_node, _ctx), do: {:error, :invalid_filter}

  defp compile_group(children, ctx, combine_with) do
    with {:ok, condition, nil} <- combine(children, nil, &compiled(&1, ctx, &2), combine_with),
         do: {:ok, condition}
  end

  # Folds the non-empty `children` left to right: `step` compiles a child
  # against a state it threads (`nil` in `compile/2`, the lift accumulator
  # in `lift/3`), and `combine_with` combines the conditions.
  defp combine(children, state, step, combine_with) do
    Enum.reduce_while(children, {:ok, nil, state}, fn child, {:ok, left, state} ->
      child |> step.(state) |> joined(left, combine_with)
    end)
  end

  defp joined({:ok, condition, state}, nil, _combine_with), do: {:cont, {:ok, condition, state}}

  defp joined({:ok, condition, state}, left, combine_with),
    do: {:cont, {:ok, combine_with.(left, condition), state}}

  defp joined(error, _left, _combine_with), do: {:halt, error}

  # Looks `key` up in `map` (which may be anything), or returns `{:error, error}`.
  defp fetch(map, key, error) do
    case map do
      %{^key => value} -> {:ok, value}
      _missing -> {:error, error}
    end
  end

  # Comparisons.

  defp signature(adapter, op, %Column{pg_type: pg_type} = column) do
    with {:ok, %{lhs: lhs, rhs: rhs}} <- supported(adapter.operator_signature(op), op),
         true <- adapter.lhs_compatible?(lhs, column) do
      {:ok, rhs}
    else
      false -> {:error, {:operator_type_mismatch, op, pg_type}}
      error -> error
    end
  end

  defp signature(adapter, op, _not_a_column) do
    with {:ok, _signature} <- supported(adapter.operator_signature(op), op),
         do: {:error, :invalid_filter}
  end

  defp supported({:ok, signature}, _op), do: {:ok, signature}
  defp supported(:unsupported, op), do: {:error, {:unsupported_operator, op}}

  defp bind(operand, rhs, column, %{adapter: adapter} = ctx) do
    with :ok <- adapter.bindable(rhs, column), do: bind_operand(operand, rhs, column, ctx)
  end

  # Literals were cast at parse time; only their shape is checked here, so a
  # malformed AST is refused instead of reaching `compile_operator/5`.
  defp bind_operand({:literal, value}, rhs, _column, _ctx),
    do: value |> literal_shape?(rhs) |> literal(value)

  defp bind_operand({:session, name}, _rhs, _column, %{session: :validate}),
    do: {:ok, {:validated, name}}

  defp bind_operand({:session, name}, rhs, column, %{
         session: %Session{vars: vars},
         adapter: adapter
       }) do
    with {:ok, raw} <- fetch(vars, name, {:missing_session_variable, name}),
         {:ok, value} <-
           {:session, raw} |> adapter.cast_value(rhs, column, :permission) |> cast_session(name) do
      {:ok, {:session_value, value}}
    end
  end

  defp bind_operand(_operand, _rhs, _column, _ctx), do: {:error, :invalid_filter}

  defp literal_shape?(nil, rhs), do: rhs == :column
  defp literal_shape?(value, rhs) when rhs in [:column_array, :text_array], do: is_list(value)
  defp literal_shape?(value, :boolean), do: is_boolean(value)
  defp literal_shape?(value, :text), do: is_binary(value)
  defp literal_shape?(_value, rhs), do: rhs in [:column, :jsonb]

  defp literal(true, value), do: {:ok, {:value, value}}
  defp literal(false, _value), do: {:error, :invalid_filter}

  defp cast_session({:ok, value}, _name), do: {:ok, value}
  defp cast_session({:error, reason}, name), do: {:error, {:invalid_session_value, name, reason}}

  defp comparison({:validated, _name}, _op, _column, _ctx), do: dynamic(true)

  # A session value is never NULL (a missing variable is an error and no
  # cast yields `nil`), so the null arm of Hasura's null-aware form is
  # always false: compared as on a non-null column, it is a plain `col = $n`
  # with the same truth table, which plans better. A `nil` would take the
  # literal-NULL form, never a raise.
  defp comparison({:session_value, nil}, op, column, ctx),
    do: comparison({:value, nil}, op, column, ctx)

  defp comparison({:session_value, value}, op, %Column{} = column, ctx),
    do: comparison({:value, value}, op, %{column | nullable?: false}, ctx)

  defp comparison(
         {:value, value},
         op,
         %Column{name: name} = column,
         %{adapter: adapter, binding: binding, mode: mode}
       ),
       do: adapter.compile_operator(op, dynamic(field(as(^binding), ^name)), value, column, mode)

  # Relationship and exists scopes.

  defp fetch_relationship(%Table{relationships: relationships} = table, name) do
    case relationships do
      %{^name => %Relationship{mapping: [_ | _]} = relationship} -> {:ok, relationship}
      _missing -> {:error, {:unknown_relationship, Table.ref(table), name}}
    end
  end

  defp descend(%{depth: depth}, _ref) when depth >= @max_depth, do: {:error, :too_deep}

  defp descend(%{tables: tables, depth: depth} = ctx, ref) do
    with {:ok, target} <- Table.fetch(tables, ref),
         do: {:ok, %{ctx | table: target, binding: Aliases.at(depth + 1), depth: depth + 1}}
  end

  # The mapping equalities `remote = local`. The local side is named through
  # `parent_as/1` for an `EXISTS` correlated to an outer binding, or `as/1`
  # for a join at the same query level.
  defp correlation([{local, remote} | rest], parent, binding) do
    Enum.reduce(rest, pair(local, remote, parent, binding), fn {local, remote}, acc ->
      dynamic(^acc and ^pair(local, remote, parent, binding))
    end)
  end

  defp pair(local, remote, {:parent_as, parent}, binding),
    do: dynamic(field(as(^binding), ^remote) == field(parent_as(^parent), ^local))

  defp pair(local, remote, {:as, parent}, binding),
    do: dynamic(field(as(^binding), ^remote) == field(as(^parent), ^local))

  defp exists(%{table: %Table{schema: schema, name: name}, binding: binding}, condition) do
    sub = from(t in name, prefix: ^schema, as: ^binding, where: ^condition, select: 1)
    dynamic(exists(subquery(sub)))
  end
end

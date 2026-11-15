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

  import Ecto.Query, only: [dynamic: 1, from: 2, subquery: 1]

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
  @spec public_reason(reason()) ::
          :forbidden
          | {:missing_session_variable, String.t()}
          | {:invalid_session_value, String.t(), term()}
  def public_reason({:missing_session_variable, _name} = reason), do: reason
  def public_reason({:invalid_session_value, _name, _detail} = reason), do: reason
  def public_reason(_internal), do: :forbidden

  @doc """
  Compiles `ast` like `compile/2`, returning only public reasons
  (`public_reason/1`).
  """
  @spec compile_public(AST.t(), ctx()) ::
          {:ok, Query.dynamic_expr()}
          | {:error,
             :forbidden
             | {:missing_session_variable, String.t()}
             | {:invalid_session_value, String.t(), term()}}
  def compile_public(ast, ctx),
    do: with({:error, reason} <- compile(ast, ctx), do: {:error, public_reason(reason)})

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
    do: Code.ensure_loaded?(adapter) and function_exported?(adapter, :index_pushdown?, 2)

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

  @doc """
  Compiles `ast` against `ctx.table`. See the moduledoc.
  """
  @spec compile(AST.t(), ctx()) :: {:ok, Query.dynamic_expr()} | {:error, reason()}
  def compile({:and, []}, _ctx), do: {:ok, dynamic(true)}
  def compile({:or, []}, _ctx), do: {:ok, dynamic(false)}

  def compile({:and, children}, ctx) when is_list(children),
    do: combine(children, ctx, fn left, right -> dynamic(^left and ^right) end)

  def compile({:or, children}, ctx) when is_list(children),
    do: combine(children, ctx, fn left, right -> dynamic(^left or ^right) end)

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
      {:ok, exists(inner, dynamic(^correlation(mapping, parent, binding) and ^condition))}
    end
  end

  def compile({:exists, ref, child}, ctx) do
    with {:ok, inner} <- descend(ctx, ref),
         {:ok, condition} <- compile(child, inner) do
      {:ok, exists(inner, condition)}
    end
  end

  def compile(_node, _ctx), do: {:error, :invalid_filter}

  defp combine(children, ctx, join),
    do: Enum.reduce_while(children, nil, &(&1 |> compile(ctx) |> joined(&2, join)))

  defp joined({:ok, condition}, nil, _join), do: {:cont, {:ok, condition}}
  defp joined({:ok, condition}, {:ok, acc}, join), do: {:cont, {:ok, join.(acc, condition)}}
  defp joined(error, _acc, _join), do: {:halt, error}

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

  defp correlation([{local, remote} | rest], parent, binding) do
    Enum.reduce(rest, pair(local, remote, parent, binding), fn {local, remote}, acc ->
      dynamic(^acc and ^pair(local, remote, parent, binding))
    end)
  end

  defp pair(local, remote, parent, binding),
    do: dynamic(field(as(^binding), ^remote) == field(parent_as(^parent), ^local))

  defp exists(%{table: %Table{schema: schema, name: name}, binding: binding}, condition) do
    sub = from(t in name, prefix: ^schema, as: ^binding, where: ^condition, select: 1)
    dynamic(exists(subquery(sub)))
  end
end

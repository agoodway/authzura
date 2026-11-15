defmodule Authzura.Input do
  @moduledoc """
  Validated outside input: builds an `Authzura.Plan` from an untrusted,
  JSON-decoded request instead of a caller's Ecto query.

  The request is a map with any of these keys (atoms, or the same names as
  strings, as `Jason.decode/1` returns them; `nil` means absent):

    * `columns` - a non-empty list of column-name strings to select
    * `filter` - a filter in the source's input syntax (a Hasura `bool_exp`
      for `Authzura.Sources.Hasura`)
    * `order_by` - a list of `{column, direction}` tuples or single-key
      `%{column => direction}` maps, each naming a distinct column. The
      direction is `:asc`, `:desc`, `:asc_nulls_first`, `:asc_nulls_last`,
      `:desc_nulls_first` or `:desc_nulls_last`, or the same as a string
    * `limit` and `offset` - non-negative integers in the `bigint` range
    * `preload` - a tree of relationship names to preload (see
      `Authzura.Preload.Tree`); accepted only by `Authzura.all_input/4`,
      with at most 2 levels and 8 nodes (or the instance's stricter limits),
      and only in its JSON form: strings, lists, `null` and string-keyed maps
      A preload's `order_by` takes the same `%{column => direction}` maps;
      its tuple form is Ecto's `{direction, column}`, the reverse of the
      root's `{column, direction}`

  `build/5`:

    1. The queryable must be a bare schema module or a bare table name;
       anything else is `{:invalid_input, :not_a_root}`.
    2. The request's shape is checked. A malformed one is
       `{:invalid_input, reason}` with `:not_a_map`, `{:unknown_keys, keys}`,
       `{:duplicate_key, key}`, `{:columns, :invalid | :empty}`,
       `{:order_by, :invalid | :duplicate_column}`, `{:preload, :invalid}`
       (a preload that is not in its JSON form), `:limit` or `:offset`.
       More than 32 `order_by` terms is `{:too_many, :order_by}`.
    3. Access: the role's permission must exist (`:forbidden`) and expose
       the select root field (`:root_field_disabled`), before anything about
       its columns is revealed. More distinct `columns` than the role may
       select is `{:invalid_input, {:too_many, :columns}}`.
    4. The filter is parsed with the `c:Authzura.Source.parse_input/2` of
       the instance's source, with input limits (syntactic depth 8, 100
       nodes), against a table that holds only the columns the role may
       select (for a schema, those that map to a field) and no
       relationships. A name the source reports as `{:unknown_field, name}`
       is therefore a column the role cannot see, whether or not it exists,
       and is reported with step 5's forbidden columns; other parse errors
       are `{:invalid_input, [{path, reason}]}`. The resulting AST is
       checked again, source-independently: a session reference,
       relationship or `_exists`, or a tree over the limits is
       `{:invalid_input, [{[], reason}]}`, and an `_in`, `_nin` or
       `_has_keys_*` list of more than 10,000 elements is
       `{:invalid_input, {:too_many, :list}}` and more than 16 pattern
       operands (`_like`, `_similar`, `_regex` and their variants) is
       `{:invalid_input, {:too_many, :patterns}}`.
    5. Every column named in `columns`, the filter or `order_by` must be in
       the role's select columns; otherwise `{:forbidden_columns, cols}`.
       Sorting on a kind Postgres cannot order (`json`, unknown types) is
       `{:invalid_input, {:order_by, :unorderable}}`.
    6. The input filter is compiled in `:input` mode (plain `=`/`<>`), the
       sort and paging are applied, and the query goes through
       `Authzura.Scope.build/4`, which fences the input filter behind the
       permission filter (compiled in `:permission` mode) as
       `permission AND (CASE WHEN permission THEN input ELSE false END)`,
       so the input is never evaluated on a row the role cannot see,
       selects the projection and caps the limit. The plan carries the
       input AST in `input`. With the instance option `input_index_pushdown`,
       the top-level `_eq`/`_in` comparisons on plain leakproof columns (see
       `Authzura.Compiler.pushdown/3`) are also ANDed outside the fence:
       `permission AND pushdown AND (CASE ...)`.

  Input preloads get at most 32 `order_by` terms per relationship
  (`{:invalid_input, {:too_many, :preload_order_by}}`).

  Nothing here creates atoms from the request, and building never raises
  on a JSON-decoded term. Casting refuses every value Postgres would refuse
  at run time, except `SIMILAR TO` and regular-expression patterns, which
  only Postgres can judge: the executors and `Authzura.scope_input/4` check
  those with `Authzura.Executor.check_input/1` before the read, as
  `{:invalid_input, {:invalid_pattern, column}}`.
  """

  import Ecto.Query, only: [dynamic: 1, from: 2, limit: 2, offset: 2, order_by: 2]

  import Authzura.Util, only: [is_plain_map: 1]

  alias Authzura.{AST, Compiler, Plan, Scope, Session, Telemetry, Util}
  alias Authzura.Model.{Permission, Snapshot, Table}
  alias Authzura.Store.Generation
  alias Ecto.{Query, Queryable}

  @root :authzura_input

  @limits %{binding_depth: 0, syntactic_depth: 8, nodes: 100}

  @preload_limits %{depth: 2, nodes: 8}

  @max_bigint 9_223_372_036_854_775_807

  # Caps on list-valued input (see the moduledoc).
  @max_list 10_000
  @max_order_by 32
  @list_ops [:in, :nin, :has_keys_any, :has_keys_all]
  @max_patterns 16
  @pattern_ops AST.pattern_ops()

  @keys %{
    columns: :columns,
    filter: :filter,
    order_by: :order_by,
    limit: :limit,
    offset: :offset,
    preload: :preload
  }

  @string_keys Map.new(@keys, fn {key, key} -> {Atom.to_string(key), key} end)

  @typedoc "Why a request is invalid; see the moduledoc."
  @type reason ::
          Scope.reason()
          | {:invalid_input,
             :not_a_root
             | :not_a_map
             | :limit
             | :offset
             | {:unknown_keys, [term()]}
             | {:duplicate_key, atom()}
             | {:columns, :invalid | :empty}
             | {:order_by, :invalid | :duplicate_column | :unorderable}
             | {:preload, :invalid}
             | {:too_many, :list | :patterns | :columns | :order_by | :preload_order_by}
             | {:invalid_pattern, String.t()}
             | :rejected_by_database
             | [{[String.t()], term()}]}

  @doc """
  Builds the plan for `input` on `queryable`. `opts` are per-call options
  validated by `Authzura.Options.call!/1`, plus `mode: :scope | :execute`
  as for `Authzura.Scope.build/4`.
  """
  @spec build(Queryable.t(), Session.t(), term(), Generation.t(), keyword()) ::
          {:ok, Plan.t()} | {:error, reason()}
  def build(queryable, %Session{role: role} = session, input, %Generation{} = generation, opts) do
    metadata = %{instance: opts[:instance], role: role}

    Telemetry.span(
      :input,
      metadata,
      fn -> plan(queryable, session, input, generation, opts) end,
      &outcome/1
    )
  end

  # The table is the resolved root, only known once the plan is built.
  defp outcome({:ok, %Plan{root: {_prefix, table}}}), do: %{result: :ok, table: table}

  defp outcome({:error, reason}),
    do: %{result: :error, reason_class: Telemetry.reason_class(reason)}

  defp plan(queryable, session, input, generation, opts) do
    with :ok <- bare_root(queryable),
         {:ok, request} <- request(input),
         {:ok, %Permission{table: ref} = permission} <-
           Scope.permission(queryable, session, generation, opts),
         :ok <- Scope.root_field(permission),
         %{table: table} = ctx = context(generation, ref, session, @root),
         visible = visible_columns(queryable, permission),
         :ok <- columns_cap(Map.get(request, :columns), visible),
         {:ok, ast, unseen} <-
           filter(Map.get(request, :filter), generation, visible(ctx, visible)),
         :ok <- permitted(queryable, request, ast, unseen, permission),
         :ok <- orderable(Map.get(request, :order_by, []), table),
         {:ok, condition} <- compile(ast, ctx),
         {:ok, hoisted} <- hoisted(ast, ctx, generation),
         {:ok, plan} <-
           queryable
           |> query(request)
           |> Scope.build(
             session,
             generation,
             scope_opts(opts, request, generation, condition, hoisted)
           ) do
      {:ok, %{with_comparisons(plan, ast, ctx) | input: ast, cache_statements?: false}}
    end
  end

  @typedoc "What an input condition is compiled against; see `context/4`."
  @type context :: %{
          table: Table.t(),
          tables: %{Table.table_ref() => Table.t()},
          adapter: module(),
          session: Session.t(),
          binding: atom()
        }

  @doc """
  The context an input condition on the root `ref` is compiled in: its
  table, every table of the generation, the adapter, the session and the
  root's `binding`.
  """
  @spec context(Generation.t(), Table.table_ref(), Session.t(), atom()) :: context()
  def context(
        %Generation{snapshot: %Snapshot{tables: tables}, config: %{adapter: adapter}},
        ref,
        %Session{} = session,
        binding
      )
      when is_atom(binding),
      do: %{
        table: Map.fetch!(tables, ref),
        tables: tables,
        adapter: adapter,
        session: session,
        binding: binding
      }

  @doc """
  Compiles `ast` (or `nil`, no condition) in `:input` mode, or in `:pinned`
  mode (see `t:Authzura.Adapter.mode/0`), against the root binding of `ctx`.
  A failure is `{:invalid_input, [{[], reason}]}`.
  """
  @spec compile(AST.t() | nil, context(), :input | :pinned) ::
          {:ok, Query.dynamic_expr() | nil} | {:error, {:invalid_input, [{[], term()}]}}
  def compile(ast, ctx, mode \\ :input)

  def compile(nil, _ctx, _mode), do: {:ok, nil}

  def compile(
        ast,
        %{
          table: table,
          tables: tables,
          adapter: adapter,
          session: session,
          binding: binding
        },
        mode
      ) do
    ctx = %{Compiler.root_ctx(table, tables, session, adapter, mode) | binding: binding}

    with {:error, reason} <- Compiler.compile(ast, ctx), do: invalid(reason)
  end

  @doc """
  Returns `plan` with `enum_comparisons?` also set when `ast`, compiled with
  `ctx`, compares an enum column (see `Authzura.Compiler.compares_enum?/3`).
  """
  @spec with_comparisons(Plan.t(), AST.t() | nil, context()) :: Plan.t()
  def with_comparisons(%Plan{enum_comparisons?: enum?} = plan, ast, %{
        table: table,
        tables: tables
      }),
      do: %{plan | enum_comparisons?: enum? or Compiler.compares_enum?(ast, table, tables)}

  # With `input_index_pushdown`, the input comparisons that also run outside the
  # fence (see `Authzura.Compiler.pushdown/3`), compiled like the fenced ones.
  defp hoisted(
         ast,
         %{table: table, adapter: adapter} = ctx,
         %Generation{config: %{input_index_pushdown: true}}
       ),
       do: ast |> Compiler.pushdown(table, adapter) |> compile(ctx, :pinned)

  defp hoisted(_ast, _ctx, %Generation{}), do: {:ok, nil}

  # The root.

  defp bare_root(name) when is_binary(name), do: :ok

  defp bare_root(module) when is_atom(module), do: module |> schema?() |> schema_root()
  defp bare_root(_queryable), do: schema_root(false)

  defp schema_root(true), do: :ok
  defp schema_root(false), do: {:error, {:invalid_input, :not_a_root}}

  defp schema?(module),
    do: Code.ensure_loaded?(module) and function_exported?(module, :__schema__, 2)

  # The request's shape.

  defp request(input) when is_plain_map(input) do
    input
    |> Enum.reduce_while({:ok, %{}}, &entry/2)
    |> validate_entries()
  end

  defp request(_input), do: {:error, {:invalid_input, :not_a_map}}

  defp entry({key, value}, {:ok, acc}) do
    case known_key(key) do
      nil ->
        {:cont, {:unknown, [key]}}

      name when is_map_key(acc, name) ->
        {:halt, {:error, {:invalid_input, {:duplicate_key, name}}}}

      name ->
        {:cont, {:ok, Map.put(acc, name, value)}}
    end
  end

  defp entry({key, _value}, {:unknown, keys}) do
    case known_key(key) do
      nil -> {:cont, {:unknown, [key | keys]}}
      _name -> {:cont, {:unknown, keys}}
    end
  end

  defp known_key(key) when is_atom(key), do: Map.get(@keys, key)
  defp known_key(key) when is_binary(key), do: Map.get(@string_keys, key)
  defp known_key(_key), do: nil

  defp validate_entries({:unknown, keys}),
    do: {:error, {:invalid_input, {:unknown_keys, Enum.reverse(keys)}}}

  defp validate_entries({:error, _reason} = error), do: error

  defp validate_entries({:ok, entries}) do
    present = Enum.reject(entries, fn {_key, value} -> is_nil(value) end)

    with {:ok, values} <- Util.map_ok(present, &entry_value/1), do: {:ok, Map.new(values)}
  end

  defp entry_value({key, value}) do
    case value(key, value) do
      {:ok, value} -> {:ok, {key, value}}
      {:error, reason} -> {:error, {:invalid_input, reason}}
    end
  end

  defp value(:columns, []), do: {:error, {:columns, :empty}}

  defp value(:columns, columns) when is_list(columns),
    do: columns |> Enum.all?(&is_binary/1) |> column_names(columns)

  defp value(:columns, _columns), do: {:error, {:columns, :invalid}}

  defp value(:order_by, order) when is_list(order) and length(order) > @max_order_by,
    do: {:error, {:too_many, :order_by}}

  defp value(:order_by, order) when is_list(order) do
    with {:ok, terms} <- Util.map_ok(order, &order_term/1),
         :ok <- distinct_columns(terms),
         do: {:ok, terms}
  end

  defp value(:order_by, _order), do: {:error, {:order_by, :invalid}}

  defp value(bound, n) when bound in [:limit, :offset] and is_integer(n) and n in 0..@max_bigint,
    do: {:ok, n}

  defp value(bound, _n) when bound in [:limit, :offset], do: {:error, bound}

  defp value(:preload, tree), do: tree |> json_tree?() |> json_preload(tree)

  defp value(_key, value), do: {:ok, value}

  # A preload is read in its JSON form only: strings, lists, `null` and
  # string-keyed maps. Atoms, tuples and structs are Elixir-only terms.
  defp json_tree?(nil), do: true
  defp json_tree?(name) when is_binary(name), do: true
  defp json_tree?(list) when is_list(list), do: Enum.all?(list, &json_tree?/1)

  defp json_tree?(map) when is_plain_map(map),
    do: Enum.all?(map, fn {key, value} -> is_binary(key) and json_tree?(value) end)

  defp json_tree?(_term), do: false

  defp json_preload(true, tree), do: {:ok, tree}
  defp json_preload(false, _tree), do: {:error, {:preload, :invalid}}

  defp column_names(true, columns), do: {:ok, columns}
  defp column_names(false, _columns), do: {:error, {:columns, :invalid}}

  defp order_term({column, direction}) when is_binary(column), do: direction(column, direction)

  defp order_term(term) when is_plain_map(term) and map_size(term) == 1,
    do: term |> Map.to_list() |> hd() |> order_term()

  defp order_term(_term), do: {:error, {:order_by, :invalid}}

  defp direction(column, direction) do
    case Util.direction(direction) do
      {:ok, direction} -> {:ok, {column, direction}}
      :error -> {:error, {:order_by, :invalid}}
    end
  end

  defp distinct_columns(terms) do
    columns = Enum.map(terms, &elem(&1, 0))
    distinct(length(Enum.uniq(columns)) == length(columns))
  end

  defp distinct(true), do: :ok
  defp distinct(false), do: {:error, {:order_by, :duplicate_column}}

  # The filter.

  # More distinct names than the role can see cannot all be allowed. The
  # bound is the role's own column count, so it reveals nothing about the
  # table.
  defp columns_cap(nil, _visible), do: :ok

  defp columns_cap(columns, visible),
    do: columns |> Enum.uniq() |> length() |> at_most(length(visible), :columns)

  defp at_most(n, max, key) when n > max, do: {:error, {:invalid_input, {:too_many, key}}}
  defp at_most(_n, _max, _key), do: :ok

  # The filter is parsed against the columns the role may select and
  # nothing else: no relationships and no hidden columns, so a hidden
  # column, a relationship or a name that does not exist all look the same.
  defp visible(%{table: %Table{columns: columns} = table} = ctx, names),
    do: %{ctx | table: %{table | columns: Map.take(columns, names), relationships: %{}}}

  # The columns the role may select (for a schema, those that map to a field).
  defp visible_columns(queryable, %Permission{columns: allowed}),
    do: Enum.filter(allowed, &selectable?(queryable, &1))

  defp filter(nil, _generation, _ctx), do: {:ok, nil, []}

  defp filter(
         json,
         %Generation{config: %{source: {source, source_opts}}},
         %{table: table, tables: tables, adapter: adapter}
       ) do
    parse_ctx = %{
      table: table,
      tables: tables,
      adapter: adapter,
      limits: @limits,
      source_opts: source_opts
    }

    case source.parse_input(json, parse_ctx) do
      {:ok, ast} -> with {:ok, ast} <- checked(ast), do: {:ok, ast, []}
      {:error, errors} -> parse_errors(errors)
    end
  end

  # A name the role cannot see is reported as a forbidden column, with the
  # request's other forbidden columns, before any other parse error.
  defp parse_errors(errors) do
    case for({_path, {:unknown_field, name}} <- errors, do: name) do
      [] -> {:error, {:invalid_input, errors}}
      unseen -> {:ok, nil, unseen}
    end
  end

  # Defense in depth: whatever the source returned, input never reads the
  # session, never leaves the root row, and stays within the input limits.
  defp checked(ast) do
    cond do
      MapSet.size(AST.session_refs(ast)) > 0 -> invalid(:session_reference)
      AST.binding_depth(ast) > 0 -> invalid(:relationship_in_input)
      AST.syntactic_depth(ast) > @limits.syntactic_depth -> invalid(:too_deep)
      AST.node_count(ast) > @limits.nodes -> invalid(:too_large)
      long_list?(ast) -> {:error, {:invalid_input, {:too_many, :list}}}
      patterns(ast) > @max_patterns -> {:error, {:invalid_input, {:too_many, :patterns}}}
      true -> {:ok, ast}
    end
  end

  defp patterns(ast), do: ast |> AST.comparisons() |> Enum.count(&pattern?/1)

  defp pattern?({:compare, _column, op, _value}), do: op in @pattern_ops

  defp long_list?(ast) do
    Enum.any?(AST.comparisons(ast), fn
      {:compare, _column, op, {:literal, list}} when op in @list_ops and is_list(list) ->
        length(list) > @max_list

      _comparison ->
        false
    end)
  end

  defp invalid(reason), do: {:error, {:invalid_input, [{[], reason}]}}

  # Columns.

  defp permitted(queryable, request, ast, unseen, %Permission{} = permission) do
    named =
      Map.get(request, :columns, []) ++
        filter_columns(ast, unseen) ++
        Enum.map(Map.get(request, :order_by, []), &elem(&1, 0))

    named
    |> Enum.uniq()
    |> Enum.reject(&(Permission.allows?(permission, &1) and selectable?(queryable, &1)))
    |> Util.forbidden_columns()
  end

  defp filter_columns(nil, unseen), do: Enum.sort(unseen)
  defp filter_columns(ast, []), do: ast |> AST.root_columns() |> Enum.sort()

  # A schema's column counts only when it maps back to a field.
  defp selectable?(name, _column) when is_binary(name), do: true
  defp selectable?(schema, column), do: Scope.field_for(schema, column) != nil

  # Kinds Postgres cannot sort are refused rather than left to fail at
  # execution.
  defp orderable(terms, %Table{} = table),
    do: Table.orderable(table, Enum.map(terms, &elem(&1, 0)))

  # The query.

  # The input condition is not added here: `Authzura.Scope.build/4` fences
  # it behind the permission filter.
  defp query(queryable, request) do
    from(r in queryable, as: ^@root)
    |> order(queryable, Map.get(request, :order_by))
    |> page(:limit, Map.get(request, :limit))
    |> page(:offset, Map.get(request, :offset))
  end

  defp order(query, _queryable, nil), do: query

  defp order(query, queryable, terms) do
    order_by(
      query,
      ^Enum.map(terms, fn {column, dir} ->
        key = key(queryable, column)
        {dir, dynamic(field(as(^@root), ^key))}
      end)
    )
  end

  defp key(name, column) when is_binary(name), do: column
  defp key(schema, column), do: Scope.field_for(schema, column)

  defp page(query, _bound, nil), do: query
  defp page(query, :limit, n), do: limit(query, ^n)
  defp page(query, :offset, n), do: offset(query, ^n)

  defp scope_opts(opts, request, generation, condition, hoisted) do
    [:columns, :preload]
    |> Enum.reduce(opts, fn key, opts ->
      case Map.fetch(request, key) do
        {:ok, value} -> Keyword.put(opts, key, value)
        :error -> opts
      end
    end)
    |> Keyword.put(:preload_limits, preload_limits(generation))
    |> Keyword.put(:input_filter, condition)
    |> Keyword.put(:input_pushdown, hoisted)
  end

  # Input preloads get stricter limits than the instance's, never looser.
  defp preload_limits(%Generation{config: %{max_preload_depth: depth, max_preload_nodes: nodes}}),
    do: %{
      depth: min(depth, @preload_limits.depth),
      nodes: min(nodes, @preload_limits.nodes),
      order_by: @max_order_by
    }
end

defmodule Authzura.Scope do
  @moduledoc """
  Builds an `Authzura.Plan` from a caller's queryable, a session and one
  policy generation.

  `build/4`:

    1. Validates the query shape with `Authzura.QueryShape`.
    2. **Root.** Derives the physical `{prefix, source}` with Ecto's own
       precedence: the `from` prefix (which holds a schema's
       `@schema_prefix`), the schema prefix, the query prefix, then the
       instance's `default_prefix`. The prefix is then **pinned** on the root
       `from`, so neither a repo `prefix:` option, a `search_path` nor a CTE
       of the same name can redirect the read. `table:` is only an assertion.
    3. **Access.** Looks up the `{role, root}` template. A missing or denied
       permission is `:forbidden`, and one whose `root_fields` exclude
       `:select` is `:root_field_disabled` (a read by primary key also
       accepts `:select_by_pk`; see `root_field/2`). The configured admin role skips
       the template (the root must still be a known table) and gets every
       column, no filter and no limit.
    4. **Columns.** Fields map to columns through
       `__schema__(:field_source, field)`. Virtual or unknown fields and
       columns the role cannot read are `{:forbidden_columns, columns}`. The
       default is every allowed column (for schemas, those that map to a
       field) except those of base kind `:other`, which the repo may not be
       able to decode (`Authzura.Model.Table.default_columns/2`); they are
       selected only when named.
    5. **Select.** A map of exactly the projection: field atoms for schema
       queries, column strings for table queries.
    6. **Filter and limit.** Reuses the root's alias or attaches
       `:__authzura_0`, ANDs in the compiled row filter, and caps the limit
       at `min(caller, permission)`.
    7. **Combinations.** Every branch must have the same physical root. Each
       is scoped like the root, with the same projection in the same order
       and its own permission-capped limit. The parent's `order_by`, `limit`
       and `offset` apply to the whole combination, as in Ecto, so the
       parent's cap bounds the whole result.

  Only public reasons are returned; a filter that fails to compile at
  request time (never expected after load-time validation) is `:forbidden`.
  """

  import Ecto.Query, only: [dynamic: 1, from: 2, limit: 2, select: 2, where: 2]

  import Authzura.Preload.Tree, only: [is_empty_tree: 1]

  alias Authzura.{Compiler, Plan, QueryShape, SchemaFields, Session, Util}
  alias Authzura.Compiler.Aliases
  alias Authzura.Model.{Column, Permission, Relationship, Snapshot, Table}
  alias Authzura.Preload.Tree
  alias Authzura.Store.Generation
  alias Ecto.{Query, Queryable}
  alias Ecto.Query.FromExpr

  @type reason ::
          :forbidden
          | {:forbidden_columns, [String.t()]}
          | {:missing_session_variable, String.t()}
          | {:invalid_session_value, String.t(), term()}
          | {:unsupported_query, atom() | {:preload, String.t()}}
          | :root_field_disabled

  @branch_bounds %{max_rows: nil, input: nil, pushdown: nil}

  @typep target :: %{
           root: Table.table_ref(),
           table: Table.t(),
           schema: module() | nil,
           permission: Permission.t(),
           admin?: boolean()
         }

  @doc """
  Builds the plan. `opts` are per-call options validated by
  `Authzura.Options.call!/1`, plus the internal `mode: :scope | :execute`
  (default `:scope`). An explicit `columns: []` is
  `{:unsupported_query, :empty_columns}`, and a pinned limit or offset that
  is not a nonnegative integer is `{:unsupported_query, :limit | :offset}`.

  Preloads (the query's own and `opts[:preload]`) are refused in `:scope`
  mode with `{:unsupported_query, :preload_requires_execute}`. In `:execute`
  mode the query's Ecto preloads are translated with
  `Authzura.Preload.Tree.from_ecto_query/2`, merged with `opts[:preload]`,
  validated with `Authzura.Preload.Tree.validate/5` and stripped from the
  query; `plan.preloads` holds the validated nodes, or `nil` for none. The
  limits are the instance's `max_preload_depth` and `max_preload_nodes`,
  unless the internal `preload_limits: %{depth: d, nodes: n}` overrides
  them. Each top-level relationship's local mapping columns are added to
  the projection and the select as `public?: false` columns when not
  already selected. Preloads on a combination are
  `{:unsupported_query, :combination_preload}`.

  The internal `max_rows: n` also caps the parent query's limit at `n` (the
  `:one` executor passes 2). It never caps a combination branch, whose
  limit would change the combined result.

  The internal `root_field: :select | :select_by_pk` names the root field
  the read needs (default `:select`; see `root_field/2`).

  The internal `input_filter: condition` is an untrusted filter (from
  `Authzura.Input`) for the parent query. It is evaluated only on rows the
  permission filter admits:
  `permission AND (CASE WHEN permission THEN input ELSE false END)`.
  A caller's own `where` gets no such fence: Postgres may evaluate it on
  rows the role cannot see (see "Trusted predicates" in `Authzura.scope/3`).

  The internal `input_pushdown: condition` (set only when the instance has
  `input_index_pushdown: true`) is the part of that input the planner may also
  see outside the fence:
  `permission AND pushdown AND (CASE WHEN permission THEN input ELSE false END)`.
  `Authzura.Compiler.pushdown/3` admits only leakproof `_eq`/`_in` comparisons.
  """
  @spec build(Queryable.t(), Session.t(), Generation.t(), keyword()) ::
          {:ok, Plan.t()} | {:error, reason()}
  def build(
        queryable,
        %Session{} = session,
        %Generation{config: %{repo: repo, adapter: adapter}} = generation,
        opts
      ) do
    mode = Keyword.get(opts, :mode, :scope)

    with {:ok, query, %{root: root, permission: permission} = target} <-
           resolve(queryable, session, generation, opts, mode),
         :ok <- root_field(permission, Keyword.get(opts, :root_field, :select)),
         {:ok, columns} <- requested_columns(Keyword.get(opts, :columns)),
         {:ok, projection} <- projection(target, columns),
         {:ok, preloads} <- preloads(query, target, {session, generation}, opts, mode),
         {:ok, projection} <- stitching(projection, preloads, target),
         {:ok, query} <-
           scope_query(
             query,
             target,
             {session, generation},
             root_bounds(opts),
             {:select, projection, target}
           ) do
      {:ok,
       %Plan{
         query: %{query | preloads: [], assocs: []},
         root: root,
         projection: projection,
         shape: shape(target),
         preloads: preloads,
         other_columns: other_columns(target, projection, preloads),
         enum_comparisons?: enum_comparisons?(target, preloads, generation),
         repo: repo,
         adapter: adapter,
         session: session,
         exec: exec(opts, generation)
       }}
    end
  end

  @doc """
  Filters `queryable` with the role's row permission and nothing else, for
  integrations that apply columns and limits themselves.

  It runs the same root, access and filter path as `build/4` in `:scope`
  mode (so the same shape, root-field, prefix, alias and session-variable
  checks apply) but adds no select, permission limit or order: the caller's
  own clauses are kept. Returns the query and the permission it was built
  from, both from `generation`.
  """
  @spec filter_rows(Queryable.t(), Session.t(), Generation.t(), keyword()) ::
          {:ok, Query.t(), Permission.t()} | {:error, reason()}
  def filter_rows(queryable, %Session{} = session, %Generation{} = generation, opts) do
    with {:ok, query, %{permission: permission} = target} <-
           resolve(queryable, session, generation, opts, :scope),
         :ok <- root_field(permission),
         :ok <- no_combinations(query),
         {:ok, query} <-
           scope_query(query, target, {session, generation}, root_bounds([]), :filter_only),
         do: {:ok, query, permission}
  end

  defp no_combinations(%Query{combinations: []}), do: :ok

  defp no_combinations(%Query{}),
    do: {:error, {:unsupported_query, :combination_requires_scope}}

  @doc """
  Returns the select permission that applies to `queryable`'s root for the
  session's role (a synthesized full permission for the admin role).

  This is introspection: `root_fields` is not enforced here, and the
  returned permission carries it.
  """
  @spec permission(Queryable.t(), Session.t(), Generation.t(), keyword()) ::
          {:ok, Permission.t()} | {:error, reason()}
  def permission(queryable, %Session{} = session, %Generation{} = generation, opts) do
    with {:ok, _query, %{permission: permission}} <-
           resolve(queryable, session, generation, opts, :execute),
         do: {:ok, permission}
  end

  @doc """
  Checks that the role may read every one of `columns` on `queryable`'s root.
  This is not query certification: it checks names only.
  """
  @spec validate_columns(
          Queryable.t(),
          Session.t(),
          Generation.t(),
          [atom() | String.t()],
          keyword()
        ) :: :ok | {:error, reason()}
  def validate_columns(queryable, %Session{} = session, %Generation{} = generation, columns, opts)
      when is_list(columns) do
    with {:ok, _query, target} <- resolve(queryable, session, generation, opts, :execute),
         {:ok, _projection} <- projection(target, columns),
         do: :ok
  end

  # Root and access.

  @spec resolve(Queryable.t(), Session.t(), Generation.t(), keyword(), QueryShape.mode()) ::
          {:ok, Query.t(), target()} | {:error, reason()}
  defp resolve(queryable, session, generation, opts, mode) do
    query = Queryable.to_query(queryable)

    with :ok <- QueryShape.validate(query, mode),
         root = root_ref(query, generation),
         :ok <- assert_table(root, Keyword.get(opts, :table)),
         {:ok, target} <- target(generation, session, root, schema(query)) do
      {:ok, query, target}
    end
  end

  @doc """
  The physical `{prefix, source}` root of `query`, whose `from` must be a
  table source (as `Authzura.QueryShape` checks): the `from` prefix, the
  schema's `@schema_prefix`, the query prefix, then the instance's
  `default_prefix`.
  """
  @spec root_ref(Query.t(), Generation.t()) :: Table.table_ref()
  def root_ref(%Query{prefix: prefix} = query, %Generation{config: %{default_prefix: default}}),
    do: root(query, [prefix, default])

  # The physical root of a query whose `from` is a table source, which
  # `QueryShape` has already checked. The last fallback is always a string.
  defp root(%Query{from: %FromExpr{source: {name, schema}, prefix: prefix}}, fallbacks)
       when is_binary(name),
       do: {Enum.find([prefix, schema_prefix(schema) | fallbacks], &is_binary/1), name}

  defp schema_prefix(nil), do: nil
  defp schema_prefix(schema), do: schema.__schema__(:prefix)

  @doc """
  The Ecto schema of `query`'s table source, or `nil` for a bare table. Like
  `root_ref/2`, it expects a `from` that `Authzura.QueryShape` has checked.
  """
  @spec schema(Query.t()) :: module() | nil
  def schema(%Query{from: %FromExpr{source: {_name, schema}}}), do: schema

  defp assert_table(_root, nil), do: :ok
  defp assert_table(root, root), do: :ok
  defp assert_table(_root, _table), do: {:error, {:unsupported_query, :table_mismatch}}

  defp target(generation, %Session{role: role}, root, schema) do
    with {:ok, %{template: {permission, _filter}, table: table, admin?: admin?}} <-
           Generation.access(generation, role, root),
         do: {:ok, target(root, table, schema, permission, admin?)}
  end

  defp target(root, table, schema, permission, admin?),
    do: %{root: root, table: table, schema: schema, permission: permission, admin?: admin?}

  @doc """
  Checks that `permission` exposes the root field a read needs: `:ok`, or
  `{:error, :root_field_disabled}`. A list or single-row read (`:select`,
  the default) needs `select`; a read by primary key (`:select_by_pk`, for
  `Authzura.get/4`) needs `select_by_pk` or `select`. The admin role's
  synthesized permission keeps the default `root_fields: :all`.
  """
  @spec root_field(Permission.t(), :select | :select_by_pk) ::
          :ok | {:error, :root_field_disabled}
  def root_field(permission, read \\ :select)

  def root_field(%Permission{root_fields: :all}, _read), do: :ok

  def root_field(%Permission{root_fields: fields}, :select) when is_list(fields),
    do: select_enabled(:select in fields)

  def root_field(%Permission{root_fields: fields}, :select_by_pk) when is_list(fields),
    do: select_enabled(:select in fields or :select_by_pk in fields)

  defp select_enabled(true), do: :ok
  defp select_enabled(false), do: {:error, :root_field_disabled}

  @doc """
  Returns `{field, column}` for every field of `schema`, in field order,
  whose column is one of `columns`: the columns a schema query can select.
  """
  @spec field_columns(module(), [String.t()]) :: [{atom(), String.t()}]
  def field_columns(schema, columns) when is_atom(schema) and is_list(columns) do
    %{by_column: by_column, rank: rank} = SchemaFields.get(schema)

    for(column <- Enum.uniq(columns), field = Map.get(by_column, column), do: {field, column})
    |> Enum.sort_by(fn {field, _column} -> Map.fetch!(rank, field) end)
  end

  @doc """
  Returns the field of `schema` whose source is the column `column`, or
  `nil` when no field maps to it.
  """
  @spec field_for(module(), String.t()) :: atom() | nil
  def field_for(schema, column) when is_atom(schema) and is_binary(column),
    do: schema |> SchemaFields.by_column() |> Map.get(column)

  # Columns.

  # Hasura selects at least one field, so an explicit empty list is refused.
  defp requested_columns([]), do: {:error, {:unsupported_query, :empty_columns}}
  defp requested_columns(columns), do: {:ok, columns}

  # The default leaves out `:other` columns (see `Table.default_columns/2`).
  defp projection(%{schema: nil, table: table, permission: %Permission{columns: allowed}}, nil),
    do: {:ok, table |> Table.default_columns(allowed) |> Enum.map(&column(&1, &1))}

  # In field order, from the schema's cached field list.
  defp projection(%{schema: schema, table: table, permission: %Permission{} = permission}, nil) do
    %{fields: fields, by_column: by_column} = SchemaFields.get(schema)

    {:ok,
     for(
       {field, source} <- fields,
       Map.fetch!(by_column, source) == field,
       Permission.allows?(permission, source),
       Table.default_column?(table, source),
       do: column(field, source)
     )}
  end

  # Names are looked up in the schema's cached maps and the permission's
  # column set, so a wide table costs no scan per requested column.
  defp projection(%{schema: schema, permission: %Permission{} = allowed}, requested)
       when is_list(requested) do
    lookups = %{fields: fields_by_column(schema), allowed: allowed}
    results = requested |> Enum.uniq() |> Enum.map(&lookup(schema, &1, lookups))

    with :ok <- Util.forbidden_columns(for {:error, name} <- results, do: name),
         do: {:ok, Enum.uniq_by(for({:ok, column} <- results, do: column), & &1.key)}
  end

  defp lookup(nil, name, lookups) when is_atom(name),
    do: lookup(nil, Atom.to_string(name), lookups)

  defp lookup(nil, name, %{allowed: allowed}) when is_binary(name),
    do: permitted(name, name, allowed)

  defp lookup(schema, field, %{allowed: allowed}) when is_atom(field),
    do: schema |> column_for(field) |> lookup_field(field, allowed)

  defp lookup(_schema, name, %{fields: fields, allowed: allowed}) when is_binary(name),
    do: fields |> Map.get(name) |> lookup_name(name, allowed)

  # Each column's field (the first, in field order, as `field_for/2`).
  defp fields_by_column(nil), do: %{}
  defp fields_by_column(schema), do: SchemaFields.by_column(schema)

  defp lookup_field(nil, field, _allowed), do: {:error, Atom.to_string(field)}
  defp lookup_field(source, field, allowed), do: permitted(field, source, allowed)

  defp lookup_name(nil, name, _allowed), do: {:error, name}
  defp lookup_name(field, name, allowed), do: permitted(field, name, allowed)

  defp permitted(key, column, allowed),
    do: allowed |> Permission.allows?(column) |> permit(key, column)

  defp permit(true, key, column), do: {:ok, column(key, column)}
  defp permit(false, _key, column), do: {:error, column}

  @doc """
  Returns the column (as a string) that `field` of `schema` reads, or `nil`
  for a virtual or unknown field.
  """
  @spec column_for(module(), atom()) :: String.t() | nil
  def column_for(schema, field) when is_atom(schema) and is_atom(field),
    do: schema |> SchemaFields.by_field() |> Map.get(field)

  defp column(key, column), do: %{key: key, column: column, public?: true}

  defp shape(%{schema: nil}), do: :map_by_column
  defp shape(%{schema: _schema}), do: :map_by_field

  # Preloads. `QueryShape` has already refused Ecto preloads in `:scope`
  # mode; in `:execute` mode they are translated, merged with the option
  # and validated, and the plan carries the validated nodes (`nil` for none).

  defp preloads(%Query{}, _target, _env, opts, :scope),
    do: opts |> Keyword.get(:preload) |> scope_preload()

  defp preloads(%Query{} = query, %{root: root}, {_session, generation} = env, opts, :execute) do
    with {:ok, ecto} <- Tree.from_ecto_query(query, generation),
         option = Keyword.get(opts, :preload),
         :ok <- combination_preload(query, Enum.reject([ecto, option], &is_empty_tree(&1))),
         {:ok, nodes} <- validate_preloads(ecto, option, root, env, limits(opts, generation)) do
      {:ok, none(nodes)}
    end
  end

  defp scope_preload(empty) when is_empty_tree(empty), do: {:ok, nil}
  defp scope_preload(_preload), do: {:error, {:unsupported_query, :preload_requires_execute}}

  defp limits(opts, %Generation{config: %{max_preload_depth: depth, max_preload_nodes: nodes}}),
    do: Keyword.get(opts, :preload_limits, %{depth: depth, nodes: nodes})

  # Checked before validation, so a union reports the combination first.
  defp combination_preload(%Query{combinations: [_ | _]}, [_ | _]),
    do: {:error, {:unsupported_query, :combination_preload}}

  defp combination_preload(%Query{}, _tree), do: :ok

  defp validate_preloads(ecto, option, _root, _env, _limits)
       when is_empty_tree(ecto) and is_empty_tree(option),
       do: {:ok, []}

  # Only the translation of the query's own preloads may carry Ecto
  # associations, so it is passed apart from the caller's option.
  defp validate_preloads(ecto, option, root, {session, generation}, limits),
    do: Tree.validate(ecto, option, root, session, generation, limits)

  defp none([]), do: nil
  defp none(nodes), do: nodes

  # Whether the read binds enum labels in their own type anywhere: in the
  # root's row filter, a level's row filter or a level's enum key.
  defp enum_comparisons?(%{admin?: true}, preloads, generation),
    do: levels_compare_enum?(preloads, generation)

  defp enum_comparisons?(
         %{table: table, permission: %Permission{filter: filter}},
         preloads,
         %Generation{snapshot: %Snapshot{tables: tables}} = generation
       ),
       do:
         Compiler.compares_enum?(filter, table, tables) or
           levels_compare_enum?(preloads, generation)

  defp levels_compare_enum?(nil, _generation), do: false

  defp levels_compare_enum?(nodes, %Generation{snapshot: %Snapshot{tables: tables}} = generation),
    do:
      Enum.any?(nodes, fn %{
                            table: table,
                            template: {_permission, filter},
                            key_columns: keys,
                            children: children
                          } ->
        Enum.any?(
          keys,
          &match?(%Column{base_kind: :enum, type_schema: schema} when is_binary(schema), &1)
        ) or
          Compiler.compares_enum?(filter, table, tables) or
          levels_compare_enum?(children, generation)
      end)

  # The selected `:other` columns, root first, then every preload level.
  defp other_columns(%{table: table}, projection, preloads),
    do: Table.other_kind_columns(table, Enum.map(projection, & &1.column)) ++ levels(preloads)

  defp levels(nil), do: []

  defp levels(nodes),
    do:
      Enum.flat_map(nodes, fn %{table: table, columns: columns, children: children} ->
        Table.other_kind_columns(table, columns) ++ levels(children)
      end)

  # Every top-level relationship's local mapping columns are read for
  # stitching. Those not already projected are added as private columns,
  # which the executor strips from the output.
  defp stitching(projection, nil, _target), do: {:ok, projection}

  defp stitching(projection, nodes, %{schema: schema}) do
    selected = MapSet.new(projection, & &1.column)

    keys =
      for %{rel: %Relationship{name: name, mapping: mapping}} <- nodes,
          {local, _remote} <- mapping,
          local not in selected,
          do: {name, local}

    with {:ok, hidden} <- keys |> Enum.uniq_by(&elem(&1, 1)) |> Util.map_ok(&hidden(schema, &1)),
         do: {:ok, projection ++ hidden}
  end

  defp hidden(nil, {_name, column}), do: {:ok, private(column, column)}

  defp hidden(schema, {name, column}),
    do: schema |> field_for(column) |> hidden_field(name, column)

  defp hidden_field(nil, name, _column), do: {:error, {:unsupported_query, {:preload, name}}}
  defp hidden_field(field, _name, column), do: {:ok, private(field, column)}

  defp private(key, column), do: %{column(key, column) | public?: false}

  # Scoping.

  # What applies to the parent query only: the executor's `max_rows` and
  # the input filter of `Authzura.Input`.
  defp root_bounds(opts),
    do: %{
      max_rows: Keyword.get(opts, :max_rows),
      input: Keyword.get(opts, :input_filter),
      pushdown: Keyword.get(opts, :input_pushdown)
    }

  # `output` says how each filtered query (the parent and every branch) is
  # completed: `{:select, projection, target}` caps the limit and selects;
  # `:filter_only` leaves the query as filtered.
  defp scope_query(%Query{} = query, %{root: root} = target, env, bounds, output) do
    with {:ok, scoped} <- scope_one(query, target, env, bounds, output),
         {:ok, branches} <- scope_branches(query, root, target, env, output) do
      {:ok, %{scoped | combinations: branches}}
    end
  end

  defp scope_branches(
         %Query{combinations: branches, prefix: parent_prefix},
         root,
         target,
         {_session, %Generation{config: %{default_prefix: default}}} = env,
         output
       ) do
    Util.map_ok(branches, fn {kind, %Query{prefix: branch_prefix} = branch} ->
      with ^root <- root(branch, [branch_prefix, parent_prefix, default]),
           {:ok, scoped} <- scope_one(branch, target, env, @branch_bounds, output) do
        {:ok, {kind, scoped}}
      else
        {:error, _reason} = error -> error
        _other_root -> {:error, {:unsupported_query, :combination_tables}}
      end
    end)
  end

  defp scope_one(
         %Query{from: from, limit: limit, offset: offset} = query,
         %{root: {prefix, _name}} = target,
         env,
         %{max_rows: max_rows, input: input, pushdown: pushdown},
         output
       ) do
    {query, binding} = root_alias(%{query | from: %{from | prefix: prefix}})

    with {:ok, caller_limit} <- bound(limit, :limit),
         {:ok, _offset} <- bound(offset, :offset),
         {:ok, query} <- filter(query, binding, target, env, input, pushdown) do
      {:ok, finish(query, binding, caller_limit, max_rows, output)}
    end
  end

  defp finish(query, binding, caller_limit, max_rows, {:select, projection, target}) do
    query
    |> cap(caller_limit, row_bound(target, max_rows))
    |> select(^selection(projection, binding))
  end

  defp finish(query, _binding, _caller_limit, _max_rows, :filter_only), do: query

  defp root_alias(%Query{from: %FromExpr{as: nil}} = query) do
    binding = Aliases.at(0)
    {from(q in query, as: ^binding), binding}
  end

  defp root_alias(%Query{from: %FromExpr{as: binding}} = query), do: {query, binding}

  defp filter(query, _binding, %{admin?: true}, _env, input, _pushdown),
    do: {:ok, gated(query, nil, input, nil)}

  defp filter(
         query,
         binding,
         %{table: table, permission: %Permission{filter: ast}},
         {session, %Generation{snapshot: %Snapshot{tables: tables}, config: %{adapter: adapter}}},
         input,
         pushdown
       ) do
    ctx = %{Compiler.root_ctx(table, tables, session, adapter, :permission) | binding: binding}

    with {:ok, condition} <- Compiler.compile_public(ast, ctx),
         do: {:ok, gated(query, condition, input, pushdown)}
  end

  # The input filter is evaluated only on rows the permission admits: SQL
  # leaves the order of `AND` operands to the planner, but a `CASE` fixes
  # it, so an input predicate that fails or runs long on some values can
  # never report on hidden rows. The permission stays a conjunct of its own
  # so the planner can still use it for index access.
  #
  # With `input_index_pushdown`, `pushdown` (comparisons the adapter marks
  # leakproof, from `Authzura.Compiler.pushdown/3`) is one more conjunct
  # outside the fence, so the planner can use an index on it. The fence
  # still holds the whole input.
  defp gated(query, nil, nil, _pushdown), do: query
  defp gated(query, nil, input, _pushdown), do: where(query, ^input)
  defp gated(query, permission, nil, _pushdown), do: where(query, ^permission)

  defp gated(query, permission, input, nil),
    do: where(query, ^dynamic(^permission and ^fenced(permission, input)))

  defp gated(query, permission, input, pushdown),
    do: where(query, ^dynamic(^permission and ^pushdown and ^fenced(permission, input)))

  defp fenced(permission, input),
    do: dynamic(fragment("CASE WHEN ? THEN ? ELSE false END", ^permission, ^input))

  # The caller's limit or offset value. Literals were checked by `QueryShape`;
  # a pinned `^n` is checked here, whether or not a permission cap applies.
  defp bound(nil, _reason), do: {:ok, nil}
  defp bound(%{expr: n}, _reason) when is_integer(n), do: {:ok, n}

  defp bound(%{expr: {:^, _meta, [index]}, params: params}, reason) do
    case Enum.at(params, index) do
      {n, _type} when is_integer(n) and n >= 0 -> {:ok, n}
      _other -> {:error, {:unsupported_query, reason}}
    end
  end

  # The bound on a query: the permission limit (none for the admin role) and,
  # for the parent query only, the executor's `max_rows`.
  defp row_bound(%{admin?: true}, max_rows), do: max_rows
  defp row_bound(%{permission: %Permission{limit: nil}}, max_rows), do: max_rows
  defp row_bound(%{permission: %Permission{limit: max}}, nil), do: max
  defp row_bound(%{permission: %Permission{limit: max}}, max_rows), do: min(max, max_rows)

  defp cap(query, _caller, nil), do: query
  defp cap(query, nil, max), do: limit(query, ^max)
  defp cap(query, n, max), do: limit(query, ^min(n, max))

  defp selection(projection, binding),
    do: Map.new(projection, fn %{key: key} -> {key, dynamic(field(as(^binding), ^key))} end)

  defp exec(opts, %Generation{} = generation) do
    %{
      instance: Keyword.fetch!(opts, :instance),
      read_only: read_only(Generation.connection_read_only?(generation)),
      repo_opts: Keyword.fetch!(opts, :repo_opts),
      input_pattern_timeout: input_pattern_timeout(generation),
      in_transaction: Keyword.fetch!(opts, :in_transaction),
      hooks: hooks(Keyword.get(opts, :between_levels)),
      isolation: Keyword.get(opts, :isolation, :repeatable_read)
    }
  end

  defp input_pattern_timeout(%Generation{config: config}),
    do: Map.get(config, :input_pattern_timeout)

  defp read_only(true), do: :connection
  defp read_only(false), do: :transaction

  defp hooks(nil), do: %{}
  defp hooks(fun) when is_function(fun, 0), do: %{between_levels: fun}
end

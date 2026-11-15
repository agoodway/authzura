defmodule Authzura.Preload.Tree do
  @moduledoc """
  Preload trees: validation against the relationship allowlist, and
  translation of plain Ecto preloads.

  ## Grammar

  A tree names **Hasura relationships**. Names are atoms or strings and stay
  strings internally: no atom is ever created from a tree. A tree is:

    * a name, or `nil`, `[]` or `%{}` for none
    * a list whose elements are names, `{name, value}` pairs, or nested
      lists or maps of entries
    * a map of `name => value`

  A relationship's value is read by its **shape**, never by guessing from
  its keys:

    * `nil` or `[]` - no options, no children
    * a name - a single child: `comments: :author`
    * a list of names only - leaf children: `comments: [:author, :likes]`
    * a keyword list or map (atom or string keys, as JSON decodes) - the
      options of that relationship. The only keys are `columns`, `order_by`
      and `preload`; any other key, or a repeated one, is
      `{:unsupported_query, {:preload, name}}`. Children other than plain
      leaves go under `preload`.

  Options:

    * `columns` - target columns (atoms or strings) to select. The default
      is every column the role may select on the target, except those of
      base kind `:other` (selected only when named).
    * `order_by` - a list of `{direction, column}` pairs (Ecto's keyword
      order, `[desc: :id]`), single-key `%{column => direction}` maps (the
      JSON form, the same order as the root `order_by` of `Authzura.Input`)
      or bare columns (ascending). A direction is one of
      `t:Authzura.Util.direction/0`, as an atom or a string.
    * `preload` - the nested tree.

  Examples:

      # Elixir
      [:author, comments: [columns: [:id, :body], order_by: [desc: :id], preload: [:author]]]

      # JSON (all_input)
      {"author": {}, "comments": {"columns": ["id", "body"],
                                  "order_by": [{"id": "desc"}],
                                  "preload": ["author"]}}

  A relationship literally named `columns`, `order_by` or `preload` is a
  child like any other: `comments: [:columns]` or
  `comments: [preload: [columns: []]]`.

  Entries naming the same relationship merge; conflicting `columns` or
  `order_by` are `{:unsupported_query, {:preload, name}}`. The merged entry
  keeps the first entry's key, and is keyed by fields when any of the
  entries came from an Ecto association.

  ## Result keys

  A relationship's value nests under the caller's own term: the atom or
  string of the `preload:` option, or the Ecto association's name. Rows
  loaded for an Ecto association are keyed by the related schema's field
  atoms, and by default select only the allowed columns that map to a field
  (an explicit column that maps to none is forbidden); every other
  relationship's rows are keyed by column strings. No atom is created.

  There is no per-relationship limit option: an array relationship is
  bounded per parent by its target's permission limit.

  ## Validation

  `validate/5` bounds the work before anything else: while it descends it
  counts every raw element it visits (wrappers and duplicates included) and
  the raw nesting depth, and it rejects a tree over the depth limit or, once
  merged, over the node limit. All of these are
  `{:unsupported_query, :preload_limit}`. Only then does it walk the
  allowlist. A relationship is allowed only when it is declared on its
  parent table, it is `preloadable?`, and the role has a select permission
  on its target (the target's `root_fields` are ignored, as in Hasura); any
  other relationship is `:forbidden`. The configured admin role reaches
  every declared relationship to a known table, with every column and no
  filter (see `Authzura.Store.Generation.access/3`).

  ## Ranking without a sort

  An array relationship whose target has a permission limit and that has no
  `order_by` keeps, per parent, the first rows by the target's primary key,
  even when the role may not select those key columns. Only the relative
  order of rows the role may already read is involved, so nothing hidden is
  returned; give an `order_by` when the choice matters.
  """

  import Authzura.Util, only: [is_plain_map: 1]

  alias Authzura.{AST, Compiler, SchemaFields, Scope, Session, Util}
  alias Authzura.Model.{Column, Permission, Relationship, Snapshot, Table}
  alias Authzura.Store.Generation
  alias Ecto.Association.{BelongsTo, Has}
  alias Ecto.Query
  alias Ecto.Query.FromExpr

  @typedoc "A preload tree; see the moduledoc."
  @type tree :: term()

  @typedoc """
  A validated relationship to preload, with what loading it needs.

  `key` is the caller's own term for the relationship (an atom or a
  string) and the key its value nests under. `schema` is the related Ecto
  schema when the preload came from an Ecto association (its rows are then
  keyed by field atoms), or `nil` (rows keyed by column strings).

  `table` is the target table, `key_columns` its columns in mapping order,
  and `condition` the target's row filter compiled with the session against
  the alias `Authzura.Compiler.Aliases.at(0)`. A node holds only these
  terms, never the generation, so a process holding a plan does not keep
  (or, on a reload, copy) the whole snapshot.

  `layout` is added by `Authzura.Executor` before loading: how its finished
  rows are keyed (see `Authzura.Preload.Loader.load/7`).
  """
  @type preload_node :: %{
          optional(:layout) => map(),
          rel: Relationship.t(),
          key: atom() | String.t(),
          schema: module() | nil,
          template: {Permission.t(), AST.t()},
          table: Table.t(),
          key_columns: [Column.t()],
          condition: Query.dynamic_expr(),
          columns: [String.t()],
          order_by: [{Util.direction(), String.t()}],
          children: [preload_node()]
        }

  @type limits :: %{
          required(:depth) => pos_integer(),
          required(:nodes) => pos_integer(),
          optional(:order_by) => pos_integer()
        }

  @type reason ::
          :forbidden
          | {:missing_session_variable, String.t()}
          | {:invalid_session_value, String.t(), term()}
          | {:forbidden_columns, [String.t()]}
          | {:invalid_input, {:order_by, :unorderable} | {:too_many, :preload_order_by}}
          | {:unsupported_query,
             :preload | :preload_limit | :empty_columns | {:preload, String.t()}}

  @option_keys %{
    :columns => :columns,
    :order_by => :order_by,
    :preload => :preload,
    "columns" => :columns,
    "order_by" => :order_by,
    "preload" => :preload
  }

  # The raw traversal budget: every visited element counts, so redundant
  # wrappers and duplicates cannot make parsing cost more than this many
  # times the node limit, and wrappers cannot nest much deeper than the tree.
  @raw_factor 4
  @raw_depth_slack 4

  # Tags a translated Ecto association: `{tag, related_schema, children}`.
  # Only a tree passed as `validate/6`'s `ecto` argument may carry it.
  @ecto_assoc :__authzura_ecto_assoc__

  @doc "Guards an empty tree: `nil`, `[]` or `%{}`."
  defguard is_empty_tree(tree) when tree in [nil, []] or tree == %{}

  @doc """
  Validates `tree` from the table `root` for the session's role.

  Returns the validated nodes in order, or:

    * `{:unsupported_query, :preload_limit}` when the tree is deeper than
      `limits.depth`, has more than `limits.nodes` nodes once merged, or
      needs more raw work than the limits allow (see the moduledoc)
    * `{:invalid_input, {:too_many, :preload_order_by}}` when the optional
      `limits.order_by` is set (`Authzura.Input` sets 32) and a
      relationship's `order_by` has more terms
    * `{:unsupported_query, :preload}` or
      `{:unsupported_query, {:preload, name}}` for a malformed tree, and
      `{:unsupported_query, :empty_columns}` for `columns: []`
    * `:forbidden` for a relationship the role may not follow
    * `{:missing_session_variable, name}` or
      `{:invalid_session_value, name, reason}` when a target's row filter
      does not compile for the session (every node's filter is compiled
      here, whether or not any parent row reaches it)
    * `{:forbidden_columns, columns}` for `columns` or `order_by` outside
      the target's allowed columns, and
      `{:invalid_input, {:order_by, :unorderable}}` for sorting on a kind
      Postgres cannot order
  """
  @spec validate(tree(), Table.table_ref(), Session.t(), Generation.t(), limits()) ::
          {:ok, [preload_node()]} | {:error, reason()}
  def validate(tree, root, %Session{} = session, %Generation{} = generation, limits),
    do: validate(nil, tree, root, session, generation, limits)

  @doc """
  Like `validate/5`, with `ecto` the translation of the query's own Ecto
  preloads (`from_ecto_query/2`, or `nil`) merged before `tree` and counted
  against the same limits.

  Only `ecto` may carry translated associations; the same value anywhere in
  `tree` is `{:unsupported_query, {:preload, name}}`.
  """
  @spec validate(
          tree(),
          tree(),
          Table.table_ref(),
          Session.t(),
          Generation.t(),
          limits()
        ) :: {:ok, [preload_node()]} | {:error, reason()}
  def validate(
        ecto,
        tree,
        root,
        %Session{role: role} = session,
        %Generation{snapshot: %Snapshot{tables: tables}, config: %{adapter: adapter}} =
          generation,
        %{depth: depth, nodes: nodes} = limits
      )
      when is_integer(depth) and depth > 0 and is_integer(nodes) and nodes > 0 do
    bounds = %{
      depth: depth,
      raw_depth: 2 * depth + @raw_depth_slack,
      order_by: Map.get(limits, :order_by)
    }

    ctx = %{
      role: role,
      generation: generation,
      tables: tables,
      session: session,
      adapter: adapter
    }

    level = %{depth: 1, raw: 1, ecto?: false}

    with {:ok, translated, left} <-
           entries(ecto, %{level | ecto?: true}, @raw_factor * nodes, bounds),
         {:ok, given, _left} <- entries(tree, level, left, bounds),
         {:ok, entries} <- merge(translated ++ given),
         :ok <- node_limit(count(entries), nodes),
         do: Util.map_ok(entries, &resolve(&1, root, ctx))
  end

  @doc """
  The parent columns `nodes` are stitched on: every local mapping column, in
  node and mapping order, without repeats.
  """
  @spec parent_columns([preload_node()]) :: [String.t()]
  def parent_columns(nodes) when is_list(nodes),
    do:
      Enum.uniq(
        for %{rel: %Relationship{mapping: mapping}} <- nodes,
            {local, _remote} <- mapping,
            do: local
      )

  @doc """
  Translates the preloads of `query` into a tree of relationship names, or
  `nil` when it has none. Each association becomes
  `{name, {marker, related_schema, children}}`, an internal value shape that
  `validate/6` (as its `ecto` argument only) reads as "children, keyed by the related schema's fields"
  (see `t:preload_node/0`), so an association named like an option key is
  never read as options.

  Only plain, nested association names are accepted, on `belongs_to`,
  `has_one` and `has_many` associations of the root schema with no `where`,
  `preload_order`, `through` or custom source. Each must match the root
  table's (or its parent's) Hasura relationship of the same name, with the
  same kind, target and ordered mapping.

  The caller's own query is trusted code and this check is role-independent,
  so an association that cannot be translated faithfully (a custom preload
  query, a preload function, a join-bound preload in `query.assocs`, a table
  root, or no matching relationship) is
  `{:unsupported_query, {:preload, name}}`, with `name` the relationship
  name as a string. A root that is not a table source is
  `{:unsupported_query, :preload}`. Whether the role may follow a
  translated relationship is decided by `validate/5`.
  """
  @spec from_ecto_query(Query.t(), Generation.t()) ::
          {:ok, [{atom(), {atom(), module(), list()}}] | nil}
          | {:error, {:unsupported_query, :preload | {:preload, String.t()}}}
  def from_ecto_query(%Query{preloads: [], assocs: []}, %Generation{}), do: {:ok, nil}

  def from_ecto_query(%Query{assocs: [{name, _binding} | _rest]}, %Generation{}),
    do: unsupported(name)

  def from_ecto_query(
        %Query{from: %FromExpr{source: {source, schema}}, preloads: preloads} = query,
        %Generation{snapshot: %Snapshot{tables: tables}} = generation
      )
      when is_binary(source),
      do: translate(preloads, schema, Scope.root_ref(query, generation), tables)

  def from_ecto_query(%Query{}, %Generation{}), do: {:error, {:unsupported_query, :preload}}

  # Normalizing. An entry is %{name, columns, order_by, children}, with
  # `nil` for options that were not given. `level` is the logical depth and
  # the raw nesting depth; `left` is the remaining raw element budget.

  defp entries(empty, _level, left, _bounds) when is_empty_tree(empty), do: {:ok, [], left}

  defp entries(_tree, %{depth: depth, raw: raw}, _left, %{depth: max, raw_depth: max_raw})
       when depth > max or raw > max_raw,
       do: limit()

  defp entries(name, level, left, bounds) when is_atom(name) or is_binary(name),
    do: entries([name], level, left, bounds)

  defp entries(tree, level, left, bounds) when is_list(tree) or is_plain_map(tree) do
    tree
    |> Enum.reduce_while({:ok, [], left}, fn element, {:ok, acc, left} ->
      case visit(element, level, left - 1, bounds) do
        {:ok, entries, left} -> {:cont, {:ok, [entries | acc], left}}
        error -> {:halt, error}
      end
    end)
    |> merged_entries()
  end

  defp entries(_tree, _level, _left, _bounds), do: {:error, {:unsupported_query, :preload}}

  defp visit(_element, _level, left, _bounds) when left < 0, do: limit()

  defp visit(name, _level, left, _bounds) when is_atom(name) or is_binary(name),
    do: {:ok, [entry(name, %{}, [])], left}

  defp visit({name, value}, level, left, bounds) when is_atom(name) or is_binary(name),
    do: branch(name, value, level, left, bounds)

  defp visit(nested, %{raw: raw} = level, left, bounds)
       when is_list(nested) or is_plain_map(nested),
       do: entries(nested, %{level | raw: raw + 1}, left, bounds)

  defp visit(_element, _level, _left, _bounds), do: {:error, {:unsupported_query, :preload}}

  defp merged_entries({:ok, lists, left}) do
    with {:ok, merged} <- lists |> Enum.reverse() |> Enum.concat() |> merge(),
         do: {:ok, merged, left}
  end

  defp merged_entries(error), do: error

  defp branch(key, value, %{depth: depth, raw: raw, ecto?: ecto?} = level, left, bounds) do
    name = name(key)
    children_level = %{level | depth: depth + 1, raw: raw + 2}

    with {:ok, options} <- options(value, name, ecto?),
         {:ok, columns} <- columns(Map.get(options, :columns), name),
         {:ok, order} <- order_by(Map.get(options, :order_by), name, bounds),
         {:ok, children, left} <-
           entries(Map.get(options, :preload), children_level, left, bounds) do
      options = Map.merge(options, %{columns: columns, order_by: order})
      {:ok, [entry(key, options, children)], left}
    end
  end

  # `key` is the caller's term, kept for the result; `name` the relationship.
  defp entry(key, options, children) do
    %{
      name: name(key),
      key: key,
      schema: Map.get(options, :schema),
      columns: Map.get(options, :columns),
      order_by: Map.get(options, :order_by),
      children: children
    }
  end

  defp name(name) when is_atom(name), do: Atom.to_string(name)
  defp name(name) when is_binary(name), do: name

  defp name?(name), do: is_atom(name) or is_binary(name)

  # A translated association, accepted only in the `ecto` tree.
  defp options({@ecto_assoc, schema, children}, _name, true = _ecto?),
    do: {:ok, %{preload: children, schema: schema}}

  defp options(value, name, _ecto?), do: options(value, name)

  # A value's shape decides what it is; see the moduledoc.
  defp options(nil, _name), do: {:ok, %{}}
  defp options([], _name), do: {:ok, %{}}

  defp options(child, _name) when is_atom(child) or is_binary(child),
    do: {:ok, %{preload: [child]}}

  defp options(value, name) when is_list(value),
    do: value |> Enum.all?(&name?/1) |> list_options(value, name)

  defp options(value, name) when is_plain_map(value), do: option_pairs(value, name)
  defp options(_value, name), do: unsupported(name)

  defp list_options(true, children, _name), do: {:ok, %{preload: children}}
  defp list_options(false, pairs, name), do: option_pairs(pairs, name)

  defp option_pairs(pairs, name),
    do: Enum.reduce_while(pairs, {:ok, %{}}, &option_pair(&1, &2, name))

  defp option_pair({key, value}, {:ok, options}, name) when is_map_key(@option_keys, key),
    do: put_option(options, Map.fetch!(@option_keys, key), value, name)

  defp option_pair(_pair, _acc, name), do: {:halt, unsupported(name)}

  defp put_option(options, option, _value, name) when is_map_key(options, option),
    do: {:halt, unsupported(name)}

  defp put_option(options, option, value, _name),
    do: {:cont, {:ok, Map.put(options, option, value)}}

  defp columns(nil, _name), do: {:ok, nil}
  defp columns([], _name), do: {:error, {:unsupported_query, :empty_columns}}

  defp columns(columns, name) when is_list(columns),
    do: Util.map_ok(columns, &column(&1, name))

  defp columns(_columns, name), do: unsupported(name)

  defp column(column, _name) when is_atom(column) or is_binary(column), do: {:ok, name(column)}
  defp column(_column, name), do: unsupported(name)

  defp order_by(nil, _name, _bounds), do: {:ok, nil}

  defp order_by(terms, _name, %{order_by: max})
       when is_list(terms) and is_integer(max) and length(terms) > max,
       do: {:error, {:invalid_input, {:too_many, :preload_order_by}}}

  defp order_by(terms, name, _bounds) when is_list(terms),
    do: Util.map_ok(terms, &order_term(&1, name))

  defp order_by(_terms, name, _bounds), do: unsupported(name)

  defp order_term({direction, column}, name) do
    with {:ok, column} <- column(column, name),
         {:ok, direction} <- direction(direction, name),
         do: {:ok, {direction, column}}
  end

  defp order_term(term, name) when is_plain_map(term) and map_size(term) == 1 do
    [{column, direction}] = Map.to_list(term)
    order_term({direction, column}, name)
  end

  defp order_term(column, name),
    do: with({:ok, column} <- column(column, name), do: {:ok, {:asc, column}})

  defp direction(direction, name),
    do: with(:error <- Util.direction(direction), do: unsupported(name))

  # Merging entries of the same name, keeping the first occurrence's place.

  defp merge(entries) do
    entries
    |> Enum.reduce_while({:ok, [], %{}}, fn %{name: name} = entry, {:ok, order, merged} ->
      case merged do
        %{^name => previous} -> combine(previous, entry, order, merged)
        %{} -> {:cont, {:ok, [name | order], Map.put(merged, name, entry)}}
      end
    end)
    |> merged()
  end

  defp combine(
         %{name: name, schema: schema, columns: columns, order_by: order_by, children: children} =
           previous,
         %{
           schema: new_schema,
           columns: new_columns,
           order_by: new_order_by,
           children: new_children
         },
         order,
         merged
       ) do
    with {:ok, columns} <- pick(columns, new_columns, name),
         {:ok, order_by} <- pick(order_by, new_order_by, name),
         {:ok, children} <- merge(children ++ new_children) do
      combined = %{
        previous
        | schema: schema || new_schema,
          columns: columns,
          order_by: order_by,
          children: children
      }

      {:cont, {:ok, order, Map.put(merged, name, combined)}}
    else
      error -> {:halt, error}
    end
  end

  defp merged({:ok, order, merged}),
    do: {:ok, order |> Enum.reverse() |> Enum.map(&Map.fetch!(merged, &1))}

  defp merged(error), do: error

  defp pick(nil, value, _name), do: {:ok, value}
  defp pick(value, nil, _name), do: {:ok, value}
  defp pick(value, value, _name), do: {:ok, value}
  defp pick(_one, _other, name), do: unsupported(name)

  defp count(entries),
    do: Enum.reduce(entries, 0, fn %{children: children}, acc -> acc + 1 + count(children) end)

  defp node_limit(count, max) when count > max, do: limit()
  defp node_limit(_count, _max), do: :ok

  defp limit, do: {:error, {:unsupported_query, :preload_limit}}

  # Resolving against the allowlist.

  defp resolve(
         %{
           name: name,
           key: key,
           schema: schema,
           columns: columns,
           order_by: order,
           children: entries
         },
         parent,
         %{role: role, generation: generation} = ctx
       ) do
    with {:ok, %Relationship{target: target} = rel} <- relationship(ctx, parent, name),
         {:ok, %{template: {permission, _filter} = template, table: table}} <-
           Generation.access(generation, role, target),
         columns = Enum.uniq(columns || default_columns(table, permission, schema)),
         order = order || [],
         sorted = Enum.map(order, &elem(&1, 1)),
         :ok <- forbidden(columns, schema, sorted, permission),
         :ok <- Table.orderable(table, sorted),
         {:ok, key_columns} <- key_columns(rel, table),
         {:ok, condition} <- condition(template, table, ctx),
         {:ok, children} <- Util.map_ok(entries, &resolve(&1, target, ctx)) do
      {:ok,
       %{
         rel: rel,
         key: key,
         schema: schema,
         template: template,
         table: table,
         key_columns: key_columns,
         condition: condition,
         columns: columns,
         order_by: order,
         children: children
       }}
    end
  end

  # The target's key columns, in mapping order.
  defp key_columns(%Relationship{mapping: mapping}, %Table{columns: columns}),
    do: Util.map_ok(mapping, &key_column(columns, &1))

  defp key_column(columns, {_local, remote}) when is_map_key(columns, remote),
    do: {:ok, Map.fetch!(columns, remote)}

  defp key_column(_columns, _pair), do: {:error, :forbidden}

  # The target's row filter, compiled once for the whole call.
  defp condition({_permission, filter}, table, %{
         tables: tables,
         session: session,
         adapter: adapter
       }) do
    Compiler.compile_public(
      filter,
      Compiler.root_ctx(table, tables, session, adapter, :permission)
    )
  end

  # Columns outside `selectable` and sorted columns outside `allowed`,
  # checked against sets so a wide target costs no scan per column.
  defp forbidden(columns, schema, sorted, permission) do
    fields = fields_by_column(schema)

    rejected =
      Enum.reject(columns, &selectable?(&1, fields, permission)) ++
        Enum.reject(sorted, &Permission.allows?(permission, &1))

    rejected
    |> Enum.uniq()
    |> Util.forbidden_columns()
  end

  defp fields_by_column(nil), do: nil
  defp fields_by_column(schema), do: SchemaFields.by_column(schema)

  defp selectable?(column, nil, permission), do: Permission.allows?(permission, column)

  defp selectable?(column, fields, permission),
    do: is_map_key(fields, column) and Permission.allows?(permission, column)

  # An association's rows are keyed by field, so, as at the root, only the
  # allowed columns that map to one of its fields can be selected.
  defp default_columns(table, %Permission{columns: allowed}, nil),
    do: Table.default_columns(table, allowed)

  defp default_columns(table, %Permission{columns: allowed}, schema) do
    selectable = for {_field, column} <- Scope.field_columns(schema, allowed), do: column
    Table.default_columns(table, selectable)
  end

  defp relationship(%{tables: tables}, parent, name) do
    case tables do
      %{^parent => %Table{relationships: %{^name => %Relationship{preloadable?: true} = rel}}} ->
        {:ok, rel}

      %{} ->
        {:error, :forbidden}
    end
  end

  # Translating Ecto preloads.

  defp translate(name, schema, parent, tables) when is_atom(name),
    do: translate([name], schema, parent, tables)

  defp translate(preloads, schema, parent, tables) when is_list(preloads) do
    with {:ok, lists} <- Util.map_ok(preloads, &ecto_element(&1, schema, parent, tables)),
         do: {:ok, Enum.concat(lists)}
  end

  defp ecto_element(name, schema, parent, tables) when is_atom(name),
    do: ecto_assoc(name, [], schema, parent, tables)

  defp ecto_element({name, nested}, schema, parent, tables)
       when is_atom(name) and (is_atom(nested) or is_list(nested)),
       do: ecto_assoc(name, nested, schema, parent, tables)

  defp ecto_element({name, _query_or_function}, _schema, _parent, _tables) when is_atom(name),
    do: unsupported(name)

  defp ecto_element(nested, schema, parent, tables) when is_list(nested),
    do: translate(nested, schema, parent, tables)

  defp ecto_element(_preload, _schema, _parent, _tables),
    do: {:error, {:unsupported_query, :preload}}

  defp ecto_assoc(name, nested, schema, parent, tables) do
    rel_name = name(name)

    with {:ok, assoc} <- association(schema, name),
         {:ok, rel} <- matching(assoc, parent, rel_name, tables) do
      ecto_children(nested, assoc, rel, tables)
    else
      :error -> unsupported(rel_name)
    end
  end

  defp ecto_children(
         nested,
         %{field: key, related: related},
         %Relationship{target: target},
         tables
       ) do
    with {:ok, children} <- translate(nested, related, target, tables),
         do: {:ok, [{key, {@ecto_assoc, related, children}}]}
  end

  defp association(nil, _name), do: :error

  defp association(schema, name), do: plain(schema.__schema__(:association, name))

  defp plain(%BelongsTo{related: related, queryable: related, where: []} = assoc),
    do: {:ok, assoc}

  defp plain(%Has{related: related, queryable: related, where: [], preload_order: []} = assoc),
    do: {:ok, assoc}

  defp plain(_assoc), do: :error

  defp matching(
         %{
           cardinality: cardinality,
           owner: owner,
           owner_key: owner_key,
           related: related,
           related_key: related_key
         },
         {prefix, _name} = parent,
         name,
         tables
       ) do
    target = {related.__schema__(:prefix) || prefix, related.__schema__(:source)}
    mapping = [{Scope.column_for(owner, owner_key), Scope.column_for(related, related_key)}]
    kind = kind(cardinality)

    case tables do
      %{
        ^parent => %Table{
          relationships: %{
            ^name => %Relationship{kind: ^kind, target: ^target, mapping: ^mapping} = rel
          }
        }
      } ->
        {:ok, rel}

      %{} ->
        :error
    end
  end

  defp kind(:one), do: :object
  defp kind(:many), do: :array

  defp unsupported(name), do: {:error, {:unsupported_query, {:preload, name(name)}}}
end

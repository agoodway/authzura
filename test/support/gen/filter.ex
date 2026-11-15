defmodule Authzura.Gen.Filter do
  @moduledoc """
  Hasura `bool_exp` generators for `Authzura.Gen`, their size (`stats/1`)
  and the operator tags they exercise (`tags/2`).

  A permission filter (`permission/2`) may use every accepted feature:
  the comparison operators, `_in`/`_nin` (also `[]`), `_is_null`, the
  like, ilike, similar and regex families, the `jsonb` operators,
  `_and`/`_or` (also `[]`) and `_not`, `_exists`, relationships to depth
  3, the `{"col": value}` shorthand, `$` aliases and session variables
  spelled in mixed case. It has depth at most 6 and at most 40 nodes. An
  input filter (`input/2`) is what a GraphQL `where` can say: columns the
  role sees, no relationship, `_exists`, session variable, shorthand or
  alias, depth at most 3. Neither ever names a `json` column, and literals
  come from `Authzura.Test.Seed.values/0`.
  """

  import StreamData, except: [filter: 2, filter: 3]

  alias Authzura.Gen.Catalog

  @nullable_relationships Catalog.nullable_relationships()

  @max_depth 6
  @max_nodes 40
  @input_depth 3
  @max_hops 3

  @comparisons ~w(_eq _neq _gt _lt _gte _lte)
  @patterns %{
    "_like" => ["%a%", "A%", "%1", "%ta%"],
    "_nlike" => ["%a%", "b%"],
    "_ilike" => ["a%", "%A%"],
    "_nilike" => ["a%", "%x%"],
    "_similar" => ["(A|b)%", "%[0-9]"],
    "_nsimilar" => ["(A|b)%"],
    "_regex" => ["^[A-Z]", "1$"],
    "_nregex" => ["^[A-Z]"],
    "_iregex" => ["^g", "A"],
    "_niregex" => ["^g"]
  }

  # `_and`/`_or` lengths: sometimes empty, mostly one to three children.
  @list_lengths [{1, 0}, {4, 1}, {4, 2}, {2, 3}]

  @list_keys ~w(_and _or $and $or)
  @not_keys ~w(_not $not)
  @exists_keys ~w(_exists $exists)

  @operator_tags for op <-
                       ~w(eq neq gt lt gte lte in nin is_null like nlike ilike nilike similar
                         nsimilar regex nregex iregex niregex contains contained_in has_key
                         has_keys_any has_keys_all and or not exists)a,
                     prefix <- ["_", "$"],
                     into: %{},
                     do: {prefix <> Atom.to_string(op), :"_#{op}"}

  @empty_tags %{_and: :_and_empty, _or: :_or_empty, _in: :_in_empty, _nin: :_nin_empty}

  @input_operators (@operator_tags |> Map.values() |> Enum.uniq()) -- [:_exists]
  @input_operators @input_operators ++ Map.values(@empty_tags)
  @operators @input_operators ++
               [:_exists, :rel_depth_3, :shorthand, :dollar_alias, :session_mixed_case]

  @users {"public", "users"}
  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @kinds {"public", "key_kinds"}

  # One known-valid filter per coverage tag (and per boundary variable
  # kind), for `Authzura.Gen` to place when a draw lacks it.
  @features %{
    _eq: {@users, %{"id" => %{"_eq" => 3}}},
    _neq: {@users, %{"id" => %{"_neq" => 3}}},
    _gt: {@users, %{"id" => %{"_gt" => 3}}},
    _lt: {@users, %{"id" => %{"_lt" => 30}}},
    _gte: {@users, %{"id" => %{"_gte" => 3}}},
    _lte: {@users, %{"id" => %{"_lte" => 30}}},
    _in: {@users, %{"id" => %{"_in" => [1, 2, 5]}}},
    _nin: {@users, %{"id" => %{"_nin" => [1, 2]}}},
    _in_empty: {@users, %{"_or" => [%{"id" => %{"_in" => []}}, %{"id" => %{"_gt" => 5}}]}},
    _nin_empty: {@users, %{"_and" => [%{"id" => %{"_nin" => []}}, %{"id" => %{"_gt" => 5}}]}},
    _is_null: {@users, %{"manager_id" => %{"_is_null" => false}}},
    _like: {@users, %{"email" => %{"_like" => "%1%"}}},
    _nlike: {@users, %{"email" => %{"_nlike" => "%1%"}}},
    _ilike: {@users, %{"email" => %{"_ilike" => "user1%"}}},
    _nilike: {@users, %{"email" => %{"_nilike" => "user1%"}}},
    _similar: {@users, %{"email" => %{"_similar" => "%(1|2)%"}}},
    _nsimilar: {@users, %{"email" => %{"_nsimilar" => "%(1|2)%"}}},
    _regex: {@users, %{"email" => %{"_regex" => "^u"}}},
    _nregex: {@users, %{"email" => %{"_nregex" => "^u"}}},
    _iregex: {@users, %{"email" => %{"_iregex" => "^user1"}}},
    _niregex: {@users, %{"email" => %{"_niregex" => "^user1"}}},
    _contains: {@articles, %{"assignees" => %{"_contains" => %{"1" => true}}}},
    _contained_in:
      {@articles, %{"assignees" => %{"_contained_in" => %{"1" => true, "5" => false}}}},
    _has_key: {@articles, %{"assignees" => %{"_has_key" => "2"}}},
    _has_keys_any: {@articles, %{"assignees" => %{"_has_keys_any" => ["1", "3"]}}},
    _has_keys_all: {@articles, %{"assignees" => %{"_has_keys_all" => ["2", "6"]}}},
    _and: {@users, %{"_and" => [%{"id" => %{"_gt" => 3}}, %{"id" => %{"_lt" => 30}}]}},
    _or: {@users, %{"_or" => [%{"id" => %{"_lt" => 5}}, %{"id" => %{"_gt" => 30}}]}},
    _not: {@users, %{"_not" => %{"id" => %{"_lt" => 10}}}},
    _and_empty: {@users, %{"_or" => [%{"_and" => []}, %{"id" => %{"_gt" => 5}}]}},
    _or_empty: {@users, %{"_and" => [%{"_or" => []}, %{"id" => %{"_gt" => 5}}]}},
    _exists:
      {@users,
       %{
         "_exists" => %{
           "_table" => %{"schema" => "public", "name" => "organizations"},
           "_where" => %{"id" => %{"_eq" => 1}}
         }
       }},
    rel_depth_3: {@comments, %{"article" => %{"author" => %{"org" => %{"id" => %{"_gt" => 3}}}}}},
    shorthand: {@users, %{"is_admin" => false}},
    dollar_alias: {@users, %{"id" => %{"$gt" => 3}}},
    session_mixed_case: {@users, %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}},
    int: {@users, %{"id" => %{"_gte" => "X-Hasura-User-Id"}}},
    bool: {@users, %{"is_admin" => %{"_eq" => "X-Hasura-Flag"}}},
    int_array: {@articles, %{"id" => %{"_in" => "X-Hasura-Article-Ids"}}},
    text_array: {@kinds, %{"code" => %{"_in" => "X-Hasura-Codes"}}}
  }

  @typedoc "A JSON bool_exp."
  @type t :: map()

  @doc "`{table, filter}`: a known-valid permission filter that exercises `tag`."
  @spec feature(atom()) :: {Catalog.table(), t()}
  def feature(tag), do: Map.fetch!(@features, tag)

  @doc "The tags a batch's permission filters must reach."
  @spec operators() :: [atom()]
  def operators, do: @operators

  @doc "The tags the input filters must reach."
  @spec input_operators() :: [atom()]
  def input_operators, do: @input_operators

  @doc """
  A permission filter on `table`: `%{}` sometimes, else a full tree.
  `join_lift: true` adds object-only chains and negated chains for the
  join-lift property's coverage; the default distribution is unchanged.
  """
  @spec permission(Catalog.table(), keyword()) :: StreamData.t(t())
  def permission(table, opts \\ []) do
    ctx = permission_ctx(table, 0)

    frequency(
      [{1, constant(%{})}, {7, bool_tree(ctx, @max_depth)}] ++
        permission_chains(ctx, Keyword.get(opts, :join_lift, false))
    )
  end

  defp permission_chains(ctx, true) do
    chains = object_chains(ctx)
    fallbacks = for {_weight, chain} <- chains, do: {4, map(chain, &%{"_not" => &1})}
    chains ++ fallbacks
  end

  defp permission_chains(_ctx, false), do: []

  @doc "A caller filter on `table` over the `visible` columns: often none."
  @spec input(Catalog.table(), [String.t()]) :: StreamData.t(t())
  def input(table, visible) do
    ctx = %{table: table, columns: Catalog.filterable(table, visible), mode: :input, hops: 0}
    frequency([{1, constant(%{})}, {2, bool_tree(ctx, @input_depth)}])
  end

  @doc "Depth (nested operators and relationships) and node count of a filter."
  @spec stats(t()) :: %{depth: non_neg_integer(), nodes: non_neg_integer()}
  def stats(filter) do
    {depth, nodes} = measure(filter)
    %{depth: depth, nodes: nodes}
  end

  @doc "The operator and form tags `filter` (on `table`) exercises."
  @spec tags(t() | nil, Catalog.table()) :: [atom()]
  def tags(nil, _table), do: []
  def tags(filter, table), do: filter |> tags(table, 0) |> Enum.reject(&is_nil/1)

  @doc "The session variables `filter` references, lowercased."
  @spec session_refs(t()) :: [String.t()]
  def session_refs(filter), do: filter |> refs() |> Enum.map(&String.downcase/1) |> Enum.uniq()

  @doc "Whether `value` is a session variable reference."
  @spec session_ref?(term()) :: boolean()
  def session_ref?(value) when is_binary(value),
    do: value |> String.downcase() |> String.starts_with?("x-hasura-")

  def session_ref?(_value), do: false

  @doc "`filter` ANDed with `other` (either may be `nil`)."
  @spec and_where(t() | nil, t() | nil) :: t() | nil
  def and_where(nil, other), do: other
  def and_where(filter, nil), do: filter
  def and_where(filter, other), do: %{"_and" => [filter, other]}

  # Generation.

  defp permission_ctx(table, hops),
    do: %{
      table: table,
      columns: Catalog.filterable(table, Catalog.names(table)),
      mode: :permission,
      hops: hops
    }

  defp bool_tree(%{columns: []}, _depth), do: constant(%{})
  defp bool_tree(ctx, depth) when depth <= 1, do: leaf(ctx)

  defp bool_tree(ctx, depth) do
    child = bool_tree(ctx, depth - 1)

    ([
       {6, leaf(ctx)},
       {1, logic_list(ctx, "_and", child)},
       {3, logic_list(ctx, "_or", child)},
       {1, bind(logic_key(ctx, "_not"), fn key -> map(child, &%{key => &1}) end)}
     ] ++ relationship_trees(ctx, depth) ++ exists_trees(ctx, depth))
    |> frequency()
    |> map(&cap/1)
  end

  defp logic_list(ctx, key, child) do
    bind(logic_key(ctx, key), fn key ->
      @list_lengths
      |> Enum.map(fn {weight, n} -> {weight, constant(n)} end)
      |> frequency()
      |> bind(&list_of(child, length: &1))
      |> map(&%{key => &1})
    end)
  end

  defp logic_key(%{mode: :permission}, "_" <> name = key),
    do: frequency([{4, constant(key)}, {1, constant("$" <> name)}])

  defp logic_key(_ctx, key), do: constant(key)

  defp relationship_trees(%{mode: :permission, hops: hops, table: table}, depth)
       when hops < @max_hops do
    case Catalog.relationships(table) do
      [] ->
        []

      relationships ->
        [{4, bind(member_of(relationships), &relationship_tree(&1, hops, depth))}]
    end
  end

  defp relationship_trees(_ctx, _depth), do: []

  defp relationship_tree({name, {_kind, target, _mapping}}, hops, depth),
    do: target |> permission_ctx(hops + 1) |> bool_tree(depth - 1) |> map(&%{name => &1})

  # The unrestricted trees above retain arrays, OR/NOT and EXISTS for
  # fallback coverage. This additional family keeps every hop liftable:
  # fixture object mappings target integer primary keys, and the terminal
  # leaf cannot introduce a non-liftable sibling. Prefer nullable mappings
  # so sampling a permission batch gives several nullable lifted reads.
  # permission/2 also draws negated copies, preserving fallback coverage
  # even in batches whose unrestricted trees happen to have few arrays.
  defp object_chains(%{table: table, hops: hops}) when hops < @max_hops do
    choices =
      for {_name, {:object, _target, _mapping}} = relationship <- Catalog.relationships(table),
          do: {chain_weight(relationship), constant(relationship)}

    object_chain(choices, hops)
  end

  defp object_chains(_ctx), do: []

  defp object_chain([], _hops), do: []

  defp object_chain(choices, hops) do
    chain =
      choices
      |> frequency()
      |> bind(fn {name, {:object, target, _mapping}} ->
        ctx = permission_ctx(target, hops + 1)

        [{1, leaf(ctx)} | object_chains(ctx)]
        |> frequency()
        |> map(&%{name => &1})
      end)

    [{8, chain}]
  end

  defp chain_weight({name, _relationship}) when name in @nullable_relationships, do: 4
  defp chain_weight(_relationship), do: 1

  defp exists_trees(%{mode: :permission, hops: hops}, depth),
    do: [{1, bind(member_of(Catalog.tracked()), &exists_tree(&1, hops, depth))}]

  defp exists_trees(_ctx, _depth), do: []

  defp exists_tree({schema, name} = table, hops, depth) do
    table
    |> permission_ctx(hops)
    |> bool_tree(depth - 1)
    |> map(&%{"_exists" => %{"_table" => %{"schema" => schema, "name" => name}, "_where" => &1}})
  end

  # Rare kinds are drawn more: a `jsonb` column (only
  # `articles.assignees`) has five operators of its own (and an input
  # filter only reaches it on an `articles` root), and a `bool` column is
  # where a session flag can be compared.
  defp leaf(%{table: table, columns: columns, mode: mode} = ctx) do
    columns
    |> Enum.map(&{leaf_weight(Catalog.kind(table, &1), mode), constant(&1)})
    |> frequency()
    |> bind(&column_leaf(ctx, &1))
  end

  defp leaf_weight(:jsonb, :input), do: 15
  defp leaf_weight(:jsonb, :permission), do: 5
  defp leaf_weight(:bool, _mode), do: 3
  defp leaf_weight(_kind, _mode), do: 1

  defp column_leaf(%{table: table} = ctx, column) do
    table
    |> Catalog.kind(column)
    |> comparisons(ctx, Catalog.pool(table, column))
    |> one_of()
    |> bind(&spell(&1, ctx))
    |> map(&operator_leaf(column, &1))
  end

  # A permission leaf sometimes uses the `$` alias or the `_eq` shorthand.
  defp spell({op, value}, %{mode: :permission}) do
    shorthand = if op == "_eq", do: [{6, constant({:shorthand, value})}], else: []
    aliased = {2, constant({"$" <> String.trim_leading(op, "_"), value})}
    frequency([{6, constant({op, value})}, aliased | shorthand])
  end

  defp spell(pair, _ctx), do: constant(pair)

  defp operator_leaf(column, {:shorthand, value}), do: %{column => value}
  defp operator_leaf(column, {op, value}), do: %{column => %{op => value}}

  defp comparisons(:jsonb, _ctx, maps) do
    keys = maps |> Enum.flat_map(&Map.keys/1) |> Enum.uniq() |> then(&["1" | &1])

    [
      map(member_of(maps), &{"_contains", &1}),
      map(member_of(maps), &{"_contained_in", Map.put(&1, "9", true)}),
      map(member_of(keys), &{"_has_key", &1}),
      map(list_of(member_of(keys), max_length: 3), &{"_has_keys_any", &1}),
      map(list_of(member_of(keys), max_length: 2), &{"_has_keys_all", &1}),
      null_check()
    ]
  end

  defp comparisons(kind, ctx, values) do
    [null_check(), list_op(ctx, kind, values, "_in"), list_op(ctx, kind, values, "_nin")] ++
      scalar_ops(ctx, kind, member_of(values)) ++ pattern_ops(kind)
  end

  defp null_check, do: map(boolean(), &{"_is_null", &1})

  defp list_op(ctx, kind, values, op) do
    literal = map(list_of(member_of(values), max_length: 3), &{op, &1})

    case variable(ctx, array_kind(kind)) do
      nil -> literal
      variable -> frequency([{2, literal}, {1, map(variable, &{op, &1})}])
    end
  end

  defp scalar_ops(ctx, kind, value) do
    operand =
      case variable(ctx, kind) do
        nil -> value
        variable -> frequency([{2, value}, {1, variable}])
      end

    kind |> scalar_operators() |> Enum.map(fn op -> map(operand, &{op, &1}) end)
  end

  defp array_kind(:int), do: :int_array
  defp array_kind(:text), do: :text_array
  defp array_kind(_kind), do: nil

  defp scalar_operators(kind) when kind in [:int, :float, :text, :time], do: @comparisons
  defp scalar_operators(_kind), do: ["_eq", "_neq"]

  defp pattern_ops(:text),
    do: Enum.map(@patterns, fn {op, patterns} -> map(member_of(patterns), &{op, &1}) end)

  defp pattern_ops(_kind), do: []

  # A spelling of a session variable of `kind`, in permission filters only.
  defp variable(%{mode: :permission}, kind) do
    case for(
           {_name, ^kind, spellings} <- Catalog.variables(),
           spelling <- spellings,
           do: spelling
         ) do
      [] -> nil
      spellings -> member_of(spellings)
    end
  end

  defp variable(_ctx, _kind), do: nil

  # Size. `cap/1` keeps at most 40 nodes, dropping trailing children;
  # `stats/1` counts the same way.

  defp cap(filter), do: filter |> cap(@max_nodes) |> elem(0)

  defp cap(map, budget) when is_map(map) do
    {entries, used} = budgeted(Map.to_list(map), budget, &cap_entry/2)
    {Map.new(entries), used}
  end

  defp cap_entry({key, list}, budget) when is_list(list) and key in @list_keys do
    {kids, used} = budgeted(list, budget - 1, &cap/2)
    {{key, kids}, used + 1}
  end

  defp cap_entry({key, %{"_where" => where} = exists}, budget) when key in @exists_keys do
    {where, used} = cap(where, budget - 1)
    {{key, %{exists | "_where" => where}}, used + 1}
  end

  defp cap_entry({key, body} = entry, budget) do
    if filter_body?(key, body) do
      {body, used} = cap(body, budget - 1)
      {{key, body}, used + 1}
    else
      {entry, 1}
    end
  end

  # Keeps items, in order, while the budget lasts.
  defp budgeted(items, budget, cap) do
    {kept, used} =
      Enum.reduce(items, {[], 0}, fn
        _item, {kept, used} when used >= budget ->
          {kept, used}

        item, {kept, used} ->
          {item, n} = cap.(item, budget - used)
          {[item | kept], used + n}
      end)

    {Enum.reverse(kept), used}
  end

  defp measure(map) when is_map(map), do: map |> Enum.map(&measure_entry/1) |> combine()

  defp measure_entry({key, list}) when is_list(list) and key in @list_keys,
    do: list |> Enum.map(&measure/1) |> combine() |> deeper()

  defp measure_entry({key, %{"_where" => where}}) when key in @exists_keys,
    do: where |> measure() |> deeper()

  defp measure_entry({key, body}) do
    if filter_body?(key, body), do: body |> measure() |> deeper(), else: {1, 1}
  end

  defp combine(sizes),
    do: Enum.reduce(sizes, {0, 0}, fn {d, n}, {depth, nodes} -> {max(d, depth), n + nodes} end)

  defp deeper({depth, nodes}), do: {depth + 1, nodes + 1}

  # `_not` bodies and relationship bodies (a map with a non-operator key)
  # are filters; operator maps and shorthand values are leaves.
  defp filter_body?(key, _body) when key in @not_keys, do: true

  defp filter_body?(_key, body) when is_map(body) and map_size(body) > 0,
    do: Enum.any?(Map.keys(body), &(not operator_key?(&1)))

  defp filter_body?(_key, _body), do: false

  defp operator_key?("_" <> _rest), do: true
  defp operator_key?("$" <> _rest), do: true
  defp operator_key?(_key), do: false

  # Tags.

  defp tags(map, table, hops) when is_map(map),
    do: Enum.flat_map(map, &entry_tags(&1, table, hops))

  defp tags(_other, _table, _hops), do: []

  defp entry_tags({key, list}, table, hops) when is_list(list) and key in @list_keys do
    tag = Map.fetch!(@operator_tags, key)
    [tag, alias_tag(key), empty_tag(tag, list) | Enum.flat_map(list, &tags(&1, table, hops))]
  end

  defp entry_tags({key, body}, table, hops) when key in @not_keys,
    do: [:_not, alias_tag(key) | tags(body, table, hops)]

  defp entry_tags(
         {key, %{"_table" => %{"schema" => s, "name" => n}, "_where" => where}},
         _t,
         hops
       )
       when key in @exists_keys,
       do: [:_exists, alias_tag(key) | tags(where, {s, n}, hops)]

  defp entry_tags({key, body}, table, hops) do
    case Catalog.relationship(table, key) do
      {_kind, target, _mapping} -> [depth_tag(hops + 1) | tags(body, target, hops + 1)]
      nil -> column_tags(body)
    end
  end

  defp depth_tag(@max_hops), do: :rel_depth_3
  defp depth_tag(_hops), do: nil

  defp column_tags(ops) when is_map(ops) do
    Enum.flat_map(ops, fn {op, value} ->
      tag = Map.fetch!(@operator_tags, op)
      [tag, alias_tag(op), empty_tag(tag, value), session_tag(value)]
    end)
  end

  defp column_tags(value), do: [:shorthand, session_tag(value)]

  defp empty_tag(tag, []), do: Map.get(@empty_tags, tag)
  defp empty_tag(_tag, _value), do: nil

  defp alias_tag("$" <> _rest), do: :dollar_alias
  defp alias_tag(_key), do: nil

  defp session_tag(value) do
    if session_ref?(value) and value != String.downcase(value), do: :session_mixed_case
  end

  defp refs(map) when is_map(map), do: Enum.flat_map(map, fn {_key, value} -> refs(value) end)
  defp refs(list) when is_list(list), do: Enum.flat_map(list, &refs/1)
  defp refs(value), do: if(session_ref?(value), do: [value], else: [])
end

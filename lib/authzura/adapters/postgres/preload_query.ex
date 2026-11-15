defmodule Authzura.Adapters.Postgres.PreloadQuery do
  @moduledoc """
  Builds the query that loads one preload level, for
  `Authzura.Adapters.Postgres.preload_level_query/2`.

  ## Shape

  The parent keys travel as one `unnest` source:

      unnest($1::bigint[], $2::citext[]) WITH ORDINALITY AS p(k1, k2, idx)

    * **One array parameter per key column**, whatever the number of
      parents, so a batch never approaches Postgres's 65,535 bind-parameter
      limit. `idx` is the key tuple's 1-based position (the loader sends
      each distinct tuple once).
    * **SQL equality per mapping pair**, ANDed, so Postgres decides
      equality: complete tuples match (crossed tuples never do), a `NULL`
      key matches nothing, `citext` keys compare case-insensitively (they
      bind as `citext[]` through `Authzura.Adapters.Postgres.Citext`) and
      enum keys bind as `varchar[]` and are cast to the column's
      schema-qualified enum type (`t.c = p.k1::"public"."status"`, built
      from introspected metadata only), so an index on the column applies.
      An enum column without a quotable type compares as text.
    * The `unnest` fragment is literal SQL per arity: one clause per arity
      from 1 to 8 (the composite-key maximum), generated at compile time.
      Each array is `type(^values, ^ecto_type)` with the type from
      `key_array_param/2`.

  The target table is read under its explicit prefix with its row filter
  (the node's `condition`, compiled with the session against the alias
  `:__authzura_0` when the tree was validated), selecting
  the requested columns and the stitching columns the children need. The
  rank order is the node's `order_by` followed by the target's primary key
  columns it does not name (ascending, as a tiebreaker, so a limited level
  is deterministic).

  An **unlimited array relationship** reads every child in one join,
  ordered by `p.idx` and then the rank order:

      SELECT t.c..., p.idx FROM "schema"."target" AS t
      JOIN (SELECT * FROM unnest(...) ...) AS p ON t.c1 = p.k1
      WHERE <row filter> ORDER BY p.idx, <rank order>

  An object relationship whose target key columns are exactly the target's
  primary key matches at most one row per key tuple and takes this shape
  too.

  A **bounded level** (an array relationship with a permission limit, or
  any other object relationship, bounded at 2 rows to detect a cardinality
  violation) takes one of two shapes, chosen from the target's introspected
  indexes (`Table.indexes`).

  When an index starts with the key columns (in any order) followed by the
  first rank column, stored in the rank's direction and nulls placement or
  their exact reverse, and every key equality can use an index (an enum
  key compared as text cannot), each key tuple is read through a **lateral subquery**
  that stops after the bound, so the cost follows the rows returned rather
  than the rows that exist (each parent is an index range scan):

      SELECT s.c..., p.idx FROM (SELECT * FROM unnest(...) ...) AS p
      INNER JOIN LATERAL (
        SELECT t.c..., row_number() OVER (ORDER BY <rank order>) AS rn
        FROM "schema"."target" AS t
        WHERE <row filter> AND t.c1 = p.k1
        ORDER BY <rank order> LIMIT $n) AS s ON TRUE
      ORDER BY p.idx, s.rn

  Without such an index the lateral form is unsafe: Postgres may walk
  another index (the primary key, say) in rank order and filter on the key,
  which on skewed data reads most of the table for every parent. The level
  is then a **windowed join**, bounded by the children that exist:

      SELECT ... FROM (
        SELECT t.c..., p.idx,
               row_number() OVER (PARTITION BY p.idx ORDER BY <rank order>) AS rn
        FROM "schema"."target" AS t JOIN (SELECT * FROM unnest(...) ...) AS p
          ON t.c1 = p.k1
        WHERE <row filter>) AS s
      WHERE s.rn <= $n ORDER BY s.idx, s.rn

  With no rank order at all (no `order_by`, no primary key), both order by
  `p.idx`, a constant per parent.

  ## Result rows

  Each row is a map of column name strings to values plus the atom key
  `:idx`, which never collides with a column name. A subquery's select map
  needs atom keys, so a ranked subquery names its columns from a fixed
  compile-time pool of positional slots (Postgres allows at most 1600
  columns per table, and the selection never repeats a column) and the
  outer query maps them back.
  """

  import Ecto.Query,
    only: [
      dynamic: 1,
      dynamic: 2,
      from: 2,
      join: 5,
      limit: 2,
      order_by: 2,
      order_by: 3,
      select: 3,
      select_merge: 3,
      subquery: 1,
      where: 3,
      windows: 3
    ]

  alias Authzura.Adapters.Postgres.Citext
  alias Authzura.Compiler.Aliases
  alias Authzura.Model.{Column, Permission, Relationship, Table}
  alias Authzura.Preload.Tree
  alias Ecto.{Query, Type, UUID}

  @max_keys 8
  @keys :__authzura_keys
  @max_columns 1600
  @slots List.to_tuple(for i <- 0..(@max_columns - 1), do: :"__authzura_c#{i}")

  @doc """
  Builds the level query for `node`, whose `key_columns` (the target's key
  columns, in mapping order) number 1 to 8. `key_values` holds one list of
  key values (in the same order) per key tuple.
  """
  @spec build(Tree.preload_node(), [[term()]]) :: {:ok, Query.t()}
  def build(
        %{
          rel: %Relationship{kind: kind, target: {schema, name}},
          template: {%Permission{limit: limit}, _filter},
          table: %Table{} = table,
          key_columns: [_ | _] = key_columns,
          condition: condition,
          columns: columns,
          order_by: order,
          children: children
        },
        key_values
      )
      when length(key_columns) <= @max_keys do
    rank = rank(order, table)

    level = %{
      target: from(t in name, prefix: ^schema, as: ^Aliases.at(0), where: ^condition),
      key_columns: key_columns,
      params:
        key_values
        |> transpose(length(key_columns))
        |> Enum.zip_with(key_columns, &key_array_param/2),
      selected: Enum.uniq(columns ++ Tree.parent_columns(children)),
      ranking: Enum.map(rank, fn {direction, column} -> {direction, column_expr(column)} end)
    }

    {:ok, shape(strategy(kind, limit, key_columns, table, rank), level)}
  end

  @doc """
  The array parameter for one key column: `{values, ecto_type}`, bound as
  `type(^values, ^ecto_type)`. Integer kinds bind as `bigint[]`, text and
  enum as `varchar[]`, citext as `citext[]` and uuid as `uuid[]` (raw
  16-byte values, as schemaless reads return them, are encoded first).
  """
  @spec key_array_param([term()], Column.t()) :: {[term()], Type.t()}
  def key_array_param(values, %Column{base_kind: kind}) when kind in [:integer, :bigint],
    do: {values, {:array, :integer}}

  def key_array_param(values, %Column{base_kind: kind}) when kind in [:text, :enum],
    do: {values, {:array, :string}}

  def key_array_param(values, %Column{base_kind: :citext}), do: {values, {:array, Citext}}

  def key_array_param(values, %Column{base_kind: :uuid}),
    do: {Enum.map(values, &uuid/1), {:array, UUID}}

  defp uuid(<<_::128>> = raw), do: UUID.cast!(raw)
  defp uuid(value), do: value

  # One list per key column, from one list per parent.
  defp transpose(rows, arity) do
    rows
    |> Enum.reverse()
    |> Enum.reduce(
      List.duplicate([], arity),
      &Enum.zip_with(&1, &2, fn value, acc -> [value | acc] end)
    )
  end

  # How a level is read: `:join` for every matching row, `{:lateral, bound}`
  # when an index serves each parent's rank order, `{:window, bound}`
  # otherwise.
  defp strategy(kind, limit, key_columns, table, rank) do
    case rank_bound(kind, limit, Enum.map(key_columns, & &1.name), table) do
      nil -> :join
      bound -> bounded(bound, served?(table, key_columns, rank))
    end
  end

  defp bounded(bound, true), do: {:lateral, bound}
  defp bounded(bound, false), do: {:window, bound}

  # An index whose leading columns are the key columns (in any order),
  # followed by the first rank column stored in the rank's direction and
  # nulls placement (or their exact reverse, scanned backward), lets each
  # parent's bounded read be an index range scan in rank order. Without one,
  # Postgres may walk another index in rank order filtering on the key,
  # which on skewed data reads most of the table per parent, so the
  # windowed join (bounded by the children that exist) is used instead. So
  # it is when a key equality cannot use an index at all.
  defp served?(%Table{indexes: indexes}, key_columns, rank) do
    names = Enum.map(key_columns, & &1.name)

    Enum.all?(key_columns, &indexable_key?/1) and
      Enum.any?(indexes, &serves?(&1, names, Enum.take(rank, 1)))
  end

  # An enum key without a quotable type compares as text, which no index
  # on the column serves.
  defp indexable_key?(%Column{base_kind: :enum, type_schema: nil}), do: false
  defp indexable_key?(%Column{}), do: true

  defp serves?(index, names, first) do
    {lead, rest} = Enum.split(index, length(names))

    Enum.sort(Enum.map(lead, &elem(&1, 0))) == Enum.sort(names) and
      leading_order?(rest, first)
  end

  defp leading_order?(_rest, []), do: true

  defp leading_order?([{column, stored} | _rest], [{direction, column}]),
    do: placement(direction) in [placement(stored), reverse(placement(stored))]

  defp leading_order?(_rest, _first), do: false

  # `{descending?, nulls_first?}` of a sort direction (Postgres puts NULLs
  # last ascending and first descending by default).
  defp placement(:asc), do: {false, false}
  defp placement(:asc_nulls_last), do: {false, false}
  defp placement(:asc_nulls_first), do: {false, true}
  defp placement(:desc), do: {true, true}
  defp placement(:desc_nulls_first), do: {true, true}
  defp placement(:desc_nulls_last), do: {true, false}

  defp reverse({descending?, nulls_first?}), do: {not descending?, not nulls_first?}

  # Every matching row, in one ordered join (no window: nothing is cut).
  defp shape(:join, %{
         target: target,
         params: params,
         key_columns: keys,
         ranking: ranking,
         selected: selected
       }) do
    target
    |> unnest_join(params, on(keys, &joined_key/1))
    |> order_by([t, p], ^[{:asc, dynamic([t, p], p.idx)} | ranking])
    |> select([t, p], ^Map.new(selected, &{&1, column_expr(&1)}))
    |> select_merge([t, p], %{idx: p.idx})
  end

  # Per parent, a lateral subquery stops after `bound` rows in rank order,
  # so the cost follows the rows returned, not the rows that exist.
  defp shape({:lateral, bound}, %{
         target: target,
         params: params,
         key_columns: keys,
         ranking: ranking_terms,
         selected: selected
       }) do
    ranking = nonempty_ranking(ranking_terms, dynamic(field(parent_as(^@keys), :idx)))

    per_parent =
      target
      |> where([t], ^on(keys, &lateral_key/1))
      |> windows([t], w: [order_by: ^ranking])
      |> order_by(^ranking)
      |> limit(^bound)
      |> select([t], ^slots(selected))
      |> select_merge([t], %{rn: over(row_number(), :w)})

    params
    |> unnest_source()
    |> join(:inner_lateral, [p], s in subquery(per_parent), on: true)
    |> order_by([p, s], [p.idx, s.rn])
    |> select([p, s], ^unslot(selected, &dynamic([p, s], field(s, ^&1))))
    |> select_merge([p, s], %{idx: p.idx})
  end

  # Every child joined and ranked per parent, then cut at `bound`.
  defp shape({:window, bound}, %{
         target: target,
         params: params,
         key_columns: keys,
         ranking: ranking_terms,
         selected: selected
       }) do
    ranking = nonempty_ranking(ranking_terms, dynamic([t, p], p.idx))

    ranked =
      target
      |> unnest_join(params, on(keys, &joined_key/1))
      |> windows([t, p], w: [partition_by: p.idx, order_by: ^ranking])
      |> select([t], ^slots(selected))
      |> select_merge([t, p], %{idx: p.idx, rn: over(row_number(), :w)})

    from(s in subquery(ranked),
      where: s.rn <= ^bound,
      order_by: [s.idx, s.rn],
      select: ^unslot(selected, &dynamic([s], field(s, ^&1)))
    )
    |> select_merge([s], %{idx: s.idx})
  end

  # A window needs an order; with none, every row of a parent ties.
  defp nonempty_ranking([], idx), do: [asc: idx]
  defp nonempty_ranking(ranking, _idx), do: ranking

  # `t.remote_i = <key_i>`, ANDed; `key` gives the i-th key expression.
  defp on(key_columns, key) do
    key_columns
    |> Enum.with_index(1)
    |> Enum.map(fn {column, i} -> key_equality(column, key.(i)) end)
    |> Enum.reduce(&dynamic(^&2 and ^&1))
  end

  # Enum keys travel as varchar and are cast to the column's own type, so
  # an index on the column applies; an enum without a quotable type
  # compares as text.
  defp key_equality(%Column{name: remote, base_kind: :enum, type_schema: nil}, key),
    do: dynamic([t], fragment("?::text", field(t, ^remote)) == ^key)

  defp key_equality(
         %Column{name: remote, base_kind: :enum, type_schema: schema, pg_type: type},
         key
       ),
       do:
         dynamic(
           [t],
           field(t, ^remote) == fragment("?::?.?", ^key, identifier(^schema), identifier(^type))
         )

  defp key_equality(%Column{name: remote}, key), do: dynamic([t], field(t, ^remote) == ^key)

  # The i-th key of the joined `unnest`, or of the lateral subquery's parent.
  defp joined_key(i), do: dynamic([t, p], field(p, ^key(i)))
  defp lateral_key(i), do: dynamic(field(parent_as(^@keys), ^key(i)))

  for i <- 1..@max_keys do
    defp key(unquote(i)), do: unquote(:"k#{i}")
  end

  for arity <- 1..@max_keys do
    pairs =
      for i <- 1..arity, do: {Macro.var(:"v#{i}", __MODULE__), Macro.var(:"t#{i}", __MODULE__)}

    params = for {v, t} <- pairs, do: quote(do: type(^unquote(v), ^unquote(t)))
    marks = Enum.map_join(1..arity, ", ", fn _i -> "?" end)
    keys = Enum.map_join(1..arity, ", ", &"k#{&1}")
    sql = "SELECT * FROM unnest(#{marks}) WITH ORDINALITY AS p(#{keys}, idx)"

    defp unnest_join(query, unquote(pairs), on),
      do: join(query, :inner, [t], p in fragment(unquote(sql), unquote_splicing(params)), on: ^on)

    defp unnest_source(unquote(pairs)),
      do: from(p in fragment(unquote(sql), unquote_splicing(params)), as: ^@keys)
  end

  # The node's order, then the primary key columns it does not name
  # (ascending), so ties never make a limited level nondeterministic.
  defp rank(order, %Table{primary_key: pk}) do
    sorted = Enum.map(order, &elem(&1, 1))
    order ++ for column <- pk, column not in sorted, do: {:asc, column}
  end

  defp column_expr(column), do: dynamic([t], field(t, ^column))

  defp slots(columns) do
    columns
    |> Enum.with_index()
    |> Map.new(fn {column, i} -> {slot(i), column_expr(column)} end)
  end

  defp slot(i), do: elem(@slots, i)

  # Maps the slots back to column names; `field` reads one slot.
  defp unslot(columns, field) do
    columns
    |> Enum.with_index()
    |> Map.new(fn {column, i} -> {column, field.(slot(i))} end)
  end

  # An object relationship on exactly the target's primary key matches at
  # most one row per key tuple, so it needs no bound; any other object
  # relationship reads 2 rows, enough to detect a cardinality violation.
  defp rank_bound(:array, limit, _names, %Table{}), do: limit

  defp rank_bound(:object, _limit, names, %Table{primary_key: [_ | _] = pk}) do
    if Enum.sort(names) == Enum.sort(pk), do: nil, else: 2
  end

  defp rank_bound(:object, _limit, _names, %Table{}), do: 2
end

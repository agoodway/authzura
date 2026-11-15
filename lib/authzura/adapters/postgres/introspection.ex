defmodule Authzura.Adapters.Postgres.Introspection do
  @moduledoc """
  Reads tables, columns, keys and enum labels from the Postgres catalog.

  Every query receives the schema and table names as bind parameters (two
  parallel `text[]` values), so no identifier is ever interpolated into SQL.
  The fingerprint hashes, in SQL, the same column rows plus every constraint
  and index definition, in a deterministic order (an index decides the shape
  of a limited preload level, so creating or dropping one reloads).

  `Column.pg_type` is the catalog type name (`pg_type.typname`, for example
  `int8`, `varchar`, `bpchar`, `citext`, or an enum's own name; array types
  keep their `_name` form). Enum names are not schema-qualified there; an
  enum column's type schema is `Column.type_schema`.

  The fingerprint also covers each column's type schema and each enum
  column's labels, so renaming or adding a label, or moving a type to
  another schema (even between two schemas on the `search_path`, where
  `format_type` prints the same name), reloads the snapshot. Comparisons
  bind labels in the enum's own schema-qualified type, where an unknown
  label or type is an error until then (`:stale_permissions`).

  Each column row also carries `generated?` and `eq_leakproof?` (whether
  its `pg_catalog` equality is `LEAKPROOF`, see `Authzura.Model.Column`),
  and the table its kind (`relkind`: table, or view/materialized view).
  `Authzura.Adapters.Postgres.index_pushdown?/2` reads them for
  `input_index_pushdown`, so the fingerprint covers all three and a change
  reloads the snapshot. It also covers `relhassubclass` and the primary-key
  constraint and index inputs to `Table.strict_key?`, including
  `condeferrable` and `indisvalid`.

  A type that classified `:other` (an extension type such as PostGIS
  `geography`, or `cube`) is `:decodable` when the data repo's own Postgrex
  types module (its `:types` config, `Postgrex.DefaultTypes` by default)
  has an extension for it: introspection calls the module's generated
  `find/2` on the type's catalog names, the same match Postgrex makes, so
  no query runs and any transaction, sandbox or pool works. A `:decodable`
  column is in the default projection; one the module has no extension for
  stays `:other`. Composites and arrays stay `:other`. Only `:other` is
  considered, so a type-specific kind claimed in the kinds table is never
  overridden.
  """

  alias Authzura.Adapter
  alias Authzura.Model.{Column, Table}
  alias Ecto.UUID
  alias Postgrex.TypeInfo

  # Shared FROM prefix: binds the requested (schema, name) pairs to pg_class.
  @tables_from """
  FROM unnest($1::text[], $2::text[]) AS r(s, n)
  JOIN pg_namespace ns ON ns.nspname = r.s
  JOIN pg_class c ON c.relnamespace = ns.oid AND c.relname = r.n
    AND c.relkind IN ('r', 'p', 'v', 'm')
  """

  # Column names of a constraint's key array, in key order.
  ordered_names = fn keys, rel ->
    """
    ARRAY(SELECT a.attname::text
          FROM unnest(k.#{keys}) WITH ORDINALITY AS u(attnum, ord)
          JOIN pg_attribute a ON a.attrelid = k.#{rel} AND a.attnum = u.attnum
          ORDER BY u.ord)
    """
  end

  # The base type of a type: a domain resolves through `typbasetype`,
  # recursively, to the type it is ultimately over.
  base_type = fn type_oid ->
    """
    (WITH RECURSIVE chain(oid, base) AS (
       SELECT d.oid, d.typbasetype FROM pg_type d WHERE d.oid = #{type_oid}
       UNION ALL
       SELECT d.oid, d.typbasetype FROM chain JOIN pg_type d ON d.oid = chain.base
     )
     SELECT oid FROM chain WHERE base = 0)
    """
  end

  # Whether the `OPERATOR(pg_catalog.=)` an operand of the column resolves to
  # is `LEAKPROOF`. The operators considered are the schema `pg_catalog`'s
  # `=` on the column's type (or, with none of its own, on the types it is
  # binary-coercible to, as `varchar` is to `text`; a type whose own `=` lives
  # in another schema, like `citext`, has none), against itself, `bigint`
  # (how integer operands bind) or `text` (`name = text`). A domain column,
  # and a type with no such operator, is not leakproof.
  @eq_leakproof """
  (a.atttypid = t.oid AND coalesce((
     SELECT bool_and(p.proleakproof)
     FROM pg_operator o JOIN pg_proc p ON p.oid = o.oprcode
     WHERE o.oprname = '=' AND o.oprnamespace = 'pg_catalog'::regnamespace
       AND o.oprleft IN (
         SELECT unnest(CASE WHEN EXISTS (
                  SELECT 1 FROM pg_operator d
                  WHERE d.oprname = '=' AND d.oprnamespace = 'pg_catalog'::regnamespace
                    AND d.oprleft = t.oid AND d.oprright = t.oid)
                THEN ARRAY[t.oid]
                WHEN EXISTS (
                  SELECT 1 FROM pg_operator d
                  WHERE d.oprname = '=' AND d.oprleft = t.oid AND d.oprright = t.oid)
                THEN ARRAY[]::oid[]
                ELSE ARRAY(SELECT c.casttarget FROM pg_cast c
                           WHERE c.castsource = t.oid AND c.castmethod = 'b') END))
       AND o.oprright IN (o.oprleft, 'int8'::regtype, 'text'::regtype)), false))
  """

  # The schema the `citext` extension is installed in (`NULL` without it),
  # which is where its `=` lives. A type named `citext` anywhere else is not
  # the extension's, so its equality is never named.
  @citext_schema """
  (SELECT x.nspname::text FROM pg_extension e JOIN pg_namespace x ON x.oid = e.extnamespace
   WHERE e.extname = 'citext')
  """

  # A column's type, its element type when it is an array, both resolved
  # through domains, with their binary send functions (which Postgrex
  # matches its decoders on).
  @columns_sql """
  SELECT ns.nspname, c.relname, c.relkind::text, a.attname::text, a.attnotnull,
         t.typname::text, t.typtype::text, et.typname::text, et.typtype::text,
         ARRAY(SELECT e.enumlabel::text FROM pg_enum e
               WHERE e.enumtypid = t.oid ORDER BY e.enumsortorder),
         tns.nspname::text, t.typsend::text, et.typsend::text,
         a.attgenerated <> '',
         #{@eq_leakproof},
         #{@citext_schema},
         t.oid::int, t.typreceive::text, t.typoutput::text, t.typinput::text
  #{@tables_from}
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
  JOIN pg_type t ON t.oid = #{base_type.("a.atttypid")}
  JOIN pg_namespace tns ON tns.oid = t.typnamespace
  LEFT JOIN pg_type et ON t.typcategory = 'A' AND et.oid = #{base_type.("t.typelem")}
  ORDER BY ns.nspname, c.relname, a.attnum
  """

  # The last column marks a key that is strictly unique: not deferrable,
  # with a valid index, and no inheritance children. A partitioned table's
  # key is enforced across its partitions, so `relkind = 'p'` is allowed, but
  # only while the key index is valid (`ALTER TABLE ONLY ... ADD PRIMARY KEY`
  # on a partitioned table leaves it invalid, and duplicates get in).
  @primary_keys_sql """
  SELECT ns.nspname, c.relname, #{ordered_names.("conkey", "conrelid")},
         NOT k.condeferrable AND pi.indisvalid AND (NOT c.relhassubclass OR c.relkind = 'p')
  #{@tables_from}
  JOIN pg_constraint k ON k.conrelid = c.oid AND k.contype = 'p'
  JOIN pg_index pi ON pi.indexrelid = k.conindid
  """

  # An index's key columns (never `INCLUDE` columns), with their
  # `indoption` bits, operator class and collation, in index order.
  @index_keys """
  FROM unnest(i.indkey::int2[], i.indoption::int2[], i.indclass::oid[], i.indcollation::oid[])
         WITH ORDINALITY AS u(attnum, opt, opclass, coll, ord)
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = u.attnum
  WHERE u.ord <= i.indnkeyatts
  """

  # Valid, non-partial btree indexes on plain columns: key column names and
  # `indoption` bits (1 = DESC, 2 = NULLS FIRST). An index with any key
  # column on a non-default operator class, or on a collation other than
  # the column's, is left out, because the key equality and order Authzura
  # emits may not be able to use it.
  @indexes_sql """
  SELECT ns.nspname, c.relname,
         ARRAY(SELECT a.attname::text #{@index_keys} ORDER BY u.ord),
         ARRAY(SELECT u.opt::int #{@index_keys} ORDER BY u.ord)
  #{@tables_from}
  JOIN pg_index i ON i.indrelid = c.oid AND i.indisvalid
    AND i.indpred IS NULL AND i.indexprs IS NULL
  JOIN pg_class ic ON ic.oid = i.indexrelid
  JOIN pg_am am ON am.oid = ic.relam AND am.amname = 'btree'
  WHERE NOT EXISTS (
    SELECT 1 #{@index_keys}
    AND (u.coll IS DISTINCT FROM a.attcollation
         OR NOT (SELECT oc.opcdefault FROM pg_opclass oc WHERE oc.oid = u.opclass)))
  ORDER BY ns.nspname, c.relname, ic.relname
  """

  @foreign_keys_sql """
  SELECT ns.nspname, c.relname, rns.nspname, rc.relname,
         #{ordered_names.("conkey", "conrelid")},
         #{ordered_names.("confkey", "confrelid")}
  #{@tables_from}
  JOIN pg_constraint k ON k.conrelid = c.oid AND k.contype = 'f'
  JOIN pg_class rc ON rc.oid = k.confrelid
  JOIN pg_namespace rns ON rns.oid = rc.relnamespace
  ORDER BY ns.nspname, c.relname, k.conname
  """

  @fingerprint_sql """
  SELECT md5(coalesce(string_agg(line, '|' ORDER BY line), ''))
  FROM (
    SELECT concat_ws(':', 'column', ns.nspname, c.relname, a.attname,
                     format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attgenerated,
                     c.relkind, c.relhassubclass, #{@eq_leakproof},
                     (SELECT tn.nspname FROM pg_type ty
                      JOIN pg_namespace tn ON tn.oid = ty.typnamespace
                      WHERE ty.oid = a.atttypid),
                     (SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder)
                      FROM pg_enum e WHERE e.enumtypid = a.atttypid)) AS line
    #{@tables_from}
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    JOIN pg_type t ON t.oid = #{base_type.("a.atttypid")}
    UNION ALL
    SELECT concat_ws(':', 'constraint', ns.nspname, c.relname, k.conname,
                     k.contype, pg_get_constraintdef(k.oid)) AS line
    #{@tables_from}
    JOIN pg_constraint k ON k.conrelid = c.oid
    UNION ALL
    SELECT concat_ws(':', 'index', ns.nspname, c.relname,
                     pg_get_indexdef(i.indexrelid), i.indisvalid) AS line
    #{@tables_from}
    JOIN pg_index i ON i.indrelid = c.oid
  ) lines
  """

  # The binary send functions (and type names) Postgrex's default types
  # decode (`Postgrex.DefaultTypes`), so a value of such a type always
  # decodes. Records are left out: their fields may not.
  @decodable_sends ~w(
    bit_send varbit_send boolsend box_send cidr_send inet_send circle_send
    date_send float4send float8send int2send int4send int8send pg_lsn_send interval_send
    line_send lseg_send macaddr_send namesend numeric_send oidsend regprocsend
    regproceduresend regopersend regoperatorsend regclasssend regtypesend regconfigsend
    xidsend cidsend path_send point_send poly_send multirange_send range_send bpcharsend
    textsend varcharsend byteasend enum_send unknownsend citextsend charsend tidsend
    time_send timestamp_send timestamptz_send timetz_send tsvectorsend uuid_send void_send
    xid8send ltree_send lquery_send
  )
  @decodable_names ~w(json jsonb hstore ltxtquery)

  @kinds %{
    "int2" => {:integer, :integer},
    "int4" => {:integer, :integer},
    "int8" => {:bigint, :integer},
    "numeric" => {:numeric, :decimal},
    "float4" => {:float, :float},
    "float8" => {:float, :float},
    "bool" => {:boolean, :boolean},
    "text" => {:text, :string},
    "varchar" => {:text, :string},
    "bpchar" => {:text, :string},
    # The identifier type (`information_schema.sql_identifier` is a domain
    # over it); Postgres compares it with text through its `name`/`text`
    # operators, so it is read and compared as text.
    "name" => {:text, :string},
    "citext" => {:citext, :string},
    "uuid" => {:uuid, UUID},
    "timestamptz" => {:timestamptz, :utc_datetime_usec},
    "timestamp" => {:timestamp, :naive_datetime_usec},
    "date" => {:date, :date},
    "jsonb" => {:jsonb, :map},
    "json" => {:json, :map}
  }

  @doc """
  Introspects the given tables and views.

  Returns the tables keyed by `{schema, name}` plus the foreign keys declared
  on them. Refs that do not exist are simply absent from the result.
  """
  @spec introspect(module(), [Table.table_ref()]) ::
          {:ok, %{Table.table_ref() => Table.t()}, [Adapter.fk()]} | {:error, term()}
  def introspect(repo, refs) do
    params = bind_params(refs)

    with {:ok, columns} <- query(repo, @columns_sql, params),
         {:ok, pks} <- query(repo, @primary_keys_sql, params),
         {:ok, indexes} <- query(repo, @indexes_sql, params),
         {:ok, fks} <- query(repo, @foreign_keys_sql, params) do
      types = types(repo)

      tables =
        columns
        |> Enum.group_by(fn [schema, name | _] -> {schema, name} end)
        |> Map.new(fn {ref, rows} -> {ref, build_table(ref, rows, types)} end)
        |> put_primary_keys(pks)
        |> put_indexes(indexes)

      {:ok, tables, Enum.map(fks, &build_fk/1)}
    end
  end

  @doc """
  Returns the md5 of the structure (columns, types, enum labels,
  nullability, constraints and indexes) of the given tables, computed in
  SQL.
  """
  @spec fingerprint(module(), [Table.table_ref()]) :: {:ok, binary()} | {:error, term()}
  def fingerprint(repo, refs) do
    with {:ok, [[digest]]} <- query(repo, @fingerprint_sql, bind_params(refs)), do: {:ok, digest}
  end

  # The data repo's Postgrex types module (what its connections decode with).
  defp types(repo), do: Keyword.get(repo.config(), :types, Postgrex.DefaultTypes)

  defp bind_params(refs), do: refs |> Enum.uniq() |> Enum.unzip() |> Tuple.to_list()

  defp query(repo, sql, params) do
    with {:ok, %{rows: rows}} <- repo.query(sql, params), do: {:ok, rows}
  end

  defp build_table({schema, name}, [[_, _, relkind | _] | _] = rows, types) do
    kind = table_kind(relkind)

    %Table{
      schema: schema,
      name: name,
      kind: kind,
      columns: Map.new(rows, &build_column(kind, types, &1))
    }
  end

  defp build_column(kind, types, [
         _,
         _,
         _,
         name,
         not_null?,
         typname,
         typtype,
         elem_name,
         elem_type,
         labels,
         type_schema,
         send,
         elem_send,
         generated?,
         eq_leakproof?,
         citext_schema,
         type_oid,
         type_receive,
         type_output,
         type_input
       ]) do
    element = element(elem_name, elem_type, elem_send)

    info = %TypeInfo{
      oid: type_oid,
      type: typname,
      send: send,
      receive: type_receive,
      output: type_output,
      input: type_input
    }

    {base_kind, ecto_type} =
      {typname, typtype, send}
      |> classify(element)
      |> promote(typtype, info, types)

    column = %Column{
      name: name,
      pg_type: typname,
      base_kind: base_kind,
      ecto_type: ecto_type,
      enum_labels: enum_labels(base_kind, labels),
      type_schema: type_schema(base_kind, type_schema, typname, citext_schema),
      element_kind: element_kind(base_kind, element),
      nullable?: kind == :view or not not_null?,
      generated?: generated?,
      eq_leakproof?: eq_leakproof?
    }

    {name, column}
  end

  defp element_kind(:array, element), do: element |> classify(nil) |> elem(0)
  defp element_kind(_base_kind, _element), do: nil

  defp enum_labels(:enum, labels), do: labels
  defp enum_labels(_base_kind, _labels), do: nil

  # An enum's type is cast to, and a `citext` column's equality is named by,
  # a schema, when Ecto can quote it. A `citext` type outside the
  # extension's schema has none.
  defp type_schema(:enum, schema, typname, _citext_schema),
    do: (schema <> typname) |> String.contains?(~s(")) |> unquoted_schema(schema)

  defp type_schema(:citext, schema, _typname, schema),
    do: schema |> String.contains?(~s(")) |> unquoted_schema(schema)

  defp type_schema(_base_kind, _schema, _typname, _citext_schema), do: nil

  defp unquoted_schema(true = _quote?, _schema), do: nil
  defp unquoted_schema(false, schema), do: schema

  defp table_kind(relkind) when relkind in ["v", "m"], do: :view
  defp table_kind(_relkind), do: :table

  defp element(nil, _typtype, _send), do: nil
  defp element(name, typtype, send), do: {name, typtype, send}

  # `{base_kind, ecto_type}` of a (domain-resolved) type, and of an array
  # from its element. A type Authzura does not compare is `:decodable` when
  # Postgrex's default types decode it, and `:other` otherwise (an
  # extension type, a composite whose fields might not decode, or an array
  # of such).
  defp classify({_typname, "e", _send}, _element), do: {:enum, :string}
  defp classify({_typname, "c", _send}, _element), do: {:other, :any}

  # Only a true array (`array_send`) is decoded element by element;
  # `int2vector` and the like have an element type but a send of their own.
  defp classify({_typname, _typtype, "array_send"}, {_name, _typtype_e, _send_e} = element) do
    case classify(element, nil) do
      {:other, _ecto_type} -> {:other, :any}
      {_kind, ecto_type} -> {:array, {:array, ecto_type}}
    end
  end

  defp classify({typname, _typtype, send}, _element),
    do: Map.get_lazy(@kinds, typname, fn -> decodable(typname, send) end)

  defp decodable(typname, send) when send in @decodable_sends or typname in @decodable_names,
    do: {:decodable, :any}

  defp decodable(_typname, _send), do: {:other, :any}

  # Only a type that classified `:other` is looked at (a kind claimed in
  # `@kinds`, or `@decodable_sends`, is never overridden), and only a plain
  # base type: a composite or an array stays `:other`, since whether its
  # fields or elements decode is not what the types module's `find` answers.
  # The repo's Postgrex types module is asked whether it has an extension for
  # the type, on the same catalog names Postgrex itself matches on. No query
  # runs, so it works in any transaction, sandbox or pool.
  defp promote({:other, _ecto_type} = kind, "b", %TypeInfo{send: send} = info, types)
       when send != "array_send" do
    case find(types, info) do
      {_format, _extension} -> {:decodable, :any}
      _no_extension -> kind
    end
  end

  defp promote(kind, _typtype, _info, _types), do: kind

  # `find/2` is what Postgrex generates in a types module; `nil` is no
  # extension (a `{:super_binary, _, _}` match needs sub-types, and is not one
  # of a plain type).
  defp find(types, info) do
    types.find(info, :any)
  rescue
    _error -> nil
  end

  defp put_primary_keys(tables, pks) do
    Enum.reduce(pks, tables, fn [schema, name, columns, strict?], acc ->
      Map.update!(acc, {schema, name}, &%{&1 | primary_key: columns, strict_key?: strict?})
    end)
  end

  defp put_indexes(tables, indexes) do
    indexes
    |> Enum.group_by(fn [schema, name | _columns] -> {schema, name} end, &index_columns/1)
    |> Enum.reduce(tables, fn {ref, columns}, acc ->
      Map.update!(acc, ref, &%{&1 | indexes: columns})
    end)
  end

  defp index_columns([_schema, _name, names, options]),
    do: Enum.zip_with(names, options, &{&1, index_direction(&2)})

  # `indoption` bit 1 is DESC, bit 2 NULLS FIRST; the defaults are
  # ASC NULLS LAST and DESC NULLS FIRST.
  defp index_direction(0), do: :asc
  defp index_direction(2), do: :asc_nulls_first
  defp index_direction(1), do: :desc_nulls_last
  defp index_direction(3), do: :desc

  defp build_fk([schema, name, ref_schema, ref_name, columns, ref_columns]) do
    %{
      table: {schema, name},
      columns: columns,
      ref_table: {ref_schema, ref_name},
      ref_columns: ref_columns
    }
  end
end

defmodule Authzura.Adapters.Postgres do
  @moduledoc """
  The Postgres adapter: operator signatures, value casting, comparison
  compilation, introspection and preload level queries.

  Introspection and fingerprinting delegate to
  `Authzura.Adapters.Postgres.Introspection`, value casting to
  `Authzura.Adapters.Postgres.Values`, and preload level queries to
  `Authzura.Adapters.Postgres.PreloadQuery`.

  ## Operators

  `operator_signature/1` is the single list of operators the adapter
  compiles. Anything else is `:unsupported` and must be denied at load.

  `compile_operator/5` takes the cast value (from `cast_value/4`) and binds it
  as a typed parameter chosen by the column's `base_kind`, using the forms
  pinned in `test/feasibility/ecto_constructs_test.exs`:

    * integers `type(^v, :integer)`, numeric `type(^v, :decimal)`, float
      `type(^v, :float)` (`real` columns `fragment("?::real", ^v)`), boolean `type(^v, :boolean)`, text `type(^v, :string)`
    * bpchar `fragment("?::bpchar", ^v)` for comparisons, so `=`, `<` and
      `_in` (which infers `bpchar[]`) all use the column's padding rules;
      pattern operators bind it as text
    * citext `fragment("?::citext", ^v)`, so comparisons stay
      case-insensitive
    * uuid `type(^v, Ecto.UUID)`
    * timestamptz `fragment("?::timestamptz", ^v)` (`type(^v, :utc_datetime_usec)`
      would bind a zone-less `timestamp`), timestamp `fragment("?::timestamp", ^v)`
      and date `type(^v, :date)`
    * jsonb `fragment("?::jsonb", ^v)`, so any JSON value (including a bare
      string) is sent as JSON
    * enum equality and membership compare the column, uncast, with the
      value cast to the enum's own type, schema-qualified and quoted from
      introspected metadata only (`$1::"public"."status"` and
      `col = ANY($1::"public"."status"[])`), so an index on the column
      applies. An enum column without a quotable type (`Column.type_schema`
      is `nil`) compares as text against a varchar parameter instead. Enum
      ordering (`:gt` ...) compares the column to an untyped parameter, so
      Postgres uses the enum's sort order. Labels are checked by
      `cast_value/4` before any SQL runs.

  `:in`/`:nin` bind one array parameter (`col = ANY($1)`); `[]` compiles to
  `false`/`true`.

  ## Comparison modes and NULL

  The spec describes `compile_operator(op, lhs, rhs, nullable?)`. This
  adapter takes the whole `Column.t()` (which carries `nullable?` and the
  type) plus an explicit mode, because the spec also requires two comparison
  modes (`:permission` and `:input`) that a nullability flag alone cannot
  express.

    * In `:permission` mode, `:eq` and `:neq` on a nullable column use
      Hasura's null-aware forms, `lhs = v OR (lhs IS NULL AND v IS NULL)` and
      `lhs <> v OR (lhs IS NOT NULL AND v IS NULL)`. Non-null columns and
      `:input` mode use plain `=` and `<>`. `Authzura.Compiler` compiles a
      session value (never `NULL`) as on a non-null column, since the null
      arm can only be false for it.
    * A `nil` value (a literal `null`) cannot be bound (`== ^nil` raises), so
      it is compiled to what Hasura's SQL evaluates with `v` = `NULL`. In
      `:permission` mode on a nullable column, `:eq` is
      `lhs IS NULL OR NULL` and `:neq` is `lhs IS NOT NULL OR NULL`: true
      where Hasura's form is true, and unknown (never false) elsewhere, so a
      surrounding `NOT` matches nothing, as in Hasura. Every other
      comparison with `nil` is `NULL::boolean`, which no row satisfies
      either way.

  `compile_operator/5` assumes its inputs were validated: the operator is
  supported, the column matches the signature's `lhs`, and the value came
  from `cast_value/4`. Any other combination is a programming error and
  raises `ArgumentError` rather than emitting SQL; it is never reached with
  an uncast user value.

  ## Relationship key kinds

  `supported_key_kind?/1` accepts the preload key kinds proven in the
  feasibility catalog: integer and bigint (including smallint), text and
  varchar, citext, uuid and enum columns. `bpchar` is refused because of its
  padding semantics, as are boolean, numeric, float, timestamp, jsonb, array
  and unclassified columns.
  """

  @behaviour Authzura.Adapter

  import Ecto.Query, only: [dynamic: 1]

  alias Authzura.Adapter
  alias Authzura.Adapters.Postgres.{InputCheck, Introspection, PreloadQuery, Values}
  alias Authzura.Model.{Column, Table}
  alias Ecto.{Query, UUID}

  @text_ops %{
    like: "LIKE",
    nlike: "NOT LIKE",
    ilike: "ILIKE",
    nilike: "NOT ILIKE",
    similar: "SIMILAR TO",
    nsimilar: "NOT SIMILAR TO",
    regex: "~",
    iregex: "~*",
    nregex: "!~",
    niregex: "!~*"
  }

  @jsonb_ops %{contains: "@>", contained_in: "<@"}
  # `\\?` is Ecto's escape for a literal `?` in fragment SQL.
  @key_ops %{has_key: "\\?", has_keys_any: "\\?|", has_keys_all: "\\?&"}
  @key_list_ops [:has_keys_any, :has_keys_all]
  @binary_ops @text_ops |> Map.merge(@jsonb_ops) |> Map.merge(@key_ops)

  @signatures [
                {[:eq, :neq, :gt, :lt, :gte, :lte], :any, :column},
                {[:in, :nin], :any, :column_array},
                {[:is_null], :any, :boolean},
                {Map.keys(@text_ops), :text, :text},
                {Map.keys(@jsonb_ops), :jsonb, :jsonb},
                {[:has_key], :jsonb, :text},
                {@key_list_ops, :jsonb, :text_array}
              ]
              |> Enum.flat_map(fn {ops, lhs, rhs} ->
                Enum.map(ops, &{&1, %{lhs: lhs, rhs: rhs}})
              end)
              |> Map.new()

  @equality [:eq, :neq]
  @ordering [:gt, :lt, :gte, :lte]
  @comparison @equality ++ @ordering
  # One source of truth: every kind Values can cast is a kind this adapter binds.
  @text_kinds Values.text_kinds()
  @bindable Values.scalar_kinds()
  @key_kinds [:integer, :bigint, :text, :citext, :uuid, :enum]
  @transaction_read_only "SELECT current_setting('transaction_read_only')"

  @integer_kinds Column.integer_kinds()

  # The kinds whose same-type `=` is the key's own equality and that carry
  # no collation. Text-family types are left out: their `=` follows the
  # collation the comparison resolves to, which can be the local column's
  # nondeterministic one while the key is unique only under its own (`'a'`
  # then matches both `'A'` and `'a'`), and introspection does not record
  # collations. Unknown kinds (`:decodable`, `:other`) and `json`/`jsonb`
  # are left out too.
  @same_type_kinds [
    :integer,
    :bigint,
    :numeric,
    :float,
    :boolean,
    :uuid,
    :timestamptz,
    :timestamp,
    :date,
    :enum
  ]

  @impl Adapter
  @doc "Whether a join equality preserves a strictly unique target key."
  @spec lossless_join_pair?(Column.t(), Column.t()) :: boolean()
  def lossless_join_pair?(%Column{base_kind: local}, %Column{base_kind: remote})
      when local in @integer_kinds and remote in @integer_kinds,
      do: true

  def lossless_join_pair?(
        %Column{base_kind: kind, pg_type: type, type_schema: schema},
        %Column{base_kind: kind, pg_type: type, type_schema: schema}
      )
      when kind in @same_type_kinds,
      do: true

  def lossless_join_pair?(_local, _remote), do: false

  @impl Adapter
  @doc "Introspects tables and views; see `Authzura.Adapters.Postgres.Introspection.introspect/2`."
  defdelegate introspect(repo, refs), to: Introspection

  @impl Adapter
  @doc "Fingerprints table structure; see `Authzura.Adapters.Postgres.Introspection.fingerprint/2`."
  defdelegate fingerprint(repo, refs), to: Introspection

  @impl Adapter
  @doc """
  Whether `rhs_kind` can be bound against `column`; see
  `Authzura.Adapters.Postgres.Values.bindable/2`.

      iex> alias Authzura.Model.Column
      iex> span = %Column{name: "span", pg_type: "interval", base_kind: :other, ecto_type: :any}
      iex> Authzura.Adapters.Postgres.bindable(:column, span)
      {:error, {:unsupported_type, "interval"}}
      iex> Authzura.Adapters.Postgres.bindable(:text, span)
      :ok
  """
  defdelegate bindable(rhs_kind, column), to: Values

  @impl Adapter
  @doc "Casts an operand; see `Authzura.Adapters.Postgres.Values.cast_value/4`."
  defdelegate cast_value(operand, rhs_kind, column, mode \\ :permission), to: Values

  @impl Adapter
  @doc "Builds one preload level's query; see `Authzura.Adapters.Postgres.PreloadQuery.build/2`."
  defdelegate preload_level_query(node, key_values), to: PreloadQuery, as: :build

  @impl Adapter
  @doc """
  Checks that a statement outside any transaction on `repo` runs read-only
  (`transaction_read_only` is `on`, as on a hot standby or with
  `default_transaction_read_only = on`): `:ok`, or
  `{:error, {:read_only_not_enforced, setting}}`.
  """
  @spec verify_read_only(module()) :: :ok | {:error, term()}
  def verify_read_only(repo) do
    case repo.query(@transaction_read_only) do
      {:ok, %{rows: [["on"]]}} -> :ok
      {:ok, %{rows: [[setting]]}} -> {:error, {:read_only_not_enforced, setting}}
      {:error, _reason} = error -> error
    end
  end

  @impl Adapter
  @doc "Checks an input filter's patterns; see `Authzura.Adapters.Postgres.InputCheck.run/4`."
  defdelegate check_input(repo, ast, opts, telemetry), to: InputCheck, as: :run

  @impl Adapter
  @doc """
  Returns the left- and right-side kinds of `op`, or `:unsupported`.

      iex> Authzura.Adapters.Postgres.operator_signature(:has_key)
      {:ok, %{lhs: :jsonb, rhs: :text}}

      iex> Authzura.Adapters.Postgres.operator_signature(:st_within)
      :unsupported
  """
  @spec operator_signature(term()) ::
          {:ok, %{lhs: Adapter.lhs_kind(), rhs: Adapter.rhs_kind()}} | :unsupported
  def operator_signature(op) when is_map_key(@signatures, op), do: {:ok, @signatures[op]}
  def operator_signature(_op), do: :unsupported

  @impl Adapter
  @doc """
  Whether `column` fits the operator left side `lhs`: `:any` fits every
  column, `:text` fits text, varchar, bpchar and citext, and `:jsonb` fits
  jsonb only.

      iex> alias Authzura.Model.Column
      iex> title = %Column{name: "title", pg_type: "text", base_kind: :text, ecto_type: :string}
      iex> Authzura.Adapters.Postgres.lhs_compatible?(:text, title)
      true
      iex> Authzura.Adapters.Postgres.lhs_compatible?(:jsonb, title)
      false
  """
  @spec lhs_compatible?(Adapter.lhs_kind(), Column.t()) :: boolean()
  def lhs_compatible?(:any, %Column{}), do: true
  def lhs_compatible?(:text, %Column{base_kind: kind}) when kind in @text_kinds, do: true
  def lhs_compatible?(:jsonb, %Column{base_kind: :jsonb}), do: true
  def lhs_compatible?(_lhs, %Column{}), do: false

  @impl Adapter
  @doc """
  Whether an `_eq` or `_in` input comparison on `column` may also run outside
  the input fence: a table (not a view or materialized view), a stored
  column whose pg_catalog equality is `LEAKPROOF` (see
  `Authzura.Model.Column`), compared with an operand bound as a typed
  parameter (see `operand_binding/2`, which `compile_operator/5` uses too).
  """
  @spec index_pushdown?(Table.t(), Column.t()) :: boolean()
  def index_pushdown?(
        %Table{kind: :table},
        %Column{generated?: false, eq_leakproof?: true} = column
      ),
      do: match?({kind, _sql} when kind in [:type, :cast], operand_binding(column, :equality))

  def index_pushdown?(%Table{}, %Column{}), do: false

  @impl Adapter
  @doc """
  Whether `column` can be a relationship key in preload queries (see the
  moduledoc for the accepted kinds).
  """
  @spec supported_key_kind?(Column.t()) :: boolean()
  def supported_key_kind?(%Column{pg_type: "bpchar"}), do: false
  def supported_key_kind?(%Column{base_kind: kind}), do: kind in @key_kinds

  @impl Adapter
  @doc """
  Compiles `lhs op value` into an Ecto dynamic.

  `lhs` is a dynamic for the column (for example
  `dynamic(field(as(^alias), ^name))`), `value` is the result of
  `cast_value/4` for the operator's right side, and `mode` is `:permission`
  or `:input`. See the moduledoc for the NULL rules.
  """
  @spec compile_operator(atom(), Query.dynamic_expr(), term(), Column.t(), Adapter.mode()) ::
          Query.dynamic_expr()
  def compile_operator(:is_null, lhs, true, %Column{}, _mode), do: dynamic(is_nil(^lhs))
  def compile_operator(:is_null, lhs, false, %Column{}, _mode), do: dynamic(not is_nil(^lhs))

  def compile_operator(op, lhs, nil, %Column{nullable?: true}, :permission) when op in @equality,
    do: null_literal(op, lhs)

  def compile_operator(op, _lhs, nil, %Column{}, _mode) when op in @comparison, do: unknown()

  def compile_operator(:in, _lhs, [], %Column{}, _mode), do: dynamic(false)
  def compile_operator(:nin, _lhs, [], %Column{}, _mode), do: dynamic(true)

  def compile_operator(op, lhs, value, %Column{base_kind: :enum, type_schema: nil} = column, mode)
      when op in @equality or op in [:in, :nin],
      do: compile_operator(op, dynamic(fragment("?::text", ^lhs)), value, as_text(column), mode)

  # `:pinned` is `:input` with the equality named by its schema,
  # `OPERATOR(pg_catalog.=)`: an operator the database owner defines on the
  # column or operand type (exact-match, so it would win resolution) can then
  # never be chosen. A `citext` column's equality lives in the extension's
  # schema (`Column.type_schema`); without one `cast_value/4` has refused it.
  def compile_operator(:eq, lhs, value, %Column{} = column, :pinned),
    do: pinned_equality(lhs, param(value, column, :equality), column)

  def compile_operator(:in, lhs, values, %Column{} = column, :pinned) when is_list(values),
    do: pinned_membership(lhs, array_operand(values, column), column)

  def compile_operator(op, lhs, values, %Column{base_kind: kind} = column, _mode)
      when op in [:in, :nin] and kind in @bindable and is_list(values),
      do: lhs |> membership(values, column) |> negate(op == :nin)

  def compile_operator(
        op,
        lhs,
        value,
        %Column{base_kind: kind, nullable?: true} = column,
        :permission
      )
      when op in @equality and kind in @bindable,
      do: null_aware(op, lhs, value, column)

  def compile_operator(op, lhs, value, %Column{base_kind: kind} = column, _mode)
      when op in @equality and kind in @bindable,
      do: compare(op, lhs, param(value, column, :equality))

  def compile_operator(op, lhs, value, %Column{base_kind: kind} = column, _mode)
      when op in @ordering and kind in @bindable,
      do: compare(op, lhs, param(value, column, :ordering))

  def compile_operator(op, lhs, value, %Column{base_kind: kind} = column, _mode)
      when is_map_key(@text_ops, op) and kind in @text_kinds and is_binary(value),
      do: binary_op(op, lhs, param(value, column, :pattern))

  def compile_operator(op, lhs, value, %Column{base_kind: :jsonb}, _mode)
      when is_map_key(@jsonb_ops, op),
      do: binary_op(op, lhs, dynamic(fragment("?::jsonb", ^value)))

  def compile_operator(:has_key, lhs, key, %Column{base_kind: :jsonb}, _mode) when is_binary(key),
    do: binary_op(:has_key, lhs, dynamic(type(^key, :string)))

  def compile_operator(op, lhs, keys, %Column{base_kind: :jsonb}, _mode)
      when op in @key_list_ops and is_list(keys),
      do: binary_op(op, lhs, dynamic(type(^keys, {:array, :string})))

  def compile_operator(op, _lhs, _value, %Column{pg_type: pg_type}, mode) do
    raise ArgumentError,
          "cannot compile #{inspect(op)} on a #{pg_type} column in #{inspect(mode)} mode"
  end

  defp pinned_equality(lhs, rhs, %Column{base_kind: :citext, type_schema: schema}),
    do: dynamic(fragment("? OPERATOR(?.=) ?", ^lhs, identifier(^schema), ^rhs))

  defp pinned_equality(lhs, rhs, %Column{}),
    do: dynamic(fragment("? OPERATOR(pg_catalog.=) ?", ^lhs, ^rhs))

  defp pinned_membership(lhs, array, %Column{base_kind: :citext, type_schema: schema}),
    do: dynamic(fragment("? OPERATOR(?.=) ANY(?)", ^lhs, identifier(^schema), ^array))

  defp pinned_membership(lhs, array, %Column{}),
    do: dynamic(fragment("? OPERATOR(pg_catalog.=) ANY(?)", ^lhs, ^array))

  # SQL NULL comparisons: never false, so `NOT` cannot turn them into true.
  defp unknown, do: dynamic(fragment("NULL::boolean"))

  defp null_literal(:eq, lhs), do: dynamic(is_nil(^lhs) or ^unknown())
  defp null_literal(:neq, lhs), do: dynamic(not is_nil(^lhs) or ^unknown())

  # `v IS NULL` binds the value a second time, as Hasura emits it.
  defp null_aware(op, lhs, value, column),
    do: null_aware_form(op, lhs, param(value, column, :equality), param(value, column, :equality))

  defp null_aware_form(:eq, lhs, rhs, v),
    do: dynamic(^lhs == ^rhs or (is_nil(^lhs) and is_nil(^v)))

  defp null_aware_form(:neq, lhs, rhs, v),
    do: dynamic(^lhs != ^rhs or (not is_nil(^lhs) and is_nil(^v)))

  defp compare(:eq, lhs, rhs), do: dynamic(^lhs == ^rhs)
  defp compare(:neq, lhs, rhs), do: dynamic(^lhs != ^rhs)
  defp compare(:gt, lhs, rhs), do: dynamic(^lhs > ^rhs)
  defp compare(:lt, lhs, rhs), do: dynamic(^lhs < ^rhs)
  defp compare(:gte, lhs, rhs), do: dynamic(^lhs >= ^rhs)
  defp compare(:lte, lhs, rhs), do: dynamic(^lhs <= ^rhs)

  defp negate(condition, true), do: dynamic(not (^condition))
  defp negate(condition, false), do: condition

  # An enum column whose type cannot be quoted, compared as the text it casts to.
  defp as_text(%Column{} = column), do: %{column | base_kind: :text, pg_type: "text"}

  # Membership: one array parameter; Postgres takes its type from the column.
  defp membership(lhs, values, %Column{base_kind: :uuid}),
    do: dynamic(^lhs in type(^values, {:array, UUID}))

  defp membership(lhs, values, %Column{base_kind: :enum, type_schema: schema, pg_type: type}),
    do:
      dynamic(
        fragment("? = ANY(?::?.?[])", ^lhs, ^values, identifier(^schema), identifier(^type))
      )

  defp membership(lhs, values, %Column{}), do: dynamic(^lhs in ^values)

  # The array parameter of a membership test, typed where the column's own
  # type cannot be inferred.
  defp array_operand(values, %Column{base_kind: :uuid}),
    do: dynamic(type(^values, {:array, UUID}))

  defp array_operand(values, %Column{base_kind: :enum, type_schema: schema, pg_type: type}),
    do: dynamic(fragment("?::?.?[]", ^values, identifier(^schema), identifier(^type)))

  defp array_operand(values, %Column{}), do: dynamic(^values)

  # How an operand is bound against a column. Every binding is a typed
  # parameter (an Ecto `type/2`, or a cast of the parameter: both resolved
  # when the statement is prepared), never a cast of the column, so no
  # conversion runs per row. `param/3` binds by it and `index_pushdown?/2`
  # relies on it; `:raw` is an untyped parameter (enum ordering).
  defp operand_binding(%Column{base_kind: kind}, _use) when kind in [:integer, :bigint],
    do: {:type, :integer}

  defp operand_binding(%Column{base_kind: :numeric}, _use), do: {:type, :decimal}
  # real binds as real, as Hasura types the operand: a float8 parameter
  # would widen the column instead, and 0.1::real is not 0.1.
  defp operand_binding(%Column{pg_type: "float4"}, _use), do: {:cast, "real"}
  defp operand_binding(%Column{base_kind: :float}, _use), do: {:type, :float}
  defp operand_binding(%Column{base_kind: :boolean}, _use), do: {:type, :boolean}
  # bpchar binds as bpchar so `=`, `<` and `_in` all use its padding rules.
  defp operand_binding(%Column{pg_type: "bpchar"}, use) when use != :pattern,
    do: {:cast, "bpchar"}

  defp operand_binding(%Column{base_kind: :text}, _use), do: {:type, :string}
  defp operand_binding(%Column{base_kind: :citext}, _use), do: {:cast, "citext"}
  defp operand_binding(%Column{base_kind: :uuid}, _use), do: {:type, UUID}
  defp operand_binding(%Column{base_kind: :timestamptz}, _use), do: {:cast, "timestamptz"}
  defp operand_binding(%Column{base_kind: :timestamp}, _use), do: {:cast, "timestamp"}
  defp operand_binding(%Column{base_kind: :date}, _use), do: {:type, :date}
  defp operand_binding(%Column{base_kind: :jsonb}, _use), do: {:cast, "jsonb"}

  defp operand_binding(%Column{base_kind: :enum, type_schema: schema, pg_type: type}, :equality),
    do: {:enum, schema, type}

  defp operand_binding(%Column{base_kind: :enum}, :ordering), do: :raw

  defp param(value, %Column{} = column, use), do: bind(value, operand_binding(column, use))

  defp bind(value, {:type, type}), do: dynamic(type(^value, ^type))
  defp bind(value, :raw), do: dynamic(^value)

  defp bind(value, {:enum, schema, type}),
    do: dynamic(fragment("?::?.?", ^value, identifier(^schema), identifier(^type)))

  for sql <- ~w(real bpchar citext timestamptz timestamp jsonb) do
    defp bind(value, {:cast, unquote(sql)}),
      do: dynamic(fragment(unquote("?::#{sql}"), ^value))
  end

  for {op, sql} <- @binary_ops do
    defp binary_op(unquote(op), lhs, rhs),
      do: dynamic(fragment(unquote("? #{sql} ?"), ^lhs, ^rhs))
  end
end

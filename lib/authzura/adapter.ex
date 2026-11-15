defmodule Authzura.Adapter do
  @moduledoc """
  Behaviour for the database-specific half of Authzura.

  Everything that talks SQL dialect lives behind this behaviour. Stage one
  ships a single implementation, `Authzura.Adapters.Postgres`.
  """

  alias Authzura.AST
  alias Authzura.Model.{Column, Table}
  alias Authzura.Preload.Tree
  alias Ecto.Query

  @typedoc "A foreign key read from the catalog, with columns paired by position."
  @type fk :: %{
          table: Table.table_ref(),
          columns: [String.t()],
          ref_table: Table.table_ref(),
          ref_columns: [String.t()]
        }

  @doc """
  Introspects the given tables and views.

  Returns the tables keyed by `{schema, name}` plus the foreign keys declared
  on them.
  """
  @callback introspect(repo :: module(), [Table.table_ref()]) ::
              {:ok, %{Table.table_ref() => Table.t()}, [fk()]} | {:error, term()}

  @doc """
  Returns a fingerprint of the structure (columns, types, nullability and
  constraints) of the given tables. It changes whenever that structure does.
  """
  @callback fingerprint(repo :: module(), [Table.table_ref()]) ::
              {:ok, binary()} | {:error, term()}

  @typedoc "What an operator's left side must be: any column, a text column or a jsonb column."
  @type lhs_kind :: :any | :text | :jsonb

  @typedoc "The type an operator's right side is cast to."
  @type rhs_kind :: :column | :column_array | :boolean | :text | :text_array | :jsonb

  @typedoc "A filter operand: a decoded literal or raw session-variable text."
  @type operand :: {:literal, term()} | {:session, String.t()}

  @typedoc "Whether a comparison follows permission-filter or user-input semantics. `:pinned` is `:input` for a comparison that also runs outside the input fence (`input_index_pushdown`, `get/4`'s key equality): it must name its equality operator by schema (`OPERATOR(pg_catalog.=)`, or the extension's schema for `citext`), so an operator the database owner defines can never be chosen."
  @type mode :: :permission | :input | :pinned

  @doc """
  Returns the left- and right-side kinds of an operator, or `:unsupported`
  for an operator the adapter does not compile.
  """
  @callback operator_signature(op :: term()) ::
              {:ok, %{lhs: lhs_kind(), rhs: rhs_kind()}} | :unsupported

  @doc """
  Casts an operand for a right side of `rhs_kind` against a column. Never
  raises on bad values. `mode` says whose text a literal is: a permission's
  (`:permission`, policy text Hasura would send to the database) or a
  caller's (`:input`). A session value is always policy text.
  """
  @callback cast_value(operand(), rhs_kind(), Column.t(), mode()) ::
              {:ok, term()} | {:error, term()}

  @doc """
  Compiles one comparison into an Ecto dynamic. `rhs_value` has already been
  cast by `c:cast_value/4`.
  """
  @callback compile_operator(
              op :: atom(),
              lhs :: Query.dynamic_expr(),
              rhs_value :: term(),
              Column.t(),
              mode()
            ) :: Query.dynamic_expr()

  @doc """
  Whether `column` fits an operator's left side (`lhs` from
  `c:operator_signature/1`). Load-time parsing denies a mismatch, so
  `c:compile_operator/5` never sees one.
  """
  @callback lhs_compatible?(lhs_kind(), Column.t()) :: boolean()

  @doc """
  Whether a right side of `rhs_kind` can be bound against `column` at all,
  whatever the value. `c:cast_value/4` refuses anything that is not, and
  load-time validation uses this to type-check session references.
  """
  @callback bindable(rhs_kind(), Column.t()) :: :ok | {:error, {:unsupported_type, String.t()}}

  @doc """
  Checks an untrusted input filter's literals that only the database can
  judge (a regular expression, say) with a statement that reads no table,
  before the read that uses them. A literal it refuses is
  `{:error, {:invalid_input, {:invalid_pattern, column}}}`, so the read
  itself can never fail on a value, whichever rows it evaluates. Inside a
  transaction the check must not abort it. `repo_opts` may carry
  `:statement_timeout` (milliseconds, given only inside a transaction the
  executor opened): the check then also sets it as the transaction-local
  statement timeout, in the same statement, for the read that follows.
  It is never passed on to the repo. `telemetry` is the metadata
  (`:instance`, `:table`) of the `[:authzura, :query]` span the statement
  runs in.
  """
  @callback check_input(
              repo :: module(),
              AST.t(),
              repo_opts :: keyword(),
              telemetry :: map()
            ) ::
              :ok | {:error, {:invalid_input, {:invalid_pattern, String.t()}}}

  @doc """
  Builds the query that loads one preload level for every parent at once.
  The node carries the target table, its key columns in mapping order
  (`key_columns`) and its compiled row filter (`condition`); `key_values`
  holds one list of key values per key tuple to load (the loader sends each
  distinct tuple once).
  Each result row is a map of column names to values plus `:idx` (the key
  tuple's 1-based position), ordered by position and then by rank.
  """
  @callback preload_level_query(Tree.preload_node(), key_values :: [[term()]]) ::
              {:ok, Query.t()} | {:error, term()}

  @doc """
  Checks that `repo`'s connections are read-only by themselves (for
  `read_only: :connection`): `:ok`, or
  `{:error, {:read_only_not_enforced, setting}}`.
  """
  @callback verify_read_only(repo :: module()) ::
              :ok | {:error, {:read_only_not_enforced, term()} | term()}

  @doc """
  Whether an AND-ed `_eq` or `_in` input comparison on `column` of `table`
  may also run outside the input fence (`input_index_pushdown`).

  Return `true` only when the table is a plain table, the column is stored
  (not generated), the comparison the database will resolve can neither
  fail nor reveal its operand (for Postgres: a `LEAKPROOF` equality, named
  by schema), and the value is bound as the column's own type with no
  per-row conversion. A wrong `true` lets user input run on rows the role
  cannot see.

  Optional: an adapter without it pushes nothing down.
  """
  @callback index_pushdown?(Table.t(), Column.t()) :: boolean()

  @doc """
  Whether equality between these columns preserves the target key's uniqueness.
  Return true only when coercion and collation cannot make one local value
  match distinct target keys. Optional: an adapter without it lifts no joins.
  """
  @callback lossless_join_pair?(Column.t(), Column.t()) :: boolean()

  @optional_callbacks index_pushdown?: 2, lossless_join_pair?: 2

  @doc "Whether a column can be a relationship key in preload queries."
  @callback supported_key_kind?(Column.t()) :: boolean()
end

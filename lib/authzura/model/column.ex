defmodule Authzura.Model.Column do
  @moduledoc """
  A column of a tracked table or view, as introspected from the database.

  `base_kind` is the comparison family the column belongs to, of its type
  resolved through domains (`pg_type` is then the base type's name).
  `varchar`, `bpchar` and `char` are `:text`, `smallint` is `:integer`, and
  `real` and `double precision` are `:float`. A type Authzura cannot compare
  faithfully is `:decodable` when the data repo's Postgrex types decode it
  (`bytea`, `interval`, `inet`, `time`, `point`, ranges, ...; and an
  extension type such as PostGIS `geography` when the repo's types module
  has the extension, which introspection asks the module about), and `:other` otherwise: an
  extension type the repo cannot decode, a composite, or an array of
  either. `:other` columns are left out of default selects.

  `type_schema` is the schema of an enum column's type, so comparisons can
  cast to the schema-qualified enum type (`pg_type` is its unqualified
  name). For a `citext` column it is the `citext` extension's schema, where
  its `=` lives. It is `nil` for every other column, for an enum whose schema
  or type name contains a double quote (which Ecto cannot quote as an
  identifier; such enums compare as text), and for a `citext` type outside
  the extension's schema or whose schema has one.

  `element_kind` is the base kind of an `:array` column's element (`nil`
  for every other column), so an array is orderable only when its element
  is.

  `generated?` is true for a stored or virtual generated column.
  `eq_leakproof?` is true when every `=` operator Postgres can resolve for
  the column's base type (against itself, or against `bigint`, which is how
  integer operands bind) is marked `LEAKPROOF` in `pg_proc`: it can neither
  raise nor reveal its operands, which is Postgres' own condition for
  running a qual ahead of a security barrier. `Authzura.Adapters.Postgres`
  uses both to decide what `input_index_pushdown` may hoist.
  """

  @enforce_keys [:name, :pg_type, :base_kind, :ecto_type]
  defstruct [
    :name,
    :pg_type,
    :base_kind,
    :ecto_type,
    enum_labels: nil,
    type_schema: nil,
    element_kind: nil,
    nullable?: true,
    generated?: false,
    eq_leakproof?: false
  ]

  @type base_kind ::
          :integer
          | :bigint
          | :numeric
          | :float
          | :boolean
          | :text
          | :citext
          | :uuid
          | :timestamptz
          | :timestamp
          | :date
          | :jsonb
          | :json
          | :enum
          | :array
          | :decodable
          | :other

  @type t :: %__MODULE__{
          name: String.t(),
          pg_type: String.t(),
          base_kind: base_kind(),
          ecto_type: atom() | {:array, atom()},
          enum_labels: [String.t()] | nil,
          type_schema: String.t() | nil,
          element_kind: base_kind() | nil,
          nullable?: boolean(),
          generated?: boolean(),
          eq_leakproof?: boolean()
        }

  @integer_kinds [:integer, :bigint]

  @doc "The integer base kinds (`smallint`, `integer` and `bigint` columns)."
  @spec integer_kinds() :: [base_kind()]
  def integer_kinds, do: @integer_kinds
end

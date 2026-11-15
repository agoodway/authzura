defmodule Authzura.Parity.Read do
  @moduledoc """
  One read, described once and run both through Hasura GraphQL and through
  Authzura by `Authzura.Parity.Runner`.

  A root read names its `table`; a nested read (an entry of
  `relationships`) names the relationship instead and inherits nothing but
  the session. Fields:

    * `table` - `{schema, name}` of the root. Its GraphQL root field is
      `name` for `public` and `schema_name` otherwise (Hasura's default)
    * `columns` - the selected columns, as strings
    * `where` - a Hasura `bool_exp` for the caller's filter. A root read
      with `where` goes through `Authzura.all_input/4` (untrusted input,
      like a GraphQL `where`), so its table must be in `public`; every other
      read goes through `Authzura.all/3`
    * `order_by` - Ecto's keyword form, `[asc: :id]`
    * `limit` - the caller's limit (root only)
    * `offset` - the caller's offset (root only). Authzura has no
      per-relationship limit or offset, so neither is ever nested
    * `relationships` - `[{name, %Read{}}]`, the nested selections. They
      become GraphQL nested fields and Authzura `preload:` entries
    * `sample` - `{target_table, %{parent_column => child_column}}` for a
      nested array relationship whose target has a permission limit and no
      `order_by`. Both sides may keep different rows, so each side is
      checked on its own: every child must be a row of `target_table`
      (read by Hasura's admin) and must belong to its parent through the
      mapping (so both columns must be selected); then the two sides are
      compared by per-parent cardinality

  Build one with `new/1` or `nested/1`.
  """

  @enforce_keys [:columns]
  defstruct table: nil,
            columns: [],
            where: nil,
            order_by: nil,
            limit: nil,
            offset: nil,
            relationships: [],
            sample: nil

  @type t :: %__MODULE__{
          table: {String.t(), String.t()} | nil,
          columns: [String.t()],
          where: map() | nil,
          order_by: keyword(atom()) | nil,
          limit: non_neg_integer() | nil,
          offset: non_neg_integer() | nil,
          relationships: [{String.t(), t()}],
          sample: {{String.t(), String.t()}, %{String.t() => String.t()}} | nil
        }

  @doc "A root read on `{schema, name}`; `fields` are the struct's other keys."
  @spec new({String.t(), String.t()}, keyword()) :: t()
  def new({schema, name} = table, fields) when is_binary(schema) and is_binary(name),
    do: struct!(__MODULE__, [{:table, table} | fields])

  @doc "A nested read for `relationships`."
  @spec nested(keyword()) :: t()
  def nested(fields), do: struct!(__MODULE__, fields)

  @doc "The GraphQL root field (and type name) of `table`."
  @spec root_field({String.t(), String.t()}) :: String.t()
  def root_field({"public", name}), do: name
  def root_field({schema, name}), do: "#{schema}_#{name}"
end

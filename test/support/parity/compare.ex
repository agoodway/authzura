defmodule Authzura.Parity.Compare do
  @moduledoc """
  Normalizes Hasura and Authzura results into one comparable shape, checks
  sampled relationships, and decides when two errors are equivalent.

  ## Values, by declared column type

  `value/2` canonicalizes one value by its column's `base_kind`, as
  Authzura introspected it (`Authzura.Model.Column`), never by sniffing
  the value. Each kind accepts exactly the shapes the two sides return for
  it, and anything else becomes `{:type_mismatch, kind, value}`, which
  never equals a well-typed value:

    * `:integer`, `:bigint`, `:numeric`, `:float` - an integer, float or
      `Decimal` becomes `{:number, normalized_decimal_string}`
    * `:uuid` - a 16-byte binary (Authzura) or a 36-character string
      (Hasura) becomes the lowercase string
    * `:timestamptz` - a `DateTime` or an ISO-8601 string with an offset
      becomes `{:timestamp, unix_microseconds}`; `:timestamp` is the same
      with `NaiveDateTime`s and strings without an offset (microseconds
      since year 0, whatever the precision; a string with an offset is a
      mismatch); `:date` likewise
    * `:jsonb`, `:json`, `:array` - decoded JSON with every number
      canonicalized as above
    * `:boolean` - a boolean; text-like kinds (`:text`, `:citext`, `:enum`) -
      a string; `:other` - kept as is

  ## Rows

  `normalize/3` canonicalizes a result for an `Authzura.Parity.Read`
  against the instance's tables (`%{{schema, name} => %Table{}}`), walking
  relationships to their targets. A row must hold exactly the read's
  columns and relationships: a missing key becomes `:missing`, an
  unexpected one is kept under `:unexpected`, so either fails the
  comparison. Rows of a read without `order_by` are sorted (by `"id"` when
  selected, else by the whole row) so they compare as sets; ordered reads
  keep their order. A sampled relationship (see `Authzura.Parity.Read`)
  becomes `{:sample, count}`.

  `check_samples/4` is the other half of a sample: it returns
  `{:error, strays}` with every sampled child that is not a row of the
  target table, or that does not belong to its parent through the
  mapping.

  ## Errors

  `equivalent?/2` pairs a Hasura `extensions.code` with an Authzura
  reason. The pairing is deliberately coarse: one Hasura code covers
  several Authzura reasons (`validation-failed` is what Hasura answers for
  any field missing from a role's schema), so tests pin the exact reason
  themselves.

  | Hasura code | Authzura reason |
  |---|---|
  | `not-found` | `{:missing_session_variable, _}` |
  | `validation-failed` | `{:forbidden_columns, _}`, `:forbidden`, `:root_field_disabled` |
  | `access-denied` | `{:invalid_session, :role_not_allowed, _}` |
  | `data-exception` | `{:invalid_session_value, _, _}` |
  | `invalid-jwt` | `{:invalid_jwt, _}` |
  | `jwt-missing-role-claims` | `{:jwt_missing_role_claims, _}` |
  | `jwt-invalid-claims` | `{:jwt_invalid_claims, _}` |
  """

  alias Authzura.Model.{Column, Relationship, Table}
  alias Authzura.Parity.Read
  alias Ecto.UUID

  @type tables :: %{{String.t(), String.t()} => Table.t()}
  @numbers [:integer, :bigint, :numeric, :float]
  @texts [:text, :citext, :enum]
  @documents [:jsonb, :json, :array]

  @doc "Whether Hasura's error `code` and Authzura's `reason` mean the same failure."
  @spec equivalent?(String.t(), term()) :: boolean()
  def equivalent?("not-found", {:missing_session_variable, _name}), do: true
  def equivalent?("validation-failed", {:forbidden_columns, _columns}), do: true
  def equivalent?("validation-failed", :forbidden), do: true
  def equivalent?("validation-failed", :root_field_disabled), do: true
  def equivalent?("access-denied", {:invalid_session, :role_not_allowed, _role}), do: true
  def equivalent?("data-exception", {:invalid_session_value, _name, _reason}), do: true
  def equivalent?("invalid-jwt", {:invalid_jwt, _reason}), do: true
  def equivalent?("jwt-missing-role-claims", {:jwt_missing_role_claims, _claim}), do: true
  def equivalent?("jwt-invalid-claims", {:jwt_invalid_claims, _reason}), do: true
  def equivalent?(_code, _reason), do: false

  @doc "Canonical rows of `rows`, a result of the root `read`, against `tables`."
  @spec normalize([map()], Read.t(), tables()) :: [term()]
  def normalize(rows, %Read{table: ref} = read, tables) when is_list(rows),
    do: rows(rows, read, Map.fetch!(tables, ref), tables)

  @doc """
  `:ok` when every sampled child in `rows` is a row of its target table (as
  `members` returns it for the sampled read) and belongs to its parent;
  otherwise `{:error, strays}`.
  """
  @spec check_samples([map()], Read.t(), tables(), (Read.t() -> [map()])) ::
          :ok | {:error, [map()]}
  def check_samples(rows, %Read{table: ref} = read, tables, members) do
    case strays(rows, read, Map.fetch!(tables, ref), tables, members) do
      [] -> :ok
      strays -> {:error, strays}
    end
  end

  @doc "The canonical form of `value` for a column of `kind` (see the moduledoc)."
  @spec value(term(), Column.base_kind()) :: term()
  def value(nil, _kind), do: nil
  def value(value, kind) when kind in @numbers, do: number(value, kind)
  def value(<<_::binary-16>> = value, :uuid), do: UUID.load!(value)
  def value(<<_::binary-36>> = value, :uuid), do: uuid_string(UUID.cast(value), value)

  def value(%DateTime{} = value, :timestamptz),
    do: {:timestamp, DateTime.to_unix(value, :microsecond)}

  def value(value, :timestamptz) when is_binary(value),
    do: parsed(DateTime.from_iso8601(value), value, :timestamptz)

  def value(%NaiveDateTime{} = value, :timestamp), do: {:timestamp, naive(value)}

  # `NaiveDateTime.from_iso8601/1` drops an offset; a `timestamp` never
  # carries one, so a string with an offset is a mismatch.
  def value(value, :timestamp) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, _datetime, _offset} -> mismatch(:timestamp, value)
      {:error, _reason} -> parsed(NaiveDateTime.from_iso8601(value), value, :timestamp)
    end
  end

  def value(%Date{} = value, :date), do: {:date, Date.to_iso8601(value)}

  def value(value, :date) when is_binary(value),
    do: parsed(Date.from_iso8601(value), value, :date)

  def value(value, kind) when kind in @documents, do: document(value)
  def value(value, :boolean) when is_boolean(value), do: value
  def value(value, kind) when kind in @texts and is_binary(value), do: value
  def value(value, :other), do: value
  def value(value, kind), do: mismatch(kind, value)

  defp number(value, _kind) when is_integer(value), do: decimal(Decimal.new(value))
  defp number(value, _kind) when is_float(value), do: decimal(Decimal.from_float(value))
  defp number(%Decimal{} = value, _kind), do: decimal(value)
  defp number(value, kind), do: mismatch(kind, value)

  defp decimal(decimal),
    do: {:number, decimal |> Decimal.normalize() |> Decimal.to_string(:normal)}

  defp uuid_string({:ok, uuid}, _value), do: String.downcase(uuid)
  defp uuid_string(:error, value), do: mismatch(:uuid, value)

  defp parsed({:ok, %DateTime{} = datetime, _offset}, _value, :timestamptz),
    do: value(datetime, :timestamptz)

  defp parsed({:ok, %NaiveDateTime{} = datetime}, _value, :timestamp),
    do: value(datetime, :timestamp)

  defp parsed({:ok, %Date{} = date}, _value, :date), do: value(date, :date)
  defp parsed(_error, value, kind), do: mismatch(kind, value)

  # Microseconds since year 0, whatever the value's precision: Postgres
  # sends `.000000` where Hasura's JSON drops the fraction.
  defp naive(datetime) do
    {seconds, microseconds} = NaiveDateTime.to_gregorian_seconds(datetime)
    seconds * 1_000_000 + microseconds
  end

  defp mismatch(kind, value), do: {:type_mismatch, kind, value}

  defp document(value) when is_number(value), do: number(value, :jsonb)
  defp document(value) when is_map(value), do: Map.new(value, fn {k, v} -> {k, document(v)} end)
  defp document(value) when is_list(value), do: Enum.map(value, &document/1)
  defp document(value), do: value

  defp rows(rows, read, table, tables) do
    rows
    |> Enum.map(&row(&1, read, table, tables))
    |> order(read)
  end

  defp row(row, %Read{columns: columns, relationships: relationships}, table, tables)
       when is_map(row) do
    expected = columns ++ Enum.map(relationships, &elem(&1, 0))

    columns
    |> Map.new(&{&1, column(row, &1, table)})
    |> Map.merge(Map.new(relationships, &relationship(row, &1, table, tables)))
    |> put_unexpected(Map.drop(row, expected))
  end

  defp column(row, name, %Table{columns: columns}) do
    case Map.fetch(row, name) do
      {:ok, raw} -> value(raw, Map.fetch!(columns, name).base_kind)
      :error -> :missing
    end
  end

  defp relationship(row, {name, read}, table, tables) do
    case Map.fetch(row, name) do
      {:ok, raw} -> {name, related(raw, read, target(table, name, tables), tables)}
      :error -> {name, :missing}
    end
  end

  defp put_unexpected(row, unexpected) when map_size(unexpected) == 0, do: row
  defp put_unexpected(row, unexpected), do: Map.put(row, :unexpected, unexpected)

  defp target(%Table{relationships: relationships}, name, tables) do
    %Relationship{target: target} = Map.fetch!(relationships, name)
    Map.fetch!(tables, target)
  end

  defp related(nil, _read, _table, _tables), do: nil
  defp related(%{} = object, read, table, tables), do: row(object, read, table, tables)

  defp related(rows, %Read{sample: nil} = read, table, tables) when is_list(rows),
    do: rows(rows, read, table, tables)

  defp related(rows, %Read{}, _table, _tables) when is_list(rows), do: {:sample, length(rows)}

  defp order(rows, %Read{order_by: nil}), do: Enum.sort_by(rows, &sort_key/1)
  defp order(rows, %Read{}), do: rows

  defp sort_key(%{"id" => id} = row), do: {0, id, row}
  defp sort_key(row), do: {1, row}

  defp strays(rows, %Read{relationships: relationships}, table, tables, members) do
    for parent <- rows,
        {name, read} <- relationships,
        children = Map.get(parent, name),
        children != nil,
        stray <-
          children_strays(parent, children, read, target(table, name, tables), tables, members),
        do: stray
  end

  defp children_strays(_parent, %{} = child, read, table, tables, members),
    do: strays([child], read, table, tables, members)

  defp children_strays(_parent, children, %Read{sample: nil} = read, table, tables, members),
    do: strays(children, read, table, tables, members)

  defp children_strays(
         parent,
         children,
         %Read{sample: {_ref, mapping}} = read,
         table,
         tables,
         members
       ) do
    known = read |> members.() |> MapSet.new(&row(&1, read, table, tables))

    Enum.reject(children, fn child ->
      MapSet.member?(known, row(child, read, table, tables)) and linked?(parent, child, mapping)
    end)
  end

  # Mapped columns of a parent and its child share a type, so raw equality
  # within one side is enough.
  defp linked?(parent, child, mapping),
    do: Enum.all?(mapping, fn {from, to} -> Map.fetch!(parent, from) == Map.fetch!(child, to) end)
end

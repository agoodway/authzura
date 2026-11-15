defmodule Authzura.Adapters.Postgres.Values do
  @moduledoc """
  Casts filter operands to the Elixir values bound as typed Postgres
  parameters, and parses Postgres array literals.

  Operands are tagged:

    * `{:literal, term}` is an already-decoded JSON value from metadata or
      input. It is never JSON-decoded again, so a string literal stays a
      string even when compared against jsonb.
    * `{:session, raw}` is session-variable text, parsed for the right side.
      jsonb is `Jason.decode/1`d and arrays go through
      `parse_array_literal/1`.

  Casting is strict and never raises. A value that does not parse is
  `{:error, {:invalid_value, type}}`, where `type` is the column's
  `pg_type` for a `:column` or `:column_array` right side, and `"text"`,
  `"bool"` or `"jsonb"` for the fixed right sides. A column kind Authzura
  cannot bind faithfully is `{:error, {:unsupported_type, pg_type}}`.

  Per kind:

    * `:integer`, `:bigint` - integers in the bigint range. Session text
      matches `-?[0-9]+` (an optional `+` is accepted), nothing else.
    * `:numeric` - a finite `Decimal`. `NaN` and infinities are refused.
    * `:float` - a float. Literal integers are widened when they fit.
    * `:boolean` - `true t yes y 1` and `false f no n 0`, case-insensitively.
    * `:uuid` - validated and canonicalized (lowercase, hyphenated). Raw
      16-byte binaries are refused.
    * `:timestamptz` - the forms Postgres (and so Hasura) accepts: ISO-8601
      (`2026-01-01T10:00:00+02:00`), the space-separated
      `2026-01-01 10:00:00[.ffffff]`, or a bare date `2026-01-01` (its
      midnight), each with or without an offset. A missing offset is read
      as UTC. At most six fractional digits are accepted (Postgres would
      round a seventh). The result is a UTC `DateTime`, no earlier than
      Postgres's 4714-11-24 00:00:00 UTC BC.
    * `:timestamp` - the same forms, as a `NaiveDateTime`. A valid offset is
      ignored, as Postgres ignores it for `timestamp`.
    * `:date` - `YYYY-MM-DD` only, as a `Date`.
      Dates and timestamps are no earlier than 4714-11-24 BC.
    * `:text`, `:citext` - passed through unchanged and never truncated, but
      NUL bytes and invalid UTF-8 are refused (also for enum labels).
    * `:enum` - must be one of the column's introspected `enum_labels`.
    * `:jsonb` - any JSON value except a top-level `null`. Strings and keys
      must be valid UTF-8 without NUL (`\\u0000`), and literals must be JSON
      terms (string keys, no atoms or tuples). Integers must stay under
      2^435000, so jsonb's numeric can hold them.

  An array (`:column_array`) is bound with the column's own element type,
  so each element must also fit that type: `int2` and `int4` elements
  their ranges, and `real` (`float4`) elements a value that neither
  overflows nor underflows to zero. Anything else is
  `{:invalid_value, pg_type}`, never an encoding error at execution.

  A `nil` literal is allowed only for a `:column` right side, where the
  compiler gives it Hasura's SQL `NULL` semantics. It is refused inside
  arrays and for every other right side.
  """

  import Authzura.Util, only: [is_plain_map: 1]

  alias Authzura.{Adapter, Util}
  alias Authzura.Model.Column
  alias Ecto.UUID

  @type reason ::
          {:invalid_value, String.t()} | {:unsupported_type, String.t()} | :invalid_array_literal

  @bigint_range -9_223_372_036_854_775_808..9_223_372_036_854_775_807
  @type_ranges %{
    "int2" => -32_768..32_767,
    "int4" => -2_147_483_648..2_147_483_647
  }
  # The earliest `timestamptz` Postgres holds: 4714-11-24 00:00:00 UTC BC
  # (astronomical year -4713). ISO-8601 years never reach its upper bound.
  @min_date Date.new!(-4713, 11, 24)
  # A seconds field with seven or more fractional digits.
  @sub_microsecond ~r/:\d{2}[.,]\d{7}/
  @min_timestamp NaiveDateTime.new!(@min_date, ~T[00:00:00])
  @min_timestamptz DateTime.from_naive!(@min_timestamp, "Etc/UTC")
  # jsonb holds numbers with at most 131072 digits before the point; every
  # integer under 2^435000 has fewer (435000 * log10(2) < 130948).
  @max_json_integer_bits 435_000
  @integer_kinds Column.integer_kinds()
  @string_kinds [:text, :citext]
  @scalar_kinds @integer_kinds ++
                  @string_kinds ++
                  [
                    :numeric,
                    :float,
                    :boolean,
                    :uuid,
                    :timestamptz,
                    :timestamp,
                    :date,
                    :enum,
                    :jsonb
                  ]
  @max_float_integer trunc(1.797_693_134_862_315_7e308)
  @truthy ~w(true t yes y 1)
  @falsy ~w(false f no n 0)
  # Postgres's array_isspace/1.
  @whitespace [?\s, ?\t, ?\n, ?\r, ?\v, ?\f]

  @doc "The column base kinds `cast_value/4` can cast (and the adapter can bind)."
  @spec scalar_kinds() :: [Column.base_kind()]
  def scalar_kinds, do: @scalar_kinds

  @doc "The column base kinds that compare as text (the `:text` left side)."
  @spec text_kinds() :: [Column.base_kind()]
  def text_kinds, do: @string_kinds

  @doc """
  Whether a right side of `rhs_kind` can be bound against `column` at all,
  whatever the value. The fixed right sides (`:boolean`, `:text`,
  `:text_array`, `:jsonb`) always can; `:column` and `:column_array` need a
  column kind in `scalar_kinds/0`.
  """
  @spec bindable(Adapter.rhs_kind(), Column.t()) ::
          :ok | {:error, {:unsupported_type, String.t()}}
  def bindable(rhs_kind, %Column{base_kind: kind})
      when rhs_kind in [:column, :column_array] and kind in @scalar_kinds,
      do: :ok

  def bindable(rhs_kind, %Column{}) when rhs_kind in [:boolean, :text, :text_array, :jsonb],
    do: :ok

  def bindable(_rhs_kind, %Column{pg_type: pg_type}), do: {:error, {:unsupported_type, pg_type}}

  @doc """
  Casts `operand` for the operator right side `rhs_kind` against `column`.
  A right side that is not `bindable/2` is refused before the value is read.

  Used at load time for literals and at request time for session values.
  """
  @spec cast_value(Adapter.operand(), Adapter.rhs_kind(), Column.t(), Adapter.mode()) ::
          {:ok, term()} | {:error, reason()}
  def cast_value(operand, rhs_kind, column, mode \\ :permission)

  # A pinned `citext` comparison names the extension's schema; with none
  # resolved it is refused rather than left to the `search_path`.
  def cast_value(_operand, :column, %Column{base_kind: :citext, type_schema: nil}, :pinned),
    do: {:error, {:unsupported_type, "citext"}}

  def cast_value(operand, rhs_kind, %Column{} = column, mode) do
    with :ok <- bindable(rhs_kind, column), do: cast(operand, rhs_kind, column, mode)
  end

  defp cast({:literal, nil}, :column, %Column{}, _mode), do: {:ok, nil}

  defp cast(operand, :column, %Column{} = column, mode), do: cast_column(operand, column, mode)

  defp cast(operand, :column_array, %Column{pg_type: pg_type} = column, mode),
    do: cast_list(operand, pg_type, &cast_column(&1, column, mode))

  defp cast(operand, :boolean, %Column{}, _mode),
    do: operand |> scalar(:boolean, nil) |> result("bool")

  defp cast(operand, :text, %Column{}, _mode),
    do: operand |> scalar(:text, nil) |> result("text")

  defp cast(operand, :text_array, %Column{} = column, mode),
    do: cast_list(operand, "text", &cast(&1, :text, column, mode))

  defp cast(operand, :jsonb, %Column{}, _mode),
    do: operand |> scalar(:jsonb, nil) |> result("jsonb")

  @doc """
  Parses a one-dimensional
  Postgres array literal into its element strings.

  Handles `{}`, double-quoted elements, backslash escapes, commas inside
  quotes, and whitespace around unquoted elements. Unquoted `NULL`, empty
  elements and nested arrays are refused.
  """
  @spec parse_array_literal(String.t()) :: {:ok, [String.t()]} | {:error, :invalid_array_literal}
  def parse_array_literal(text) when is_binary(text) do
    with "{" <> body <- trim(text),
         {:ok, elements} <- body |> skip_ws() |> open() do
      {:ok, elements}
    else
      _invalid -> {:error, :invalid_array_literal}
    end
  end

  def parse_array_literal(_text), do: {:error, :invalid_array_literal}

  # Policy text (a session value, or a literal in a permission) for a
  # timestamptz must carry its offset: Postgres would read it in a TimeZone
  # Authzura cannot know.
  defp cast_column({:session, s}, %Column{base_kind: :timestamptz, pg_type: pg_type}, _mode)
       when is_binary(s),
       do: s |> zoned() |> result(pg_type)

  defp cast_column({:literal, s}, %Column{base_kind: :timestamptz, pg_type: pg_type}, :permission)
       when is_binary(s),
       do: s |> zoned() |> result(pg_type)

  # Each operand, scalar or array element, must fit the column's own type,
  # not just the kind's, since Postgres types it as the column.
  defp cast_column(operand, %Column{base_kind: kind, pg_type: pg_type} = column, _mode),
    do: operand |> scalar(kind, column) |> fitting(pg_type) |> result(pg_type)

  defp fitting({:ok, value}, pg_type), do: value |> fits?(pg_type) |> checked(value)
  defp fitting(error, _pg_type), do: error

  defp fits?(n, pg_type) when is_map_key(@type_ranges, pg_type),
    do: n in Map.fetch!(@type_ranges, pg_type)

  defp fits?(f, "float4"), do: float4?(f)
  defp fits?(_value, _pg_type), do: true

  # A float a `real` holds: not out of range (Erlang encodes it as
  # infinity) and not a nonzero value that underflows to zero, both of
  # which Postgres refuses for `real` text input.
  defp float4?(f) do
    case <<f::float-32>> do
      <<narrowed::float-32>> -> narrowed != 0.0 or f == 0.0
      _infinity -> false
    end
  end

  # Scalar parsing: {:ok, value} or :error.

  defp scalar({:literal, n}, kind, _column)
       when kind in @integer_kinds and is_integer(n) and n in @bigint_range,
       do: {:ok, n}

  defp scalar({:session, raw}, kind, _column) when kind in @integer_kinds and is_binary(raw) do
    with {n, ""} when n in @bigint_range <- Integer.parse(raw), do: {:ok, n}
  end

  defp scalar({:literal, n}, :numeric, _column) when is_integer(n), do: {:ok, Decimal.new(n)}
  defp scalar({:literal, f}, :numeric, _column) when is_float(f), do: {:ok, Decimal.from_float(f)}

  defp scalar({:session, raw}, :numeric, _column) when is_binary(raw) do
    with {%Decimal{coef: coef} = d, ""} when is_integer(coef) <- Decimal.parse(raw), do: {:ok, d}
  end

  defp scalar({:literal, f}, :float, _column) when is_float(f), do: {:ok, f}

  defp scalar({:literal, n}, :float, _column)
       when is_integer(n) and abs(n) <= @max_float_integer,
       do: {:ok, n * 1.0}

  defp scalar({:session, raw}, :float, _column) when is_binary(raw) do
    with {f, ""} <- parse_float(raw), do: {:ok, f}
  end

  defp scalar({:literal, b}, :boolean, _column) when is_boolean(b), do: {:ok, b}

  defp scalar({:session, raw}, :boolean, _column) when is_binary(raw),
    do: raw |> String.downcase() |> boolean()

  defp scalar({tag, s}, kind, _column)
       when tag in [:literal, :session] and kind in @string_kinds and is_binary(s),
       do: text(s)

  defp scalar({tag, s}, :uuid, _column)
       when tag in [:literal, :session] and is_binary(s) and byte_size(s) != 16,
       do: UUID.cast(s)

  defp scalar({tag, s}, :timestamptz, _column) when tag in [:literal, :session] and is_binary(s),
    do: s |> instant() |> since(@min_timestamptz)

  defp scalar({tag, s}, :timestamp, _column) when tag in [:literal, :session] and is_binary(s),
    do: s |> local() |> since(@min_timestamp)

  defp scalar({tag, s}, :date, _column) when tag in [:literal, :session] and is_binary(s),
    do: s |> Date.from_iso8601() |> since(@min_date)

  defp scalar({tag, s}, :enum, %Column{enum_labels: labels})
       when tag in [:literal, :session] and is_binary(s) and is_list(labels),
       do: labels |> Enum.member?(s) |> checked(s)

  defp scalar({:literal, value}, :jsonb, _column) when not is_nil(value), do: json(value)

  defp scalar({:session, raw}, :jsonb, _column) when is_binary(raw),
    do: raw |> Jason.decode() |> decoded()

  defp scalar(_operand, _kind, _column), do: :error

  defp result({:ok, value}, _type), do: {:ok, value}
  defp result(_error, type), do: {:error, {:invalid_value, type}}

  # `Float.parse/1` raises ArgumentError (instead of returning :error) when a
  # long digit string overflows the float range.
  defp parse_float(raw) do
    Float.parse(raw)
  rescue
    ArgumentError -> :error
  end

  # Dates and times. An instant with an offset is that instant; one without
  # is read as UTC. More than six fractional digits are refused: Postgres
  # rounds the seventh where Elixir truncates it.
  defp instant(s), do: s |> offset() |> instant(s)

  defp instant({:ok, datetime, _offset}, _s), do: {:ok, datetime}
  defp instant(error, s), do: error |> local(s) |> utc()

  # An instant that carries its own offset, and nothing else.
  defp zoned(s), do: s |> offset() |> zoned_instant() |> since(@min_timestamptz)

  defp zoned_instant({:ok, datetime, _offset}), do: {:ok, datetime}
  defp zoned_instant(_error), do: :error

  defp offset(s), do: s |> microseconds?() |> parsed(s, &DateTime.from_iso8601/1)

  # Wall-clock time: ISO-8601 or the space-separated form, or a bare date at
  # midnight. A valid offset is ignored, as Postgres does for `timestamp`;
  # an invalid one fails the parse.
  defp local(s), do: s |> offset() |> local(s)

  defp local({:ok, _datetime, _offset}, s), do: NaiveDateTime.from_iso8601(s)
  defp local({:error, :missing_offset}, s), do: NaiveDateTime.from_iso8601(s)
  defp local({:error, :sub_microsecond} = error, _s), do: error
  defp local({:error, _reason}, s), do: s |> Date.from_iso8601() |> midnight()

  defp microseconds?(s), do: not Regex.match?(@sub_microsecond, s)

  defp parsed(true, s, parse), do: parse.(s)
  defp parsed(false, _s, _parse), do: {:error, :sub_microsecond}

  defp midnight({:ok, date}), do: NaiveDateTime.new(date, ~T[00:00:00])
  defp midnight(error), do: error

  defp utc({:ok, naive}), do: DateTime.from_naive(naive, "Etc/UTC")
  defp utc(error), do: error

  # No earlier than the type's Postgres minimum.
  defp since({:ok, %module{} = value}, %module{} = min),
    do: checked(module.compare(value, min) != :lt, value)

  defp since(_error, _min), do: :error

  # Postgres text cannot hold NUL, and Postgrex would raise on invalid UTF-8.
  defp text(s), do: s |> safe_text?() |> checked(s)

  defp safe_text?(s), do: String.valid?(s) and not String.contains?(s, <<0>>)

  defp checked(true, value), do: {:ok, value}
  defp checked(false, _value), do: :error

  defp decoded({:ok, nil}), do: :error
  defp decoded({:ok, value}), do: json(value)
  defp decoded({:error, _reason}), do: :error

  # A JSON value Postgrex can encode and jsonb accepts (no NUL, so no \u0000).
  defp json(value), do: value |> json?() |> checked(value)

  defp json?(value) when is_binary(value), do: safe_text?(value)

  defp json?(n) when is_integer(n),
    do: n |> abs() |> :binary.encode_unsigned() |> bit_size() <= @max_json_integer_bits

  defp json?(value) when is_float(value) or is_boolean(value) or is_nil(value), do: true
  defp json?(values) when is_list(values), do: Enum.all?(values, &json?/1)

  defp json?(map) when is_plain_map(map),
    do: Enum.all?(map, fn {key, value} -> is_binary(key) and json?(key) and json?(value) end)

  defp json?(_value), do: false

  defp boolean(raw) when raw in @truthy, do: {:ok, true}
  defp boolean(raw) when raw in @falsy, do: {:ok, false}
  defp boolean(_raw), do: :error

  # Arrays: literals are lists already; session text is an array literal.

  defp cast_list({:literal, values}, _type, cast) when is_list(values),
    do: values |> Enum.map(&{:literal, &1}) |> Util.map_ok(cast)

  defp cast_list({:session, raw}, _type, cast) when is_binary(raw) do
    with {:ok, elements} <- parse_array_literal(raw) do
      elements |> Enum.map(&{:session, &1}) |> Util.map_ok(cast)
    end
  end

  defp cast_list(_operand, type, _cast), do: {:error, {:invalid_value, type}}

  # Array-literal parser. Each step returns {:ok, elements} or :error.

  defp open("}" <> rest), do: finish(rest, [])
  defp open(body), do: element(body, [])

  defp element(body, acc) do
    with {:ok, value, rest} <- body |> skip_ws() |> read_element() do
      rest |> skip_ws() |> separator([value | acc])
    end
  end

  defp separator("," <> rest, acc), do: element(rest, acc)
  defp separator("}" <> rest, acc), do: finish(rest, acc)
  defp separator(_rest, _acc), do: :error

  defp finish(rest, acc), do: rest |> trim() |> finished(acc)

  defp finished("", acc), do: {:ok, Enum.reverse(acc)}
  defp finished(_trailing, _acc), do: :error

  defp read_element(~s(") <> rest), do: quoted(rest, [])
  defp read_element(body), do: unquoted(body, [], [], false)

  defp quoted(<<?\\, c, rest::binary>>, acc), do: quoted(rest, [acc, c])
  defp quoted(~s(") <> rest, acc), do: {:ok, IO.iodata_to_binary(acc), rest}
  defp quoted(<<c, rest::binary>>, acc), do: quoted(rest, [acc, c])
  defp quoted("", _acc), do: :error

  # `trail` holds unescaped whitespace that is dropped if the element ends.
  defp unquoted(<<?\\, c, rest::binary>>, acc, trail, _escaped?),
    do: unquoted(rest, [acc, trail, c], [], true)

  defp unquoted(<<c, _rest::binary>> = rest, acc, _trail, escaped?) when c in [?,, ?}],
    do: acc |> IO.iodata_to_binary() |> unquoted_value(escaped?, rest)

  defp unquoted(<<c, _rest::binary>>, _acc, _trail, _escaped?) when c in [?", ?{], do: :error

  defp unquoted(<<c, rest::binary>>, acc, trail, escaped?) when c in @whitespace,
    do: unquoted(rest, acc, [trail, c], escaped?)

  defp unquoted(<<c, rest::binary>>, acc, trail, escaped?),
    do: unquoted(rest, [acc, trail, c], [], escaped?)

  defp unquoted("", _acc, _trail, _escaped?), do: :error

  defp unquoted_value("", false, _rest), do: :error

  defp unquoted_value(value, false, rest),
    do: value |> String.upcase() |> unquoted_null(value, rest)

  defp unquoted_value(value, true, rest), do: {:ok, value, rest}

  defp unquoted_null("NULL", _value, _rest), do: :error
  defp unquoted_null(_upcased, value, rest), do: {:ok, value, rest}

  defp skip_ws(<<c, rest::binary>>) when c in @whitespace, do: skip_ws(rest)
  defp skip_ws(text), do: text

  defp trim(text), do: text |> skip_ws() |> String.reverse() |> skip_ws() |> String.reverse()
end

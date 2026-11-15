defmodule Authzura.Adapters.Postgres.ValuesTest do
  use ExUnit.Case, async: true

  alias Authzura.Adapters.Postgres.Values
  alias Authzura.Model.Column

  @uuid "11111111-1111-1111-1111-111111111111"

  @base %Column{name: "c", pg_type: "int8", base_kind: :bigint, ecto_type: :any}
  @bigint @base
  @int4 %{@base | pg_type: "int4", base_kind: :integer}
  @numeric %{@base | pg_type: "numeric", base_kind: :numeric}
  @float %{@base | pg_type: "float8", base_kind: :float}
  @real %{@base | pg_type: "float4", base_kind: :float}
  @int2 %{@base | pg_type: "int2", base_kind: :integer}
  @bool %{@base | pg_type: "bool", base_kind: :boolean}
  @text %{@base | pg_type: "text", base_kind: :text}
  @citext %{@base | pg_type: "citext", base_kind: :citext}
  @uuid_column %{@base | pg_type: "uuid", base_kind: :uuid}
  @tstz %{@base | pg_type: "timestamptz", base_kind: :timestamptz}
  @timestamp %{@base | pg_type: "timestamp", base_kind: :timestamp}
  @date %{@base | pg_type: "date", base_kind: :date}
  @jsonb %{@base | pg_type: "jsonb", base_kind: :jsonb}
  @point %{@base | pg_type: "point", base_kind: :other}
  @enum %{
    @base
    | pg_type: "article_status",
      base_kind: :enum,
      enum_labels: ["draft", "review", "published"]
  }

  describe "parse_array_literal/1" do
    test "plain, empty and quoted literals" do
      assert Values.parse_array_literal("{1,2,3}") == {:ok, ["1", "2", "3"]}
      assert Values.parse_array_literal("{}") == {:ok, []}
      assert Values.parse_array_literal(~s({"a,b","c\\"d"})) == {:ok, ["a,b", ~s(c"d)]}
    end

    test "trims unquoted whitespace and keeps quoted whitespace" do
      assert Values.parse_array_literal(" { 1 , 2 } ") == {:ok, ["1", "2"]}
      assert Values.parse_array_literal(~s({" a ",b\\ })) == {:ok, [" a ", "b "]}
      assert Values.parse_array_literal("{ }") == {:ok, []}
    end

    test "quoted NULL is a string" do
      assert Values.parse_array_literal(~s({"NULL"})) == {:ok, ["NULL"]}
    end

    test "rejects malformed literals" do
      for bad <- [
            "{1,2",
            "1,2}",
            "",
            "{1,,2}",
            "{,}",
            "{1,}",
            "{NULL}",
            "{null,1}",
            "{{1,2}}",
            ~s({"a"b}),
            ~s({"a),
            "{a\\}",
            "{1} x",
            ~s({a"b})
          ] do
        assert Values.parse_array_literal(bad) == {:error, :invalid_array_literal}, bad
      end
    end
  end

  describe "integers" do
    test "strict session parsing" do
      assert Values.cast_value({:session, "42"}, :column, @bigint) == {:ok, 42}
      assert Values.cast_value({:session, "-7"}, :column, @int4) == {:ok, -7}

      for bad <- ["abc", "1.5", " 1", "1 ", "", "1e3", "0x10"] do
        assert Values.cast_value({:session, bad}, :column, @bigint) ==
                 {:error, {:invalid_value, "int8"}}
      end
    end

    test "literals must be in the bigint range" do
      assert Values.cast_value({:literal, 5}, :column, @bigint) == {:ok, 5}

      assert Values.cast_value({:literal, 9_223_372_036_854_775_808}, :column, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value({:session, "9223372036854775808"}, :column, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value({:literal, "5"}, :column, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value({:literal, 5.0}, :column, @bigint) ==
               {:error, {:invalid_value, "int8"}}
    end
  end

  # Postgres refuses an operand outside the column type's range
  # (`22003 numeric_value_out_of_range`), so it is refused for scalars as for
  # array elements, whatever the source.
  describe "scalars beyond the column type's range" do
    test "int2 and int4 take only their own ranges" do
      assert Values.cast_value({:session, "32767"}, :column, @int2) == {:ok, 32_767}

      assert Values.cast_value({:literal, -2_147_483_648}, :column, @int4) ==
               {:ok, -2_147_483_648}

      for {column, operand} <- [
            {@int2, {:session, "40000"}},
            {@int2, {:session, "32768"}},
            {@int2, {:literal, -32_769}},
            {@int4, {:session, "3000000000"}},
            {@int4, {:literal, 2_147_483_648}}
          ],
          mode <- [:permission, :input] do
        assert Values.cast_value(operand, :column, column, mode) ==
                 {:error, {:invalid_value, column.pg_type}},
               inspect({operand, mode})
      end
    end

    test "real refuses values that overflow or underflow float4" do
      assert Values.cast_value({:literal, 0.1}, :column, @real) == {:ok, 0.1}

      for operand <- [
            {:session, "1e300"},
            {:session, "1e39"},
            {:literal, 1.0e39},
            {:literal, 1.0e-50}
          ] do
        assert Values.cast_value(operand, :column, @real) == {:error, {:invalid_value, "float4"}},
               inspect(operand)
      end

      assert {:ok, _f} = Values.cast_value({:session, "1e300"}, :column, @float)
    end
  end

  test "\"abc\" cast for bigint is an invalid value" do
    assert Values.cast_value({:session, "abc"}, :column, @bigint) ==
             {:error, {:invalid_value, "int8"}}
  end

  test "numeric becomes a finite Decimal" do
    assert {:ok, %Decimal{} = d} = Values.cast_value({:session, "10.50"}, :column, @numeric)
    assert Decimal.equal?(d, Decimal.new("10.5"))
    assert {:ok, %Decimal{}} = Values.cast_value({:literal, 3}, :column, @numeric)
    assert {:ok, %Decimal{}} = Values.cast_value({:literal, 1.25}, :column, @numeric)

    for bad <- ["NaN", "Infinity", "-inf", "1.2.3", "x", ""] do
      assert Values.cast_value({:session, bad}, :column, @numeric) ==
               {:error, {:invalid_value, "numeric"}}
    end
  end

  test "float parsing is strict" do
    assert Values.cast_value({:session, "1.5"}, :column, @float) == {:ok, 1.5}
    assert Values.cast_value({:literal, 2}, :column, @float) == {:ok, 2.0}

    assert Values.cast_value({:session, "1.5x"}, :column, @float) ==
             {:error, {:invalid_value, "float8"}}
  end

  describe "booleans" do
    test "accepted spellings, case-insensitively" do
      for raw <- ["true", "T", "yes", "Y", "1", "TRUE"] do
        assert Values.cast_value({:session, raw}, :column, @bool) == {:ok, true}
      end

      for raw <- ["false", "F", "no", "N", "0", "False"] do
        assert Values.cast_value({:session, raw}, :column, @bool) == {:ok, false}
      end
    end

    test "\"T\" is true and junk is invalid" do
      assert Values.cast_value({:session, "T"}, :column, @bool) == {:ok, true}

      assert Values.cast_value({:session, "maybe"}, :column, @bool) ==
               {:error, {:invalid_value, "bool"}}

      assert Values.cast_value({:literal, "true"}, :column, @bool) ==
               {:error, {:invalid_value, "bool"}}
    end

    test "the :boolean right side (is_null)" do
      assert Values.cast_value({:literal, true}, :boolean, @text) == {:ok, true}
      assert Values.cast_value({:session, "f"}, :boolean, @text) == {:ok, false}

      assert Values.cast_value({:literal, nil}, :boolean, @text) ==
               {:error, {:invalid_value, "bool"}}
    end
  end

  describe "text" do
    test "a 64-character string stays intact" do
      long = String.duplicate("x", 64)
      assert Values.cast_value({:session, long}, :column, @text) == {:ok, long}
      assert Values.cast_value({:session, long}, :column, @citext) == {:ok, long}
    end

    test "a pinned citext comparison needs the extension's schema" do
      assert Values.cast_value({:literal, "a"}, :column, @citext, :pinned) ==
               {:error, {:unsupported_type, "citext"}}

      citext = %{@citext | type_schema: "public"}
      assert Values.cast_value({:literal, "a"}, :column, citext, :pinned) == {:ok, "a"}
      assert Values.cast_value({:literal, "a"}, :column, @citext, :input) == {:ok, "a"}
    end

    test "literals must be strings" do
      assert Values.cast_value({:literal, "a"}, :text, @jsonb) == {:ok, "a"}

      assert Values.cast_value({:literal, 1}, :column, @text) ==
               {:error, {:invalid_value, "text"}}
    end
  end

  describe "uuid" do
    test "validated and canonicalized" do
      upper = String.upcase(@uuid)
      assert Values.cast_value({:session, upper}, :column, @uuid_column) == {:ok, @uuid}
    end

    test "\"not-a-uuid\" and raw 16-byte strings are invalid" do
      assert Values.cast_value({:session, "not-a-uuid"}, :column, @uuid_column) ==
               {:error, {:invalid_value, "uuid"}}

      assert Values.cast_value({:session, "abcdefghijklmnop"}, :column, @uuid_column) ==
               {:error, {:invalid_value, "uuid"}}
    end
  end

  describe "timestamps and dates" do
    test "timestamptz takes ISO-8601 and Postgres's space-separated forms" do
      for {input, expected} <- [
            {"2026-01-01T02:00:00+02:00", ~U[2026-01-01 00:00:00Z]},
            {"2026-01-01 02:00:00+02:00", ~U[2026-01-01 00:00:00Z]},
            {"2026-01-01 02:00:00.123456-01:00", ~U[2026-01-01 03:00:00.123456Z]},
            {"2026-01-01T00:00:00Z", ~U[2026-01-01 00:00:00Z]}
          ] do
        assert {:ok, %DateTime{} = dt} = Values.cast_value({:session, input}, :column, @tstz)
        assert DateTime.compare(dt, expected) == :eq, input
      end
    end

    # In input mode a missing offset is read as UTC.
    test "input timestamptz without an offset is UTC, and a bare date is its midnight" do
      for {input, expected} <- [
            {"2026-01-01", ~U[2026-01-01 00:00:00Z]},
            {"2026-01-01 10:20:30", ~U[2026-01-01 10:20:30Z]},
            {"2026-01-01 10:20:30.5", ~U[2026-01-01 10:20:30.5Z]},
            {"2026-01-01T10:20:30", ~U[2026-01-01 10:20:30Z]}
          ] do
        assert {:ok, %DateTime{} = dt} =
                 Values.cast_value({:literal, input}, :column, @tstz, :input)

        assert DateTime.compare(dt, expected) == :eq, input
      end
    end

    # Hasura sends policy text to Postgres, which reads a missing offset in
    # the session's TimeZone. Authzura cannot know that zone, so a policy
    # operand (a permission literal or any session value) needs an offset.
    test "policy timestamptz without an offset is refused" do
      for input <- ["2026-01-01", "2026-01-01 10:20:30", "2026-01-01T10:20:30"],
          {operand, mode} <- [
            {{:literal, input}, :permission},
            {{:session, input}, :permission},
            {{:session, input}, :input}
          ] do
        assert Values.cast_value(operand, :column, @tstz, mode) ==
                 {:error, {:invalid_value, "timestamptz"}},
               inspect({operand, mode})
      end

      assert Values.cast_value(
               {:session, "{2026-01-01T00:00:00Z,2026-01-02}"},
               :column_array,
               @tstz
             ) == {:error, {:invalid_value, "timestamptz"}}

      assert {:ok, [_one, _two]} =
               Values.cast_value(
                 {:literal, ["2026-01-01T00:00:00Z", "2026-01-02 00:00:00+02:00"]},
                 :column_array,
                 @tstz,
                 :permission
               )
    end

    test "timestamptz refuses anything else" do
      for bad <- ["yesterday", "2026-13-01", "2026-01-01 25:00:00", "2026-01-01  10:00:00", ""] do
        assert Values.cast_value({:session, bad}, :column, @tstz) ==
                 {:error, {:invalid_value, "timestamptz"}}
      end
    end

    test "timestamp takes the same forms and ignores an offset, as Postgres does" do
      for {input, expected} <- [
            {"2026-01-01", ~N[2026-01-01 00:00:00]},
            {"2026-01-01 10:20:30.25", ~N[2026-01-01 10:20:30.25]},
            {"2026-01-01T10:20:30", ~N[2026-01-01 10:20:30]},
            {"2026-01-01 10:20:30+02:00", ~N[2026-01-01 10:20:30]}
          ] do
        assert {:ok, %NaiveDateTime{} = naive} =
                 Values.cast_value({:session, input}, :column, @timestamp)

        assert NaiveDateTime.compare(naive, expected) == :eq, input
      end

      assert Values.cast_value({:session, "noon"}, :column, @timestamp) ==
               {:error, {:invalid_value, "timestamp"}}
    end

    # Postgres rounds a seventh fractional digit where Elixir would truncate
    # it, so a literal could compare one microsecond off at a boundary.
    test "more than six fractional digits are refused" do
      for column <- [@tstz, @timestamp],
          input <- ["2026-01-01 10:00:00.1234567", "2026-01-01T10:00:00.9999995Z"] do
        assert Values.cast_value({:literal, input}, :column, column) ==
                 {:error, {:invalid_value, column.pg_type}}
      end

      assert {:ok, _six} =
               Values.cast_value({:literal, "2026-01-01 10:00:00.123456Z"}, :column, @tstz)
    end

    test "date takes YYYY-MM-DD only" do
      assert Values.cast_value({:session, "2026-02-28"}, :column, @date) == {:ok, ~D[2026-02-28]}
      assert Values.cast_value({:literal, "2026-02-28"}, :column, @date) == {:ok, ~D[2026-02-28]}

      for bad <- ["2026-02-30", "2026-02-28T00:00:00", "28/02/2026", "20260228", ""] do
        assert Values.cast_value({:session, bad}, :column, @date) ==
                 {:error, {:invalid_value, "date"}}
      end
    end

    test "dates and timestamps before Postgres's 4714-11-24 BC are refused" do
      assert {:ok, _date} = Values.cast_value({:session, "-4713-11-24"}, :column, @date)

      for {column, type} <- [{@date, "date"}, {@timestamp, "timestamp"}, {@tstz, "timestamptz"}] do
        assert Values.cast_value({:session, "-4713-11-23"}, :column, column) ==
                 {:error, {:invalid_value, type}}
      end
    end

    test "arrays of dates and timestamps cast element by element" do
      assert Values.cast_value({:literal, ["2026-01-01", "2026-01-02"]}, :column_array, @date) ==
               {:ok, [~D[2026-01-01], ~D[2026-01-02]]}

      assert Values.cast_value({:session, "{2026-01-01,nope}"}, :column_array, @timestamp) ==
               {:error, {:invalid_value, "timestamp"}}
    end
  end

  test "enum values must be introspected labels" do
    assert Values.cast_value({:session, "draft"}, :column, @enum) == {:ok, "draft"}

    assert Values.cast_value({:session, "bogus"}, :column, @enum) ==
             {:error, {:invalid_value, "article_status"}}
  end

  describe "jsonb" do
    test "session text is decoded, literals are not decoded again" do
      assert Values.cast_value({:session, ~s({"7":true})}, :jsonb, @jsonb) ==
               {:ok, %{"7" => true}}

      assert Values.cast_value({:literal, ~s({"7":true})}, :jsonb, @jsonb) ==
               {:ok, ~s({"7":true})}

      assert Values.cast_value({:session, "{nope"}, :jsonb, @jsonb) ==
               {:error, {:invalid_value, "jsonb"}}

      assert Values.cast_value({:session, "null"}, :jsonb, @jsonb) ==
               {:error, {:invalid_value, "jsonb"}}
    end

    test "a jsonb column compared with :column decodes too" do
      assert Values.cast_value({:session, "[1]"}, :column, @jsonb) == {:ok, [1]}
    end
  end

  describe "arrays" do
    test "session arrays are parsed and each element cast" do
      assert Values.cast_value({:session, "{1,2,3}"}, :column_array, @bigint) == {:ok, [1, 2, 3]}
      assert Values.cast_value({:session, "{}"}, :column_array, @bigint) == {:ok, []}

      assert Values.cast_value({:session, ~s({"a,b","c"})}, :text_array, @jsonb) ==
               {:ok, ["a,b", "c"]}
    end

    test "literal arrays are lists cast element by element" do
      assert Values.cast_value({:literal, [1, 2]}, :column_array, @bigint) == {:ok, [1, 2]}
      assert Values.cast_value({:literal, ["a"]}, :text_array, @jsonb) == {:ok, ["a"]}
    end

    test "bad arrays and bad elements are errors" do
      assert Values.cast_value({:session, "{1,2"}, :column_array, @bigint) ==
               {:error, :invalid_array_literal}

      assert Values.cast_value({:session, "{1,x}"}, :column_array, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value({:literal, [1, nil]}, :column_array, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value({:literal, 1}, :column_array, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value({:literal, [1]}, :text_array, @jsonb) ==
               {:error, {:invalid_value, "text"}}
    end
  end

  test "a float literal beyond the float range is invalid, not an ArithmeticError" do
    assert Values.cast_value({:literal, Integer.pow(10, 400)}, :column, @float) ==
             {:error, {:invalid_value, "float8"}}

    assert Values.cast_value({:literal, -Integer.pow(10, 400)}, :column, @float) ==
             {:error, {:invalid_value, "float8"}}
  end

  test "session floats beyond the float range are invalid, not an ArgumentError" do
    huge = "1" <> String.duplicate("0", 309)

    assert Values.cast_value({:session, huge}, :column, @float) ==
             {:error, {:invalid_value, "float8"}}

    assert Values.cast_value({:session, "{1.5,#{huge}}"}, :column_array, @float) ==
             {:error, {:invalid_value, "float8"}}

    assert Values.cast_value({:session, "1" <> String.duplicate("0", 308)}, :column, @float) ==
             {:ok, 1.0e308}
  end

  describe "NUL bytes and invalid UTF-8" do
    test "are refused for text, citext and enum values" do
      for {column, type} <- [{@text, "text"}, {@citext, "citext"}, {@enum, "article_status"}],
          bad <- ["a\0b", <<0xFF, 0xFE>>],
          tag <- [:literal, :session] do
        assert Values.cast_value({tag, bad}, :column, column) == {:error, {:invalid_value, type}}
      end

      assert Values.cast_value({:session, "a\0"}, :text, @jsonb) ==
               {:error, {:invalid_value, "text"}}

      assert Values.cast_value({:session, ~s({"a\0"})}, :text_array, @jsonb) ==
               {:error, {:invalid_value, "text"}}
    end

    test "are refused anywhere inside jsonb values" do
      for bad <- [
            {:session, ~s({"a": "x\\u0000"})},
            {:session, ~s({"x\\u0000": 1})},
            {:literal, %{"a" => ["x\0"]}},
            {:literal, %{"x\0" => 1}},
            {:literal, <<0xFF>>},
            {:literal, %{"a" => :atom}},
            {:literal, %{1 => "a"}},
            {:literal, {:tuple}}
          ] do
        assert Values.cast_value(bad, :jsonb, @jsonb) == {:error, {:invalid_value, "jsonb"}},
               inspect(bad)
      end

      assert Values.cast_value({:literal, %{"a" => [1, 2.5, true, nil, "b"]}}, :jsonb, @jsonb) ==
               {:ok, %{"a" => [1, 2.5, true, nil, "b"]}}
    end
  end

  describe "nil and malformed operands" do
    test "a nil literal is allowed only for a :column right side" do
      assert Values.cast_value({:literal, nil}, :column, @bigint) == {:ok, nil}

      assert Values.cast_value({:literal, nil}, :text, @text) ==
               {:error, {:invalid_value, "text"}}

      assert Values.cast_value({:literal, nil}, :jsonb, @jsonb) ==
               {:error, {:invalid_value, "jsonb"}}
    end

    test "non-string session values and untagged operands never raise" do
      assert Values.cast_value({:session, 1}, :column, @bigint) ==
               {:error, {:invalid_value, "int8"}}

      assert Values.cast_value(:oops, :column, @bigint) == {:error, {:invalid_value, "int8"}}
    end

    test "unsupported column kinds and right sides are errors" do
      assert Values.cast_value({:session, "x"}, :column, @point) ==
               {:error, {:unsupported_type, "point"}}

      assert Values.cast_value({:session, "x"}, :nope, @text) ==
               {:error, {:unsupported_type, "text"}}
    end
  end
end

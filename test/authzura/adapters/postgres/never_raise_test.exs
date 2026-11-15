defmodule Authzura.Adapters.Postgres.NeverRaiseTest do
  @moduledoc """
  Sweeps every fixture column against every right-side kind with a fixed
  list of hostile operands. `cast_value/3` must return a tuple, and whatever
  it accepts must compile (in both modes) to SQL that Postgres executes.
  """

  use Authzura.DataCase, async: true

  alias Authzura.Adapters.Postgres
  alias Authzura.Model.Column

  @root :__authzura_0
  @refs [
    {"public", "articles"},
    {"public", "users"},
    {"public", "key_kinds"},
    {"public", "org_memberships"}
  ]

  # The operator that exercises each right side, and the left side it needs.
  @operators [
    column: {:eq, :any},
    column: {:gt, :any},
    column_array: {:in, :any},
    boolean: {:is_null, :any},
    text: {:like, :text},
    text: {:has_key, :jsonb},
    text_array: {:has_keys_any, :jsonb},
    jsonb: {:contains, :jsonb}
  ]

  @hostile_text [
    "",
    "a\0b",
    <<0xFF, 0xFE>>,
    <<"T", 0xC3>>,
    ~s("\\u0000"),
    ~s({"a":"\\u0000"}),
    ~s({"\\u0000":1}),
    ~s("\\ud800"),
    "1e400",
    "nan",
    "inf",
    "-0",
    "+5",
    " 5",
    "9223372036854775808",
    "1" <> String.duplicate("0", 309),
    String.duplicate("9", 5000),
    "1e5000",
    "1e-20000",
    "1e200000",
    "-9999-01-01T00:00:00Z",
    "0000-01-01T00:00:00Z",
    "-4714-11-23T00:00:00Z",
    "9999-12-31T23:59:59-23:59",
    "32768",
    "2147483648",
    "2026-13-01T00:00:00Z",
    "2026-02-30",
    "2026-01-01",
    "20260101",
    "2026-01-01 10:00:00",
    "2026-01-01 10:00:00.1234567",
    "2026-01-01T10:00:00+25:00",
    "2026-01-01 24:00:00",
    "-4713-11-24",
    "-4713-11-23 23:59:59",
    "9999-12-31 23:59:59.999999",
    "null",
    "[null]",
    ~s({"a":null}),
    "İ",
    "TRUE\0",
    "{a\0}",
    ~s({"\\u0000"})
  ]

  @hostile_literals [
    nil,
    Integer.pow(10, 400),
    -Integer.pow(10, 400),
    1.0e308,
    "a\0b",
    <<0xFF>>,
    %{"a" => <<0>>},
    %{<<0>> => 1},
    %{a: 1},
    [1, {:x}],
    {:tuple},
    :atom,
    %{"k" => [nil]},
    [],
    %{},
    Decimal.new(1),
    ~U[2026-01-01 00:00:00Z],
    ~D[2026-01-01],
    ~N[2026-01-01 00:00:00],
    Integer.pow(10, 140_000),
    [32_767, -32_768],
    [32_768],
    [-32_769],
    [2_147_483_648],
    [-2_147_483_649],
    [9_223_372_036_854_775_808],
    [3.5e38],
    [-1.0e39],
    [1.0e-50]
  ]

  @operands Enum.map(@hostile_text, &{:session, &1}) ++
              Enum.map(@hostile_text, &{:session, "{" <> &1 <> "}"}) ++
              Enum.map(@hostile_literals, &{:literal, &1})

  test "hostile operands are cast to tuples and accepted values execute" do
    {:ok, tables, _fks} = Postgres.introspect(Repo, @refs)

    for {{_schema, table}, %{columns: columns}} <- tables,
        {_name, column} <- columns,
        {rhs, {op, lhs_kind}} <- @operators,
        lhs_kind?(lhs_kind, column),
        operand <- @operands do
      label = inspect({table, column.name, op, operand}, limit: 5, printable_limit: 40)

      case Postgres.cast_value(operand, rhs, column) do
        {:ok, value} -> assert_executes(table, column, op, value, label)
        {:error, _reason} -> :ok
      end
    end
  end

  defp lhs_kind?(:any, %Column{}), do: true
  defp lhs_kind?(:text, %Column{base_kind: kind}), do: kind in [:text, :citext]
  defp lhs_kind?(:jsonb, %Column{base_kind: kind}), do: kind == :jsonb

  defp assert_executes(table, %Column{name: name} = column, op, value, label) do
    lhs = dynamic(field(as(^@root), ^name))

    for mode <- [:permission, :input] do
      condition = Postgres.compile_operator(op, lhs, value, column, mode)
      query = from(t in table, prefix: "public", as: ^@root, where: ^condition, select: 1)
      assert is_list(Repo.all(query)), label
    end
  end
end

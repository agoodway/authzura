defmodule Authzura.Parity.SessionDivergenceTest do
  @moduledoc """
  The session-value divergences the randomized differential found against
  Hasura v2.51.6 (`test/parity/reviewed_divergences.exs`), pinned on the
  local fixture database without Hasura: each skipped
  `:hasura_divergence` test asserts what Hasura answers (observed against
  the real Hasura), its companion what Authzura does, and the predicate
  test checks each entry's `case?` against Postgres itself.
  """

  use Authzura.CommittedCase, async: false

  alias Authzura.Gen.{Catalog, Mutation}
  alias Authzura.HasuraFixture
  alias Authzura.Parity.{Fixture, Read, Runner, Verdict}

  @users {"public", "users"}
  @namespace "https://hasura.io/jwt/claims"

  # `_or: []` is false, so the comparison is dead code Postgres folds away
  # before it ever casts the session value.
  @dead_cast %{"_and" => [%{"_or" => []}, %{"id" => %{"_eq" => "X-Hasura-User-Id"}}]}
  @own_row %{"id" => %{"_eq" => "X-Hasura-User-Id"}}

  @types %{int: "int8", bool: "boolean", int_array: "int4[]", text_array: "text[]"}
  @strict_types %{int: "int4", bool: "boolean", int_array: "int4[]", text_array: "text[]"}
  @extra_values [
    "abc",
    "1.0",
    "",
    "9223372036854775808",
    " 1",
    "1 ",
    "\t1",
    "1\n",
    "\u00A01",
    "maybe",
    "{1,abc}",
    ~s|{"a|
  ]

  setup %{test: test} do
    :ok = Fixture.seed!(Repo)

    metadata =
      Fixture.metadata([
        {@users, %{role: "dead_cast", permission: %{columns: ["id"], filter: @dead_cast}}},
        {@users, %{role: "own_row", permission: %{columns: ["id"], filter: @own_row}}}
      ])

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata)}
  end

  describe "session-cast-eager" do
    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): Authzura casts every referenced session value " <>
             "before the query and fails closed; Hasura's SQL never casts a value whose " <>
             "comparison Postgres folds away"
    test "a value no evaluated comparison uses, with an uncastable user id", %{instance: i} do
      assert read("dead_cast", "abc", i) == {:ok, []}
    end

    test "Authzura denies it before the query", %{instance: i} do
      assert {:error, {:invalid_session_value, "x-hasura-user-id", {:invalid_value, _type}}} =
               read("dead_cast", "abc", i)
    end
  end

  describe "session-text-strict" do
    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): Authzura parses session text strictly and fails " <>
             "closed; Postgres casts ' 1' to 1"
    test "an integer session value with surrounding whitespace", %{instance: i} do
      assert read("own_row", " 1", i) == {:ok, [%{"id" => 1}]}
    end

    test "Authzura denies it", %{instance: i} do
      assert {:error, {:invalid_session_value, "x-hasura-user-id", {:invalid_value, _type}}} =
               read("own_row", " 1", i)
    end
  end

  test "each entry's case? holds only for values Postgres treats as the entry says" do
    entries = Map.new(Verdict.divergences(), &{&1.id, &1})
    values = Enum.uniq(Mutation.boundary_forms() ++ @extra_values)

    for {kind, name} <- kinds(), value <- values do
      c = jwt_case(name, value)
      reason = reason(name)

      # The other variable's reason never matches.
      refute Enum.any?(entries, fn {_id, e} -> e.case?.(c, reason("x-hasura-other")) end)

      if entries["session-cast-eager"].case?.(c, reason),
        do: refute(casts?(value, @types[kind]), "#{inspect(value)} casts to #{@types[kind]}")

      if entries["session-text-strict"].case?.(c, reason),
        do:
          assert(
            casts?(value, @strict_types[kind]),
            "#{inspect(value)} fails #{@strict_types[kind]}"
          )
    end

    for id <- ["session-cast-eager", "session-text-strict"] do
      assert Enum.any?(kinds(), fn {_kind, name} ->
               Enum.any?(values, &entries[id].case?.(jwt_case(name, &1), reason(name)))
             end),
             "#{id}'s case? matches no value"
    end
  end

  defp reason(name), do: {:invalid_session_value, name, {:invalid_value, "int8"}}

  defp read(role, user_id, instance) do
    claims = %{
      "sub" => "1",
      @namespace => %{
        "x-hasura-default-role" => role,
        "x-hasura-allowed-roles" => [role],
        "x-hasura-user-id" => user_id
      }
    }

    @users
    |> Read.new(columns: ["id"], order_by: [asc: :id])
    |> Runner.authzura({:jwt, claims, nil}, instance)
  end

  # One variable of each kind the entries reason about.
  defp kinds do
    Catalog.variables()
    |> Enum.filter(fn {_name, kind, _spellings} -> Map.has_key?(@types, kind) end)
    |> Enum.uniq_by(fn {_name, kind, _spellings} -> kind end)
    |> Enum.map(fn {name, kind, _spellings} -> {kind, name} end)
  end

  defp jwt_case(name, value) do
    session = %{name => value, "x-hasura-default-role" => "r", "x-hasura-allowed-roles" => ["r"]}
    %{auth: {:jwt, %{@namespace => session}, nil}, read: nil, tags: []}
  end

  defp casts?(value, type) do
    match?({:ok, _result}, Repo.query("SELECT CAST($1::text AS #{type})", [value], log: false))
  end
end

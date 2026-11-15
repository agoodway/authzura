# Reviewed divergences of the randomized differential suite
# (`Authzura.Parity.Verdict`): over-denials the owner accepted. An entry
# turns an over-deny into `{:reviewed_divergence, id}` only when both its
# `case?` (on the generated case and Authzura's reason, so the two are
# correlated: the session variable the reason names must be the one whose
# value the entry is about) and its `reason?` (on the reason alone) hold.
# `coverage_row` is the `Test` cell of the entry's row in the
# "Divergences" table of docs/hasura-test-coverage.md.
#
# Evaluated with `Code.eval_file/1`; it must return the list.

alias Authzura.Gen
alias Authzura.Gen.Catalog

# The value and kind of the session variable `reason` names, or nil.
named = fn
  c, {:invalid_session_value, name, _why} ->
    case Map.fetch(Gen.variables(c), name) do
      {:ok, value} -> {Catalog.variable_kind(name), value}
      :error -> nil
    end

  _c, _reason ->
    nil
end

# Session values Postgres rejects for the variable's column type, by the
# variable's kind (checked against Postgres by
# test/parity/session_divergence_test.exs).
rejected = %{
  int: ["abc", "1.0", "", "9223372036854775808"],
  bool: ["maybe", ""],
  int_array: ["{1,abc}"],
  text_array: [~s|{"a|]
}

# An integer beyond the range of the column's own type (`int2`, `int4`):
# Postgres refuses it only where it casts the value as that type, so the
# variable's kind alone does not decide it; the reason's type does.
ranges = %{"int2" => -32_768..32_767, "int4" => -2_147_483_648..2_147_483_647}

out_of_range? = fn
  {:int, value}, {:invalid_session_value, _name, {:invalid_value, type}} ->
    with {:ok, range} <- Map.fetch(ranges, type),
         {n, ""} <- Integer.parse(value) do
      n not in range
    else
      _other -> false
    end

  _named, _reason ->
    false
end

# Session text Postgres casts but Authzura's strict grammar refuses (also
# checked against Postgres). Postgres's integer input skips C `isspace`
# characters around the digits.
space = "[ \\t\\n\\x0B\\f\\r]"
padded = Regex.compile!("^#{space}*[+-]?[0-9]+#{space}*$")
null? = &(&1 =~ ~r/[{,]\s*NULL\s*[,}]/i)

lenient = fn
  :int, value ->
    value =~ padded and not (value =~ ~r/^[+-]?[0-9]+$/)

  :int_array, value ->
    null?.(value) and value =~ ~r/^\{\s*(NULL|[+-]?[0-9]+)(\s*,\s*(NULL|[+-]?[0-9]+))*\s*\}$/i

  :text_array, value ->
    null?.(value) and value =~ ~r/^\{[^{}"\\]*\}$/

  _kind, _value ->
    false
end

[
  %{
    # Authzura casts every session value a permission references before it
    # runs the query and fails closed; Hasura casts inside the SQL, so a
    # value whose comparison Postgres folds away is never cast.
    id: "session-cast-eager",
    coverage_row: "`test/parity/session_divergence_test.exs:60`",
    case?: fn c, reason ->
      case named.(c, reason) do
        {kind, value} ->
          value in Map.get(rejected, kind, []) or out_of_range?.({kind, value}, reason)

        nil ->
          false
      end
    end,
    reason?: &match?({:invalid_session_value, _name, _why}, &1)
  },
  %{
    # Owner-reviewed. Authzura parses session text strictly
    # (`Authzura.Adapters.Postgres.Values`: an integer is `[+-]?[0-9]+`, an
    # array literal has no unquoted NULL element) and fails closed; Postgres
    # casts ` 1` to 1 and reads `{NULL,1}` as an array holding NULL, so
    # Hasura compares against them.
    id: "session-text-strict",
    coverage_row: "`test/parity/session_divergence_test.exs:75`",
    case?: fn c, reason ->
      case named.(c, reason) do
        {kind, value} -> lenient.(kind, value)
        nil -> false
      end
    end,
    reason?: &match?({:invalid_session_value, _name, _why}, &1)
  }
]

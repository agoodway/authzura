defmodule Authzura.Adapters.Postgres.InputCheck do
  @moduledoc """
  Checks the patterns of an untrusted input filter with Postgres before the
  read that uses them.

  Postgres compiles a `SIMILAR TO` pattern or a regular expression only
  when it first evaluates it, and with a generic plan that can be on any
  row. Every such pattern is therefore matched against the empty string
  first, in one constant statement that reads no table:

      SELECT count(*) FROM unnest($1::text[], $2::text[]) AS p(kind, pattern)
      WHERE CASE kind WHEN 'regex' THEN '' ~ pattern ...

  A negated operator compiles its pattern like the plain one, so `_nregex`
  is checked as `~`, `_niregex` as `~*` and `_nsimilar` as `SIMILAR TO`.
  Only when the statement fails are the patterns checked one at a time, to
  name the first column whose pattern Postgres refuses. Inside a
  transaction each statement runs in a savepoint, so a refused pattern
  never aborts it.

  `LIKE` patterns need no check: the only literal Postgres refuses there, a
  trailing escape, is refused when the input is parsed.

  With a `:statement_timeout` option the combined statement also sets the
  transaction-local `statement_timeout` to the smaller of that value and the
  session's own (`0`, none, takes the option's), so the read that follows in
  the same transaction is bounded at no extra round trip. The savepoint
  is released on success, which keeps the setting until the transaction
  ends; a refused pattern rolls it back with the savepoint.
  """

  alias Authzura.AST
  alias Authzura.Telemetry
  alias Ecto.Adapters.SQL
  alias Postgrex.Error, as: PostgresError

  @kinds %{
    regex: "regex",
    nregex: "regex",
    iregex: "iregex",
    niregex: "iregex",
    similar: "similar",
    nsimilar: "similar"
  }

  # Every check statement holds it; benchmarks classify the statement by it.
  @marker "AS p(kind, pattern)"

  @patterns """
  FROM unnest($1::text[], $2::text[]) #{@marker}
  WHERE CASE kind
    WHEN 'regex' THEN '' ~ pattern
    WHEN 'iregex' THEN '' ~* pattern
    ELSE '' SIMILAR TO pattern
  END
  """
  # Named, so each is prepared once per connection (one exchange per check).
  @statement {"authzura_pattern_check", "SELECT count(*) " <> @patterns}
  # The smaller of the configured bound and the session's own
  # `statement_timeout` (milliseconds; 0 means none), so a stricter
  # database setting is never raised.
  @bounded """
  set_config('statement_timeout', (
    SELECT CASE WHEN s.setting::bigint = 0 THEN $3::bigint
                ELSE least(s.setting::bigint, $3::bigint) END
    FROM pg_settings AS s WHERE s.name = 'statement_timeout'
  )::text, true)
  """
  @timed {"authzura_pattern_check_timed", "SELECT count(*), " <> @bounded <> @patterns}

  @doc """
  The text every check statement contains, also after `pg_stat_statements`
  normalizes it, so tools can tell the check from the read.
  """
  @spec marker() :: String.t()
  def marker, do: @marker

  @doc "The check statements' SQL: without and with the statement timeout."
  @spec statements() :: [String.t()]
  def statements, do: [elem(@statement, 1), elem(@timed, 1)]

  @doc """
  Checks the patterns of `ast` through `repo` with `opts`: `:ok`, or
  `{:error, {:invalid_input, {:invalid_pattern, column}}}` for the first
  pattern Postgres refuses. A filter without patterns runs no statement.
  The statement reads only its parameters, so every Postgres error it
  raises (2201B, 22025, 2200C, ...) is taken as a refused pattern; none is
  raised.
  """
  @spec run(module(), AST.t(), keyword(), map()) ::
          :ok | {:error, {:invalid_input, {:invalid_pattern, String.t()}}}
  def run(repo, ast, opts, telemetry) do
    {timeout, opts} = Keyword.pop(opts, :statement_timeout)

    case patterns(ast) do
      [] ->
        :ok

      patterns ->
        check(patterns, timeout, {repo, savepoint(repo.in_transaction?(), opts), telemetry})
    end
  end

  defp patterns(ast) do
    for {:compare, column, op, {:literal, pattern}} <- AST.comparisons(ast),
        is_map_key(@kinds, op),
        do: {column, Map.fetch!(@kinds, op), pattern}
  end

  defp savepoint(true, opts), do: Keyword.put(opts, :mode, :savepoint)
  defp savepoint(false, opts), do: opts

  defp check(patterns, timeout, env),
    do: patterns |> accepted?(timeout, env) |> outcome(patterns, env)

  defp outcome(true, _patterns, _env), do: :ok

  defp outcome(false, patterns, env),
    do: {:error, {:invalid_input, {:invalid_pattern, first_refused(patterns, env)}}}

  # The combined statement was refused, so one of its patterns is.
  defp first_refused([first | _rest] = patterns, env) do
    {column, _kind, _pattern} = Enum.find(patterns, first, &refused?(&1, env))
    column
  end

  defp refused?(pattern, env), do: not accepted?([pattern], nil, env)

  # A refused pattern is an ordinary outcome, not a failure of the statement:
  # its span stops normally with `result: :rejected`.
  defp accepted?(patterns, timeout, {repo, opts, telemetry}) do
    kinds = Enum.map(patterns, &elem(&1, 1))
    values = Enum.map(patterns, &elem(&1, 2))
    {statement, params} = timed([kinds, values], timeout)

    result =
      Telemetry.query(:setup, :root, telemetry, fn -> statement(repo, statement, params, opts) end)

    result != :rejected
  end

  defp timed(params, nil), do: {@statement, params}
  defp timed(params, timeout), do: {@timed, params ++ [timeout]}

  defp statement(repo, {name, sql}, params, opts) do
    SQL.query!(repo, sql, params, Keyword.put(opts, :cache_statement, name))
  rescue
    PostgresError -> :rejected
  end
end

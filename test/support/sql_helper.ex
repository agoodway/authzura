defmodule Authzura.SqlHelper do
  @moduledoc "Renders the SQL of a query against the test repo, for SQL-shape assertions."

  alias Authzura.Test.Repo
  alias Ecto.Adapters.SQL
  alias Ecto.{Query, SubQuery}

  @doc "The SQL string `query` runs as an `all` read on the test repo."
  @spec sql(Ecto.Queryable.t()) :: String.t()
  def sql(query) do
    {sql, _params} = SQL.to_sql(:all, Repo, query)
    sql
  end

  @doc "Counts non-overlapping occurrences of text in SQL."
  @spec occurrences(String.t(), String.t()) :: non_neg_integer()
  def occurrences(sql, text), do: length(String.split(sql, text)) - 1

  @doc "Every subquery reachable from the query's where clauses, depth first."
  @spec subqueries(Query.t()) :: [Query.t()]
  def subqueries(%Query{wheres: wheres}) do
    Enum.flat_map(wheres, fn %{subqueries: subs} ->
      Enum.flat_map(subs, fn %SubQuery{query: query} -> [query | subqueries(query)] end)
    end)
  end

  @doc "Splits the first input fence into the preceding SQL, permission and input."
  @spec fence_split(String.t()) :: {String.t(), String.t(), String.t()}
  def fence_split(sql) do
    [outside, fenced] = String.split(sql, "CASE WHEN ", parts: 2)
    [condition, input] = String.split(fenced, " THEN ", parts: 2)
    {outside, condition, input}
  end

  @doc "The SQL preceding the input fence, optionally restricted to its WHERE."
  @spec outside_fence(String.t(), keyword()) :: String.t()
  def outside_fence(sql, opts \\ []) do
    {outside, _condition, _input} = fence_split(sql)
    outside_where(outside, Keyword.get(opts, :where_only, false))
  end

  defp outside_where(outside, false), do: outside

  defp outside_where(outside, true) do
    [_select, where] = String.split(outside, "WHERE", parts: 2)
    where
  end
end

defmodule Authzura.SqlHelper do
  @moduledoc "Renders the SQL of a query against the test repo, for SQL-shape assertions."

  alias Authzura.Test.Repo
  alias Ecto.Adapters.SQL

  @doc "The SQL string `query` runs as an `all` read on the test repo."
  @spec sql(Ecto.Queryable.t()) :: String.t()
  def sql(query) do
    {sql, _params} = SQL.to_sql(:all, Repo, query)
    sql
  end
end

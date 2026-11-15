defmodule Authzura.QueryShape do
  @moduledoc """
  Structural validation of a caller's Ecto query against the grammar
  `Authzura.scope/3` and the executors accept.

  It checks shape only; it never reads permissions. A query is rejected with
  `{:error, {:unsupported_query, reason}}`:

    * **Sources.** `:fragment_source` (a fragment or `values` root),
      `:subquery_source`, `:modifying_cte` (an `update_all` or `delete_all`
      CTE anywhere in the query, including inside CTEs, joined subqueries,
      `where` and `order_by` subqueries and combination branches) and `:fragment_cte`.
    * **Clauses.** `:existing_select` (`select` or `select_merge`),
      `:aggregate` (`group_by`, `having` or `windows`), `:lock`, `:distinct`
      (any form), `:with_ties`, and `:limit` for a `limit` or `offset` that is
      neither a nonnegative integer literal nor a pinned `^n`. A pinned value
      is checked when the query is scoped or run.
    * **Preloads and combinations.** `:preload_requires_execute` for any
      preload in `:scope` mode. `:execute` mode accepts them structurally;
      `Authzura.Scope.build/4` translates and validates them with
      `Authzura.Preload.Tree`, which rejects every non-plain form. For `union`, `union_all`, `except` and
      `intersect`: `:combination_preload` when the parent or a branch has a
      preload, `:combination_tables` when a branch names another table, and
      `:combination_shape` when a branch has its own select, preload,
      combination or unsupported clause, or a source other than the parent's.
      Whether branches share the same *physical* root (prefixes included) is
      checked by `Authzura.Scope`.
    * **Aliases.** `:reserved_alias` for any `:__authzura_*` binding.

  The caller's `join`, `where`, `order_by` and read-only CTEs are accepted.
  """

  alias Authzura.Util
  alias Ecto.{Query, SubQuery}
  alias Ecto.Query.{FromExpr, LimitExpr, QueryExpr, WithExpr}

  @type mode :: :scope | :execute

  @type reason ::
          :fragment_source
          | :subquery_source
          | :modifying_cte
          | :fragment_cte
          | :existing_select
          | :aggregate
          | :lock
          | :distinct
          | :with_ties
          | :limit
          | :preload_requires_execute
          | :combination_tables
          | :combination_preload
          | :combination_shape
          | :reserved_alias

  @reserved "__authzura_"

  @doc "Validates `query` for `mode`. See the moduledoc for the reasons."
  @spec validate(Query.t(), mode()) :: :ok | {:error, {:unsupported_query, reason()}}
  def validate(%Query{} = query, mode) when mode in [:scope, :execute] do
    tree = tree(query)

    with :ok <- source(query),
         :ok <- Util.first_error(tree, &ctes/1),
         :ok <- clauses(query),
         :ok <- combinations(query),
         :ok <- preloads(query, mode),
         :ok <- Util.first_error(tree, &aliases/1) do
      :ok
    else
      {:error, reason} -> {:error, {:unsupported_query, reason}}
    end
  end

  # Every query reachable from `query`, itself included.
  defp tree(%Query{} = query), do: [query | Enum.flat_map(children(query), &tree/1)]

  defp children(%Query{
         with_ctes: ctes,
         from: from,
         joins: joins,
         combinations: branches,
         wheres: wheres,
         order_bys: order_bys
       }) do
    cte_queries(ctes) ++
      sub([from | joins]) ++
      Enum.map(branches, fn {_kind, branch} -> branch end) ++
      Enum.flat_map(wheres ++ order_bys, &expr_subqueries/1)
  end

  defp cte_queries(%WithExpr{queries: queries}),
    do: for({_name, _opts, %Query{} = cte} <- queries, do: cte)

  defp cte_queries(nil), do: []

  defp sub(exprs),
    do: for(%{source: %SubQuery{query: %Query{} = inner}} <- exprs, do: inner)

  # `where` and `order_by` expressions; Ecto refuses subqueries in a join's
  # `on`, and `having` is rejected outright.
  defp expr_subqueries(%{subqueries: subqueries}),
    do: for(%SubQuery{query: %Query{} = inner} <- subqueries, do: inner)

  # Sources.

  defp source(%Query{from: from}), do: root_source(from)

  defp root_source(%FromExpr{source: {name, _schema}}) when is_binary(name), do: :ok
  defp root_source(%FromExpr{source: %SubQuery{}}), do: {:error, :subquery_source}
  defp root_source(_from), do: {:error, :fragment_source}

  defp ctes(%Query{with_ctes: %WithExpr{queries: queries}}), do: Util.first_error(queries, &cte/1)
  defp ctes(%Query{with_ctes: nil}), do: :ok

  defp cte({_name, _opts, %QueryExpr{}}), do: {:error, :fragment_cte}

  defp cte({_name, %{operation: operation}, _query}) when operation in [:update_all, :delete_all],
    do: {:error, :modifying_cte}

  defp cte({_name, _opts, %Query{}}), do: :ok

  # Clauses.

  defp clauses(%Query{select: select}) when select != nil, do: {:error, :existing_select}
  defp clauses(%Query{group_bys: [_ | _]}), do: {:error, :aggregate}
  defp clauses(%Query{havings: [_ | _]}), do: {:error, :aggregate}
  defp clauses(%Query{windows: [_ | _]}), do: {:error, :aggregate}
  defp clauses(%Query{lock: lock}) when lock != nil, do: {:error, :lock}
  defp clauses(%Query{distinct: distinct}) when distinct != nil, do: {:error, :distinct}
  defp clauses(%Query{limit: %LimitExpr{with_ties: true}}), do: {:error, :with_ties}

  defp clauses(%Query{limit: limit, offset: offset}) do
    with :ok <- bound(limit), do: bound(offset)
  end

  defp bound(nil), do: :ok
  defp bound(%{expr: n}) when is_integer(n) and n >= 0, do: :ok
  defp bound(%{expr: {:^, _meta, [_index]}}), do: :ok
  defp bound(_expr), do: {:error, :limit}

  # Preloads.

  defp preloads(%Query{preloads: [], assocs: []}, _mode), do: :ok
  defp preloads(%Query{}, :execute), do: :ok
  defp preloads(%Query{}, :scope), do: {:error, :preload_requires_execute}

  defp preload?(%Query{preloads: [], assocs: []}), do: false
  defp preload?(%Query{}), do: true

  # Combinations.

  defp combinations(%Query{combinations: []}), do: :ok

  defp combinations(%Query{preloads: [], assocs: [], combinations: branches} = query),
    do: Util.first_error(branches, &branch(&1, query))

  defp combinations(%Query{}), do: {:error, :combination_preload}

  defp branch({_kind, %Query{from: branch_from} = branch}, %Query{from: %FromExpr{source: source}}) do
    cond do
      preload?(branch) -> {:error, :combination_preload}
      different_table?(branch_from, source) -> {:error, :combination_tables}
      branch_shape(branch, source) != :ok -> {:error, :combination_shape}
      true -> :ok
    end
  end

  defp different_table?(%FromExpr{source: {name, _schema}}, {root, _root_schema})
       when is_binary(name),
       do: name != root

  defp different_table?(_from, _source), do: false

  defp branch_shape(%Query{from: %FromExpr{source: source}, combinations: []} = branch, source),
    do: clauses(branch)

  defp branch_shape(_branch, _source), do: {:error, :combination_shape}

  # Aliases. `aliases` holds every named binding: the `from` and each join.

  defp aliases(%Query{aliases: aliases}),
    do: aliases |> Map.keys() |> Enum.any?(&reserved?/1) |> reserved()

  defp reserved?(name) when is_atom(name),
    do: name |> Atom.to_string() |> String.starts_with?(@reserved)

  defp reserved(true), do: {:error, :reserved_alias}
  defp reserved(false), do: :ok
end

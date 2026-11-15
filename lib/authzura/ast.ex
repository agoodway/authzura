defmodule Authzura.AST do
  @moduledoc """
  The source-independent filter AST and helpers that walk it.

  Depth and node limits are measured in AST units: every node, including
  `:and`, `:or` and `:not`, counts as one.
  """

  alias Authzura.Model.Table

  @type value :: {:literal, term()} | {:session, String.t()}

  @type t ::
          {:and, [t()]}
          | {:or, [t()]}
          | {:not, t()}
          | {:compare, String.t(), atom(), value()}
          | {:relationship, String.t(), t()}
          | {:exists, Table.table_ref(), t()}

  @like_ops [:like, :nlike, :ilike, :nilike]
  @pattern_ops @like_ops ++ [:similar, :nsimilar, :regex, :iregex, :nregex, :niregex]

  @doc "The `LIKE`-family operators: their right-hand side is a `LIKE` pattern."
  @spec like_ops() :: [atom()]
  def like_ops, do: @like_ops

  @doc "Every pattern operator: the `LIKE` family, `SIMILAR TO` and the regex matches."
  @spec pattern_ops() :: [atom()]
  def pattern_ops, do: @pattern_ops

  @doc "Returns the names of every session variable the filter references."
  @spec session_refs(t()) :: MapSet.t(String.t())
  def session_refs(node), do: union(node, &own_session_refs/1, &children/1)

  @doc "Counts nested relationship and exists levels."
  @spec binding_depth(t()) :: non_neg_integer()
  def binding_depth(node), do: depth(node, &binding_weight/1)

  @doc "Counts every nesting level, including `:and`, `:or` and `:not`."
  @spec syntactic_depth(t()) :: pos_integer()
  def syntactic_depth(node), do: depth(node, fn _node -> 1 end)

  @doc "Counts every node in the filter."
  @spec node_count(t()) :: pos_integer()
  def node_count(node) do
    node |> children() |> Enum.reduce(1, &(node_count(&1) + &2))
  end

  @doc """
  Flattens `ast` into its top-level conjuncts: the children of nested `:and`
  nodes, reached through no `:or`, `:not`, relationship or exists node. `nil`
  has none.
  """
  @spec conjuncts(t() | nil) :: [t()]
  def conjuncts(nil), do: []
  def conjuncts({:and, children}), do: Enum.flat_map(children, &conjuncts/1)
  def conjuncts(node), do: [node]

  @doc "Returns the columns compared on the root table, skipping relationship and exists subtrees."
  @spec root_columns(t()) :: MapSet.t(String.t())
  def root_columns(node), do: union(node, &own_column/1, &root_children/1)

  @doc "Returns every comparison in the filter, in document order, at any depth."
  @spec comparisons(t()) :: [t()]
  def comparisons({:compare, _column, _op, _value} = node), do: [node]
  def comparisons(node), do: node |> children() |> Enum.flat_map(&comparisons/1)

  # Traversal lives here: a new node shape needs one `children/1` clause.
  defp children({:compare, _column, _op, _value}), do: []
  defp children({:not, child}), do: [child]
  defp children({:relationship, _name, child}), do: [child]
  defp children({:exists, _table, child}), do: [child]
  defp children({group, children}) when group in [:and, :or], do: children

  defp root_children({scope, _name, _child}) when scope in [:relationship, :exists], do: []
  defp root_children(node), do: children(node)

  defp binding_weight({scope, _name, _child}) when scope in [:relationship, :exists], do: 1
  defp binding_weight(_node), do: 0

  defp own_session_refs({:compare, _column, _op, {:session, name}}), do: [name]
  defp own_session_refs(_node), do: []

  defp own_column({:compare, column, _op, _value}), do: [column]
  defp own_column(_node), do: []

  defp depth(node, weight) do
    deepest = node |> children() |> Enum.map(&depth(&1, weight)) |> Enum.max(fn -> 0 end)
    weight.(node) + deepest
  end

  defp union(node, own, next) do
    node
    |> next.()
    |> Enum.reduce(MapSet.new(own.(node)), &MapSet.union(union(&1, own, next), &2))
  end
end

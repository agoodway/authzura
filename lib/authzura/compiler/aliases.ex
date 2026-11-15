defmodule Authzura.Compiler.Aliases do
  @moduledoc """
  The fixed pool of correlation aliases, `:__authzura_0` through
  `:__authzura_15`.

  Alias 0 is the root binding; each nested relationship or `_exists` level
  takes the next one. The pool is written out literally so no atom is ever
  built at runtime.
  """

  @max 15

  @doc "The highest alias index (and so the deepest binding depth)."
  @spec max_index() :: 15
  def max_index, do: @max

  @doc """
  Returns the alias at `index` (0..15). Any other index raises
  `FunctionClauseError`; callers check depth first.

      iex> Authzura.Compiler.Aliases.at(0)
      :__authzura_0
      iex> Authzura.Compiler.Aliases.at(15)
      :__authzura_15
  """
  @spec at(0..15) :: atom()
  def at(0), do: :__authzura_0
  def at(1), do: :__authzura_1
  def at(2), do: :__authzura_2
  def at(3), do: :__authzura_3
  def at(4), do: :__authzura_4
  def at(5), do: :__authzura_5
  def at(6), do: :__authzura_6
  def at(7), do: :__authzura_7
  def at(8), do: :__authzura_8
  def at(9), do: :__authzura_9
  def at(10), do: :__authzura_10
  def at(11), do: :__authzura_11
  def at(12), do: :__authzura_12
  def at(13), do: :__authzura_13
  def at(14), do: :__authzura_14
  def at(15), do: :__authzura_15
end

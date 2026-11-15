defmodule Authzura.Util do
  @moduledoc "Small helpers shared across Authzura's modules."

  @directions Map.new(
                ~w(asc desc asc_nulls_first asc_nulls_last desc_nulls_first desc_nulls_last)a,
                &{&1, &1}
              )

  @string_directions Map.new(@directions, fn {dir, dir} -> {Atom.to_string(dir), dir} end)

  @typedoc "A sort direction, as Ecto's `order_by` takes it."
  @type direction ::
          :asc | :desc | :asc_nulls_first | :asc_nulls_last | :desc_nulls_first | :desc_nulls_last

  @doc """
  Guards a map that is not a struct, the shape JSON decodes to.
  """
  defguard is_plain_map(term) when is_map(term) and not is_struct(term)

  @doc """
  Maps `fun` over `list`, where `fun` returns `{:ok, value}` or an error.
  Returns `{:ok, values}` in order, or the first error, without calling
  `fun` on the rest.

      iex> Authzura.Util.map_ok([1, 2], &{:ok, &1 * 2})
      {:ok, [2, 4]}
      iex> Authzura.Util.map_ok([1, :x, :y], fn
      ...>   n when is_integer(n) -> {:ok, n}
      ...>   other -> {:error, other}
      ...> end)
      {:error, :x}
  """
  @spec map_ok([a], (a -> {:ok, b} | error)) :: {:ok, [b]} | error
        when a: term(), b: term(), error: term()
  def map_ok(list, fun) when is_list(list) and is_function(fun, 1) do
    list
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case fun.(item) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        error -> {:halt, error}
      end
    end)
    |> reverse()
  end

  @doc """
  Reads a sort direction given as an atom or the same name as a string,
  without creating atoms.

      iex> Authzura.Util.direction("desc_nulls_last")
      {:ok, :desc_nulls_last}
      iex> Authzura.Util.direction(:asc)
      {:ok, :asc}
      iex> Authzura.Util.direction("sideways")
      :error
  """
  @spec direction(term()) :: {:ok, direction()} | :error
  def direction(direction) when is_map_key(@directions, direction),
    do: {:ok, Map.fetch!(@directions, direction)}

  def direction(direction) when is_map_key(@string_directions, direction),
    do: {:ok, Map.fetch!(@string_directions, direction)}

  def direction(_direction), do: :error

  @doc """
  `:ok` for no forbidden columns, otherwise the public
  `{:forbidden_columns, columns}` denial.

      iex> Authzura.Util.forbidden_columns([])
      :ok
      iex> Authzura.Util.forbidden_columns(["salary"])
      {:error, {:forbidden_columns, ["salary"]}}
  """
  @spec forbidden_columns([String.t()]) :: :ok | {:error, {:forbidden_columns, [String.t()]}}
  def forbidden_columns([]), do: :ok
  def forbidden_columns([_ | _] = columns), do: {:error, {:forbidden_columns, columns}}

  @doc """
  Runs `check` on each item of `items` until one returns something other
  than `:ok`, and returns that; `:ok` when every check passes.

      iex> Authzura.Util.first_error([1, 2], fn _n -> :ok end)
      :ok
      iex> Authzura.Util.first_error([1, 2, 3], fn
      ...>   1 -> :ok
      ...>   n -> {:error, n}
      ...> end)
      {:error, 2}
  """
  @spec first_error(Enumerable.t(), (term() -> :ok | error)) :: :ok | error when error: term()
  def first_error(items, check) when is_function(check, 1),
    do: Enum.find_value(items, :ok, &failure(check.(&1)))

  defp failure(:ok), do: nil
  defp failure(error), do: error

  defp reverse({:ok, values}), do: {:ok, Enum.reverse(values)}
  defp reverse(error), do: error
end

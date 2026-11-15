defmodule Authzura.Bench.Stats do
  @moduledoc """
  The summary statistics the benchmarks share. Test harness only.
  """

  @doc """
  The median of a non-empty list of numbers: the middle value, or the mean
  of the two middle values.

      iex> Authzura.Bench.Stats.median([3, 1, 2])
      2
      iex> Authzura.Bench.Stats.median([4, 1, 2, 3])
      2.5
  """
  @spec median([number(), ...]) :: number()
  def median([_ | _] = numbers) do
    sorted = Enum.sort(numbers)
    middle = div(length(sorted), 2)

    case rem(length(sorted), 2) do
      1 -> Enum.at(sorted, middle)
      0 -> (Enum.at(sorted, middle - 1) + Enum.at(sorted, middle)) / 2
    end
  end

  @doc """
  The coefficient of variation: the **sample** standard deviation (`n - 1`)
  over the mean. It is the conservative choice for a handful of
  repetitions, leaning toward "inconclusive". `0.0` for a single value or a
  zero mean.

      iex> Authzura.Bench.Stats.cv([2.0, 2.0, 2.0])
      0.0
      iex> Float.round(Authzura.Bench.Stats.cv([1.0, 3.0]), 4)
      0.7071
  """
  @spec cv([number(), ...]) :: float()
  def cv([_single]), do: 0.0

  def cv([_ | _] = numbers) do
    count = length(numbers)
    mean = Enum.sum(numbers) / count
    variance = Enum.sum_by(numbers, &((&1 - mean) ** 2)) / (count - 1)

    if mean == 0, do: 0.0, else: :math.sqrt(variance) / mean
  end
end

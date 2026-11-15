defmodule Authzura.Adapters.Postgres.Citext do
  @moduledoc """
  An `Ecto.Type` for binding `citext` parameters.

  Its only job is the parameter cast: `type(^values, {:array, Citext})`
  emits `$n::citext[]`, so preload keys compare to a `citext` column
  case-insensitively, as Postgres compares them. A `varchar[]` parameter
  would compare case-sensitively. Strings pass through unchanged; anything else is refused.
  """

  use Ecto.Type

  alias Ecto.Type

  @type t :: String.t()

  @impl Type
  @doc "The database type, `:citext`."
  @spec type() :: :citext
  def type, do: :citext

  @impl Type
  @doc "Accepts a string as is."
  @spec cast(term()) :: {:ok, t()} | :error
  def cast(value) when is_binary(value), do: {:ok, value}
  def cast(_value), do: :error

  @impl Type
  @doc "Loads a string as is."
  @spec load(term()) :: {:ok, t()} | :error
  def load(value) when is_binary(value), do: {:ok, value}
  def load(_value), do: :error

  @impl Type
  @doc "Dumps a string as is."
  @spec dump(term()) :: {:ok, t()} | :error
  def dump(value) when is_binary(value), do: {:ok, value}
  def dump(_value), do: :error
end

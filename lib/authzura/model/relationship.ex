defmodule Authzura.Model.Relationship do
  @moduledoc """
  A relationship from one table to another, with its column mapping.

  `preloadable?` defaults to `false`: `Authzura.Validator` grants it at load
  only when preloads can batch the mapping's key kinds safely. A relationship
  that is not preloadable still works in filters.
  """

  alias Authzura.Model.Table

  @enforce_keys [:name, :kind, :target, :mapping]
  defstruct [:name, :kind, :target, :mapping, preloadable?: false]

  @type t :: %__MODULE__{
          name: String.t(),
          kind: :object | :array,
          target: Table.table_ref(),
          mapping: [{local :: String.t(), remote :: String.t()}],
          preloadable?: boolean()
        }
end

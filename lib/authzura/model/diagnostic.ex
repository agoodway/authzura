defmodule Authzura.Model.Diagnostic do
  @moduledoc """
  A finding recorded while loading or validating permissions.

  A `:deny` diagnostic means the role, table and operation it names is
  refused. A `:warning` records a narrower loss, such as a relationship that
  cannot be preloaded.

  A diagnostic about a function permission names the function in `function`
  and carries no `table`.
  """

  alias Authzura.Model.{Permission, Snapshot, Table}

  @enforce_keys [:severity, :reason]
  defstruct [:severity, :role, :table, :function, :operation, :reason, path: []]

  @type t :: %__MODULE__{
          severity: :deny | :warning,
          role: String.t() | nil,
          table: Table.table_ref() | nil,
          function: Snapshot.function_ref() | nil,
          operation: Permission.operation() | nil,
          path: [String.t()],
          reason: term()
        }
end

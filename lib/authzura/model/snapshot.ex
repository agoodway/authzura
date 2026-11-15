defmodule Authzura.Model.Snapshot do
  @moduledoc """
  An immutable view of every table and permission a source produced.

  `version` is opaque to Authzura; each source decides what it is.
  """

  alias Authzura.Model.{Diagnostic, Permission, Table}

  @enforce_keys [:version]
  defstruct [:version, tables: %{}, permissions: %{}, diagnostics: []]

  @type t :: %__MODULE__{
          tables: %{Table.table_ref() => Table.t()},
          permissions: %{
            {String.t(), Table.table_ref(), Permission.operation()} => Permission.t()
          },
          version: term(),
          diagnostics: [Diagnostic.t()]
        }
end

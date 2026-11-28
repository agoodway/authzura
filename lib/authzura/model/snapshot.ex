defmodule Authzura.Model.Snapshot do
  @moduledoc """
  An immutable view of every table, permission and function grant a source
  produced.

  `version` is opaque to Authzura; each source decides what it is.

  `functions` holds the explicit execute grants of the tracked functions: a
  function reference `{schema, name}` maps to the `MapSet` of roles allowed to
  execute it. A tracked function nobody may execute maps to an empty set, so
  "tracked, no grants" differs from "not tracked". Only grants written in the
  metadata are recorded; a source never infers one (see
  `Authzura.Sources.Hasura.Metadata`).
  """

  alias Authzura.Model.{Diagnostic, Permission, Table}

  @enforce_keys [:version]
  defstruct [:version, tables: %{}, permissions: %{}, functions: %{}, diagnostics: []]

  @typedoc "A function's schema and name."
  @type function_ref :: {schema :: String.t(), name :: String.t()}

  @type t :: %__MODULE__{
          tables: %{Table.table_ref() => Table.t()},
          permissions: %{
            {String.t(), Table.table_ref(), Permission.operation()} => Permission.t()
          },
          functions: %{function_ref() => MapSet.t(String.t())},
          version: term(),
          diagnostics: [Diagnostic.t()]
        }
end

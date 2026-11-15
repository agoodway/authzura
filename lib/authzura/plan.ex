defmodule Authzura.Plan do
  @moduledoc """
  A scoped read, shared by `scope/3`, the input APIs, the executors and the
  preload loader.

    * `query` - the caller's query with the root prefix pinned, the row
      filter ANDed in, the projection selected and the limit capped
    * `root` - the physical `{prefix, source}` of the root table
    * `projection` - the selected columns. The select itself is a map, so
      result rows carry no column order. `key` is the result key
      (a field atom for schema queries, the column string for table queries);
      `public?` is `false` for columns read only for stitching
    * `shape` - `:map_by_field` for schema queries, `:map_by_column` for
      table queries
    * `preloads` - the validated preload nodes (`Authzura.Preload.Tree`), or `nil`
    * `repo` and `adapter` - the instance's data repo and adapter, from the
      generation the plan was built with. The plan never holds the
      generation itself: a process holding a plan keeps only these small
      terms, so publishing a new generation (which makes every process
      still referencing the old one copy it) costs it nothing
    * `session` - pinned for the whole operation
    * `exec` - validated execution settings from the per-call options
    * `other_columns` - the selected columns of base kind `:other`, at
      the root and at every preload level, as `{column, pg_type}`: a
      value Postgrex cannot decode is reported as one of them
    * `enum_comparisons?` - whether the read binds enum labels in their
      own type (a row filter or input comparing an enum column, or an enum
      preload key). Only then is a Postgres `22P02` or `42704` taken to mean
      the generation no longer matches the database (`:stale_permissions`)
    * `input` - the untrusted input filter of `Authzura.Input`, or `nil`.
      Its literals that only the database can judge are checked with the
      adapter's `c:Authzura.Adapter.check_input/4` before the read
    * `cache_statements?` - whether the read's statements may enter Ecto's
      query cache and the connections' prepared statements. `false` for
      plans built from an untrusted request (`Authzura.Input`), whose
      shapes the client chooses: each would otherwise stay cached until a
      restart. The SQL and the results are the same either way
  """

  alias Authzura.{AST, Session}
  alias Authzura.Model.Table
  alias Authzura.Preload.Tree
  alias Ecto.Query

  @enforce_keys [:query, :root, :projection, :shape, :repo, :adapter, :session, :exec]
  defstruct [
    :query,
    :root,
    :projection,
    :shape,
    :repo,
    :adapter,
    :session,
    :exec,
    preloads: nil,
    input: nil,
    other_columns: [],
    enum_comparisons?: false,
    cache_statements?: true
  ]

  @type column :: %{key: atom() | String.t(), column: String.t(), public?: boolean()}

  @type exec :: %{
          instance: atom(),
          read_only: :transaction | :connection,
          repo_opts: keyword(),
          input_pattern_timeout: pos_integer() | nil,
          in_transaction: :refuse | :trust_isolation,
          hooks: %{optional(:between_levels) => (-> any())},
          isolation: :repeatable_read | :read_committed
        }

  @type t :: %__MODULE__{
          query: Query.t(),
          root: Table.table_ref(),
          projection: [column()],
          shape: :map_by_field | :map_by_column,
          preloads: [Tree.preload_node()] | nil,
          repo: module(),
          adapter: module(),
          session: Session.t(),
          exec: exec(),
          input: AST.t() | nil,
          other_columns: [{String.t(), String.t()}],
          enum_comparisons?: boolean(),
          cache_statements?: boolean()
        }
end

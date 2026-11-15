defmodule Authzura.Options do
  @moduledoc """
  NimbleOptions schemas for Authzura.

  The instance schema validates the options given to `{Authzura, opts}`; the
  per-call schema validates the options of the read functions.
  """

  alias Authzura.Adapters.Postgres
  alias Authzura.Sources.Hasura

  @instance NimbleOptions.new!(
              name: [
                type: :atom,
                default: Authzura,
                doc: "The instance name. Per-call functions take it as `instance:`."
              ],
              repo: [
                type: :atom,
                required: true,
                doc: "The data repo: introspection and `all`/`one` run through it."
              ],
              source: [
                type: {:tuple, [:atom, :keyword_list]},
                default: {Hasura, []},
                doc:
                  "The `Authzura.Source` and its options. The source's `:repo` defaults to the instance `:repo`."
              ],
              adapter: [
                type: :atom,
                default: Postgres,
                doc: "The `Authzura.Adapter`."
              ],
              default_prefix: [
                type: :string,
                default: "public",
                doc: "The schema used when a query names none."
              ],
              admin_role: [
                type: {:or, [:string, nil]},
                default: nil,
                doc:
                  "An opt-in role name that bypasses permissions: it gets every column, no filter and no limit on any tracked table. `nil` (the default) disables it. Give it only to trusted sessions."
              ],
              read_only: [
                type: {:in, [:transaction, :connection]},
                default: :transaction,
                doc: """
                How executor reads are kept read-only. `:transaction` (the default) runs a read without preloads in a transaction whose first statement is `SET TRANSACTION READ ONLY`. `:connection` trusts the repo's connections to be read-only already (a hot standby, or `default_transaction_read_only = on` for the role, the database or every connection), so such a read is one statement; the Store checks `transaction_read_only` at every load and poll: a load fails while it is off, and after a failed poll reads go back to `SET TRANSACTION READ ONLY` until the next successful load. It requires a `poll_interval` and a finite `max_staleness`. Reads with preloads keep their `REPEATABLE READ, READ ONLY` transaction in both modes. See the Security guide.
                """
              ],
              poll_interval: [
                type: {:or, [:pos_integer, nil]},
                default: 5_000,
                doc:
                  "Milliseconds between version polls, or `nil` for manual reload only. With `nil` and a finite `max_staleness`, reads fail with `:stale_permissions` once `max_staleness` passes, unless you call `Authzura.reload/1` on a timer or set `max_staleness: :infinity`."
              ],
              max_staleness: [
                type: {:or, [:non_neg_integer, {:in, [:infinity]}]},
                default: 60_000,
                doc:
                  "Milliseconds a generation may go unconfirmed before reads fail with `:stale_permissions`, or `:infinity`."
              ],
              input_pattern_timeout: [
                type: {:or, [:pos_integer, nil]},
                default: 5_000,
                doc: """
                The `statement_timeout`, in milliseconds per statement, of an `all_input/4` read whose filter carries a `SIMILAR TO` or regular-expression pattern (the root statement and each preload level get it in full), or `nil` for the database's own. The pattern pre-check sets it as a transaction-local `statement_timeout` in the same statement, so it costs no round trip, and it never raises a stricter one: the session's own `statement_timeout` is kept when it is lower (and nonzero). A statement it cancels is `{:invalid_input, :statement_timeout}`. It applies only inside the transaction the executor opens: in a caller's transaction, and in `read_only: :connection` reads without preloads (one statement, no transaction), the database's own `statement_timeout` applies. See the Security guide.
                """
              ],
              input_index_pushdown: [
                type: :boolean,
                default: false,
                doc: """
                Lets index-friendly input comparisons also run outside the input fence. Off by default: the whole input of `all_input/4` and `scope_input/4` runs behind the permission fence, so Postgres cannot use an index on a column it filters and a selective filter reads every row the role may see.

                An instance option, set where the instance starts, never per call and never from request input:

                    {Authzura, name: MyApp.Authz, repo: MyApp.Repo, input_index_pushdown: true}

                What moves: an `_eq`, or an `_in` of up to 100 values, reached only through AND (`_and` or the filter map), on a plain stored table column whose `pg_catalog` `=` is leakproof, after binary-coercible relabels (`varchar` as `text`): `int2`, `int4`, `int8`, `float4`, `float8`, `text`, `varchar`, `bpchar`, `name`, `uuid`, `bool`, `date`, `timestamp`, `timestamptz`. The copy is pinned to `OPERATOR(pg_catalog.=)` and the fence still holds the whole input.

                What stays fenced (correct, no index speed): `_or`, `_not`, relationships, ranges, `_neq`, patterns and JSON operators, `numeric`, enum, `citext` and `jsonb` columns, domains, views, generated columns, `_in` of more than 100 values, and types without a leakproof equality or a binder.

                The rows returned are the same with the option on or off, there is no new error, and with it off the SQL is byte-identical to before. Risks: a Postgres-RLS-style timing side channel on whether hidden rows with a given value exist; the order of ties under `LIMIT` may change with the plan; a generation loaded before owner DDL keeps its decisions until the next reload; and roles whose permission goes through a relationship (`EXISTS`) still pay about 2-3 times on input reads in both modes, because the fence evaluates the permission twice. See the [Security guide](security.html#input-index-push-down) for the full table.
                """
              ],
              max_preload_depth: [
                type: :pos_integer,
                default: 4,
                doc: "The deepest preload tree accepted."
              ],
              max_preload_nodes: [
                type: :pos_integer,
                default: 16,
                doc: "The most preload nodes accepted."
              ],
              clock: [
                type: {:fun, 1},
                default: &System.monotonic_time/1,
                doc:
                  "A test hook: called with `:millisecond` for monotonic time, used for freshness. Default `&System.monotonic_time/1`."
              ],
              backoff: [
                type: {:or, [:non_neg_integer, {:tuple, [:non_neg_integer, :non_neg_integer]}]},
                default: {1_000, 30_000},
                doc: false
              ]
            )

  @call_schema [
    instance: [
      type: :atom,
      default: Authzura,
      doc: "The instance to read permissions from."
    ],
    columns: [
      type: {:list, {:or, [:atom, :string]}},
      doc:
        "The columns to select: field atoms (or column strings) for schema queries, column strings for table queries. Defaults to every allowed column except those of base kind `:other` (an extension type the repo's Postgrex types cannot decode, a composite), which are selected only when named."
    ],
    table: [
      type: {:tuple, [:string, :string]},
      doc:
        "An assertion on the derived `{prefix, table}` root; a mismatch fails with `{:unsupported_query, :table_mismatch}`. It never overrides the root."
    ],
    preload: [
      type: :any,
      doc: "Hasura relationships to preload. Executor-only."
    ],
    in_transaction: [
      type: {:in, [:refuse, :trust_isolation]},
      default: :refuse,
      doc:
        "Inside a caller's transaction, preloads are refused unless `:trust_isolation` states it is already `REPEATABLE READ` or stronger."
    ],
    repo_opts: [
      type: :keyword_list,
      default: [],
      doc:
        "Repo options used when executing. Only `:timeout`, `:log`, `:telemetry_options` and `:telemetry_event` are allowed; the executor enforces this."
    ]
  ]

  # Test hooks: they remove the one-snapshot guarantee of preloads, so they
  # exist only in a build configured with `config :authzura, :test_hooks, true`.
  @hook_schema [
    between_levels: [type: {:fun, 0}, doc: false],
    isolation: [
      type: {:in, [:repeatable_read, :read_committed]},
      default: :repeatable_read,
      doc: false
    ]
  ]

  @test_hooks Application.compile_env(:authzura, :test_hooks, false)
  @call_schema if @test_hooks, do: @call_schema ++ @hook_schema, else: @call_schema

  @call NimbleOptions.new!(@call_schema)

  # `filter_rows/3` applies no projection and runs nothing: only the instance
  # and the root assertion apply.
  @filter_rows NimbleOptions.new!(Keyword.take(@call_schema, [:instance, :table]))

  # The same schema with `:columns` accepting any list: `call!/1` uses it only
  # once a guard walk has found every column an atom or a string, because
  # `{:or, [:atom, :string]}` builds and inspects a rejection for each string
  # before accepting it. Anything else gets the full schema and its errors.
  @call_named_columns NimbleOptions.new!(
                        Keyword.update!(
                          @call_schema,
                          :columns,
                          &Keyword.put(&1, :type, {:list, :any})
                        )
                      )

  # Every per-call option at its default, validated once at compile time.
  @call_defaults NimbleOptions.validate!([], @call)

  @typedoc "Validated instance options."
  @type instance :: %{
          name: atom(),
          repo: module(),
          source: {module(), keyword()},
          adapter: module(),
          default_prefix: String.t(),
          admin_role: String.t() | nil,
          read_only: :transaction | :connection,
          input_pattern_timeout: pos_integer() | nil,
          input_index_pushdown: boolean(),
          poll_interval: pos_integer() | nil,
          max_staleness: non_neg_integer() | :infinity,
          max_preload_depth: pos_integer(),
          max_preload_nodes: pos_integer(),
          clock: (System.time_unit() -> integer()),
          backoff: non_neg_integer() | {non_neg_integer(), non_neg_integer()}
        }

  @doc """
  Validates instance options, raising `NimbleOptions.ValidationError`.

  #{NimbleOptions.docs(@instance)}
  """
  @spec instance!(keyword()) :: instance()
  def instance!(opts), do: opts |> NimbleOptions.validate!(@instance) |> Map.new() |> checked!()

  # `read_only: :connection` relies on the polls to notice when the
  # connections stop being read-only, so it needs them, and a bound on how
  # long an unconfirmed generation may serve.
  defp checked!(%{read_only: :connection, poll_interval: nil}),
    do: invalid!("read_only: :connection requires a poll_interval")

  defp checked!(%{read_only: :connection, max_staleness: :infinity}),
    do: invalid!("read_only: :connection requires a finite max_staleness")

  defp checked!(config), do: config

  defp invalid!(message),
    do: raise(NimbleOptions.ValidationError, key: :read_only, message: message)

  @doc false
  # The per-call schema with or without the test hooks; `call!/1` uses the
  # one this build was configured for.
  @spec call_schema(boolean()) :: keyword()
  def call_schema(true), do: Keyword.merge(@call_schema, @hook_schema)
  def call_schema(false), do: Keyword.drop(@call_schema, Keyword.keys(@hook_schema))

  @doc """
  Validates per-call options (`scope/3`, `all/3`, ...), raising
  `NimbleOptions.ValidationError`. They are kept apart from repo options,
  which go under `repo_opts:`.

  #{NimbleOptions.docs(@call)}
  """
  @spec call!(keyword()) :: keyword()
  def call!([]), do: @call_defaults

  # The common instance-only call skips the schema walk: an atom is all the
  # schema accepts for `:instance`, and every other option takes its default.
  def call!(instance: instance) when is_atom(instance),
    do: Keyword.put(@call_defaults, :instance, instance)

  def call!(opts), do: NimbleOptions.validate!(opts, schema(opts))

  @doc """
  Validates the options of `Authzura.filter_rows/3`, raising
  `NimbleOptions.ValidationError`. Only `:instance` and `:table` apply.

  #{NimbleOptions.docs(@filter_rows)}
  """
  @spec filter_rows!(keyword()) :: keyword()
  def filter_rows!(opts), do: NimbleOptions.validate!(opts, @filter_rows)

  defp schema(opts), do: opts |> named_columns?() |> schema_for()

  defp schema_for(true), do: @call_named_columns
  defp schema_for(false), do: @call

  # Every `:columns` given is a list of atoms and strings, in a keyword list.
  defp named_columns?(opts) do
    Keyword.keyword?(opts) and
      opts |> Keyword.get_values(:columns) |> Enum.all?(&names?/1)
  end

  defp names?(columns) when is_list(columns),
    do: Enum.all?(columns, &(is_atom(&1) or is_binary(&1)))

  defp names?(_columns), do: false
end

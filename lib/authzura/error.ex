defmodule Authzura.Error do
  @moduledoc """
  The catalog of failure reasons, and the exception raised by the `!`
  variants.

  Every read function returns `{:error, reason}` for an expected failure and
  never raises for one; `scope!/3`, `all!/3`, `one!/3` and `get!/4` raise this
  exception with the same term in `:reason`. Match on the shape below, not on
  the message. Nothing is ever returned partially: a failed read returns no
  rows. Metadata telemetry carries only the class of a reason (see
  `Authzura.Telemetry.reason_class/1`).

  ## Kinds

    * **denial** - the role may not do this. Expected at runtime; map it to a
      403 or 404, and do not retry.
    * **bad input** - the request or session value is malformed or out of
      bounds. Fix the input.
    * **misconfiguration** - the calling code or deployment is wrong. It
      does not depend on the role: fix the code or configuration.
    * **stale** - the loaded permissions cannot be trusted right now. Retry
      later or call `Authzura.reload/1`.

  ## Access

  | Reason | Kind | Meaning |
  |---|---|---|
  | `:forbidden` | denial | No select permission for the role on the root table (or on a preloaded relationship's target), a relationship the role may not follow (undeclared, remote, not preloadable), a `filter_rows/3` `relationship:` its parent lacks, or a table Authzura does not track. Unknown and forbidden look the same on purpose. |
  | `:root_field_disabled` | denial | The permission exists, but its `root_fields` do not enable this read (`select`, or `select_by_pk` for `Authzura.get/4`, or `select_aggregate` for a root aggregate). |
  | `{:forbidden_columns, [column]}` | denial | The request names columns the role may not select: from `columns:`, an input filter, `order_by`, or a virtual or unknown schema field. Names are column strings. |
  | `{:missing_session_variable, name}` | bad input | The role's row filter uses `X-Hasura-*` variable `name` and the session lacks it. |
  | `{:invalid_session_value, name, reason}` | bad input | The session variable `name` does not cast to the column's type. |

  ## Availability

  | Reason | Kind | Meaning |
  |---|---|---|
  | `:not_ready` | misconfiguration | The instance has published no permissions: still loading, not started, or its process died. Reads fail closed. Also the normal, retryable state at boot or while the first load is failing. Check `Authzura.status/1`. |
  | `:stale_permissions` | stale | The active generation was not confirmed current within `max_staleness`; or an enum label or type changed since load, in a read that compares enums. The next poll reloads. |

  ## Unsupported query

  `{:unsupported_query, reason}` means the caller's own query or options use
  something Authzura cannot enforce. It is a misconfiguration (a bug in the
  calling code) and does not depend on the role, with the exception noted.

  | `reason` | Meaning |
  |---|---|
  | `:fragment_source`, `:subquery_source` | The root is a fragment, `values` or subquery. |
  | `:modifying_cte`, `:fragment_cte` | A CTE that writes, or is a fragment. Read-only CTEs are fine. |
  | `:existing_select` | The query already has `select` or `select_merge`. |
  | `:aggregate` | `group_by`, `having` or windows. |
  | `:lock`, `:distinct`, `:with_ties` | The clause cannot be enforced. |
  | `:limit` / `:offset` | A limit or offset that is not a non-negative integer. |
  | `:reserved_alias` | A binding named `:__authzura_*`. |
  | `:preload_requires_execute` | A preload with `scope/3`, `scope_input/4` or `filter_rows/3`. Preloads need `all/3` and friends. |
  | `:combination_tables`, `:combination_preload`, `:combination_shape`, `:combination_requires_scope` | A `union`, `intersect` or `except` whose branches differ in table, carry preloads or their own select, or (`filter_rows/3`) any combination at all. |
  | `:empty_columns` | `columns: []`. |
  | `:table_mismatch` | The `table:` assertion does not match the derived root. |
  | `:get_requires_bare_root`, `:no_primary_key` | `Authzura.get/4` on a query with a `where`, `join` and so on, or on a table without a primary key. |
  | `:dynamic_repo` | The process uses a different `put_dynamic_repo/1` than the instance's repo. |
  | `:preload_in_transaction` | Preloads inside a caller's transaction without `in_transaction: :trust_isolation` (or the transaction's isolation is below `REPEATABLE READ`). |
  | `{:option, key}` | A `repo_opts:` key outside `:timeout`, `:log`, `:telemetry_options`, `:telemetry_event`. |
  | `:preload_limit` | The preload tree is over `max_preload_depth` or `max_preload_nodes`. |
  | `:preload` | A malformed preload tree. |
  | `{:preload, name}` | An Ecto preload Authzura cannot translate faithfully, or a relationship whose name or key would overwrite a key of its parent row. |
  | `{:object_cardinality, name}` | An object relationship matched more than one row: a data-integrity problem. |

  ## Bad input

  `{:invalid_input, reason}` comes from `Authzura.scope_input/4`,
  `Authzura.all_input/4` and `Authzura.get/4`. `Authzura.all/3` and
  `Authzura.one/3` can also return `{:order_by, :unorderable}` (a preload's
  `order_by` on a column Postgres cannot sort) and `:rejected_by_database`;
  `:invalid_pattern` and `:statement_timeout` come only from input reads. The request is the caller's, so it is bad input.

  | `reason` | Meaning |
  |---|---|
  | `:not_a_root` | The queryable is not a bare schema or table name. |
  | `:not_a_map` | The request is not a map. |
  | `{:unknown_keys, keys}`, `{:duplicate_key, key}` | An unknown request key, or one given as both atom and string. |
  | `:limit`, `:offset` | Not a non-negative bigint. |
  | `{:columns, :invalid \| :empty}` | `columns` is not a non-empty list of strings. |
  | `{:order_by, :invalid \| :duplicate_column \| :unorderable}` | A bad term, a repeated column, or a column type Postgres cannot sort. |
  | `{:preload, :invalid}` | A preload that is not in its JSON form. |
  | `{:too_many, :columns \| :list \| :patterns \| :order_by \| :preload_order_by}` | A bound exceeded: more columns than the role may see, a list over 10,000 elements, over 16 pattern operands, over 32 `order_by` terms. `:preload_order_by` is more than 32 `order_by` terms in one relationship of an `all_input/4` preload. |
  | `[{path, reason}]` | The filter does not parse or is out of bounds. `path` is the list of keys to the fault, `reason` is the source's (for Hasura, `{:unknown_field, name}` aside, which becomes `{:forbidden_columns, ...}`), or one of `:session_reference`, `:relationship_in_input`, `:too_deep`, `:too_large` at path `[]`. For `get/4`, `[{[column], {:invalid_literal, reason}}]` or `[{[column], :null_operand}]`. |
  | `{:primary_key, :invalid}` | `get/4`'s key is not a single value or every key column exactly once. |
  | `{:invalid_pattern, column}` | A `SIMILAR TO` or regular expression Postgres refuses. Raised before the read runs. |
  | `:statement_timeout` | An input read Postgres cancelled (`query_canceled`): `input_pattern_timeout` for a pattern read, but also the database's own `statement_timeout` or a cancel. |
  | `:rejected_by_database` | Postgres refused a literal in the caller's own predicate (a `like/2` on user text, say). It can reveal that a hidden row reached the predicate; see `Authzura.scope/3`. |

  ## Execution

  | Reason | Kind | Meaning |
  |---|---|---|
  | `:multiple_results` | bad input | `Authzura.one/3` matched more than one row. |
  | `{:unsupported_column_type, column}` or `{:unsupported_column_type, {:type, name}}` | misconfiguration | A selected value's type the repo's Postgrex types cannot decode (PostGIS without its extension, say). Name the columns you need, or add the type. |

  ## Other results

    * `Authzura.reload/1` returns `{:error, term}`: the load failed (database
      error, a source error such as `:unstable_source`, or
      `{:read_only_not_enforced, setting}`); the active generation is kept.
    * `Authzura.Session.new/2` returns `{:invalid_session, kind, term}` and
      `Authzura.JWT.verify/2` its own reasons (see `t:Authzura.JWT.reason/0`).
    * Option errors raise `NimbleOptions.ValidationError`, never an
      `{:error, _}`, as do Postgres failures unrelated to a user literal (a
      write in a caller's trusted code hits `read_only_sql_transaction`, say).
    * `Authzura.Error` itself is raised only by the `!` variants.
  """

  defexception [:reason]

  @typedoc "The exception: `:reason` is what the non-bang function returns in `{:error, reason}`."
  @type t :: %__MODULE__{reason: term()}

  @impl true
  def message(%__MODULE__{reason: reason}), do: "authzura error: #{inspect(reason)}"
end

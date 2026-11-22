# Configuration

An Authzura instance is configured when it is added to the supervision tree.
Every option is documented on `Authzura.Options.instance!/1`; this guide
covers the ones you will change, how permissions stay fresh, and how to
reload them.

## Supervision tree

Add an instance after the repo it reads through:

```elixir
children = [
  MyApp.Repo,
  {Authzura,
   [name: MyApp.Authz, repo: MyApp.Repo] ++ Application.get_env(:my_app, MyApp.Authz, [])}
]
```

`:name` defaults to `Authzura`, which is also the default `instance:` of
every call. `:repo` is the data repo: introspection and `all`/`one` run
through it. The metadata is read through it too, unless the source names its
own repo.

## Options

| Option | Default | Meaning |
|---|---|---|
| `poll_interval` | `5_000` | Milliseconds between version checks; `nil` for manual reloads only |
| `max_staleness` | `60_000` | Milliseconds a generation may go unconfirmed before reads fail with `:stale_permissions`; `:infinity` disables it |
| `admin_role` | `nil` | An opt-in role that bypasses permissions |
| `default_prefix` | `"public"` | The schema used when a query names none |
| `max_preload_depth`, `max_preload_nodes` | `4`, `16` | Bounds on a preload tree |
| `read_only` | `:transaction` | How reads stay read-only; see [Read-only connections](#read-only-connections) |
| `input_pattern_timeout` | `5_000` | `statement_timeout` (ms, per statement) of an `all_input/4` read with a `SIMILAR TO` or regex pattern, never above the session's own; `nil` for the database's alone. See [Security](security.md#input-limits) |
| `input_index_pushdown` | `false` | Also run AND-ed `_eq` (and `_in` up to 100 values) input comparisons on plain, leakproof table columns outside the input fence so Postgres can use an index; everything else stays fenced. A timing side channel on hidden rows. Never from request input. See [Security](security.md#input-index-push-down) |

Because the options are a keyword list, the host application can override
any of them per environment:

```elixir
config :my_app, MyApp.Authz, poll_interval: 2_000, max_staleness: 30_000
```

## Read-only connections

By default a read without preloads runs as four statements: `BEGIN`,
`SET TRANSACTION READ ONLY`, the `SELECT` and `COMMIT`. The `SET` is a named
statement, prepared once per connection, so each is one round trip
(connections started with `prepare: :unnamed`, as behind PgBouncer, prepare
it each time). When the repo's
connections are read-only already, `read_only: :connection` makes that read
one statement, which on a PK lookup takes about a quarter of the
transaction path's wall-clock time on loopback (one round trip instead of
four):

```elixir
{Authzura, name: MyApp.Authz, repo: MyApp.ReplicaRepo, read_only: :connection}
```

Use it only with a repo dedicated to Authzura reads. Its connections must
report `transaction_read_only = on` (that is what Authzura checks), through
a hot standby, which refuses writes whatever the session says, or through a
default that makes every statement read-only:
`ALTER ROLE app_reader SET default_transaction_read_only = on`,
`ALTER DATABASE app SET default_transaction_read_only = on`, or Postgrex's
`after_connect: {Postgrex, :query!, ["SET default_transaction_read_only = on", []]}`.

Only a hot standby, or a role without write privileges on the data, actually
enforces read-only. A default is just a default: any
`SET default_transaction_read_only = off` or
`SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE` on a connection
turns it off for that connection. So pair the default with a role that
cannot write, and let nothing else issue `SET`s on this repo's connections.

The instance requires a `poll_interval` and a finite `max_staleness` in this
mode. The Store checks `current_setting('transaction_read_only')` through the
repo at every load and every poll:

- A load fails while the check fails: nothing is served before one passes,
  and `Authzura.status/1` reports `last_error: :read_only_not_enforced`.
- After a failed poll, reads go back to `SET TRANSACTION READ ONLY` and stay
  there until the next successful load (a reload, or a restart), even if
  later checks pass, and a warning is logged.

Each check samples one pooled connection, so detection is probabilistic: a
connection that becomes writable is noticed only when a check happens to
read it, and until then reads on it run as it allows. The fallback being
sticky bounds the exposure to the time before that first detection, which
is why this mode relies on a repo dedicated to Authzura reads. Reads with preloads keep their
`REPEATABLE READ, READ ONLY` transaction, which they need for one snapshot.
See [Security](security.md#read-only-connections).

## Split repos

When `hdb_catalog` lives in a different database from the data, pass the data
repo as `:repo` and the metadata repo to the source:

    repo: DataRepo,
    source: {Authzura.Sources.Hasura, repo: MetadataRepo, source_name: "default"}

## Caching and freshness

The Store loads a **generation**, an immutable snapshot of the metadata and
the introspected tables, and publishes it for lock-free reads. A generation
is rebuilt only when something changed:

- Every `poll_interval`, the Store does a cheap version check: the metadata's
  `resource_version` plus a fingerprint of the tracked tables' columns and
  keys. An unchanged version just renews freshness; a changed one reloads.
- Authzura polls rather than listening for notifications, so there is no
  `NOTIFY` or trigger to install. Hasura v2 itself synchronizes metadata
  between instances by polling (`HASURA_GRAPHQL_SCHEMA_SYNC_POLL_INTERVAL`).
- A generation not confirmed current for `max_staleness` fails reads with
  `:stale_permissions`, and a failed load keeps the active generation. Reads
  fail closed rather than serve permissions that may be out of date, but
  only once that window has passed: until then a failed reload leaves the
  old generation serving, even when the poll saw a new version (see
  [Security](security.md#revocation-is-bounded-by-max_staleness)).
- Until the first generation is published, reads return `:not_ready`.

## Reload and status

Call `Authzura.reload/1` as a deploy hook after `hasura metadata apply`, so
the change applies at once instead of at the next poll:

```elixir
:ok = Authzura.reload(MyApp.Authz)

%{ready?: true, fresh?: true, last_error: nil} = Authzura.status(MyApp.Authz)

{:ok, diagnostics} = Authzura.diagnostics(MyApp.Authz)
```

`status/1` also reports the active and last observed versions and the
diagnostics count, and never waits for a running load. `last_error` is a
bounded error kind, never a raw database error.

To check metadata before you depend on it, see
[`mix authzura.check`](https://hexdocs.pm/authzura/Mix.Tasks.Authzura.Check.html).

## Testing

The version poll runs in the Store's own process. Under an Ecto SQL Sandbox
that process owns no connection, so every poll fails, freshness is never
renewed, and once `max_staleness` has passed every read returns
`:stale_permissions`. A single test file usually finishes inside that window
and passes; a long suite does not.

For the test environment only, turn the poll off and keep the generation
loaded at start authoritative for the run:

```text
config :my_app, MyApp.Authz, poll_interval: nil, max_staleness: :infinity
```

A test that changes metadata reloads explicitly with `Authzura.reload/1`
from a process the sandbox allows (or in a shared-mode test).

Never use this pair outside tests: with no poll and no staleness bound a
revoked permission keeps being served until the next `Authzura.reload/1` or
restart (see
[Security](security.md#revocation-is-bounded-by-max_staleness)).

## Telemetry

Events are emitted with `:telemetry`:

| Event | Metadata |
|---|---|
| `[:authzura, :scope, :start \| :stop \| :exception]` | `instance`, `role`; `stop` adds `result: :granted`, or `result: :denied` with `reason_class` |
| `[:authzura, :execute, :start \| :stop \| :exception]` | the same, plus `mode` (`:all` or `:one`) |
| `[:authzura, :input, ...]` | `instance`, `role`; `stop` adds `result`, and `table` on success or `reason_class` on failure |
| `[:authzura, :query, ...]` | one per statement Authzura issues: `category` (`:transaction_control`, `:setup` or `:data`), `stage` (`:root` or `:preload`), `table`; `stop` adds `rows` |
| `[:authzura, :preload, ...]` | one per preload node that has parents: `relationship`, `depth`, `parents`; `stop` adds `rows` |
| `[:authzura, :load \| :reload, ...]` | `instance`, `seq`; `stop` adds `result` and, on failure, `error_class` |

On `:exception`, the metadata adds only `kind` and `exception_class` (the
exception module, `:throw` or `:exit`).

Metadata is bounded by design: names, categories, counts and classes (the
tag of a reason, such as `:forbidden_columns`). It never carries session
values, filter literals, SQL parameters, SQL text or exception messages. For
detail, read the call's return value and `Authzura.status/1`.

Denials are therefore observable, including the ones that never reach the
database:

```elixir
defmodule MyApp.Telemetry do
  require Logger

  def handle_event([:authzura, :execute, :stop], %{duration: duration}, metadata, _config) do
    %{role: role, result: result} = metadata
    ms = System.convert_time_unit(duration, :native, :millisecond)
    Logger.info("authzura #{role} #{result} in #{ms}ms")
  end
end

:ok =
  :telemetry.attach(
    "authzura-log",
    [:authzura, :execute, :stop],
    &MyApp.Telemetry.handle_event/4,
    nil
  )
```

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Opt-in instance option `input_index_pushdown` (default `false`): an AND-ed
  `_eq`, or an `_in` of up to 100 values, on a plain table column whose
  `pg_catalog` equality Postgres marks leakproof (integers, floats, text,
  varchar, bpchar, name, uuid, bool, date, timestamp, timestamptz) also runs
  outside the input fence, so Postgres can use an index on it. Everything else
  stays fenced. Rows are identical; the cost is a timing side channel on hidden
  rows. See [Security](docs/guides/security.md#input-index-push-down).
- `Authzura.filter_rows/3`, an advanced integration primitive that ANDs the
  role's row permission into a query and returns the permission from the same
  policy generation, without a select, limit or ordering.
- Compatibility evidence: metamorphic property tests (in `mix test` and CI),
  and, on demand, a randomized differential suite against Hasura v2 with
  reviewed divergences, a port of Hasura's select-permission tests, and a
  benchmark against Hasura. See [Compatibility](docs/guides/compatibility.md).
- Telemetry events `[:authzura, :input]`, `[:authzura, :query]` and
  `[:authzura, :preload]`; query and preload events carry `:instance`.
- `Authzura.get` and `Authzura.get!` read one row by primary key.
- `read_only: :connection` option, for repos whose connections are read-only.
- `input_pattern_timeout` instance option (default `5_000` ms per
  statement, `nil` to disable): each statement of an `all_input/4` read
  whose filter has a `SIMILAR TO` or regex pattern runs under that
  transaction-local `statement_timeout`, set by the pattern pre-check at no
  extra round trip and never above a lower session `statement_timeout`; a
  statement it cancels is `{:invalid_input, :statement_timeout}`. It does not apply inside a
  caller's transaction or to `read_only: :connection` reads without
  preloads.
- `Authzura.JWT.prepare/1` validates the options and builds the key once;
  `Authzura.JWT.verify/2` accepts its result in place of the options.

### Changed

- Extension-type columns that the data repo's Postgrex types module decodes (a
  PostGIS `geography`, say) are now in the default projection, like Hasura's.
  Introspection asks the repo's Postgrex types module (no query) whether it has
  an extension for each type the default types do not decode; if so the column
  is `:decodable`, otherwise it stays `:other`, and `mix authzura.check` no
  longer warns about it. They are still not comparable or orderable.
  Composites and arrays are unchanged. A schema query now selects such a column
  by default, so a schema field type that does not match the decoded value
  (`:map` against a `%Geo.Point{}`) surfaces as an Ecto load error.
- Telemetry metadata is bounded and never carries a reason, stacktrace or
  error term: scope and execute `:stop` events carry `reason_class` (was
  `reason`), load and reload `:stop` events carry `error_class` (was
  `error`), and `:exception` events carry `kind` and `exception_class`.
  Handlers that match `%{reason: _, stacktrace: _}` no longer match.
- Pattern pre-check rejections are `:stop` events with `result: :rejected`,
  not exceptions.
- The `version` callback of `Authzura.Source` takes two arguments (was one),
  and the `check_input` and `cast_value` callbacks of `Authzura.Adapter`
  take four (were three; `cast_value` gained the comparison mode).
- Permission predicates on json columns are denied at load.
- `computed_fields` grants are ignored, with a warning.
- A `select_by_pk` root field for a role that cannot select every primary
  key column, or on a table without a primary key, denies the permission at
  load with the diagnostic reason `{:select_by_pk_without_primary_key,
  missing}`, as Hasura rejects such metadata.
- `preloadable?` defaults to false; the store validates every source.
- Session values are parsed strictly and cast eagerly, and fail closed
  (reviewed divergences from Hasura, see the compatibility guide).
- `Authzura.Options.call!/1` validates string columns without building
  rejections, which removes per-read overhead.
- `real` (`float4`) columns compare against a `real` parameter, as Hasura
  types the operand: `_eq`, `_neq`, `_gt`, `_lt` and the rest now give
  Postgres's results for values such as `0.1` (they compared against a
  `float8` before, which admitted rows a `_neq` or `_gt` should hide).
- An operand beyond the column type's range (`smallint`, `integer`, `real`)
  is refused as for array elements: a permission literal at load, a session
  value at request time (`{:invalid_session_value, name, {:invalid_value,
  type}}`) and an input literal (`{:invalid_literal, {:invalid_value,
  type}}`), where it used to be compared.
- A `timestamptz` permission literal or session value without an offset is
  refused (`{:invalid_value, "timestamptz"}`): Postgres reads such text in
  its session `TimeZone`, which Authzura cannot know. Input literals are
  still read as UTC. A reviewed divergence from Hasura.
- An input regular expression or `SIMILAR TO` pattern (`_regex`,
  `_iregex`, `_nregex`, `_niregex`, `_similar`, `_nsimilar`) with a
  backreference (`\1` to `\9`) is
  `{:invalid_input, [{path, {:invalid_literal, :backreference}}]}`.
- Input `order_by` on an array whose element type cannot be ordered
  (`point[]`, `json[]`) is `{:invalid_input, {:order_by, :unorderable}}`;
  it raised a `Postgrex.Error`. `Authzura.Model.Column` has an
  `element_kind` field.
- The Hasura source's version is `{{resource_version, digest}, fingerprint}`
  (was `{resource_version, fingerprint}`), with `digest` the `md5` of the
  metadata document, so metadata replaced at the same `resource_version`
  reloads.
- A binary JWT `:key` holding `-----BEGIN` anywhere is read as a PEM from
  that marker on (BOM, zero-width characters, quotes and `Bag Attributes`
  preambles no longer turn it into an HMAC secret); one that is not a valid
  key, or that holds a disguised `BEGIN`/`END` armour line (typographic
  dashes, spaces, zero-width characters or BOMs inside, any case), is
  `{:invalid_jwt_config, :invalid_key}`.
- The per-call `isolation:` and `between_levels:` test hooks are accepted
  only when the application is compiled with
  `config :authzura, :test_hooks, true`; otherwise they are unknown options.
- `all_input/4` runs its statements without Ecto's query cache and as
  unnamed statements, so client-chosen request shapes never accumulate in a
  cache. Run a `scope_input/4` query with `query_cache: false` likewise.
- The executor's `SET TRANSACTION`, isolation check and pattern pre-check
  are named, cached statements: one round trip each instead of two.
- A reload that keeps failing for the same observed version is retried with
  exponential backoff (1 s doubling to 30 s) instead of at every poll;
  reads still go stale on `max_staleness`. `Authzura.reload/1` always loads.
- The configured admin role's permissions are built once per generation.
- `get/4`'s key equality names its operator `OPERATOR(pg_catalog.=)`, so an
  operator the database owner defines on a domain or operand type can never be
  chosen for it (it runs beside the permission, not behind it).
- `mix authzura.check` loads the host application's config before resolving
  `--repo`, so it finds the repo in an application that depends on Authzura,
  and it no longer logs the introspection queries.

### Documentation

- Validated with `mix authzura.check`, installed as a dependency of a real
  application, against its Hasura v2 metadata: 215 tables, 900 select
  permissions, 0 denied, 37 warnings (20 ignored `computed_fields` grants, 17
  columns of other kinds left out of the default projection).
- Verified against Hasura v2.51.6: the parity suite, the randomized
  differential suite (default and deep runs) and a full benchmark rerun (both
  scales, both modes, 17 scenarios); see `bench/REPORT.md` and
  `bench/TRIAGE.md`.

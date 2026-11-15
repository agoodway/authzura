# Security

Authzura is deny by default: metadata that is unknown, untranslatable or
uncompilable denies that role, table or operation and records a diagnostic.
Nothing degrades into allowing access. It is also read-only: the public API
never writes, and write operations are refused, not half-enforced.

Authzura trusts the session it is handed; see the trust model in
[Sessions and JWT](querying.md#trust-model).

## Unsupported features

Stage one is select permissions on Postgres sources. These are not
supported, and each is denied with a diagnostic rather than approximated:

- Writes: insert, update and delete permissions are parsed and kept, but
  never enforced. The API only reads.
- Aggregate queries (`group_by`, `having`, windows, aggregate selects).
- Computed fields. A filter that references one is denied. A select
  permission's `computed_fields` grant is ignored with a `:warning`
  diagnostic and the rest of the permission is enforced; computed fields
  are never returned.
- Inherited roles and merged roles.
- Remote relationships, including `to_source` relationships in a filter.
- Filters on `json` (not `jsonb`) columns. Hasura v2 rejects these as
  inconsistent metadata, even with only `_is_null`, so the permission is
  denied. Untrusted input may still test a visible `json` column with
  `_is_null`.
- A `select_by_pk` root field for a role that cannot select every primary
  key column, or on a table without a primary key. Hasura rejects such
  metadata, so the permission is denied with
  `{:select_by_pk_without_primary_key, missing}`.
- A `timestamptz` literal or session value without an offset
  (`2026-01-01 10:00:00`, `2026-01-01`). Postgres reads such text in its
  session `TimeZone`, which Authzura cannot know, so the permission is
  denied at load and the session value at request time. Write the offset
  (`2026-01-01T10:00:00Z`). Untrusted input keeps reading it as UTC.
- Scoping joins you add yourself: your own `join`, `where` and `order_by`
  are trusted code. Read related data with permissions applied through
  [preloads](querying.md#preloads).

## Input is fenced behind the permission

Postgres is free to evaluate `WHERE` conditions in any order, so an input
predicate could otherwise run on rows the role cannot see, and a
value-dependent error or slowdown would tell the caller something about
them. The input filter is compiled as
`permission AND (CASE WHEN permission THEN input ELSE false END)`: `CASE`
fixes the order, and the separate `permission` conjunct keeps it usable for
indexes. On top of that, the known run-time refusals are moved ahead of the
read: `SIMILAR TO` and regular-expression patterns are checked by Postgres
in a statement that reads no table, and values Postgres would refuse at bind
time (out-of-range array elements, timestamps or jsonb numbers) are refused
while they are cast. By default, anything left that can fail or run long on a value is
evaluated on permitted rows only; the opt-in
[`input_index_pushdown`](#input-index-push-down) lets equality and `IN`
comparisons on plain columns also run outside the fence.

On `all_input/4`, fully liftable relationship permissions compile as inner
joins. The positive permission conjunct stays, and the CASE `WHEN` re-checks
the whole chain's mapping equalities and target conditions, never negated:
a true `WHEN` implies the row is permitted. The 10% estimate wrapper keeps
that CASE intact. A non-liftable hop keeps the whole permission as EXISTS;
`scope_input/4` is not lifted. Lifted and unlifted reads return identical row
sets (and identical sequences under a total order).

**Regression evidence.** The PostgreSQL 18 suite checks deep, partially
liftable (EXISTS fallback), nullable and partitioned relationships with
push-down off/on and lifting enabled/disabled across 18 planner regimes.
Each captured read has a matched control that removes only its CASE guard.
The suite reports the settings where that control raises on a hidden row
for each shape/push-down/lift combination, and requires generic, forced
parallel and available JIT regimes to discriminate. Fenced reads must
succeed; parallel plans must launch workers and JIT plans must compile
functions. JIT cases skip when unavailable. Evidence against hidden-row
evaluation applies to the settings that discriminate per shape; this is
regression evidence, not a proof for every plan. Hidden-row evidence is PG18
only; CI on PG18 is the version check. These tests were not run on PG16/17.
The guarantee rests on the CASE evaluation order above.

## Input index push-down

The fence above has a cost: Postgres cannot see inside a `CASE`, so it cannot
use an index on a column the input filters, and a selective `all_input/4`
filter reads every row the role may see. The instance option
`input_index_pushdown: true` (default `false`) trades a little of the fence
for index use. Measured against Hasura, `input-selective` and `input-pk` drop
from 61× and 49× (small) to about 0.7× and 0.6×; fenced shapes are unchanged.

The input is then compiled as
`permission AND pushdown AND (CASE WHEN permission THEN input ELSE false END)`.
`pushdown` is a copy of the comparisons below; the fence is unchanged and
still holds the whole input, so the rows returned are identical with the
option on or off.

| Input | With the option on | Why |
|---|---|---|
| `_eq` that is AND-ed at the top (a filter map, or `_and`), on a plain table column of type `int2`, `int4`, `int8`, `float4`, `float8`, `text`, `varchar`, `bpchar`, `name`, `uuid`, `bool`, `date`, `timestamp` or `timestamptz` | index speed | Postgres marks the `pg_catalog` equality `LEAKPROOF`: it cannot raise or reveal its operand, and the operand is a typed parameter, so nothing runs per row |
| `_in` of up to 100 values on the same columns | index speed | same; the cap bounds the signal of one request |
| `_in` of more than 100 values | fenced | a long list is a wide probe of hidden rows |
| `_or`, `_not` | fenced | not a conjunct the row must satisfy |
| `_gt`, `_lt`, `_gte`, `_lte`, `_neq`, `_nin`, `_is_null` | fenced | outside this version's scope |
| `_like`, `_ilike`, `_similar`, `_regex` and variants | fenced | patterns can fail or run long, so they keep the fence and the pattern timeout |
| relationships, `_exists` | refused in input | not allowed in untrusted filters |
| `numeric`, enum, `citext`, `jsonb` columns (and other types Postgres does not mark leakproof) | fenced | their equality is not leakproof |
| domain-typed columns | fenced | an operator declared on the domain could be a user function |
| views, materialized views, generated columns (stored or virtual) | fenced | an expression would run on hidden rows |

"Fenced" means correct, just without index speed: the comparison is evaluated
only on rows the permission admits, as with the option off.

The hoisted comparison names its operator by schema,
`column OPERATOR(pg_catalog.=) $1`, so an operator the database owner defines
on a column or operand type can never be chosen for it. `get/4` pins its key
equality the same way, whatever this option says; a `citext` key uses the
extension's own schema-qualified `=` (and is refused if that schema cannot be
resolved). `citext` equality is not leakproof, so `get/4` keeps the timing
channel described below for it too. The leakproof test is read
from the catalog at load, per type, and both it and the table kind are part of
the structure fingerprint, so a changed catalog reloads the snapshot.
A generation loaded before the owner's DDL keeps its push-down and join-lift
decisions until the next reload (a poll noticing the changed fingerprint, or
`Authzura.reload/1`); `max_staleness` bounds that window. Adding an inheritance
child can leave a loaded generation treating the parent key as strict: a
lifted read can repeat root rows until reload. The WHEN still checks real
rows, so this does not expose hidden rows.

**The trade-off.** A leakproof comparison cannot raise or reveal its operand,
but it may now be evaluated on rows the role cannot see. With an index on the
column, how long a read takes can reveal whether hidden rows carry a given
value (and, with several AND-ed comparisons, which of them also match another
column). That is a timing side channel, the one Postgres accepts for leakproof
quals ahead of a `security_barrier` view or row-level security policy (it is
why `LEAKPROOF` exists), and the one `get/4` already has: its key equality
sits beside the permission, not behind it. The `_in` cap keeps one request
from probing a wide range of hidden keys; it bounds the signal per request and
does not remove the channel, so rate limiting stays the consumer's job. The
order of tied rows under `LIMIT` is as unspecified as ever and may differ.

**What it does not change.** Unlifted relationship permissions still evaluate
EXISTS again inside CASE; push-down does not remove that cost. Fully lifted
`all_input/4` permissions avoid the second EXISTS evaluation: measured
`input-rel-permission` DB time is 0.98/1.02x Hasura at small (default/push-down;
default inconclusive, CV 0.53), with 1.00x buffers. Broad-limit remains a known gap (3.59-6.95x DB time,
9.64-9.73x buffers). See [benchmark triage](https://github.com/agoodway/authzura/blob/main/bench/TRIAGE.md).

It is off by default. Set it in application config, never from request input;
it is an instance option and no call or input can turn it on.

## Trusted-path side channels

Your own predicates are not fenced. A `where` you write and pass to
`scope/3`, `all/3` or `one/3` is trusted code, and Postgres may evaluate it
on rows the role cannot see. When it carries a user's value (a search box's
text in `like/2`, say), an error or the time it takes can reveal whether a
hidden row exists. The executors map Postgres's `invalid_escape_sequence`
(22025) and `invalid_regular_expression` (2201B) errors to
`{:invalid_input, :rejected_by_database}`, which is exactly such a signal.
Put user-controlled filters in `scope_input/4` or `all_input/4`.

## Input limits

List-valued input is capped, each over-long list being
`{:invalid_input, {:too_many, key}}`:

| Key | Limit |
|---|---|
| `:list` | 10,000 elements in an `_in`, `_nin` or `_has_keys_*` list |
| `:patterns` | 16 pattern operands (`_like`, `_similar`, `_regex` and their variants) per filter |
| `:columns` | as many distinct `columns` as the role may select |
| `:order_by` | 32 `order_by` terms at the root |
| `:preload_order_by` | 32 `order_by` terms per preload |

A filter is limited to 8 levels and 100 nodes, and input preloads to 2 levels
and 8 nodes (see [Querying](querying.md#untrusted-input)).

Pattern cost is bounded too. A regular expression or `SIMILAR TO` pattern
with a backreference (`\1` to `\9`; `SIMILAR TO` makes capturing groups
with `\"...\"`), the construct that makes Postgres's matcher exponential,
is `{:invalid_input, [{path, {:invalid_literal, :backreference}}]}`. Each
statement of a read with any `SIMILAR TO` or regex pattern runs under the
instance's `input_pattern_timeout` (default 5 seconds per statement), set
as a transaction-local `statement_timeout` by the pattern pre-check at no
extra round trip, and never above the session's own `statement_timeout`
when that is lower; a statement it cancels is
`{:invalid_input, :statement_timeout}`. It applies only in the
transaction `all_input/4` opens: inside a caller's transaction, in
`read_only: :connection` reads without preloads (one statement, no
transaction) and for queries from `scope_input/4`, the database's own
`statement_timeout` applies, so set one on the role those connections use.

Request shapes are the client's choice, so `all_input/4` runs them without
Ecto's query cache and as unnamed statements: no shape stays cached. Run a
`scope_input/4` query with `query_cache: false` for the same effect.

## No row cap yet

A role whose permission has no `limit` can read a whole table in one call,
plus every preload level. A configurable maximum row count for the input
functions is planned for a later stage; until then, set permission limits,
cap request bodies and set a `statement_timeout`.

## Read-only connections

An executor read is read-only (inside a caller's open transaction, the
caller's access mode applies instead), so trusted code that writes (a `nextval`
in a fragment, say) fails with Postgres's `read_only_sql_transaction`. Only
trusted caller code can write this way: untrusted input never reaches SQL
as anything but bound values. By default the executor enforces read-only on
every read with `SET TRANSACTION READ ONLY`.

`read_only: :connection` is a defence-in-depth opt-in that moves the
guarantee to the connection's configuration. A hot standby, or a role
without write privileges, enforces it. A
`default_transaction_read_only = on` default (role, database or
`after_connect`) does not: any `SET` on the connection can undo it, so the
repo must be dedicated to Authzura and nothing may issue `SET`s on it.
Authzura checks the setting at every load and poll (see
[Configuration](configuration.md#read-only-connections)). A failed check
stops a load, and after a failed poll reads go back to
`SET TRANSACTION READ ONLY` until the next successful load. Each check
samples one pooled connection, so detection is probabilistic: a connection
made writable is read as it allows until a check happens to sample it. The
sticky fallback bounds the exposure to that window, and the mode is only as
safe as the repo is dedicated.

## Revocation is bounded by `max_staleness`

When a reload fails, the active generation keeps serving reads until it has
gone `max_staleness` (default 60 seconds) without being confirmed current,
even after the poll has seen that the metadata changed. A revoked permission
can therefore still be served for up to `max_staleness`, and indefinitely
with `max_staleness: :infinity`. See
[Configuration](configuration.md#caching-and-freshness).

## Hasura compatibility

Authzura targets [Hasura v2](https://hasura.io/docs/2.0/) and is tested
against v2.51.6, with the
[metadata format v3](https://hasura.io/docs/2.0/migrations-metadata-seeds/metadata-format/).
Only `postgres` sources are read. Row filters follow the semantics of
Hasura's [permission rules](https://hasura.io/docs/2.0/auth/authorization/permissions/):
`bool_exp` operators, session variables, column and limit rules, and root
field visibility. They compile to schema-qualified `EXISTS` subqueries and
Ecto dynamics.

What is not supported is denied with a diagnostic, as listed under
[Unsupported features](#unsupported-features). To check your own metadata
against it, run
[`mix authzura.check`](https://hexdocs.pm/authzura/Mix.Tasks.Authzura.Check.html).

How agreement with Hasura and cost against it are measured, with the known
gaps: [Compatibility](compatibility.md).

### Running parity tests

An opt-in suite, tagged `:hasura_parity` and excluded from `mix test`,
runs the same reads through a real Hasura v2.51.6 and through Authzura. It
compares every returned key and value, or the errors. The cases run against
the fixture database, with one metadata document applied through Hasura's
own metadata API:

```bash
docker compose --profile parity up -d
export AUTHZURA_PARITY_HASURA_URL=http://localhost:8080
export AUTHZURA_PARITY_DB_URL=postgres://postgres:postgres@localhost:5432/authzura_parity
mix test --only hasura_parity
```

- Permission-semantics cases impersonate a role with the admin secret.
- Role-resolution cases send an HS256 JWT, which Authzura verifies with
  `Authzura.JWT`.
- Values are compared by each column's declared type, so a `uuid`, a
  `timestamptz` or a `numeric` compares by value whichever way each side
  encodes it.
- The error pairing is deliberately coarse: one Hasura code can stand for
  several Authzura reasons, and each test pins the exact reason itself.

  | Hasura code | Authzura reason |
  |---|---|
  | `not-found` | `{:missing_session_variable, _}` |
  | `validation-failed` | `{:forbidden_columns, _}`, `:forbidden`, `:root_field_disabled` |
  | `access-denied` | `{:invalid_session, :role_not_allowed, _}` |
  | `data-exception` | `{:invalid_session_value, _, _}` |
  | `invalid-jwt` | `{:invalid_jwt, _}` |
  | `jwt-missing-role-claims` | `{:jwt_missing_role_claims, _}` |
  | `jwt-invalid-claims` | `{:jwt_invalid_claims, _}` |

- One difference is intended. Hasura treats an allowed JWT role named
  `admin` as its admin, but Authzura grants admin access only to a
  configured `admin_role`. The suite records both behaviors.
- Any other difference found is kept as a skipped test tagged
  `:hasura_divergence`.

**The setup is destructive.** It migrates the database, truncates its
fixture tables (`TRUNCATE ... CASCADE`) and replaces Hasura's whole
metadata. Before it touches anything, the suite refuses either target
unless it looks like a parity target:

- the database named in the URL must be exactly `authzura_parity`;
- Hasura's current metadata may only have the `default` source, connected
  through `HASURA_GRAPHQL_DATABASE_URL` (as the fixture metadata is) and
  tracking nothing but fixture tables. Event triggers, functions, native
  queries, logical models, actions, remote schemas, cron triggers, query
  collections, REST endpoints and inherited roles are refused. A fresh
  Hasura passes this check.
- that `default` source must reach the database named in the URL, as
  Hasura reports it (`SELECT current_database()` through `run_sql`). Only
  database names are compared, since Hasura and the suite name the host
  differently.

`AUTHZURA_PARITY_CONFIRM_DESTRUCTIVE=1` skips every check, for a target you
chose on purpose.

These variables configure the suite:

- `AUTHZURA_PARITY_HASURA_URL`, required
- `AUTHZURA_PARITY_DB_URL`, required
- `AUTHZURA_PARITY_ADMIN_SECRET` and `AUTHZURA_PARITY_JWT_KEY`, whose
  defaults match `docker-compose.yml`

The two URLs have no defaults, so a run never reaches a Hasura or a
Postgres you did not name: without them it fails at once, before it
contacts anything.

#### Randomized differential runs

A second opt-in suite, tagged `:hasura_differential`, generates random
permission batches and reads, runs each read through the same Hasura and
through Authzura with HS256 JWTs, and classifies every pair:

- **match**;
- **leak**: anything only Authzura returns, at any depth, including any
  grant where Hasura denies. A leak fails with `LEAK` first and stops the
  run;
- **over-deny**: Hasura grants, Authzura denies. It fails unless a reviewed
  divergence in `test/parity/reviewed_divergences.exs` matches both the
  case and Authzura's reason. Each entry names its row in the coverage
  map's "Divergences" table, and more than 5 % reviewed divergences in a
  batch fails it;
- **mismatch**: anything else, such as a changed value, `null` against
  `[]`, another order, or two errors that are not equivalent.

Every array level is totally ordered. A limited level whose key the role
cannot see is checked against a no-limit twin role instead of a sample.
Each batch also checks the vacuity guards. It runs against the same
targets and guards as the parity suite:

```bash
docker compose --profile parity up -d --wait

# The default run: 300 cases in one batch.
mix test --only hasura_differential

# The deep run.
AUTHZURA_DIFF_RUNS=3000 AUTHZURA_DIFF_BATCHES=5 mix test --only hasura_differential

# The same run with the instance's `input_index_pushdown: true`; the
# rows must still equal Hasura's.
AUTHZURA_DIFF_PUSHDOWN=1 mix test --only hasura_differential

# Replay one failure with the command it prints: the run's base seed,
# its batch and run counts, and the request seed.
AUTHZURA_PROP_SEED=20261114 AUTHZURA_DIFF_BATCHES=1 AUTHZURA_DIFF_RUNS=300 \
  mix test --only hasura_differential test/parity/random_differential_test.exs --seed 239229

# Replay every saved failure.
mix test --only hasura_parity test/parity/random_replay_test.exs
```

Batch `i` draws its permissions with `AUTHZURA_PROP_SEED + i` (default
`20261114`), and the reads use ExUnit's `--seed`. A failing case is shrunk
and saved as `test/parity/cases/random/gen-<hash>.json`. The parity suite
replays every saved case, so a fixed failure stays fixed.

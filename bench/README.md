# Benchmark: test harness only

Everything under `bench/` is a harness for Authzura's own benchmark against
Hasura v2. It is compiled in `:test` and `:bench` and is never part of the
package. It reads and writes only the `authzura_bench` database and the
bench Hasura.

## Setup

The targets have no defaults, so a missing variable fails before anything is
touched. With the repo's compose file (the bench Hasura publishes `8081`):

```bash
docker compose up -d --wait postgres

export AUTHZURA_BENCH_DB_URL=postgres://postgres:postgres@127.0.0.1:5432/authzura_bench
export AUTHZURA_BENCH_HASURA_URL=http://127.0.0.1:8081
export AUTHZURA_BENCH_ADMIN_SECRET=bench

MIX_ENV=bench mix authzura.bench.seed --scale small
```

The bench migrations index the foreign keys the scenarios traverse, as adopters do.

`--scale large` seeds ten times as many rows. `--no-compose` skips starting
`hasura_bench` when you run the Hasura yourself (it needs the
`HASURA_GRAPHQL_JWT_SECRET` of `docker-compose.yml` and the `authzura_bench`
database). The database must be on a server that preloads
`pg_stat_statements`; the compose `postgres` service does.

The task creates the database and the extension, migrates it (the fixture
schema plus `priv/bench_migrations`), loads the data, runs
`VACUUM (ANALYZE)`, and replaces the bench Hasura's metadata. Before it does,
it checks that the Hasura's source reaches `authzura_bench` and tracks nothing
but the bench tables.

## Dataset

`Authzura.Bench.Dataset` fills five tables with `generate_series` inserts.
Every pseudo-random choice is `hashint8extended(i, seed)`, so a scale and a
seed always give the same rows. The seed task prints a per-table checksum.

| scale | organizations | users | org_memberships | articles | comments |
|---|---|---|---|---|---|
| small | 100 | 10 000 | 20 000 | 100 000 | 300 000 |
| large | 1 000 | 100 000 | 200 000 | 1 000 000 | 3 000 000 |

## Roles and scenarios

`Authzura.Bench.Metadata` defines the roles `tenant`, `author`, `member`,
`deep`, `limited` and `arr` (plus `open`, a negative control). None is
`admin`, and the bench instance has no `admin_role`.

`Authzura.Bench.Scenarios.all/0` lists 17 scenarios: flat, filtered,
`_exists`, three-hop, session-array, narrow-column, input-filter,
input-regex, permission-limit, deep-page and three preload shapes, plus
four regression pins: an input filter on a selective indexed column
(`input-selective`), a primary-key list through the input path
(`input-pk`), an input filter under a relationship permission
(`input-rel-permission`) and a preload over 1,000 parents
(`preload-large-batch`). Each runs
the same `Authzura.Parity.Read` on both engines as a JWT.

## The gate

`Authzura.Bench.Gate.check/2` must pass before a scenario is measured. A
scenario passes only when the two responses match (`Authzura.Parity.Verdict`),
Hasura's body has no `errors`, both return at least one row at the root and
at every preload level, and the role sees strictly between none and all of
the root table's rows. A scenario that fails is reported by id and is not
measured.

```bash
MIX_ENV=test mix test --only bench test/bench
```

## Measuring

```bash
MIX_ENV=bench mix authzura.bench --scale small
MIX_ENV=bench mix authzura.bench --scale small --mode read_only_connection
MIX_ENV=bench mix authzura.bench --scale small --mode input_index_pushdown
```

The task seeds the database first when its row counts are not those of
`--scale`, runs the gate, then measures each scenario that passed it, one
engine at a time:

- statements and DB time from `pg_stat_statements` (planning plus
  execution), over 5 alternating repetitions of 200 requests per engine,
  each after 6 warm-up requests per connection of the engine's pool (60 for
  Authzura's 10, 300 for Hasura's default 50, so every connection is past
  Postgres's switch to generic plans) and a reset. Hasura's `hdb_catalog`
  work and the statistics and catalog reads are excluded. The DB-time CV is
  that of the paired per-repetition ratios;
- plan shape and shared buffers from one `EXPLAIN (ANALYZE, BUFFERS)` per
  data statement. Authzura's statements are explained as the steady state
  runs them (prepared, executed five times, then explained), so a generic
  plan shows where Postgres switched to one; Hasura's explain endpoint
  inlines the values, so its plans are custom ones.

`read_only_connection` runs Authzura with `read_only: :connection` on
`Authzura.Bench.ReadOnlyRepo`, whose connections are read-only by
themselves. `input_index_pushdown` runs the default setup with
`input_index_pushdown: true`. The task writes `bench/results/<scale>.json`
and `bench/REPORT.md`; each mode keeps its own entry, and `--only id,id`
replaces only those scenarios. The output has numbers, verdicts, plan node types and table and
index names only: no session value, SQL text or bind value.

`--check` fails on a failing target or an aborted scenario (an
inconclusive DB time does not fail). `--requests N` changes the requests
per repetition, `--warmup N` the warm-up requests per engine, and
`--no-compose` is passed on to the seed task. Failing
and inconclusive targets are triaged in `bench/TRIAGE.md`.

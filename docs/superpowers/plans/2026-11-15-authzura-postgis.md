# Authzura PostGIS Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce Hasura v2's ten `_st_*` operators in permissions and in untrusted input, and add an output representation extension point with an opt-in GeoJSON implementation, without weakening the input fence.

**Architecture:**
- Introspection marks PostGIS columns (`Column.spatial`, `srid`, `type_schema`).
- `Authzura.GeoJSON` validates and re-encodes operands in Elixir. `BoolExp` parses the operators, and the Postgres adapter compiles them as schema-qualified PostGIS calls.
- `InputCheck` checks every operand in its constant statement before the read: input literals and session operands per read, permission literals at load.
- `Authzura.Representation` (instance option `representations:`) replaces a column's select expression. `Authzura.Representations.GeoJSON` is the built-in. Native decoding stays the default.

**Tech Stack:**
- Elixir 1.19 / OTP 28, Ecto SQL 3.13, Postgrex.
- `imresamu/postgis:18-3.6-bookworm` (Postgres 18, PostGIS 3.6) for tests, CI and parity.
- `geo_postgis`, test and bench only.
- `hasura/graphql-engine:v2.51.6` for parity.

**Spec:** `docs/superpowers/specs/2026-11-15-authzura-postgis-design.md`. Its parents are the stage-one and hardening designs. If a task and the spec conflict, the spec wins. Flag the conflict.

**Prerequisites.** Where the code differs from a name below, the code wins; note the difference in the task's checkpoint message.
- **The spec's open decisions are ruled on.** This plan assumes each recommendation. Decisions 1 (image), 3 (session operands) and 4 (invalid geometries) change Tasks 1, 5 and 8.
- **The decode probe has landed**, with its review fixes: an extension type the repo's Postgrex types decode is `:decodable`, any other is `:other`.
- **Hardening is merged:** `InputCheck`, `input_index_pushdown`, `Authzura.Parity.{Verdict, Compare, Runner, Fixture}`, the generators and the coverage map.

## Global Constraints

- **Read-only, deny by default, no atoms from metadata or input, public error reasons only.** As in the hardening plan.
- **Generic.** No application, table or role name from any adopter. `lib/` gains no dependency. Nothing depends on PgRest.
- **Native decoding is the default.** With `representations: []`, every select is byte-identical to before this plan.
- **Spatial comparisons never leave the fence.** `Authzura.Compiler.pushdown/3` never returns one, and `compile_operator/5` raises on a spatial operator in `:pinned` mode.
- **Every PostGIS function and type is schema-qualified** with `identifier(^column.type_schema)`. No SQL names PostGIS unless a spatial column, operand or representation is in play, so a database without PostGIS sees none.
- **Operand order of checks:** Elixir shape, caps, SRID, then the database pre-check, then the read. An operand string is never interpolated into SQL.
- **Caps** (spec): `geojson_limits: [max_vertices: 1_000, max_bytes: 65_536]` for input and session operands; collections nest at most 4 deep, always; 4 spatial operands per input filter; permission literals have no vertex or byte cap.
- **New public reasons**, and no others:
  - `{:invalid_input, {:invalid_geometry, column}}`
  - `{:invalid_input, {:too_many, :spatial}}`
  - `{:invalid_input, [{path, {:invalid_literal, geojson_reason}}]}`
  - `{:invalid_session_value, name, geojson_reason | :invalid_geometry}`
- **Never trade a check for speed.** The fence, the pre-check and `READ ONLY` all stay.
- **Docker.** Pin image tags. Every published port binds `127.0.0.1`. Never install a browser or a load tool.
- **Migrations.** Only `MIX_ENV=test mix ecto.gen.migration <name> -r Authzura.Test.Repo --migrations-path priv/test_migrations`, then fill in the body. Never hand-create a file or a timestamp.
- **CI.** One workflow, `ci.yml`. No scheduled runs, no new job. Parity and the differential stay on demand.
- **Public repo.** No private application, domain or local path. Hasura is cited at `github.com/hasura/graphql-engine/tree/v2.50.1`.
- **README untouched.** Details go in `@moduledoc`/`@doc`, option docs, `docs/guides/*.md` and `usage-rules.md`.
- **Quality gate.** `mix quality` passes at the end of every task.
- **Owner Elixir style.** `with` over nested conditionals; function-head matching and guards; pipes; grouped top-level aliases; no fully qualified calls in bodies.
- **Reuse first.** Before adding a function, look for one that does it (`InputCheck`, `Values`, `Compiler.compares_enum?/3`, `Compare`). If existing code cannot do it without new logic, stop and report the smallest extension point.
- **Commits.** At a **Checkpoint**, leave the changes in the working tree and stop with the suggested message. Never run `git add`, `git commit` or `git push`. No AI attribution.

## Review Focus

1. **A hidden row that makes the predicate raise.** A row the role cannot read holds a geometry with another SRID. Expected: the role's input filter on that column returns its rows with no error; only a role that can read the row gets an error tuple. Owner: Task 4.
2. **An operand Elixir accepts and PostGIS refuses** (a self-intersecting polygon, an unknown EPSG code, a projected SRID sent to a `geography` column). Expected: the same `{:invalid_geometry, column}` error whether the table is empty, all hidden or all visible, and no read statement runs. Owner: Task 5.
3. **PostGIS absent, off the search path, or shadowed.** Expected: a database without PostGIS loads and reads as before; with PostGIS in a schema off the search path, and a user function `public.st_intersects` on it, the extension's function runs. Owners: Tasks 2 and 4.
4. **Hostile GeoJSON:** 100,000 vertices, collections nested 50 deep, 4-number positions, numeric strings, a `bbox` member, a link `crs`. Expected: refused in Elixir, in bounded time, before any SQL. Owner: Task 3.
5. **A repo that cannot decode the type.** Expected: without a representation the column stays out of the default projection and naming it gives the existing other-column error, never a raise or a dropped connection; with the GeoJSON representation it is selected. Owner: Task 7.

---

## File Structure

```
docker-compose.yml, .github/workflows/ci.yml, mix.exs, config/test.exs, test/test_helper.exs
priv/test_migrations/<generated>_create_spatial_fixture.exs, test/support/{repo,geo_types,seed}.ex
test/feasibility/postgis_test.exs
lib/authzura/model/{column,table}.ex, lib/authzura/adapters/postgres/introspection.ex
lib/authzura/geojson.ex, lib/authzura/options.ex
lib/authzura/{adapter,ast,compiler,input,plan,scope,executor,validator}.ex, lib/authzura.ex
lib/authzura/sources/hasura/bool_exp.ex
lib/authzura/adapters/{postgres.ex,postgres/values.ex,postgres/input_check.ex,postgres/preload_query.ex}
lib/authzura/representation.ex, lib/authzura/representations/geojson.ex
test/authzura/{geojson_test,representation_test}.exs, test/authzura/adapters/postgres/spatial_test.exs
test/integration/{spatial_filter,spatial_check,representation}_test.exs
test/support/parity/{compare,fixture,runner}.ex, test/support/gen/filter.ex, test/parity/spatial_parity_test.exs
docs/guides/{security,querying,configuration,compatibility}.md, docs/hasura-test-coverage.md, usage-rules.md, CHANGELOG.md
```

---

### Task 1: PostGIS image, fixtures and feasibility

Model: sonnet.

**Files:**
- Modify: `docker-compose.yml` and `.github/workflows/ci.yml` (the `postgres` image becomes `imresamu/postgis:18-3.6-bookworm`; command, ports, env and health check unchanged), `mix.exs` (`{:geo_postgis, "~> 3.7", only: [:test, :bench]}`; take the current release), `config/test.exs`, `test/test_helper.exs`, `test/support/repo.ex`, `test/support/seed.ex`
- Create: `test/support/geo_types.ex`, the generated migration, `test/feasibility/postgis_test.exs`

**Interfaces:**
- Produces:
  - `Authzura.Test.GeoTypes`: `Postgrex.Types.define(Authzura.Test.GeoTypes, [Geo.PostGIS.Extension], [])`.
  - `Authzura.Test.GeoRepo`, configured like `CubeRepo` with `types: Authzura.Test.GeoTypes`.
  - Table `public.geo_places`, created after `CREATE EXTENSION IF NOT EXISTS postgis`:

    ```sql
    id bigint PRIMARY KEY, owner_id bigint NOT NULL, name text NOT NULL,
    geom geometry(Geometry, 4326), geom_any geometry,
    geom_z geometry(PointZ, 4326), geog geography(Geometry, 4326)
    ```
    with GiST indexes on `geom` and `geog`.
  - Seed rows, from Hasura's `tests-py/queries/graphql_query/permissions/setup.yaml` (`geom_table`): a point, two linestrings and two polygons, with `owner_id` 1 or 2, plus one `owner_id = 2` row whose `geom_any` has SRID 3857 (the poison row of Review Focus 1).

- [ ] **Step 1:** Switch both images. Recreate the local test container. Run `mix test`. Expected: the existing suite passes on the new image.
- [ ] **Step 2:** Generate the migration with the command in Global Constraints (name `create_spatial_fixture`), fill in `up`/`down`, add the seed rows and `GeoRepo`.
- [ ] **Step 3: Write `test/feasibility/postgis_test.exs`.** Each test pins one fact the design relies on:

  ```elixir
  test "GeoJSON without crs is SRID 4326; a named EPSG crs sets it"
  test "malformed GeoJSON, an unknown EPSG code and ::geography of SRID 3857 raise"   # record each SQLSTATE
  test "a self-intersecting polygon converts and ST_IsValid is false"
  test "a mixed-SRID predicate raises on a row and not on an empty table"
  test "a negative ST_DWithin distance raises"
  test "fragment(\"?.st_intersects(?, ?.st_geomfromgeojson(?))\", identifier(^schema), ...) runs through Ecto"
  test "that predicate uses the GiST index with enable_seqscan off"
  test "ST_AsGeoJSON(geom, 15, 4)::jsonb carries the long crs name"
  test "geography ST_DWithin takes use_spheroid as its fourth argument"
  test "GeoRepo introspects geom and geog as :decodable; Repo as :other"
  ```
- [ ] **Step 4:** Run `mix test test/feasibility/postgis_test.exs`. Expected: PASS. A fact that fails changes the design: stop and report it.
- [ ] **Step 5:** Run `mix quality` and `grep -n "image:" docker-compose.yml .github/workflows/ci.yml`. Expected: PASS; no `postgres:18` line.
- [ ] **Step 6: Checkpoint.** `test: run the suite on PostGIS and add spatial fixtures`

---

### Task 2: Spatial columns in introspection

Model: sonnet.

**Files:**
- Modify: `lib/authzura/model/column.ex`, `lib/authzura/adapters/postgres/introspection.ex`
- Test: `test/authzura/adapters/postgres/introspection_test.exs`, `test/integration/fingerprint_test.exs`

**Interfaces:**
- Produces, on `Authzura.Model.Column`:
  - `spatial :: :geometry | :geography | nil`. Set only when the column's base type (through domains) is the `geometry` or `geography` type in the schema of the `postgis` extension, found as the `citext` schema is today. Arrays are not spatial.
  - `srid :: pos_integer() | nil`: the type modifier's SRID, `nil` when unconstrained. Read without calling a PostGIS function.
  - `type_schema`: the extension's schema for a spatial column, `nil` when it holds a double quote.
  - `base_kind` is unchanged: `:decodable` or `:other`, as the probe decides.

- [ ] **Step 1: Write the failing tests.**

  ```elixir
  test "geo_places columns carry spatial, srid and type_schema" do
    # geom: {:geometry, 4326}; geom_any: {:geometry, nil}; geom_z: {:geometry, 4326}; geog: {:geography, 4326}
    # type_schema is the postgis extension's schema for all four; name: spatial nil
  end
  test "a user type named geometry in another schema is not spatial"
  test "a domain over geometry(Point, 4326) is spatial with srid 4326"
  test "the fingerprint changes when a column's SRID changes"
  test "a database without the postgis extension introspects with every spatial nil"  # unit: the schema lookup returns nil
  ```
- [ ] **Step 2:** Run them. Expected: FAIL (`spatial` is not a key).
- [ ] **Step 3:** Implement. Update the `Column` moduledoc and type.
- [ ] **Step 4:** Run `mix test test/authzura/adapters/postgres test/integration/fingerprint_test.exs`, then `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: recognise PostGIS columns in introspection`

---

### Task 3: GeoJSON operand validation

Model: sonnet.

**Files:**
- Create: `lib/authzura/geojson.ex`, `test/authzura/geojson_test.exs`
- Modify: `lib/authzura/options.ex`, `test/authzura/options_test.exs`

**Interfaces:**
- Produces:

  ```elixir
  defmodule Authzura.GeoJSON do
    defstruct [:json, :srid, :vertices, :target, :schema]
    @type t :: %__MODULE__{json: String.t(), srid: pos_integer(), vertices: non_neg_integer(),
                           target: :geometry | :geography | nil, schema: String.t() | nil}
    @type limits :: %{max_vertices: pos_integer(), max_bytes: pos_integer()}
    @type reason :: :not_geojson | :unknown_type | :invalid_coordinates | :too_few_positions
                    | :unclosed_ring | :invalid_crs | :too_deep
                    | :too_many_vertices | :too_large | {:srid_mismatch, pos_integer()}

    @spec validate(term()) :: {:ok, t()} | {:error, reason()}       # a decoded term; shape only
    @spec decode(String.t(), limits()) :: {:ok, t()} | {:error, reason()}  # session text; byte cap before decoding
    @spec within(t(), limits()) :: :ok | {:error, reason()}         # vertex and byte caps
    @spec for_column(t(), Column.t()) :: {:ok, t()} | {:error, reason()}   # SRID rule; sets target and schema
  end
  ```
- Rules (spec, Security 2):
  - Types: `Point`, `MultiPoint`, `LineString`, `MultiLineString`, `Polygon`, `MultiPolygon`, `GeometryCollection`.
  - A position is 2 or 3 numbers: floats, or integers within ±2^53. A LineString has at least 2 positions; a ring at least 4, first equal to last. No empty geometry, member or collection.
  - `crs` is absent (SRID 4326), or a name of the form `EPSG:<n>`, `urn:ogc:def:crs:EPSG::<n>` or `urn:ogc:def:crs:OGC:1.3:CRS84`. Anything else, a link `crs` included, is `:invalid_crs`.
  - Collections nest at most 4 deep (`:too_deep`), a fixed bound, so `validate/1` is bounded on its own.
  - `json` is encoded from the validated parts only: `type`, `coordinates` or `geometries`, and `crs` as `EPSG:<n>`. Other members (`bbox`, `properties`) are dropped.
  - `for_column/2`: when `column.srid` is set and differs, `{:srid_mismatch, column.srid}`.
- Instance option `geojson_limits`: a keyword list with `max_vertices` (default `1_000`) and `max_bytes` (default `65_536`), each a positive integer, documented as applying to input and session operands.

- [ ] **Step 1: Write the failing tests:** one per rule above, each asserting the exact reason, plus:

  ```elixir
  test "the encoded json drops bbox and unknown members"
  test "Hasura's test operand round-trips with srid 4326"   # the Polygon of user_can_query_geometry_values_filter_session_vars.yaml
  test "100_000 vertices is :too_many_vertices; 50 nested collections is :too_deep; neither raises"
  test "numeric strings, 1- and 4-number positions, NaN-like terms are :invalid_coordinates"
  test "decode/2 refuses text over max_bytes without decoding it"
  property "validate/1 never raises on any JSON-decoded term"
  ```
- [ ] **Step 2:** Run `mix test test/authzura/geojson_test.exs`. Expected: FAIL (module missing).
- [ ] **Step 3:** Implement `Authzura.GeoJSON` and the option.
- [ ] **Step 4:** Run the tests and `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: validate GeoJSON operands in Elixir`

---

### Task 4: The `_st_*` operators

Model: opus.

**Files:**
- Modify: `lib/authzura/adapter.ex`, `lib/authzura/ast.ex`, `lib/authzura/sources/hasura/bool_exp.ex`, `lib/authzura/compiler.ex`, `lib/authzura/input.ex`, `lib/authzura/adapters/postgres.ex`, `lib/authzura/adapters/postgres/values.ex`
- Test: `test/authzura/adapters/postgres/spatial_test.exs`, `test/authzura/sources/` (bool_exp), `test/authzura/ast_test.exs`, `test/integration/spatial_filter_test.exs`, `test/integration/input_pushdown_test.exs`

**Interfaces:**
- Consumes: `Column.spatial/srid/type_schema` (Task 2); `Authzura.GeoJSON` and `geojson_limits` (Task 3).
- Produces:
  - `Authzura.Adapter`:
    - `lhs_kind` adds `:geometry` (a `geometry` column) and `:spatial` (`geometry` or `geography`). Both need a non-nil `type_schema`.
    - `rhs_kind` adds `:geometry`, `:distance`, `:flag` and `{:parts, [{atom(), rhs_kind(), :required | {:default, term()}}]}`.
  - `Authzura.AST.value()` adds `{:parts, %{atom() => value()}}`. `session_refs/1` reads into it.
  - Signatures in `Authzura.Adapters.Postgres`:

    | Operators | `lhs` | `rhs` |
    |---|---|---|
    | `:st_contains`, `:st_crosses`, `:st_equals`, `:st_overlaps`, `:st_touches`, `:st_within`, `:st_3d_intersects` | `:geometry` | `:geometry` |
    | `:st_intersects` | `:spatial` | `:geometry` |
    | `:st_d_within` | `:spatial` | `{:parts, [distance: :distance, from: :geometry, use_spheroid: :flag]}`; `use_spheroid` defaults to `true` |
    | `:st_3d_d_within` | `:geometry` | `{:parts, [distance: :distance, from: :geometry]}` |
  - `cast_value/4`:
    - `:geometry`: a literal map through `GeoJSON.validate/1` and `for_column/2`; session text through `GeoJSON.decode/2` then `for_column/2`. The result is a `%GeoJSON{}`.
    - `:distance`: a finite number, at least 0, as a float; session text parsed as the float kind is today.
    - `:flag`: a boolean; session text as the boolean kind is today.
  - `compile_operator/5` (`s` is `column.type_schema`, `g` is `"s".st_geomfromgeojson($n::text)`, cast `::"s".geography` on a `geography` column):
    - `"s".st_contains(col, g)` and likewise `st_crosses`, `st_equals`, `st_overlaps`, `st_touches`, `st_within`, `st_intersects`, `st_3dintersects`;
    - `"s".st_dwithin(col, g, $d::float8)` on `geometry`, `"s".st_dwithin(col, g, $d::float8, $f::boolean)` on `geography`, `"s".st_3ddwithin(col, g, $d::float8)`;
    - a `nil` operand or part is `NULL::boolean`;
    - `:pinned` mode raises `ArgumentError`.
  - `BoolExp`:
    - the ten names join `@operators` (so `_` and `$` both parse);
    - a `{:parts, _}` right side takes an object: each part is tagged and cast on its own (a session variable is allowed per part in `:permission` mode), a missing required part or an unknown key is `:invalid_expression`;
    - in `:input` mode a GeoJSON operand is checked with `GeoJSON.within/2` against `ctx.geojson_limits`.
  - `Authzura.Compiler` binds a `{:parts, _}` operand part by part. A session `:geometry` value over the limits is `{:invalid_session_value, name, reason}`.
  - `Authzura.Input`: more than 4 spatial comparisons is `{:invalid_input, {:too_many, :spatial}}`.

- [ ] **Step 1: Write the failing unit tests.**

  ```elixir
  test "operator_signature/1 for the ten operators matches the table"   # also replace the :st_within doctest
  test "lhs_compatible?: geometry-only operators refuse a geography column and a nil type_schema"
  test "_st_within on geography is {:operator_type_mismatch, \"_st_within\", \"geography\"}"
  test "permission parse keeps session parts: {:parts, %{distance: {:session, \"x-hasura-geom-dist\"}, from: {:session, \"x-hasura-geom-val\"}}}"
  test "input parse refuses a session-looking string, a null, a missing from, an unknown key and a negative distance"
  test "an input operand over max_vertices is {:invalid_literal, :too_many_vertices}"
  test "five spatial comparisons is {:too_many, :spatial}"
  test "session_refs/1 finds names inside parts"
  test "compiled SQL names every PostGIS function and type by the extension schema"  # assert on the SQL text
  ```
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement, in the order adapter types, AST, `Values`, `compile_operator/5`, `BoolExp`, `Compiler`, `Input`.
- [ ] **Step 4: Write the failing integration tests** in `test/integration/spatial_filter_test.exs`, on `geo_places`:

  ```elixir
  test "a permission with _st_d_within returns the rows of Hasura's user1 test"          # ids 3, 4, 5
  test "the same permission with session distance and from returns the same rows"
  test "geography: _st_intersects and _st_d_within with use_spheroid true and false"
  test "each geometry operator, as input, equals the rows of the same SQL run directly"
  test "input is fenced: rows(role, F) == rows(role) ∩ rows(admin, F) for a spatial F"
  test "poison row: a role that cannot read the SRID-3857 row filters geom_any with no error"
  test "poison row: a role that can read it gets an error tuple, never a raise"
  test "PostGIS off the search path, and a user public.st_intersects on it: the extension's function runs"
  ```
  and in `test/integration/input_pushdown_test.exs`:

  ```elixir
  test "with input_index_pushdown: true, an AND-ed spatial comparison appears only inside the CASE"
  ```
- [ ] **Step 5:** Run `mix test test/integration/spatial_filter_test.exs test/integration/input_pushdown_test.exs test/authzura`. Expected: PASS. Run `mix quality`. Expected: PASS.
- [ ] **Step 6: Checkpoint.** `feat: enforce Hasura's PostGIS operators in permissions and input`

---

### Task 5: Operand pre-check: input, session and load

Model: opus.

**Files:**
- Modify: `lib/authzura/adapter.ex`, `lib/authzura/adapters/postgres/input_check.ex`, `lib/authzura/plan.ex`, `lib/authzura/compiler.ex`, `lib/authzura/scope.ex`, `lib/authzura/executor.ex`, `lib/authzura/validator.ex`, `lib/authzura.ex`, `lib/authzura/error.ex`, `lib/authzura/options.ex` (the `input_pattern_timeout` doc)
- Test: `test/integration/spatial_check_test.exs`, `test/authzura/adapters/postgres/` (input check), `test/authzura/validator_test.exs`

**Interfaces:**
- Consumes: `%GeoJSON{json:, target:, schema:}` literals in the AST (Tasks 3 and 4).
- Produces:
  - `Authzura.Adapter`:

    ```elixir
    @type checks :: %{input: AST.t() | nil, session: [{name :: String.t(), GeoJSON.t()}]}
    @callback check_input(repo :: module(), checks(), repo_opts :: keyword(), telemetry :: map()) ::
                :ok
                | {:error, {:invalid_input, {:invalid_pattern | :invalid_geometry, String.t()}}}
                | {:error, {:invalid_session_value, String.t(), :invalid_geometry}}
    ```
  - `InputCheck.run/4` takes `checks()`. Spatial operands come from `AST.comparisons/1` of `input` (literals, and literals inside parts) and from `session`. Each must satisfy, in the constant statement:
    - `geometry`: `"s".st_isvalid("s".st_geomfromgeojson(doc))`;
    - `geography`: `"s".st_isvalid("s".st_geomfromgeojson(doc)::"s".geography::"s".geometry)`.

    An error or a `false` is a refusal. The first refused operand is found one at a time, as for patterns. A filter with patterns and operands still costs one statement, and PostGIS is named only when an operand is present. The savepoint, telemetry and `:statement_timeout` behaviour are unchanged.
  - `Authzura.Plan` gains `session_spatial: [{String.t(), GeoJSON.t()}]`: the session spatial operands of the root permission and of every preload level's, collected beside `enum_comparisons?` by a walker in the style of `Compiler.compares_enum?/3`.
  - `Authzura.Executor.check_input/1` passes `%{input: plan.input, session: plan.session_spatial}`, and runs when either is non-empty.
  - `Authzura.scope/3` and `Authzura.filter_rows/3` run the check when the permission holds a session spatial operand, and no statement otherwise.
  - Load: `Authzura.Validator` checks each permission's literal spatial operands through the data repo with the same statement. A refusal denies that permission with a `%Diagnostic{}` carrying `{:invalid_literal, :invalid_geometry}`.
  - `input_pattern_timeout` now also bounds an `all_input/4` read whose filter holds a spatial operand. Its name is kept.

- [ ] **Step 1: Write the failing tests** in `test/integration/spatial_check_test.exs`:

  ```elixir
  for operand <- [:bow_tie_polygon, :unknown_epsg, :projected_srid_on_geography] do
    test "#{operand}: {:invalid_geometry, column} on an empty table, an all-hidden table and a visible table"
    # and the query log shows no statement on geo_places
  end
  test "a filter with a regex and a spatial operand runs one check statement"
  test "the first refused operand names its column; a refused pattern still names its own"
  test "inside a caller's transaction a refused operand does not abort it"
  test "a session operand that PostGIS refuses is {:invalid_session_value, \"x-hasura-geom-val\", :invalid_geometry} from all/3, one/3, get/4, scope/3 and filter_rows/3"
  test "a session operand in a preload level's permission is checked before the root read"
  test "a read with no spatial operand runs no check statement"          # statement count unchanged
  test "a permission whose literal operand is a bow-tie is denied at load with a diagnostic"
  test "a spatial input read runs under input_pattern_timeout"
  ```
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement, in the order `InputCheck`, `Plan` and the walker, `Executor`, `scope/3` and `filter_rows/3`, `Validator`. Add the reasons to `Authzura.Error`.
- [ ] **Step 4:** Run `mix test`. Expected: PASS, with the pattern tests unchanged. Run `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: check spatial operands with the database before any read`

---

### Task 6: Security review of the spatial filter path (gate)

Model: Fable, as an adversarial reviewer with no implementer context. It gets the spec, the diff of Tasks 2 to 5 and `docs/guides/security.md`, not the implementers' reports.

- [ ] **Step 1: Review.** The reviewer tries to break each claim, and writes a failing test for each break:
  - an input operand evaluated on a hidden row, through `_or`, `_not`, a preload, `get/4`, or `input_index_pushdown: true`;
  - an error, or a timing difference from operand conversion, that depends on whether hidden rows exist;
  - an operand that passes `Authzura.GeoJSON` and the pre-check yet makes the read raise without any stored row being at fault;
  - SQL built from operand text, a `crs` name or a metadata string; an unqualified PostGIS name;
  - a session operand that reaches a read unchecked (`scope/3`, `filter_rows/3`, preload levels, a session part inside `_st_d_within`);
  - cost: the largest operand the caps allow, times 4, against the fixture, under `input_pattern_timeout`;
  - a permission literal that is refused at load but still enforced, or accepted but never checked.
- [ ] **Step 2:** The controller rules on each finding. Critical and High findings are fixed test-first by the task's implementer; the reviewer re-checks the fixes. Anything deferred is recorded with its cost.
- [ ] **Step 3:** Run `mix test` and `mix quality`. Expected: PASS.
- [ ] **Step 4: Checkpoint.** `fix: <finding>` per fix, or none.

---

### Task 7: Output representations and the GeoJSON built-in

Model: sonnet.

**Files:**
- Create: `lib/authzura/representation.ex`, `lib/authzura/representations/geojson.ex`, `test/authzura/representation_test.exs`, `test/integration/representation_test.exs`
- Modify: `lib/authzura/options.ex`, `lib/authzura/model/{column,table}.ex`, `lib/authzura/store.ex` (or where a snapshot is built), `lib/authzura/scope.ex`, `lib/authzura/adapters/postgres/preload_query.ex`

**Interfaces:**
- Produces:

  ```elixir
  defmodule Authzura.Representation do
    @callback represents?(Column.t()) :: boolean()
    @callback select(Column.t(), field :: Ecto.Query.dynamic_expr()) :: Ecto.Query.dynamic_expr()
  end
  ```
  - Instance option `representations: [module()]`, default `[]`. At load, each column gets `Column.representation :: module() | nil`: the first module whose `represents?/1` is true.
  - `Table.default_columns/2` keeps a represented column, and `other_kind_columns/2` leaves it out.
  - The root select, `get/4` and each preload level select `module.select(column, field)` for a represented column, under the same result key. Filters, ordering, stitching keys and `filter_rows/3` use the plain column.
  - `Authzura.Representations.GeoJSON`: `represents?/1` is true for a column with `spatial` and `type_schema` set; `select/2` is `fragment("?.st_asgeojson(?, 15, 4)::jsonb", identifier(^schema), ^field)`.

- [ ] **Step 1: Write the failing tests.**

  ```elixir
  # test/integration/representation_test.exs
  test "representations: [] leaves every select's SQL unchanged"            # compare with the SQL before, root and preload
  test "GeoRepo, no representation: geom comes back as a Geo struct, in the default projection"
  test "Repo (no PostGIS types), no representation: geom is not in the default projection; naming it is the existing other-column error"
  test "Repo with the GeoJSON representation: geom and geog are in the default projection as GeoJSON maps"
  test "the GeoJSON map equals ST_AsGeoJSON(col, 15, 4)::jsonb run directly, crs included"
  test "it applies in get/4, in an object preload and in a limited array preload"
  test "a schema query keeps the field key and returns the represented value"
  test "a spatial filter and a representation on the same column both hold"
  test "a custom representation module is used for a non-spatial column, and the first claiming module wins"
  ```
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Write the behaviour's `@moduledoc` for an adopter writing one: the expression is selected only for rows the role may read, must use only its own column, and its result must decode with the repo's types.
- [ ] **Step 4:** Run `mix test` and `mix quality`. Expected: PASS.
- [ ] **Step 5: Checkpoint.** `feat: add output representations with an opt-in GeoJSON built-in`

---

### Task 8: Hasura parity and differential coverage

Model: opus. Needs the `parity` compose profile; the URLs have no defaults.

**Files:**
- Modify: `test/support/parity/{compare,fixture,runner}.ex`, `test/support/gen/filter.ex` (and its catalog), `test/parity/reviewed_divergences.exs`, `docs/hasura-test-coverage.md`, `test/hasura_scenarios/` (inventory rows)
- Create: `test/parity/spatial_parity_test.exs`
- Test: `test/property/verdict_test.exs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `Compare.value/2` reduces a value of a spatial column to `{:geo, srid, type, coordinates}`, with numbers canonical as today, from a GeoJSON map (Hasura's, or Authzura's GeoJSON representation) or from a decoded `Geo` struct. It keys on `Column.spatial` before `base_kind`.
  - `Parity.Fixture` tracks `geo_places` with three roles: Hasura's `user1` (literal `_st_d_within`) and `user2` (session `distance` and `from`) permissions, and a `geography` `_st_intersects` role. The parity instance reads through a repo with the PostGIS types.
  - `AUTHZURA_DIFF_GEOJSON=1` starts the Authzura instance with `representations: [Authzura.Representations.GeoJSON]`, as `AUTHZURA_DIFF_PUSHDOWN` does for push-down.
  - Generators add spatial input filters on `geo_places`: every operator, on both column types, with operands from a fixed grid of valid shapes, plus refused ones (wrong column type, malformed, bow-tie, over the caps).

- [ ] **Step 1: Write the failing verdict tests.**

  ```elixir
  test "a Geo struct and Hasura's GeoJSON for the same geometry are :match"
  test "a GeoJSON map with the short crs name and one with the long name are :match"
  test "a spatial value only Authzura returns is {:leak, _}"          # planted
  test "a differing coordinate is {:mismatch, _}"
  ```
- [ ] **Step 2:** Run them. Expected: FAIL. Implement `Compare`. Expected: PASS.
- [ ] **Step 3: Write `test/parity/spatial_parity_test.exs`** (`@moduletag :hasura_parity`), porting:
  - `tests-py/queries/graphql_query/permissions/user_can_query_geometry_values_filter.yaml` and `..._session_vars.yaml`, plus a missing and a malformed session value;
  - `tests-py/queries/graphql_query/boolexp/postgis/`: the geometry and geography operator cases, as input reads.
- [ ] **Step 4:** Extend the generators and the must-appear test: every operator and both column types appear, and at least 25 % of spatial cases return a row.
- [ ] **Step 5:** Run, each of them twice, without and with `AUTHZURA_DIFF_GEOJSON=1`:
  - `mix test --only hasura_parity`
  - `mix test --only hasura_differential`

  Expected: no leak and no mismatch. An over-deny on an invalid geometry is the divergence of open decision 4: add one entry to `reviewed_divergences.exs` for the owner to approve, matching the case and the `:invalid_geometry` reason. Any other over-deny fails.
- [ ] **Step 6:** Update `docs/hasura-test-coverage.md`: the two permission tests and `boolexp/postgis` move from "Out of scope" to ported, the divergence joins "Divergences", and `boolexp/raster` and `_cast` stay out with their reason. Run the sweep test. Expected: PASS.
- [ ] **Step 7:** Run `mix test` and `mix quality`. Expected: PASS.
- [ ] **Step 8: Checkpoint.** `test: add Hasura parity and differential coverage for PostGIS operators`

---

### Task 9: Docs

Model: sonnet.

**Files:**
- Modify: the `@moduledoc`/`@doc` of every module touched, `docs/guides/security.md`, `docs/guides/querying.md`, `docs/guides/configuration.md`, `docs/guides/compatibility.md`, `usage-rules.md`, `CHANGELOG.md`, `test/readme_examples_test.exs` (guide examples)

- [ ] **Step 1:** Inline docs, each stating the rule and one example:
  - `Authzura.Adapters.Postgres` (the operator table, the schema-qualified SQL, why nothing is pushed down);
  - `Authzura.GeoJSON`, `Authzura.Representation`, `Authzura.Representations.GeoJSON`;
  - the option docs of `geojson_limits`, `representations` and `input_pattern_timeout`;
  - `Authzura.Error` (the new reasons).
- [ ] **Step 2:** Guides.
  - `security.md`: a "Spatial filters" section (fence, validation, pre-check, session operands, the stored-row residual) and the new rows of "Input limits".
  - `querying.md`: the operators, GeoJSON operands, and choosing a representation.
  - `configuration.md`: the two options.
  - `compatibility.md`: what parity covers, the divergence, and that raster, `_cast` and `_eq` on spatial columns stay denied.
- [ ] **Step 3:** `usage-rules.md`, at most eight lines: spatial filters from a user go through `all_input/4` or `scope_input/4`; operands are GeoJSON; native decoding is the default and needs the repo's Postgrex types; `representations:` is instance configuration; handle `:invalid_geometry`.
- [ ] **Step 4:** `CHANGELOG.md` under `## Unreleased`: the operators, the options, the new reasons, the `check_input/4` argument change for third-party adapters, and the PostGIS test image.
- [ ] **Step 5:** Run `mix docs`, `mix test` and `mix quality`. Expected: no doc warnings; PASS. Run `git diff --stat -- README.md`. Expected: no output.
- [ ] **Step 6: Checkpoint.** `docs: document PostGIS operators and output representations`

---

### Task 10: Final review

Models: opus for the whole-branch review, Fable for the security pass. Neither gets the implementers' reports.

- [ ] **Step 1: Whole-branch review (opus)** against the spec and Global Constraints: spec coverage, duplicated logic (a second GeoJSON walker, a second check statement path, a re-implemented `Compare` clause), owner style, hand-written migration names, any private name or local path, README untouched.
- [ ] **Step 2: Security pass (Fable)** on what Task 6 did not see: representations (an expression evaluated on a row the role cannot read, at the root or in a preload), the parity harness (a representation difference hiding a leak) and the Task 6 fixes.
- [ ] **Step 3:** One fix round for Critical and Important findings, test-first; the controller verifies each reviewer repro.
- [ ] **Step 4:** Run `mix test`, `mix quality`, `mix test --only hasura_parity` and the default differential, without and with `AUTHZURA_DIFF_GEOJSON=1` and `AUTHZURA_DIFF_PUSHDOWN=1`. Expected: PASS, no leak.
- [ ] **Step 5: Checkpoint.** Report what is ready, the deferred findings with their cost, and a suggested message. Do not commit or tag.

# Authzura PostGIS support: design

## Intent

Authzura denies every PostGIS operator today (`_st_*` is `:unsupported`), and a `geometry` or `geography` column is selectable only when the repo's Postgrex types decode it. This design adds:
- Hasura v2's spatial filters, in permissions and in untrusted input;
- an extension point for how a column is returned, with GeoJSON as one opt-in implementation.

The claim under test is the stage-one claim, extended: for a select permission using `_st_*` that Authzura accepts, a read returns exactly the rows Hasura returns, Authzura denies wherever Hasura denies, and it never leaks and never raises.

It builds on the stage-one and hardening designs, on the decode probe (an extension type the repo's Postgrex types decode is `:decodable`), and on the constant pattern pre-check (`Authzura.Adapters.Postgres.InputCheck`).

It is generic: nothing assumes an application, a Postgrex geometry library or PgRest. PgRest (<https://github.com/agoodway/pgrest>) will add PostGIS on its own; the two share only Hasura's operator names and GeoJSON operands, and `filter_rows/3` keeps working beside it.

## Hasura v2 semantics relied on

Read from the source at <https://github.com/hasura/graphql-engine/tree/v2.50.1/server>.

| Fact | Source |
|---|---|
| Permission operators: `_st_contains`, `_st_crosses`, `_st_equals`, `_st_overlaps`, `_st_touches`, `_st_within`, `_st_3d_intersects`, `_st_3d_d_within` on `geometry` only; `_st_intersects`, `_st_d_within` on `geometry` and `geography`. `$` prefixes too. A wrong column type is an error. | `src-lib/Hasura/Backends/Postgres/DDL/BoolExp.hs` (`parseGeometryOp`, `parseGeometryOrGeographyOp`, `parseSTDWithinObj`, `parseST3DDWithinObj`) |
| The raster operators exist only in the GraphQL schema; the metadata parser has none, so no permission can hold one. | same file; `Instances/Schema.hs` |
| `_st_d_within` takes `{distance, from}` on `geometry` and `{distance, from, use_spheroid}` on `geography` (GraphQL default `true`). | `RQL/IR/BoolExp.hs` (`DWithinGeomOp`, `DWithinGeogOp`); `Instances/Schema.hs` |
| SQL: `ST_Contains(col, v)` ... `ST_DWithin(col, v, d)`, `ST_DWithin(col, v, d, sph)`, `ST_3DDWithin(col, v, d)`. | `Translate/BoolExp.hs` |
| An operand is GeoJSON text through `ST_GeomFromGeoJSON($n)`, then cast to the column type (`::geometry` or `::geography`). | `SQL/Value.hs` (`withConstructorFn`, `toPrepParam`) |
| Accepted GeoJSON: the seven geometry types, an optional `crs`; a position has at least 2 numbers (more than 3 ignored); a LineString at least 2 positions; a ring at least 4, closed. | `SQL/GeoJSON.hs` |
| Session variables are allowed in every operand, `distance` and `use_spheroid` included. The text goes through the same `ST_GeomFromGeoJSON(...)::type`, unchecked. | `RQL/DDL/Permission/Internal.hs` (`parseCollectableType`); `Execute/Prepare.hs` (`UVSessionVar`, `withTypeAnn`); test `tests-py/queries/graphql_query/permissions/user_can_query_geometry_values_filter_session_vars.yaml` |
| Output: `ST_AsGeoJSON(col, 15, 4)::json` for both types. | `Translate/Column.hs` (`toJSONableExp`) |

## Goals

1. **Spatial columns are recognised.** A column whose type belongs to the PostGIS extension gets `Column.spatial` (`:geometry | :geography`), its typmod SRID (`Column.srid`) and the extension's schema (`Column.type_schema`). A database without PostGIS loads as before.
2. **The ten operators**, in permissions (parsed at load) and in input (`scope_input/4`, `all_input/4`), with Hasura's column-type rules. Operands are GeoJSON. Session variables work in every operand, in permissions only.
3. **Operands are validated in Elixir, then by the database, before any row is read** (see Security).
4. **An output representation extension point**, and a built-in GeoJSON implementation. Native decoding stays the default.
5. **One PostGIS Postgres 18 image** for tests, CI and parity, with fixture tables holding `geometry` and `geography` columns.
6. **Parity and differential coverage** for `_st_*`, comparing results whatever the representation.
7. **Docs** in `@moduledoc`/`@doc`/option docs, the guides and `usage-rules.md`.

## Non-goals

- Raster operators, `_cast` between `geometry` and `geography`, and `_eq`/`_in` on a spatial column. They stay denied.
- Index speed for spatial input. It stays inside the fence, like every other input.
- A dependency on any geometry library. Tests use one to prove native decoding.
- Benchmarks, scheduled CI, README changes.

## Operators

- Names enter `Authzura.Sources.Hasura.BoolExp`; signatures and SQL live in `Authzura.Adapters.Postgres`. Geometry-only operators on a `geography` column are `{:operator_type_mismatch, key, pg_type}`: a denied permission, or invalid input.
- Every PostGIS function and type is named by the extension's schema, quoted from introspection (`"s".st_intersects(col, "s".st_geomfromgeojson($1)::"s".geography)`). A same-named function earlier on the search path is never chosen, and PostGIS need not be on the search path. Hasura emits unqualified names; the results are the same.
- `_st_d_within` operands are parts: `distance` (a finite float, at least 0, since PostGIS raises on a negative one), `from` (GeoJSON) and `use_spheroid` (boolean, default `true`, ignored on `geometry`). Unknown keys are refused.
- The SQL is the same in permission and input mode. A `null` permission operand matches no row.

## Output representation

How a column is returned is the adopter's choice, not the dialect's, so it is a small behaviour, not an adapter callback:

- `Authzura.Representation`: `represents?(column)` and `select(column, field)`, which returns the expression selected in place of the column.
- Instance option `representations: [module]`, default `[]`. The first module that claims a column wins, decided once per load.
- A represented column is in the default projection even when the repo cannot decode its type.
- `Authzura.Representations.GeoJSON` claims spatial columns and selects `"s".st_asgeojson(col, 15, 4)::jsonb`: Hasura's output, decoded as a map.
- It applies to the root select, `get/4` and every preload level. It never applies to filters, ordering or `filter_rows/3`. The expression runs only on rows the role may read.
- With no representation, nothing changes: the decode probe decides, and the value is whatever the repo's Postgrex types return.

## Security

1. **Spatial functions are not leakproof.** They can raise on a row (mixed SRIDs, an invalid stored geometry) and they cost time. Input comparisons stay inside `CASE WHEN permission THEN input ELSE false END`, and `input_index_pushdown` never hoists one.
2. **GeoJSON is validated in Elixir first** (`Authzura.GeoJSON`), before any SQL:
   - shape: Hasura's rules, stricter where it is cheaper to refuse (2 or 3 finite numbers per position, no empty geometry, a named EPSG `crs` only);
   - caps, for input and session operands: 1,000 vertices and 65,536 bytes (instance option `geojson_limits`), and 4 spatial operands per input filter; collections nest at most 4 deep, always;
   - SRID: an operand's SRID must equal the column's typmod SRID when it has one, since PostGIS would raise on the first row otherwise;
   - what reaches the database is re-encoded from the validated parts only.
3. **Then the database checks each operand once, before the read**, in the pattern pre-check's statement, which reads no table: the operand must convert (`ST_GeomFromGeoJSON`, and the `geography` cast) and be `ST_IsValid`. A refused operand is `{:invalid_input, {:invalid_geometry, column}}`. So the outcome cannot depend on which rows exist, hidden or not. The check also sets `input_pattern_timeout` for the read, as it does for patterns.
4. **Permission literals are checked at load**, the same way. A refused one denies the permission, with a diagnostic.
5. **Session operands are policy text, as elsewhere, but still checked on every read:** validated in Elixir when the session value is bound (`{:invalid_session_value, name, reason}`), then in the same pre-check statement. Every entry point that builds a scoped query runs it, `scope/3` and `filter_rows/3` included, and only when the permission holds a session spatial operand.
6. **What stays possible, and is documented:** a predicate can still raise on a stored row (an invalid geometry, or a different SRID in an unconstrained column). In input that is a row the role may read; in a permission it is the policy's own data, as in Hasura.

## Tests and infrastructure

- **One image, everywhere:** `imresamu/postgis:18-3.6-bookworm` (the community image, which publishes arm64 manifests) replaces `postgres:18` in `docker-compose.yml` and in `ci.yml`. It is Postgres 18 with PostGIS installed, so the whole suite runs on it with one database, one migration path and no extra tag or job.
- **Fixtures** come from `mix ecto.gen.migration`: the extension, and a table with constrained and unconstrained `geometry`, a 3D `geometry` and a `geography` column.
- **Native decoding** is proven with a test-only repo whose Postgrex types include a PostGIS extension.
- **Parity:** Hasura's two permission tests and its `boolexp/postgis` cases are ported. The comparison reduces a GeoJSON map and a decoded struct to the same canonical value, so both representations are compared with Hasura.
- **Differential:** generators add spatial input filters, valid and invalid; it runs with native decoding and with the GeoJSON representation.

## Open decisions

Each needs the owner's call. The plan assumes the recommendation.

1. **Image.** Switch compose and CI entirely to the PostGIS image, or keep `postgres:18` and add a `:postgis`-tagged suite with its own migrations. *Recommend: switch.* One image is simpler, the pull is a little larger, and no job is added. The cost is a community image in CI.
2. **Extension point.** A behaviour plus `representations:`, an adapter callback, or a fixed `geo_output: :native | :geojson` option. *Recommend: the behaviour.* It is two callbacks and serves any type.
3. **Session operands.** Support them with the per-read check (one extra statement on such reads, also in `scope/3` and `filter_rows/3`), validate in Elixir only, or deny at load. *Recommend: support with the check.* Hasura's own permission test uses them.
4. **Invalid but parseable geometries** (a self-intersecting polygon). Hasura runs them. *Recommend: refuse them*, in input, session values and permission literals, as a recorded divergence that fails closed. The alternative for permissions is a warning.
5. **Scope.** Raster, `_cast` and `_eq`/`_in` on spatial columns stay denied. *Recommend: yes.* No permission can hold a raster operator.
6. **Caps.** 1,000 vertices and 65,536 bytes (configurable) and 4 operands per filter, for input and session operands; permission literals uncapped. *Recommend: as stated.*
7. **Test dependency.** `geo_postgis`, test-only, for the native-decoding repo. *Recommend: yes.* The library gains no dependency.
8. **Benchmarks.** *Recommend: none now.* Fenced spatial input cannot use a GiST index, which the guide will say.

## Left to the builder

- How the SRID is read from the type modifier, without calling PostGIS in the introspection query.
- Whether the spatial check shares the pattern statement or is a second arm built only when operands exist.
- Which Hasura error codes map to the new reasons.
- Generator weights and fixture coordinates, within short decimals that survive 15 digits.

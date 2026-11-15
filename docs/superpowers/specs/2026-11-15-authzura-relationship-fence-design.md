# Authzura relationship-permission fence: design

## As shipped (2026-11-15)

This section supersedes the original proposals below wherever they differ.

- The optional `c:Authzura.Adapter.lossless_join_pair?/2` callback certifies mapping
  pairs; an adapter without it never lifts. Postgres allows integer-family pairs
  and same-type collation-free numeric, float, UUID, enum, timestamp, date and
  boolean pairs. Domains resolve to their base type. Text-family pairs, including
  text/varchar, stay EXISTS because introspection does not capture their collation.
- Lifting is all-or-nothing: any remaining relationship or `_exists` makes the
  whole permission use the original EXISTS SQL. No child EXISTS is correlated
  to a lifted alias. The returned lift contains only `joins` and `condition`.
- Fully lifted reads use `::int = ANY('{1 x20}'::int[])` (twenty ones), a 10%
  estimate. The ten-one, approximately 5% candidate was not the shipped choice.
- The estimate spike ran on PG16 at small scale only. PG17, PG18 and large-scale
  spike measurements remain deferred. The release gate is **Task 8**, on captured
  Ecto SQL on **PG18 only**. Hidden-row regression evidence is also PG18 only;
  it was not run on PG16/17. There is no version-matrix test tag. This is evidence,
  not proof for every plan.
- `input-rel-permission` buffers reach 1.00x Hasura at both scales; small default
  DB time is inconclusive and the large index target still fails. Broad-limit
  remains a gap: small buffers regress from 1.67x to 9.64x despite lower DB time.
  Text-pair lifting and array relationships unique through an index are deferred.


## Intent

An input read under a relationship permission costs 2-3.4x Hasura (`docs/hasura-differences.md` §2.1). The fence `P AND CASE WHEN P THEN input ELSE false END` repeats `P`; inside the `CASE` its `EXISTS` cannot become a join, so it runs as a correlated SubPlan per candidate row. Evidence and rejected options: internal investigation notes (not in the repo).

This design compiles the permission's liftable relationship chains as inner joins ("join-lift"), keeps the fence, and pairs the lift with a fence estimate chosen by measurement. The set of rows is unchanged, and the input still never runs on a hidden row.

## Join-lift

A `{:relationship, name, e}` node is lifted when **all** of these hold; otherwise it compiles to today's `EXISTS`, byte for byte.

1. **Reached through `_and` only.** Never under `_or` or `_not`, and never inside an `EXISTS` that was not lifted.
2. **An `:object` relationship.**
3. **The target is strictly unique on the mapping.** The mapping's remote columns, as a set, equal the target's primary key, and that key enforces uniqueness over the whole scanned relation:
   - the constraint is **not deferrable** (a deferrable key can hold duplicates inside a transaction);
   - the target has no inheritance children (`relhassubclass`). The exception is a partitioned table (`relkind 'p'`), whose key is enforced across its partitions.

   Views have no key and never lift. Introspection records this as `Table.strict_key?`, and the fingerprint covers `condeferrable`, `relhassubclass` and `relkind`.
4. **Each mapping pair compares without lossy coercion.** The adapter must certify the pair: integer-family pairs (`int2`, `int4`, `int8`) or same-type collation-free pairs (numeric, float, UUID, enum, timestamp, date and boolean). Domains resolve to their base type. Text-family pairs, including `text`/`varchar`, `bpchar` and `citext`, and lossy `float`/`numeric` against integers keep the `EXISTS`. For example, a `float8` local equals both `9007199254740992` and `9007199254740993` in a `bigint` key.
5. **Within the limits.** At most 7 joins in total, under `join_collapse_limit` 8, and unique aliases within the pool (`Aliases.max_index/0`). If either limit would be exceeded, **nothing** in the statement is lifted.

A lifted node becomes `INNER JOIN target AS alias ON mapping` plus the flat condition `mapping AND e'`. `e'` is `e` compiled against the joined alias, and its own children are lifted by the same rules. If any child needs an `EXISTS`, the whole permission falls back unchanged. Every join takes a fresh alias.

The fence text is unchanged: `P AND [pushdown AND] CASE WHEN P THEN input ELSE false END`, with the lifted `P` in both places. The estimate shape below may wrap the `CASE`.

**Where.** Only `all_input/4`, and only when an input is present. Its root must be a bare table name or schema (`Input.bare_root/1`), so no caller join or union reaches the lift. That refusal stays explicit and tested, and the internal join budget is clamped at zero.

These calls never carry an input fence, already match Hasura's shape, and are unchanged: `scope/3`, `filter_rows/3`, `all/3`, `one/3`, `get/4`, preload statements and combination branches. `scope_input/4` is not lifted (open decision 1).

## Semantics that must be preserved

| Case | `EXISTS` today | The lifted join must |
|---|---|---|
| A mapping column is NULL (nullable FK, partial-NULL composite) | false | drop the row: an inner join, and `=` on NULL is not true |
| Dangling key (no target row) | false | drop the row |
| Multiplicity | at most one boolean per row | match at most one target row (rules 3 and 4) |
| Comparison | `remote = local` | use the same `pair/4` equality, so the operators are identical |
| Sibling nodes on the same relationship | two `EXISTS` | two joins, one alias each |
| Under `_or`/`_not`, array, non-strict key, lossy pair | `EXISTS` | stay `EXISTS`, unchanged |
| Select list, `LIMIT`, `OFFSET`, `ORDER BY` | the request's | stay unchanged, at one query level |

**Row contract.** The lifted and unlifted reads return the same set of rows. Under a total order (the request's `order_by` ends in a unique key), they return the same sequence, and pagination with a unique tiebreaker gives the same pages. With ties or no order, the sequence is unspecified, as it is today. This is documented in the `all_input/4` doc.

**Guarantee rule.** The `WHEN` must imply "this row is permitted" from the values in the tuple in front of it, whatever else the plan has applied.
- **The lifted `WHEN`.** It references every lifted table and re-checks every `ON` equality and every target condition, so a true `WHEN` means real target rows satisfy the chain, which is what the `EXISTS` asserts. This relies only on the documented `CASE` evaluation order (PG docs 4.2.14 and 9.18.1). The estimate wrapper keeps the `CASE` intact.
- **Constant folding**, the documented `CASE` exception, applies only to subexpressions made of parameters alone. Those depend on the request, never on a row value, and the pattern pre-check already refuses known run-time errors.
- **The push-down exception, by design.** With `input_index_pushdown`, the hoisted leakproof `_eq`/`_in` conjuncts run outside the fence, as they do today. They cannot fail or reveal an operand; the remaining risk is a timing channel, which `docs/hasura-differences.md` §3 documents. The fence still holds the whole input.

## Estimate shape

With the SubPlan gone, the `CASE` gets the default selectivity of 0.5, and some tenants plan a primary-key walk (6-11 of 40 orgs at small). The candidates are:
- `(CASE …)::int = 1`, about 0.005;
- `(CASE …)::int = ANY('{1,…×10}'::int[])`, about 5 % (not selected);
- `(CASE …)::int = ANY('{1 x20}'::int[])`, about 10 % (shipped, twenty ones);
- anything better the spike finds.

**Task 2 rules by measurement, against matched controls.**
- **Measured scope.** The spike interleaved unlifted controls and candidates on PG16 small only. The originally proposed PG16/17/18 small/large grid was not completed; PG17/18 and large spike cells remain deferred. Task 8 used PG18 generated SQL.
- **Cases.** Selective (`input-rel-permission`), broad (`input-rel-broad-limit`, `input-col-broad-limit`), zero-match, partial-lift and `input-regex`.
- **Criteria.**
  1. Zero primary-key-walk plans across the 40 orgs, under both custom and generic plans.
  2. A median paired ratio (candidate / control per round) of at most **1.5x** on the broad cases. Each cell gets at most 3 reruns while its CV is above 15 %. A cell is borderline when the bound lies inside the range of its round ratios; after the reruns, a borderline cell counts as a fail.
  3. `input-regex` no worse than its control. This also decides whether the shape applies to non-lifted fences.

If no candidate meets criteria 1 and 2, join-lift does not ship. Task 8 re-applies the criteria to the final Ecto-generated SQL, and a failure stops the release. **Rollback** is reverting the release: `join_lift` is internal, not a public switch.

## Interop

- **`input_index_pushdown`, on and off.** The hoisted conjuncts sit beside the lifted `P`, and the rows are identical either way.
- **Preloads.** The root statement keeps its projection and a single level, so the preload keys and the `REPEATABLE READ` snapshot are untouched.
- **`QueryShape`.** It already refuses `lock`, `distinct` and aggregates.
- **Reserved aliases.** The `__authzura` prefix is reserved, so the lifted joins cannot collide with a caller's bindings.

## Tests and infrastructure

- **Hidden-row regression evidence** (evidence, not proof).
  - **Input path.** The test runs through `all_input/4`, with push-down off and on, so the real hoisted conjuncts are present.
  - **Fixture.** A committed fixture (a migration, so parallel workers see it) has a `body` column of a domain type. The domain's owner-defined `~~` operator calls an argument-only probe (`IMMUTABLE`, `PARALLEL SAFE`, not leakproof) that raises on a body marked hidden. The seed sets that marker on exactly the rows the permission rejects.
  - **Planner settings.** The investigation's 14, plus `enable_memoize` off and on, forced parallel with a check that workers actually launched, and forced JIT with a check that JIT ran. A partitioned target is also covered.
  - **Versions.** PG18 only, including CI. Not run on PG16/17; there is no version-matrix tag.
- **Row parity.** A metamorphic property compares lifted and unlifted reads (the same set, and the same sequence under a total order), with push-down off and on. Its coverage fields record how many cases lifted, fell back, exposed an invalid incomplete lift, or carried a nullable chain, and the guards have failure tests. The Hasura differential runs default and deep.
- **Lift selection.** Unit tests on `to_sql` for every rule and fallback, including a deferrable key, an inheritance parent, a partitioned target and the `float8`/`bigint` counterexample.
- **Bench.**
  - `input-rel-broad-limit` and `input-col-broad-limit` are added before the change, with a buffer pin on `input-rel-permission` (it fails before the change).
  - The primary-key-walk check reads raw custom and generic plans (`all_input/4` runs uncached), and looks at the ordered path under the root `LIMIT`.

## Open decisions

1. **Lift `scope_input/4` too?** A caller composing on the returned query with positional bindings would bind to a lifted join. *Recommend: no;* `all_input/4` only.
2. **The bound on the broad scenarios.** *Recommend:* a median paired ratio of at most 1.5x, with borderline cells failing as above.
3. **The shape on non-lifted fences.** *Recommend:* lifted reads only, unless Task 2 shows `input-col-broad-limit` within the bound and `input-regex` better on every version.
4. **A public switch.** *Recommend: none.* Use an internal `join_lift: false` for tests and the bench.
5. **Array relationships unique through an index.** *Recommend: defer.*

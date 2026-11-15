# Hasura v2 select-permission test coverage

This records which of Hasura v2's own select-permission tests Authzura's
test suite covers, where, and which ones it deliberately leaves out, so the
compatibility claim can be audited.

- Hasura sources were read at
  [v2.51.6](https://github.com/hasura/graphql-engine/tree/v2.51.6/server).
  Paths below are relative to that `server/` directory. The scenario catalog
  in the stage-one design was drawn from v2.50.1; the cited files are the
  same in both tags for everything ported here.
- Ported scenarios live in `test/hasura_scenarios/`. Each `describe` or test
  names its Hasura source file. Their fixtures (tables and rows copied from
  the Hasura setup) are built by the test migration
  `priv/test_migrations/*_create_hasura_scenario_schemas.exs`, one Postgres
  schema per Hasura source.
- Hasura's admin role (a request without `X-Hasura-Role`) is Authzura's
  opt-in `admin_role`. A Hasura GraphQL `where` argument maps to
  `all_input/4`'s `filter`, and a nested selection maps to a preload.
- A ported test that disagrees with Hasura keeps Hasura's expected result,
  is tagged `@tag :hasura_divergence` and is skipped with the reason. Run
  them with `mix test --only hasura_divergence --include skip`.
- The opt-in parity suite in `test/parity/` runs the same reads through a
  real Hasura v2.51.6 and compares the results; see
  [Running parity tests](guides/security.md#running-parity-tests). Its
  first run found that Hasura rejects any predicate on a `json` column in a
  permission (`_is_null` included) as inconsistent metadata. Authzura now
  denies such a permission at load with `{:unsupported, :json_column}`
  (`test/authzura/sources/hasura/bool_exp_test.exs`,
  `test/integration/row_filter_test.exs`,
  `test/parity/select_parity_test.exs`).

## Scenario catalog

Status: **covered** (an existing test asserts it), **partial → ported**
(only a unit-level or adapted test existed; a faithful port was added), or
**missing → ported**.

| # | Catalog item | Status | Tests |
|---|---|---|---|
| 1 | Row filters: an author sees only their own rows | covered | `test/integration/row_filter_test.exs:67`; `test/hasura_scenarios/row_filters_test.exs:51,57` |
| 2 | Row filters: published-only roles; an editor sees in-review plus published | partial → ported | `test/hasura_scenarios/row_filters_test.exs:63,77` (`SelectSpec.hs`) |
| 3 | Row filters: `{}` returns all rows | covered | `test/integration/row_filter_test.exs:81` |
| 4 | Empty forms: `_in: []` returns no rows | covered | `test/integration/row_filter_test.exs:87`; `test/authzura/adapters/postgres_test.exs:171` |
| 5 | Empty forms: `_nin: []` returns all rows | covered | `test/integration/row_filter_test.exs:87` |
| 6 | Empty forms: `_or: []` and `_and: []` (also under `_not`) | covered | `test/integration/row_filter_test.exs:93`; `test/authzura/sources/hasura/bool_exp_test.exs:53` |
| 7 | NULL: null-aware `_eq`/`_neq` on nullable columns, plain on non-null | covered | `test/integration/row_filter_test.exs:105`; `test/authzura/compiler_test.exs:45,50` |
| 8 | NULL: a literal `null`, and NULL rows under `_not` | covered | `test/integration/row_filter_test.exs:101,110` |
| 9 | NULL: `_is_null` true and false | covered | `test/integration/row_filter_test.exs:125` |
| 10 | Relationships: object, array and 3-hop | covered | `test/integration/row_filter_test.exs:132,136,140`; `test/hasura_scenarios/row_filters_test.exs:164,425` |
| 11 | Relationships: several conditions in one node match the same related row | covered | `test/integration/row_filter_test.exs:145` |
| 12 | Relationships: sibling nodes stay independent | covered | `test/integration/row_filter_test.exs:145`; `test/authzura/compiler_test.exs:92` |
| 13 | Relationships: `relationship: {}` requires a related row | covered | `test/integration/row_filter_test.exs:320` |
| 14 | Relationships: negated relationships | covered | `test/integration/row_filter_test.exs:320` |
| 15 | Relationships: multi-column mapping (`MultiColumnObjectRelationshipsSpec.hs`) | partial → ported | `test/integration/row_filter_test.exs:233` (filter); `test/hasura_scenarios/relationships_test.exs:42` (the spec's own selection) |
| 16 | Relationships: a self-relationship | covered | `test/integration/row_filter_test.exs:238`; `test/hasura_scenarios/row_filters_test.exs:420` |
| 17 | Relationships: the target's own permission is not applied inside a filter | covered | `test/integration/row_filter_test.exs:242` |
| 18 | `_exists`: uncorrelated | covered | `test/integration/row_filter_test.exs:257`; `test/hasura_scenarios/row_filters_test.exs:205,210` |
| 19 | `_exists`: same table as the root, with a session variable (`RootExistElementAliasing9457Spec.hs`) | partial → ported | `test/integration/row_filter_test.exs:262` (adapted); `test/hasura_scenarios/row_filters_test.exs:295` (+ divergence `:316`) |
| 20 | `_exists`: inside `_or` and `_not` | covered | `test/integration/row_filter_test.exs:278` |
| 21 | Shorthand: bare `col: "X-Hasura-User-Id"` equals `_eq` | partial → ported | `test/authzura/sources/hasura/bool_exp_test.exs:126` (parse); `test/hasura_scenarios/session_variables_test.exs:104,141` |
| 22 | Aliases: `$or`, `$in`, `$has_key` behave as `_or`, `_in`, `_has_key` | partial → ported | `test/authzura/sources/hasura/bool_exp_test.exs:95,108` (parse); executed: `$or` `test/hasura_scenarios/row_filters_test.exs:149`, `$has_key`/`$has_keys_*` `test/hasura_scenarios/operators_test.exs:56,61,67,77`. `$in` stays parse-only (no Hasura test executes it) |
| 23 | Mixed-case session names such as `X-HASURA-USER-ID` in metadata | partial → ported | `test/authzura/sources/hasura/bool_exp_test.exs:128` (parse); `test/hasura_scenarios/row_filters_test.exs:149` |
| 24 | Operators: the comparison set | covered | `test/integration/row_filter_test.exs:314` |
| 25 | Operators: `_like`, `_ilike`, `_similar`, `_regex` families | covered | `test/integration/row_filter_test.exs:325`; `test/hasura_scenarios/operators_test.exs:83` |
| 26 | Operators: jsonb `_contains`, `_contained_in`, `_has_key` (+ session), `_has_keys_any`, `_has_keys_all` | covered | `test/integration/row_filter_test.exs:341`; `test/hasura_scenarios/operators_test.exs:56-77` |
| 27 | Session: case-insensitive names | covered | `test/authzura/session_test.exs:6`; `test/hasura_scenarios/session_variables_test.exs:39` |
| 28 | Session: a missing variable gives an error (`select_articles_without_required_headers.yaml`) | covered | `test/integration/scope_test.exs:269`; `test/authzura/compiler_test.exs:156`; `test/hasura_scenarios/session_variables_test.exs:147,162` |
| 29 | Session: array variables `{1,2,3}` and `{}` (`PermissionSpec.hs`) | partial → ported | `test/authzura/adapters/postgres_test.exs:158,172` (adapter); `test/hasura_scenarios/session_variables_test.exs:39,46,73,77` |
| 30 | Session: quoted and comma elements (`ArrayLiteralTextEncodingSpec.hs`) | partial → ported | `test/authzura/adapters/postgres/values_test.exs:31,37` (unit); `test/hasura_scenarios/operators_test.exs:181` (the spec's literal lists) |
| 31 | Session: long values aren't truncated (`DoNotTruncateSessionVariables8158Spec.hs`) | partial → ported | `test/authzura/adapters/postgres/values_test.exs:194` (unit); `test/hasura_scenarios/session_variables_test.exs:104` |
| 32 | Session: a cast failure gives an error, never NULL | covered | `test/authzura/compiler_test.exs:165`; `test/authzura/adapters/postgres/values_test.exs:97` |
| 33 | Columns: projection holds only requested allowed columns, on the executed SQL | covered | `test/integration/scope_test.exs:116` |
| 34 | Columns: a disallowed column gives `{:forbidden_columns, _}` (`user_cannot_access_remarks_col.yaml`) | covered | `test/integration/scope_test.exs:138`; `test/hasura_scenarios/columns_test.exs:21,27` |
| 35 | Columns: `field :x, source: :y` maps to the physical column | covered | `test/integration/scope_test.exs:146` |
| 36 | Columns: a permission filter on a non-selectable column still works | missing → ported | `test/hasura_scenarios/columns_test.exs:44` |
| 37 | Input: filtering, sorting or selecting a hidden column is rejected | covered | `test/integration/input_test.exs:123` |
| 38 | Input: a relationship or `_exists` in input is rejected | covered | `test/integration/input_test.exs:175`; `test/integration/input_hardening_test.exs:141` |
| 39 | Input: the input filter is ANDed with the permission filter | covered | `test/integration/input_test.exs:200,206`; `test/hasura_scenarios/row_filters_test.exs:110,128` |
| 40 | Input: plain-equality semantics | covered | `test/integration/input_test.exs:220`; `test/authzura/compiler_test.exs:56` |
| 41 | Roles: the requested role is allowed | covered | `test/authzura/session_test.exs:33`; `test/authzura/jwt_test.exs:69` |
| 42 | Roles: a requested role that isn't allowed is rejected | covered | `test/authzura/session_test.exs:25`; `test/authzura/jwt_test.exs:73` |
| 43 | Roles: the default role is used when none is requested | covered | `test/authzura/session_test.exs:6` |
| 44 | Roles: an empty-string role counts as absent | covered | `test/authzura/session_test.exs:42` |
| 45 | Roles: a role without a permission gets `:forbidden` | covered | `test/integration/scope_test.exs:238`; `test/integration/executor_test.exs:224` |
| 46 | Roles: admin bypass only when configured | covered | `test/integration/scope_test.exs:243,248`; `test/hasura_scenarios/columns_test.exs:27` |
| 47 | Root fields: `query_root_fields: []` gives `:root_field_disabled` | covered | `test/integration/scope_test.exs:276`; `test/integration/input_test.exs:367`; `test/hasura_scenarios/relationships_test.exs:194` |
| 48 | Limits: `min(caller, permission)` | covered | `test/integration/scope_test.exs:281`; `test/integration/input_test.exs:318` |
| 49 | Limits: a negative permission limit is a load error | covered | `test/authzura/sources/hasura/metadata_test.exs:114` |
| 50 | Limits: caller `with_ties` or a non-literal limit is rejected | covered | `test/authzura/query_shape_test.exs:69,73`; `test/integration/scope_test.exs:294`; `test/hasura_scenarios/limits_test.exs:61` |
| 51 | Shapes: subquery or fragment root, existing select, group_by, distinct, with_ties rejected | covered | `test/authzura/query_shape_test.exs:17,22,49,54,64,69` |
| 52 | Shapes: a CTE named like an authorized table still reads the real table | covered | `test/integration/scope_test.exs:330`; `test/authzura/query_shape_test.exs:119` |
| 53 | Shapes: same-table union branches each scoped; caller limit/offset/order on the whole | covered | `test/integration/scope_test.exs:341,353`; `test/integration/executor_test.exs:135` |
| 54 | Shapes: a union across tables, or with preloads, is rejected | covered | `test/authzura/query_shape_test.exs:85,90`; `test/integration/scope_test.exs:364` |
| 55 | Shapes: a branch whose projection or types can't be aligned is rejected | covered | `test/authzura/query_shape_test.exs:97` |
| 56 | Shapes: a modifying CTE (even unreferenced) or a fragment CTE is rejected | covered | `test/authzura/query_shape_test.exs:26,43`; `test/integration/executor_test.exs:196` |
| 57 | Shapes: `all` runs in a read-only transaction | covered | `test/integration/read_only_test.exs:41` |
| 58 | Shapes: a pinned `limit(^n)` is accepted and checked at run time | covered | `test/integration/scope_test.exs:281,294` |
| 59 | Shapes: an existing root alias is reused | covered | `test/integration/scope_test.exs:320` |
| 60 | Shapes: a caller join colliding with a reserved alias errors | covered | `test/authzura/query_shape_test.exs:106` |
| 61 | Shapes: a caller join aliased like a relationship doesn't mis-correlate | covered | `test/integration/scope_test.exs:311` |
| 62 | Shapes: nesting deeper than the alias pool is rejected without atoms | covered | `test/authzura/compiler_test.exs:253`; `test/authzura/sources/hasura/bool_exp_test.exs:398` |
| 63 | Preloads: an allowed relationship loads with the target's filter and columns | covered | `test/integration/preload_loader_test.exs:268`; `test/integration/preload_api_test.exs:136`; `test/hasura_scenarios/session_variables_test.exs:169` |
| 64 | Preloads: undeclared relationship, or target without select permission, is `:forbidden` | covered | `test/authzura/preload/tree_test.exs:196,201` |
| 65 | Preloads: a target with disabled root fields is reachable | covered | `test/authzura/preload/tree_test.exs:206`; `test/hasura_scenarios/relationships_test.exs:171` |
| 66 | Preloads: per-parent permission limit on array relationships | covered | `test/integration/preload_loader_test.exs:190` |
| 67 | Preloads: an object relationship gives at most one row or `nil` | covered | `test/integration/preload_loader_test.exs:257,425`; divergence `test/hasura_scenarios/relationships_test.exs:95` |
| 68 | Preloads: mapping columns the role can't select are stripped | covered | `test/integration/preload_loader_test.exs:404`; `test/integration/preload_api_test.exs:151` |
| 69 | Preloads: plain Ecto preload translated; `where:`/`preload_order:`/`through:`/custom/function rejected | covered | `test/integration/preload_api_test.exs:171`; `test/authzura/preload/tree_test.exs:356,397,412` |
| 70 | Preloads: `scope`/`scope_input` with a preload is rejected | covered | `test/integration/scope_test.exs:428`; `test/integration/input_test.exs:356` |
| 71 | Preloads: composite-key and reverse object relationships | covered | `test/integration/preload_loader_test.exs:288,369`; `test/hasura_scenarios/relationships_test.exs:42` |
| 72 | Preloads: crossed composite tuples | covered | `test/integration/preload_loader_test.exs:327` |
| 73 | Preloads: partial NULL keys | covered | `test/integration/preload_loader_test.exs:334` |
| 74 | Preloads: `citext` keys | covered | `test/integration/preload_loader_test.exs:342` |
| 75 | Preloads: nested three levels deep | covered | `test/integration/preload_loader_test.exs:379` |
| 76 | Preloads: depth and node limits, repeated self-relationship, wide tree, rejected up front | covered | `test/authzura/preload/tree_test.exs:288,294`; `test/integration/preload_api_test.exs:185` |
| 77 | Preloads: one snapshot and one generation across levels | covered | `test/integration/preload_consistency_test.exs:116,133` |
| 78 | Preloads: inside a caller transaction, `:preload_in_transaction` unless trusted | covered | `test/integration/preload_api_test.exs:266,284` |
| 79 | Preloads: limited array without `order_by` by cardinality; with it by exact order | covered | `test/integration/preload_loader_test.exs:190,200` |
| 80 | Preloads: stitching fields the caller didn't request are absent | covered | `test/integration/preload_loader_test.exs:404`; `test/integration/preload_api_test.exs:151` |
| 81 | Prefixes: precedence order | covered | `test/integration/scope_test.exs:176` |
| 82 | Prefixes: conflicting prefixes resolve in that order | covered | `test/integration/scope_test.exs:176` |
| 83 | Prefixes: a `Repo.all(..., prefix:)` override can't redirect | covered | `test/integration/scope_test.exs:192`; `test/integration/executor_test.exs:183` |
| 84 | Prefixes: a non-public `search_path` doesn't change the table read | covered | `test/integration/scope_test.exs:197` |
| 85 | Prefixes: a `table:` assertion mismatch errors | covered | `test/integration/scope_test.exs:226` |
| 86 | Execution: `put_dynamic_repo` to another repo gives `:dynamic_repo` | covered | `test/integration/executor_test.exs:164` |
| 87 | Execution: a disallowed execution option is rejected | covered | `test/integration/executor_test.exs:183` |
| 88 | Reload: atomic generation swap during concurrent scoping | covered | `test/authzura/store_test.exs:409` |
| 89 | Reload: a revoked permission takes effect after a version change | covered | `test/authzura/store_test.exs:106` |
| 90 | Reload: an older generation is never published | covered | `test/authzura/store_test.exs:311,356` |
| 91 | Reload: a lower-sorting fingerprint and a `resource_version` rollback both reload | covered | `test/authzura/store_test.exs:293,302`; `test/integration/store_reload_test.exs:31` |

## Extra scenarios ported

Hasura select-permission tests that the catalog does not list, ported to
`test/hasura_scenarios/`.

| Hasura source | Scenario | Test |
|---|---|---|
| `tests-py/queries/graphql_query/permissions/anonymous_can_only_get_published_articles.yaml` | anonymous sees only published articles, with their authors; a `where` for unpublished finds none | `row_filters_test.exs:110,116` |
| `tests-py/queries/graphql_query/permissions/user_select_query_unpublished_articles.yaml` | `$or` permission ANDed with a `where`, with the author | `row_filters_test.exs:128` |
| `tests-py/queries/graphql_query/permissions/artist_select_query_Track.yaml`, `artist_select_query_Track_fail.yaml` | filter through an object relationship named like its table; missing header errors | `session_variables_test.exs:141,147` |
| `tests-py/queries/graphql_query/permissions/user_can_query_jsonb_values_filter.yaml`, `..._session_vars.yaml` | `$has_key` with a literal and with a session variable | `operators_test.exs:56,61` |
| `tests-py/queries/graphql_query/permissions/jsonb_has_any.yaml` | `$has_keys_any` with `{age}` and `{}` | `operators_test.exs:67` |
| `tests-py/queries/graphql_query/permissions/in_and_nin.yaml` | `_in`/`_nin` array session variables, including `{}` | `session_variables_test.exs:39,46` |
| `tests-py/queries/graphql_query/permissions/iregex.yaml` | `_iregex` with a session variable | `operators_test.exs:83` |
| `tests-py/queries/graphql_query/permissions/user_query_auction.yaml` | `$cgt` column comparison | `operators_test.exs:121` (divergence) |
| `tests-py/queries/graphql_query/boolexp/basic/query_account_permission_success.yaml`, `..._fail.yaml` | `_exists` on a table named `user`, admin and non-admin | `row_filters_test.exs:205,210` |
| `tests-py/queries/graphql_query/boolexp/basic/self_referential_relationships.yaml` | self array relationship under `_or` with `_ilike`; self object relationship with `_is_null` | `row_filters_test.exs:420` |
| `tests-py/queries/graphql_query/boolexp/basic/select_article_author_is_published_and_registered.yaml`, `select_article_author_not_published_or_not_registered.yaml` | object relationship under `_and` and `_or` | `row_filters_test.exs:425` |
| `tests-py/queries/graphql_query/boolexp/basic/select_author_article_where_permissions.yaml` ([#6931](https://github.com/hasura/graphql-engine/issues/6931)) | a relationship in a user `where` applies the target's permission | `relationships_test.exs:298,308` (divergence) |
| `tests-py/queries/graphql_query/boolexp/basic/select_uuid_test_in_uuid_col_postgres.yaml` | `_in` on a uuid column | `operators_test.exs:150` |
| `tests-py/queries/graphql_query/boolexp/basic/in_sql_identifier_array.yaml` | `_nin` on an `information_schema.sql_identifier` column (a domain over `name`, compared as text) | `operators_test.exs:172` |
| `tests-py/queries/graphql_query/limits/select_query_article_limit_1.yaml`, `_limit_2.yaml`, `_limit_null.yaml`, `_neg_limit_error.yaml` | caller limit with order and an object relationship; no limit; negative limit | `limits_test.exs:46,51,56,61` |
| `lib/api-tests/src/Test/Regression/ObjectRelationshipsLimit7936Spec.hs` | an object relationship whose manual mapping matches two rows | `relationships_test.exs:95` (divergence) |
| `lib/api-tests/src/Test/Regression/LongIdentifiers3796Spec.hs` | long table, column and relationship names through an array relationship | `relationships_test.exs:228` |
| `tests-py/queries/graphql_query/boolexp/search/select_city_where_{like,nlike}.yaml` | `_like` and `_nlike` on a city name, as admin input filters; a role's permission is ANDed with the pattern, and a role without one is `:forbidden` | `search_test.exs:50,55,110,115` |
| `tests-py/queries/graphql_query/boolexp/search/select_city_where_{ilike,nilike}_postgres.yaml` | `_ilike` and `_nilike` | `search_test.exs:60,65` |
| `tests-py/queries/graphql_query/boolexp/search/select_city_where_{similar,not_similar}_postgres.yaml` | `_similar` and `_nsimilar` | `search_test.exs:70,75` |
| `tests-py/queries/graphql_query/boolexp/search/select_city_where_{regex,nregex,iregex,niregex}_postgres.yaml` | the four regex operators, `_nregex` case-sensitive | `search_test.exs:80,85,90,95` |
| `tests-py/queries/graphql_query/boolexp/search/select_project_where_ilike_postgres.yaml` ([#6217](https://github.com/hasura/graphql-engine/issues/6217)) | `_ilike` on a `char(3)` column | `search_test.exs:101` |
| `tests-py/queries/graphql_query/boolexp/jsonb/select_article_author_jsonb_contains_latest.yaml`, `select_article_author_jsonb_contained_in_latest.yaml`, `select_article_author_jsonb_contained_in_bestseller_latest.yaml` | `_contains` and `_contained_in` on a jsonb array, each article with its author; operands nothing matches, a NULL jsonb value, and a permission that matches nothing return no rows | `jsonb_test.exs:108,118,124,153,159,164` |
| `tests-py/queries/graphql_query/boolexp/jsonb/select_product_jsonb_has_key_sim_type.yaml`, `select_product_jsonb_has_keys_all_ram_touchscreen.yaml`, `select_product_jsonb_has_keys_any_os_operating_system.yaml` | `_has_key` (a key with a space), `_has_keys_all` and `_has_keys_any`, with the whole `spec` document | `jsonb_test.exs:134,139,145` |
| `tests-py/queries/graphql_query/boolexp/basic/select_author_article_where_{gt,gte,lt,not_lt,in}.yaml` | comparisons on an author with its articles, as admin input filters; a role's permission is ANDed with them | `comparisons_test.exs:73,78,83,88,96,126,136` |
| `tests-py/queries/graphql_query/boolexp/basic/select_author_article_where_and_in.yaml` | `_and` of two `_in` conditions, sent as a list (Hasura's single-object form is the divergence below) | `comparisons_test.exs:103` |
| `tests-py/queries/graphql_query/boolexp/basic/select_author_article_where_in_empty_array_postgres.yaml`, `select_author_article_where_nin_empty_array_postgres.yaml`, `select_author_article_where_nin_empty_array.yaml` | `_in: []` returns no authors, `_nin: []` all | `comparisons_test.exs:114,119` |
| `lib/api-tests/src/Test/Auth/Authorization/DisableRootFields/SelectPermission/RelationshipSpec.hs` | a table with disabled root fields is reachable through a relationship | `relationships_test.exs:171,194` |

## Divergences

| Test | Hasura | Authzura | Diagnosis |
|---|---|---|---|
| `row_filters_test.exs:316` (`RootExistElementAliasing9457Spec.hs`, 2nd case) | `_ceq: ["$", "group"]` inside `_not _exists` returns two rows | the permission is denied, `:forbidden` | intended stage-one difference: column comparison operators are unsupported |
| `operators_test.exs:121` (`user_query_auction.yaml`) | `$cgt: price` returns auction 4 | denied, `:forbidden` | intended stage-one difference: column comparison operators |
| `relationships_test.exs:298,308` (#6931) | a relationship in `where` is applied with the target's permission | rejected as `:relationship_in_input`, the empty form `{articles: {}}` included (`relationships_test.exs:315`) | intended: relationships are rejected in input, and a relationship-shaped key reads the same whether it names a relationship, a hidden column or nothing |
| `relationships_test.exs:95` (`ObjectRelationshipsLimit7936Spec.hs`) | an object relationship matching two rows returns one of them | `{:unsupported_query, {:object_cardinality, "author"}}` | intended: Authzura fails closed rather than pick an arbitrary row |
| `comparisons_test.exs:164` (`select_author_article_where_lte.yaml`) | the nested `articles(where: {id: {_gt: 1}})` filters the articles | `{:unsupported_query, {:preload, "articles"}}` | intended: a preload takes columns, order and children only, so a `where` on a nested selection is rejected rather than ignored |
| `comparisons_test.exs:173` (`select_author_article_where_neq.yaml`) | the nested `articles(where: {is_published: {_neq: false}})` filters the articles | `{:unsupported_query, {:preload, "articles"}}` | intended: as above |
| `comparisons_test.exs:187` (`select_author_article_where_nin.yaml`) | the nested `articles(where: {id: {_gt: 1}})` filters the articles | `{:unsupported_query, {:preload, "articles"}}` | intended: as above |
| `comparisons_test.exs:148` (`select_author_article_where_and_in.yaml`) | `_and: {name: {_in: [...]}, id: {_in: [...]}}` (one object, coerced by GraphQL to a one-element list) returns Author 2 | `{:invalid_input, [{["_and"], :invalid_expression}]}` | intended: JSON input has no GraphQL list coercion; send a list (`comparisons_test.exs:103`). It fails closed |
| `test/parity/session_divergence_test.exs:60` | a permission whose session comparison Postgres folds away (`_and: [{_or: []}, {id: {_eq: X-Hasura-User-Id}}]`) runs with an uncastable `x-hasura-user-id` and returns no rows | `{:invalid_session_value, "x-hasura-user-id", _}` before the query | intended: Authzura casts every session value a permission references and fails closed; found by the randomized differential (`session-cast-eager`) |
| `test/integration/row_filter_test.exs:164` | a `timestamptz` literal or session value without an offset (`2026-01-03 00:00:00`) is cast in the session's `TimeZone` | the permission is denied at load (`{:invalid_literal, {:invalid_value, "timestamptz"}}`), the session value at request time | intended: Authzura cannot know the database session's `TimeZone`, so policy text without an offset fails closed; untrusted input keeps reading it as UTC. Not generated by the random suites (the seed's literals carry offsets) |
| `test/parity/session_divergence_test.exs:75` | `x-hasura-user-id: " 1"` is cast to 1 by Postgres, and an array value `{NULL,1}` holds a NULL element | `{:invalid_session_value, _, _}` | intended: strict session parsing, fails closed (`Authzura.Adapters.Postgres.Values`); found by the randomized differential (`session-text-strict`) |

## Out of scope

Hasura select-permission-related tests that were reviewed and not ported.

| Hasura source | Reason |
|---|---|
| `tests-py/queries/graphql_query/permissions/anonymous_can_only_get_published_articles_v1alpha1.yaml` | duplicate of the ported v1 file, on the GraphQL `v1alpha1` endpoint |
| `tests-py/queries/graphql_query/permissions/artist_search_tracks.yaml`, `artist_search_tracks_aggregate.yaml` | tracked SQL functions, aggregates |
| `tests-py/queries/graphql_query/permissions/staff_passed_students.yaml` | tracked SQL function |
| `tests-py/queries/graphql_query/permissions/reader_author.yaml` | computed field in a filter (denied by design, `test/authzura/sources/hasura/metadata_test.exs:325`) |
| `tests-py/queries/graphql_query/permissions/tutor_get_students.yaml`, `tutor_get_students_session.yaml` | computed fields |
| `tests-py/queries/graphql_query/permissions/user_can_query_geometry_values_filter.yaml`, `..._session_vars.yaml` | PostGIS operators, outside the stage-one operator set |
| `tests-py/queries/graphql_query/permissions/user_should_not_be_able_to_access_books_by_pk.yaml` | the `_by_pk` root field is GraphQL surface; `Authzura.get/4` honors `select_by_pk` (`test/integration/get_test.exs`) |
| `tests-py/queries/graphql_query/permissions/user_select_query_article_author.yaml` | `order_by` through a relationship in user input; input `order_by` takes columns only |
| `tests-py/queries/graphql_query/permissions/user_can_query_other_users_published_articles.yaml` | relationship in a user `where`; rejected by design, represented by the #6931 divergence |
| `tests-py/queries/graphql_query/permissions/jsonb_has_all.yaml` | the whole test is disabled upstream in `test_graphql_queries.py`; its first case is ported anyway at `operators_test.exs:77` |
| `tests-py/queries/graphql_query/permissions/inherited_roles/`, `roles_inheritance/`, `inherited_roles_mssql/` | inherited roles |
| `tests-py/queries/graphql_query/boolexp/basic/select_query_order_delivered_at_is_{null,not_null}.yaml` | duplicate of `_is_null` (catalog 9) |
| `tests-py/queries/graphql_query/boolexp/basic/select_author_article_operator_ne_not_found_err_postgres.yaml`, `..._unexpected_operator_in_where_err_postgres.yaml` | GraphQL schema validation; the equivalent unknown-operator error is `test/authzura/sources/hasura/bool_exp_test.exs:295` |
| `tests-py/queries/graphql_query/boolexp/basic/*_mssql.yaml`, `boolexp/search/*_{mssql,bigquery}.yaml`, `boolexp/spatial/` | other backends |
| `tests-py/queries/graphql_query/boolexp/jsonb/select_product_jsonb_path_{exists,match}.yaml`, `query_cast_jsonb_to_string.yaml` | jsonpath operators and `_cast`, unsupported |
| `tests-py/queries/graphql_query/boolexp/{ltree,postgis,raster}/` | operator families outside stage one |
| `tests-py/queries/graphql_query/limits/select_query_article_string_limit_error.yaml` | GraphQL argument coercion; the equivalent is `test/integration/scope_test.exs:294` |
| `lib/api-tests/src/Test/Regression/OptimizePermissionFiltersSpec.hs` | SQL shape of an experimental Hasura optimisation |
| `lib/api-tests/src/Test/Queries/Relationship/PermissionRootReferenceSpec.hs` | `_ceq` with the root reference `$` (column comparison) |
| `lib/api-tests/src/Test/Queries/PermissionsKnowAboutColumnNullabilitySpec.hs` | SQL-shape test; covered as catalog 7 (`test/authzura/compiler_test.exs:45,50`) |
| `lib/api-tests/src/Test/Auth/Authorization/DisableRootFields/{DefaultRootFieldsSpec,SelectPermission/DisableAllRootFieldsSpec,SelectPermission/EnableAggSpec,SelectPermission/EnableAllRootFieldsSpec,SelectPermission/EnablePKSpec}.hs` | GraphQL schema surface (`_by_pk`, `_aggregate`, `_stream` fields); the select root field is catalog 47 |
| `lib/api-tests/src/Test/Regression/ObjectRelationshipsLimit7936Spec.hs` ("where author name", "Order by author id", "Count articles") | relationship in user `where`/`order_by` input; aggregates |
| `lib/api-tests/src/Test/Regression/LongIdentifiers3796Spec.hs` (insert cases) | writes |
| `lib/api-tests/src/Test/Queries/Simple/ObjectQueriesSpec.hs` | plain column grants; duplicate of catalog 33 |
| `lib/api-tests/src/Test/Auth/Authorization/InheritedRoles/` | inherited roles |
| `lib/api-tests/src/Test/DataConnector/SelectPermissionsSpec.hs`, `DataConnector/MockAgent/RemoteSourcePermissionPredicateSpec.hs`, `Databases/Postgres/DataValidation/RemoteSourcePermissionPredicateSpec.hs` | non-Postgres sources; remote relationships |
| `lib/api-tests/src/Test/Databases/Postgres/BackendOnlyPermissionsSpec.hs`, `Schema/DataValidations/Permissions/{InsertSpec,UpdateSpec}.hs`, `Regression/DropColumnWithPermissions8415Spec.hs` | writes |
| `lib/api-tests/src/Test/Regression/AggregateBoolExpConflictSpec.hs`, `Queries/FilterSearch/AggregationPredicatesSpec.hs` | aggregates |
| `lib/api-tests/src/Test/Schema/CustomFieldsSpec.hs`, `Schema/DefaultValues/DefaultValuesSpec.hs` | GraphQL custom field names; insert defaults |
| `tests-py/queries/graphql_query/{permissions,limits,boolexp/basic,boolexp/jsonb,boolexp/search}/{setup,teardown}.yaml` | fixture setup and teardown, not tests; the tables and rows are in the `create_hasura_scenario_schemas` and `create_hasura_search_jsonb_schemas` test migrations |
| `tests-py/queries/graphql_query/boolexp/jsonb/select_author_article_jsonb_contains_bestseller.yaml` | relationship in a user `where` (`author(where: {articles: {...}})`) and a `where` on the nested selection; represented by the #6931 divergence and the nested-`where` divergences above |
| `lib/api-tests/src/Test/API/Metadata/LogicalModelsSpec.hs` | logical models (native queries), not Postgres tables |
| `lib/api-tests/src/Test/Auth/Authorization/DisableRootFields/Common.hs` | shared setup of the `DisableRootFields` specs, not a test |
| `lib/api-tests/src/Test/DataConnector/MockAgent/{BasicQuerySpec,DeleteMutationsSpec,InsertMutationsSpec,QueryRelationshipsSpec,UpdateMutationsSpec}.hs` | data connector (non-Postgres) sources; writes |
| `lib/api-tests/src/Test/Mutations/{Delete,Update}/ValidationSpec.hs`, `Regression/InsertOnConflict8260Spec.hs` | writes: the select permission is only a precondition for mutation validation |
| `lib/api-tests/src/Test/Schema/ComputedFields/TableSpec.hs` | computed fields |
| `lib/api-tests/src/Test/Regression/RemoteRelationshipStringifyNum8387Spec.hs`, `Schema/RemoteRelationships/XToDBArrayRelationshipSpec.hs` | remote relationships |

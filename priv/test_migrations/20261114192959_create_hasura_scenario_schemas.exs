# Test-only. These migrations build the sample tables for Authzura's own test
# suite. Applications using Authzura never run them, and Authzura requires no
# migrations in a host app (it only reads Hasura's existing `hdb_catalog`).
defmodule Authzura.Test.Repo.Migrations.CreateHasuraScenarioSchemas do
  @moduledoc """
  Builds the tables and rows of the Hasura v2 test fixtures that
  `test/hasura_scenarios` ports, one Postgres schema per Hasura source, so
  same-named tables from different Hasura suites never collide.

  The DDL and rows are copied from Hasura v2.51.6
  (https://github.com/hasura/graphql-engine/tree/v2.51.6/server). Serial ids
  are written out explicitly with the values Hasura's inserts produce. The
  rows are reference data: the scenario tests only read them, so they are
  seeded here once and never truncated.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  @schemas ~w(
    hasura_permissions
    hasura_boolexp
    hasura_limits
    hasura_select_spec
    hasura_array_permission
    hasura_array_literal
    hasura_untruncated
    hasura_root_exists
    hasura_multi_column
    hasura_object_limit
    hasura_root_fields
    hasura_long_identifiers
  )

  def up do
    Enum.each(@schemas, &execute("CREATE SCHEMA #{&1}"))
    Enum.each(statements(), &execute/1)
  end

  def down do
    Enum.each(@schemas, &execute("DROP SCHEMA IF EXISTS #{&1} CASCADE"))
  end

  defp statements do
    permissions() ++
      boolexp() ++
      limits() ++
      select_spec() ++
      array_permission() ++
      array_literal() ++
      untruncated() ++
      root_exists() ++
      multi_column() ++
      object_limit() ++ root_fields() ++ long_identifiers()
  end

  # tests-py/queries/graphql_query/permissions/setup.yaml
  defp permissions do
    [
      """
      CREATE TABLE hasura_permissions.author (
        id integer PRIMARY KEY,
        name text UNIQUE,
        is_registered boolean NOT NULL DEFAULT false,
        remarks_internal text
      )
      """,
      """
      INSERT INTO hasura_permissions.author (id, name, remarks_internal) VALUES
        (1, 'Author 1', 'remark 1'), (2, 'Author 2', 'remark 2'), (3, 'Author 3', 'remark 3')
      """,
      """
      CREATE TABLE hasura_permissions.article (
        id integer PRIMARY KEY,
        title text,
        content text,
        author_id integer NOT NULL REFERENCES hasura_permissions.author (id),
        is_published boolean NOT NULL DEFAULT false,
        published_on timestamp
      )
      """,
      """
      INSERT INTO hasura_permissions.article (id, title, content, author_id, is_published) VALUES
        (1, 'Article 1', 'Sample article content 1', 1, false),
        (2, 'Article 2', 'Sample article content 2', 1, true),
        (3, 'Article 3', 'Sample article content 3', 2, true),
        (4, 'Article 4', 'Sample article content 4', 3, false)
      """,
      ~s|CREATE TABLE hasura_permissions."Artist" (id integer PRIMARY KEY, name text NOT NULL)|,
      ~s|INSERT INTO hasura_permissions."Artist" VALUES (1, 'Camilla'), (2, 'DSP'), (3, 'Akon')|,
      """
      CREATE TABLE hasura_permissions."Track" (
        id integer PRIMARY KEY,
        name text NOT NULL,
        artist_id integer REFERENCES hasura_permissions."Artist" (id)
      )
      """,
      """
      INSERT INTO hasura_permissions."Track" VALUES
        (1, 'Keepup', 1), (2, 'Keepdown', 1), (3, 'Happy', 2)
      """,
      """
      CREATE TABLE hasura_permissions.jsonb_table (
        id integer NOT NULL PRIMARY KEY,
        jsonb_col jsonb NOT NULL
      )
      """,
      """
      INSERT INTO hasura_permissions.jsonb_table VALUES
        (1, '{"name": "Hasura", "age": 7}'), (2, '{"name": "Cross"}')
      """,
      """
      CREATE TABLE hasura_permissions.auction (
        id integer PRIMARY KEY,
        price integer NOT NULL DEFAULT 250,
        bid_price integer
      )
      """,
      """
      INSERT INTO hasura_permissions.auction (id, bid_price) VALUES
        (1, 100), (2, 120), (3, 300), (4, 260)
      """
    ]
  end

  # tests-py/queries/graphql_query/boolexp/basic/setup.yaml
  defp boolexp do
    [
      """
      CREATE TABLE hasura_boolexp.author (
        id integer PRIMARY KEY,
        name text UNIQUE,
        is_registered boolean NOT NULL DEFAULT false
      )
      """,
      """
      INSERT INTO hasura_boolexp.author VALUES
        (1, 'Author 1', true), (2, 'Author 2', true), (3, 'Author 3', false)
      """,
      """
      CREATE TABLE hasura_boolexp.article (
        id integer PRIMARY KEY,
        title text,
        content text,
        author_id integer REFERENCES hasura_boolexp.author (id),
        is_published boolean,
        published_on timestamp
      )
      """,
      """
      INSERT INTO hasura_boolexp.article (id, title, content, author_id, is_published) VALUES
        (1, 'Article 1', 'Sample article content 1', 1, false),
        (2, 'Article 2', 'Sample article content 2', 1, true),
        (3, 'Article 3', 'Sample article content 3', 2, false),
        (4, 'Article 4', 'Sample article content 4', 3, true)
      """,
      """
      CREATE TABLE hasura_boolexp.message (
        id integer PRIMARY KEY,
        content text NOT NULL,
        parent_id integer NULL REFERENCES hasura_boolexp.message (id)
      )
      """,
      """
      INSERT INTO hasura_boolexp.message VALUES
        (1, 'hello world', null), (2, 'content 2', 1), (3, 'content 3', 1),
        (4, 'ahoy', null), (5, 'content 5', 4), (6, 'hello three', 4)
      """,
      "CREATE TABLE hasura_boolexp.uuid_test (id integer PRIMARY KEY, uuid_col uuid NOT NULL)",
      """
      INSERT INTO hasura_boolexp.uuid_test VALUES
        (1, '28d6d683-1317-49f7-b1cf-7d195242e4e5'),
        (2, '28d6d683-1317-49f7-b1cf-7d195242e4e6'),
        (3, '28d6d683-1317-49f7-b1cf-7d195242e4e7')
      """,
      """
      CREATE TABLE hasura_boolexp."user" (
        id integer PRIMARY KEY,
        name text NOT NULL UNIQUE,
        is_admin boolean DEFAULT false
      )
      """,
      ~s|INSERT INTO hasura_boolexp."user" VALUES (1, 'user_1', false), (2, 'user_2', true)|,
      """
      CREATE TABLE hasura_boolexp.account (
        id integer PRIMARY KEY,
        account_no integer NOT NULL UNIQUE
      )
      """,
      "INSERT INTO hasura_boolexp.account VALUES (1, 1), (2, 2)",
      """
      CREATE TABLE hasura_boolexp.table_with_sql_identifier (
        id integer PRIMARY KEY,
        sql_id information_schema.sql_identifier
      )
      """,
      """
      INSERT INTO hasura_boolexp.table_with_sql_identifier VALUES
        (1, 'one'), (2, 'one'), (3, 'two'), (4, 'three'), (5, 'four'), (6, 'one'), (7, 'two')
      """
    ]
  end

  # tests-py/queries/graphql_query/limits/setup.yaml
  defp limits do
    [
      "CREATE TABLE hasura_limits.author (id integer PRIMARY KEY, name text UNIQUE)",
      "INSERT INTO hasura_limits.author VALUES (1, 'Author 1'), (2, 'Author 2')",
      """
      CREATE TABLE hasura_limits.article (
        id integer PRIMARY KEY,
        title text,
        content text,
        author_id integer REFERENCES hasura_limits.author (id),
        is_published boolean,
        published_on timestamp
      )
      """,
      """
      INSERT INTO hasura_limits.article (id, title, content, author_id) VALUES
        (1, 'Article 1', 'Sample article content 1', 1),
        (2, 'Article 2', 'Sample article content 2', 1),
        (3, 'Article 3', 'Sample article content 3', 2)
      """
    ]
  end

  # lib/api-tests/src/Test/Schema/DataValidations/Permissions/SelectSpec.hs
  defp select_spec do
    [
      "CREATE TABLE hasura_select_spec.author (id integer PRIMARY KEY, name text NOT NULL)",
      """
      INSERT INTO hasura_select_spec.author VALUES
        (1, 'Author 1'), (2, 'Author 2'), (3, 'Author 3')
      """,
      """
      CREATE TABLE hasura_select_spec.article (
        id integer PRIMARY KEY,
        title text NOT NULL,
        content text,
        state text NOT NULL,
        author_id integer NOT NULL REFERENCES hasura_select_spec.author (id)
      )
      """,
      """
      INSERT INTO hasura_select_spec.article VALUES
        (1, 'Article 1', 'Sample article content 1', 'InReview', 1),
        (2, 'Article 2', 'Sample article content 2', 'Published', 2),
        (3, 'Article 3', 'Sample article content 3', 'Draft', 3)
      """
    ]
  end

  # lib/api-tests/src/Test/Databases/Postgres/DataValidation/PermissionSpec.hs
  defp array_permission do
    [
      "CREATE TABLE hasura_array_permission.author (id integer PRIMARY KEY, name text NOT NULL)",
      "INSERT INTO hasura_array_permission.author VALUES (1, 'Author 1'), (2, 'Author 2')"
    ]
  end

  # lib/api-tests/src/Test/Regression/ArrayLiteralTextEncodingSpec.hs
  defp array_literal do
    [
      ~s|CREATE TABLE hasura_array_literal."table" (id integer PRIMARY KEY, str text NOT NULL)|,
      """
      INSERT INTO hasura_array_literal."table" VALUES
        (1, 'a,b'), (2, 'a,'), (3, ''), (4, ','), (5, '\\'), (6, '"'), (7, '&'), (8, 'c'),
        (9, 'שלום')
      """
    ]
  end

  # lib/api-tests/src/Test/Regression/DoNotTruncateSessionVariables8158Spec.hs
  # (a SQL Server spec upstream; its VARCHAR(50) key is text here)
  defp untruncated do
    [
      "CREATE TABLE hasura_untruncated.author (uuid text PRIMARY KEY, name text NOT NULL)",
      """
      INSERT INTO hasura_untruncated.author VALUES
        ('36a6257b-08bb-45ef-a5cf-c1b7a7997087', 'Author 1'),
        ('36a6257b-08bb-45ef-a5cf-c1b7a7', 'Author 2')
      """
    ]
  end

  # lib/api-tests/src/Test/Regression/RootExistElementAliasing9457Spec.hs
  defp root_exists do
    [
      ~s|CREATE TABLE hasura_root_exists.organization (id integer PRIMARY KEY, "group" integer NOT NULL)|,
      "INSERT INTO hasura_root_exists.organization VALUES (1, 1), (2, 1), (3, 2), (4, 2)",
      ~s|CREATE TABLE hasura_root_exists."user" (id integer PRIMARY KEY, name text NOT NULL)|,
      """
      INSERT INTO hasura_root_exists."user" VALUES
        (1, 'Alice'), (2, 'Bob'), (3, 'Charlie'), (4, 'Dave')
      """,
      """
      CREATE TABLE hasura_root_exists.organization_member (
        organization_id integer NOT NULL REFERENCES hasura_root_exists.organization (id),
        user_id integer NOT NULL REFERENCES hasura_root_exists."user" (id)
      )
      """,
      "INSERT INTO hasura_root_exists.organization_member VALUES (1, 1), (2, 2), (3, 3), (4, 4)",
      """
      CREATE TABLE hasura_root_exists.org_stuff (
        organization_id integer NOT NULL REFERENCES hasura_root_exists.organization (id),
        "group" integer NOT NULL,
        data text NOT NULL,
        public boolean NOT NULL
      )
      """,
      """
      INSERT INTO hasura_root_exists.org_stuff VALUES
        (1, 1, 'First data', true), (2, 2, 'Second data', true),
        (3, 3, 'Third data', true), (4, 4, 'Fourth data', false)
      """
    ]
  end

  # lib/api-tests/src/Test/Regression/MultiColumnObjectRelationshipsSpec.hs
  defp multi_column do
    [
      """
      CREATE TABLE hasura_multi_column."character" (
        first_name text NOT NULL,
        last_name text NOT NULL
      )
      """,
      ~s|INSERT INTO hasura_multi_column."character" VALUES ('Kaz', 'Brekker'), ('Inej', 'Ghafa')|,
      """
      CREATE TABLE hasura_multi_column.quote (
        id integer NOT NULL,
        quote text NOT NULL,
        character_first_name text NOT NULL,
        character_last_name text NOT NULL
      )
      """,
      """
      INSERT INTO hasura_multi_column.quote VALUES
        (1, 'The heart is an arrow. It demands aim to land true.', 'Inej', 'Ghafa'),
        (2, 'Im a business man. No more, no less.', 'Kaz', 'Brekker')
      """
    ]
  end

  # lib/api-tests/src/Test/Regression/ObjectRelationshipsLimit7936Spec.hs
  defp object_limit do
    [
      """
      CREATE TABLE hasura_object_limit.author (
        id integer PRIMARY KEY,
        name text NOT NULL,
        "createdAt" timestamptz NOT NULL
      )
      """,
      """
      INSERT INTO hasura_object_limit.author VALUES
        (1, 'Author 1', '2017-09-21 09:39:44Z'),
        (2, 'Author 2', '2017-09-21 09:50:44Z'),
        (3, 'Author 1', '2017-09-21 09:55:44Z')
      """,
      "CREATE TABLE hasura_object_limit.article (id integer PRIMARY KEY, author_name text NOT NULL)",
      "INSERT INTO hasura_object_limit.article VALUES (1, 'Author 1'), (2, 'Author 2')"
    ]
  end

  # lib/api-tests/src/Test/Auth/Authorization/DisableRootFields/SelectPermission/RelationshipSpec.hs
  defp root_fields do
    [
      "CREATE TABLE hasura_root_fields.author (id integer PRIMARY KEY, name text NOT NULL)",
      "INSERT INTO hasura_root_fields.author VALUES (1, 'Author 1'), (2, 'Author 2')",
      """
      CREATE TABLE hasura_root_fields.article (
        id integer PRIMARY KEY,
        title text NOT NULL,
        author_id integer REFERENCES hasura_root_fields.author (id)
      )
      """,
      """
      INSERT INTO hasura_root_fields.article VALUES
        (1, 'Article 1', 1), (2, 'Article 2', 2), (3, 'Article 3', 1)
      """
    ]
  end

  # lib/api-tests/src/Test/Regression/LongIdentifiers3796Spec.hs
  defp long_identifiers do
    [
      """
      CREATE TABLE hasura_long_identifiers.regular_table_with_a_long_name_to_test_rename_identifiers (
        id integer PRIMARY KEY,
        name text NOT NULL
      )
      """,
      """
      INSERT INTO hasura_long_identifiers.regular_table_with_a_long_name_to_test_rename_identifiers
        VALUES (1, 'Author 1'), (2, 'Author 2')
      """,
      """
      CREATE TABLE hasura_long_identifiers.i_need_a_table_with_a_long_name_to_test_rename_identifiers (
        id integer PRIMARY KEY,
        regular_id integer NOT NULL
          REFERENCES hasura_long_identifiers.regular_table_with_a_long_name_to_test_rename_identifiers (id),
        i_need_a_column_with_a_long_name_to_test_rename_identifiers integer NOT NULL,
        i_need_a_column_with_a_long_name_but_is_different integer NOT NULL
      )
      """,
      """
      INSERT INTO hasura_long_identifiers.i_need_a_table_with_a_long_name_to_test_rename_identifiers
        VALUES (1, 1, 1, 1), (2, 2, 2, 2)
      """
    ]
  end
end

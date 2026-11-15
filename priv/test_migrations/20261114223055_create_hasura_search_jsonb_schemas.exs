# Test-only. Builds sample tables for Authzura's own test suite; applications
# using Authzura never run it.
defmodule Authzura.Test.Repo.Migrations.CreateHasuraSearchJsonbSchemas do
  @moduledoc """
  Tables and rows of two more Hasura v2.51.6 fixtures ported by
  `test/hasura_scenarios`, one Postgres schema each:

    * `hasura_search`: `tests-py/queries/graphql_query/boolexp/search/setup.yaml`
      (`city` and `project`);
    * `hasura_jsonb`: `tests-py/queries/graphql_query/boolexp/jsonb/setup.yaml`
      (`author`, `article` with `tags`, and `product` with `spec`).

  Serial ids are written out with the values Hasura's inserts produce. The
  rows are reference data that the tests only read.
  """
  use Ecto.Migration

  @schemas ~w(hasura_search hasura_jsonb)

  def up do
    Enum.each(@schemas, &execute("CREATE SCHEMA #{&1}"))
    Enum.each(search() ++ jsonb(), &execute/1)
  end

  def down, do: Enum.each(@schemas, &execute("DROP SCHEMA IF EXISTS #{&1} CASCADE"))

  defp search do
    [
      "CREATE TABLE hasura_search.city (id integer PRIMARY KEY, name text NOT NULL, country text NOT NULL)",
      """
      INSERT INTO hasura_search.city VALUES
        (1, 'Durham', 'USA'), (2, 'New York', 'USA'),
        (3, 'Framlingham', 'UK'), (4, 'New Orleans', 'USA')
      """,
      "CREATE TABLE hasura_search.project (id char(3) PRIMARY KEY)",
      "INSERT INTO hasura_search.project VALUES ('abc'), ('ABC'), ('bcd'), ('BCD')"
    ]
  end

  defp jsonb do
    [
      "CREATE TABLE hasura_jsonb.author (id integer PRIMARY KEY, name text UNIQUE)",
      "INSERT INTO hasura_jsonb.author VALUES (1, 'Author 1'), (2, 'Author 2')",
      """
      CREATE TABLE hasura_jsonb.article (
        id integer PRIMARY KEY,
        title text,
        content text,
        author_id integer REFERENCES hasura_jsonb.author (id),
        is_published boolean,
        published_on timestamp,
        tags jsonb
      )
      """,
      """
      INSERT INTO hasura_jsonb.article (id, title, content, author_id, tags) VALUES
        (1, 'Article 1', 'Sample article content 1', 1, NULL),
        (2, 'Article 2', 'Sample article content 2', 1, '["bestseller", "latest"]'),
        (3, 'Article 3', 'Sample article content 3', 2, '["latest"]')
      """,
      """
      CREATE TABLE hasura_jsonb.product (
        id integer PRIMARY KEY,
        name text NOT NULL,
        category text NOT NULL,
        spec jsonb NOT NULL
      )
      """,
      """
      INSERT INTO hasura_jsonb.product VALUES
        (1, 'laptop1', 'Laptop',
         '{"Operating System": "os1", "RAM": "8GB", "Disk": "128GB", "Weight": "1.2Kg", "Processor": "processor1"}'),
        (2, 'laptop2', 'Laptop',
         '{"OS": "os2", "RAM": "16GB", "Disk": "128GB", "Weight": "1.2Kg", "Processor": "processor2", "Touchscreen": true}'),
        (3, 'mobile1', 'Mobile',
         '{"Operating System Type": "osType1", "RAM": "3GB", "Weight": "200g", "Processor": "processor2", "Network type": "4G", "SIM type": "DualSim", "Sensors": "Accelerometer sensor, E-compass, Proximity sensor", "Touchscreen": true}'),
        (4, 'kettle1', 'Electric kettle',
         '{"power": "1500W", "capacity": "1.5L", "dimensions": {"width": "20cm", "height": "19cm", "depth": "18cm"}}')
      """
    ]
  end
end

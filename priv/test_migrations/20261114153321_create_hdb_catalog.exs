# Test-only. These migrations build the sample tables for Authzura's own test
# suite. Applications using Authzura never run them, and Authzura requires no
# migrations in a host app (it only reads Hasura's existing `hdb_catalog`).
defmodule Authzura.Test.Repo.Migrations.CreateHdbCatalog do
  @moduledoc """
  Builds a stand-in for Hasura v2's `hdb_catalog.hdb_metadata` for Authzura's
  own test suite only.

  Applications using Authzura never run this migration, and Authzura requires
  no migrations in a host app (it only reads Hasura's existing `hdb_catalog`).
  It is kept separate from the fixture schema migration because the opt-in
  parity suite must migrate only the fixture migrations: real Hasura owns
  `hdb_catalog`.
  """
  use Ecto.Migration

  def up do
    # Not IF NOT EXISTS on purpose: the opt-in parity suite must migrate only
    # the fixture migrations, because real Hasura owns `hdb_catalog`, so this
    # one never meets an existing catalog.
    execute "CREATE SCHEMA hdb_catalog"

    create table(:hdb_metadata, prefix: "hdb_catalog", primary_key: false) do
      add :id, :integer, primary_key: true
      add :metadata, :json, null: false
      add :resource_version, :integer, null: false, default: 1
    end
  end

  def down do
    drop_if_exists table(:hdb_metadata, prefix: "hdb_catalog")
    execute "DROP SCHEMA IF EXISTS hdb_catalog"
  end
end

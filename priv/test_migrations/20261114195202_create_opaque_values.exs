defmodule Authzura.Test.Repo.Migrations.CreateOpaqueValues do
  @moduledoc """
  Creates `opaque_values`, whose columns Authzura cannot compare (base kind
  `:other`): `spot` (`point`, which Postgrex decodes) and `path`
  (`jsonpath`, which Postgrex's default types cannot decode). It stands in
  for PostGIS `geography`/`geometry` columns, which are not available in the
  test image.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def change do
    create table(:opaque_values, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :label, :text, null: false
      add :spot, :point, null: true
      add :path, :jsonpath, null: true
    end
  end
end

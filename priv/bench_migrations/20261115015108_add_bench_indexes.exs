# Bench-only. The fixture schema (priv/test_migrations) has primary keys but no
# index on the columns the bench permissions filter on; both engines get the
# same ones here, so neither is measured on a sequential scan the other avoids.
defmodule Authzura.Bench.Repo.Migrations.AddBenchIndexes do
  @moduledoc """
  Indexes the columns the bench permissions and relationships filter on.
  """
  use Ecto.Migration

  def change do
    create index(:articles, [:org_id])
    create index(:articles, [:author_id])
    create index(:articles, [:status, :id])
    create index(:org_memberships, [:user_id])
  end
end

defmodule Authzura.Test.Repo.Migrations.AddPreloadKeyIndexes do
  @moduledoc """
  Adds the composite indexes that let limited preload levels read each
  parent through a bounded lateral subquery: `comments (article_id, id)`
  and `membership_notes (org_id, user_id, id)`. Other key columns stay
  unindexed, so the windowed shape is exercised too.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def change do
    create index(:comments, [:article_id, :id])
    create index(:membership_notes, [:org_id, :user_id, :id])
  end
end

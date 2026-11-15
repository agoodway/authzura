# Bench-only. Adopters index their foreign keys, and both engines get the same
# indexes. comments.article_id, which the preload scenarios traverse, is
# already served by the fixture's comments (article_id, id) index.
defmodule Authzura.Bench.Repo.Migrations.AddBenchFkIndexes do
  @moduledoc """
  Indexes the foreign keys the scenarios traverse that no fixture index
  leads with.
  """
  use Ecto.Migration

  def change do
    create index(:comments, [:author_id])
    create index(:users, [:org_id])
  end
end

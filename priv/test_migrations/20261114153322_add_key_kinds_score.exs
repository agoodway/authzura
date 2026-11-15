defmodule Authzura.Test.Repo.Migrations.AddKeyKindsScore do
  @moduledoc """
  Adds a `double precision` column to `key_kinds` for the float base kind.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def change do
    alter table(:key_kinds) do
      add :score, :"double precision", null: true
    end
  end
end

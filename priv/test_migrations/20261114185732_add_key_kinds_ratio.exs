defmodule Authzura.Test.Repo.Migrations.AddKeyKindsRatio do
  @moduledoc """
  Adds a nullable `real` (float4) column to `key_kinds`, so array operands
  are range-checked for every float width as well as every integer width.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def change do
    alter table(:key_kinds) do
      add :ratio, :real, null: true
    end
  end
end

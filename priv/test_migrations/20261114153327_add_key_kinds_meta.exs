defmodule Authzura.Test.Repo.Migrations.AddKeyKindsMeta do
  @moduledoc """
  Adds a nullable `json` (not `jsonb`) column to `key_kinds`, which permission
  filters may only test with `_is_null`.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def change do
    alter table(:key_kinds) do
      add :meta, :json, null: true
    end
  end
end

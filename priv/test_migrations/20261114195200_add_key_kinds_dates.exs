defmodule Authzura.Test.Repo.Migrations.AddKeyKindsDates do
  @moduledoc """
  Adds nullable `date` and `timestamp` (without time zone) columns to
  `key_kinds`, so both kinds are swept by the never-raise tests and can be
  filtered and compared.

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def change do
    alter table(:key_kinds) do
      add :born_on, :date, null: true
      add :seen_at, :naive_datetime_usec, null: true
    end
  end
end

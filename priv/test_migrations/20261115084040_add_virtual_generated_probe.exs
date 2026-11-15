defmodule Authzura.Test.Repo.Migrations.AddVirtualGeneratedProbe do
  @moduledoc """
  Adds a VIRTUAL generated column (Postgres 18) to `pushdown_probe`, so the
  `input_index_pushdown` tests see both generated kinds. Test-only.
  """
  use Ecto.Migration

  def up do
    execute "ALTER TABLE public.pushdown_probe ADD COLUMN vdoubled bigint GENERATED ALWAYS AS (id * 2) VIRTUAL"
  end

  def down do
    execute "ALTER TABLE public.pushdown_probe DROP COLUMN vdoubled"
  end
end

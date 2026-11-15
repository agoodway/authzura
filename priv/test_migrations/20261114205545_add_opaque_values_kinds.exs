defmodule Authzura.Test.Repo.Migrations.AddOpaqueValuesKinds do
  @moduledoc """
  Adds columns to `opaque_values` that exercise type classification:

    * `blob` (`bytea`) and `span` (`interval`): Postgrex decodes them
    * `paths` (`jsonpath[]`): an array of a type Postgrex cannot decode
    * `amount` (`public.positive_amount`, a domain over a domain over
      `bigint`): classified by its base type
    * `pair` (`public.opaque_pair`, a composite): its fields might not decode

  Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def up do
    execute "CREATE DOMAIN public.amount AS bigint"
    execute "CREATE DOMAIN public.positive_amount AS public.amount CHECK (VALUE > 0)"
    execute "CREATE TYPE public.opaque_pair AS (a int, b text)"

    alter table(:opaque_values) do
      add :blob, :bytea, null: true
      add :span, :interval, null: true
      add :paths, {:array, :jsonpath}, null: true
      add :amount, :"public.positive_amount", null: true
      add :pair, :"public.opaque_pair", null: true
    end
  end

  def down do
    alter table(:opaque_values) do
      remove :blob
      remove :span
      remove :paths
      remove :amount
      remove :pair
    end

    execute "DROP TYPE public.opaque_pair"
    execute "DROP DOMAIN public.positive_amount"
    execute "DROP DOMAIN public.amount"
  end
end

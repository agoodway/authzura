# Test-only. Builds the tables of the PgRest example suite (`test/pgrest_examples`).
defmodule Authzura.Test.Repo.Migrations.CreateTodoExample do
  @moduledoc """
  A contrived multi-tenant to-do app: organizations own lists, lists own items.
  """
  use Ecto.Migration

  def change do
    create table(:orgs, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :name, :text, null: false
    end

    create table(:todo_lists, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :org_id, references(:orgs, type: :bigint), null: false
      add :owner_id, :bigint, null: false
      add :title, :text, null: false
      add :assignee_notes, :text
    end

    create table(:todo_items, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :list_id, references(:todo_lists, type: :bigint), null: false
      add :body, :text, null: false
      add :done, :boolean, null: false, default: false
    end

    create index(:todo_lists, [:org_id])
    create index(:todo_items, [:list_id])
  end
end

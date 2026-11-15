# Test-only. These migrations build the sample tables for Authzura's own test
# suite. Applications using Authzura never run them, and Authzura requires no
# migrations in a host app (it only reads Hasura's existing `hdb_catalog`).
defmodule Authzura.Test.Repo.Migrations.CreateFixtureSchema do
  @moduledoc """
  Builds the sample tables for Authzura's own test suite only.

  Applications using Authzura never run these migrations, and Authzura
  requires no migrations in a host app (it only reads Hasura's existing
  `hdb_catalog`). Later tasks append to the fixture database by adding new
  files to `priv/test_migrations`.
  """
  use Ecto.Migration

  def up do
    execute "CREATE SCHEMA IF NOT EXISTS audit"
    execute "CREATE EXTENSION IF NOT EXISTS citext"

    execute "CREATE TYPE public.article_status AS ENUM ('draft', 'review', 'published')"

    create table(:organizations, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :name, :text, null: false
    end

    create table(:users, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :org_id, references(:organizations, type: :bigint), null: false
      add :manager_id, references(:users, type: :bigint), null: true
      add :email, :citext, null: false
      add :role, :text, null: false
      add :is_admin, :boolean, null: false, default: false
      add :salary, :numeric, null: true
    end

    execute "ALTER TABLE public.users ADD CONSTRAINT users_email_key UNIQUE (email)"

    create table(:user_profiles, primary_key: false) do
      add :user_id, references(:users, type: :bigint), primary_key: true
      add :bio, :text, null: true
    end

    create table(:articles, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :org_id, references(:organizations, type: :bigint), null: false
      add :author_id, references(:users, type: :bigint), null: false
      add :editor_id, references(:users, type: :bigint), null: true
      add :status, :"public.article_status", null: false
      add :is_published, :boolean, null: false
      add :title, :text, null: false
      add :body, :text, null: true
      add :internal_notes, :text, null: true
      add :assignees, :jsonb, null: false, default: fragment("'{}'")
      add :external_ref, :uuid, null: true
      add :published_at, :timestamptz, null: true
    end

    create table(:comments, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :article_id, references(:articles, type: :bigint), null: false
      add :author_id, references(:users, type: :bigint), null: false
      add :body, :text, null: false
    end

    create table(:org_memberships, primary_key: false) do
      add :org_id, :bigint, primary_key: true
      add :user_id, :bigint, primary_key: true
      add :level, :integer, null: false
    end

    create table(:membership_notes, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :org_id, :bigint, null: true
      add :user_id, :bigint, null: true
      add :note, :text
    end

    execute """
    ALTER TABLE public.membership_notes
      ADD FOREIGN KEY (org_id, user_id) REFERENCES public.org_memberships (org_id, user_id)
    """

    create table(:"Order", primary_key: false) do
      add :"Id", :bigint, primary_key: true
      add :"line item", :text, null: true
    end

    create table(:key_kinds, primary_key: false) do
      add :id, :bigint, primary_key: true
      add :code, :"varchar(16)", null: false
      add :rank, :smallint, null: false
      add :grade, :"char(2)", null: true
    end

    execute "CREATE SEQUENCE public.test_seq"

    execute """
    CREATE VIEW public.published_articles AS
      SELECT id, org_id, author_id, title FROM public.articles WHERE is_published
    """

    create table(:users, prefix: "audit", primary_key: false) do
      add :id, :bigint, primary_key: true
      add :note, :text, null: true
    end

    create table(:article_events, prefix: "audit", primary_key: false) do
      add :id, :bigint, primary_key: true
      add :article_id, :bigint, null: false
      add :kind, :text, null: false
    end
  end

  def down do
    drop_if_exists table(:article_events, prefix: "audit")
    drop_if_exists table(:users, prefix: "audit")
    execute "DROP VIEW IF EXISTS public.published_articles"
    execute "DROP SEQUENCE IF EXISTS public.test_seq"
    drop_if_exists table(:key_kinds)
    drop_if_exists table(:"Order")
    drop_if_exists table(:membership_notes)
    drop_if_exists table(:org_memberships)
    drop_if_exists table(:comments)
    drop_if_exists table(:articles)
    drop_if_exists table(:user_profiles)
    drop_if_exists table(:users)
    drop_if_exists table(:organizations)
    execute "DROP TYPE IF EXISTS public.article_status"
    execute "DROP EXTENSION IF EXISTS citext"
    execute "DROP SCHEMA IF EXISTS audit"
  end
end

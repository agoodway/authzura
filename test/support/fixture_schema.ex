defmodule Authzura.FixtureSchema do
  @moduledoc """
  Cleanup for the fixture database.

  The tables themselves are built by the Ecto migrations in
  `priv/test_migrations`, which `mix test` runs for the test suite only. Later
  tasks append to the fixture database by adding new migration files there.
  """

  @tables ~w(
    public.comments
    public.membership_notes
    public.org_memberships
    public.articles
    public.user_profiles
    public.users
    public.organizations
    public."Order"
    public.key_kinds
    public.opaque_values
    audit.users
    audit.article_events
  )

  @tracked [
    {"public", "organizations"},
    {"public", "users"},
    {"public", "user_profiles"},
    {"public", "articles"},
    {"public", "comments"},
    {"public", "org_memberships"},
    {"public", "membership_notes"},
    {"public", "Order"},
    {"public", "key_kinds"},
    {"public", "published_articles"},
    {"audit", "users"},
    {"audit", "article_events"}
  ]

  @doc """
  The `{schema, name}` of every table (and view) the fixture metadata
  tracks, in a fixed order.
  """
  @spec tracked_refs() :: [{String.t(), String.t()}]
  def tracked_refs, do: @tracked

  @doc """
  Truncates every fixture table, plus `hdb_catalog.hdb_metadata` unless
  `hasura_catalog: false` is given (the parity suite's catalog belongs to a
  real Hasura).
  """
  @spec truncate(module(), keyword()) :: :ok
  def truncate(repo, opts \\ []) do
    tables = opts |> Keyword.get(:hasura_catalog, true) |> tables() |> Enum.join(", ")
    repo.query!("TRUNCATE #{tables} CASCADE")
    :ok
  end

  defp tables(true), do: ["hdb_catalog.hdb_metadata" | @tables]
  defp tables(false), do: @tables
end

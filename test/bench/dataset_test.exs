defmodule Authzura.Bench.DatasetTest do
  # Needs the benchmark database (see bench/README.md): mix test --only bench
  use ExUnit.Case, async: false

  alias Authzura.Bench.{Dataset, Repo}
  alias Authzura.Test.Repo, as: TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :bench

  setup_all do
    start_supervised!(Repo)
    :ok
  end

  test "the same seed gives the same per-table hash at :tiny; a different seed does not" do
    # Everything runs in a transaction that is rolled back: the loaded
    # :small dataset is left as it was.
    {:error, {first, again, other, counts}} =
      Repo.transaction(
        fn ->
          first = load_checksum(1)
          again = load_checksum(1)
          other = load_checksum(2)
          Dataset.load!(Repo, :tiny, 1)
          Repo.rollback({first, again, other, Dataset.counts(Repo)})
        end,
        timeout: :infinity
      )

    assert first == again
    assert Map.keys(first) |> Enum.sort() == Enum.sort(Map.keys(counts))

    # organizations are only ids and names, so they do not depend on the seed.
    for {table, hash} <- Map.delete(first, "organizations") do
      refute hash == other[table], "#{table} did not change with the seed"
    end

    assert first["organizations"] == other["organizations"]

    sizes = Dataset.sizes(:tiny)

    assert counts == %{
             "organizations" => sizes.organizations,
             "users" => sizes.users,
             "org_memberships" => sizes.org_memberships,
             "articles" => sizes.articles,
             "comments" => sizes.comments
           }
  end

  test "load!/3 refuses a repo on any other database before writing" do
    # The test repo's sandbox rolls back whatever a regression would write.
    :ok = Sandbox.checkout(TestRepo)

    assert_raise ArgumentError, ~r{refusing database "/authzura_test}, fn ->
      Dataset.load!(TestRepo, :tiny, 1)
    end
  end

  test "at :tiny the first 75 users have both memberships and the others none" do
    {:error, per_user} =
      Repo.transaction(
        fn ->
          Dataset.load!(Repo, :tiny, 1)

          %{rows: rows} =
            Repo.query!("""
            SELECT u.id, count(m.user_id) FROM public.users u
            LEFT JOIN public.org_memberships m ON m.user_id = u.id GROUP BY u.id ORDER BY u.id
            """)

          Repo.rollback(rows)
        end,
        timeout: :infinity
      )

    assert per_user == Enum.map(1..100, &[&1, if(&1 <= 75, do: 2, else: 0)])
  end

  test "the scales have the documented sizes" do
    assert Dataset.sizes(:tiny) == %{
             organizations: 5,
             users: 100,
             org_memberships: 150,
             articles: 1_000,
             comments: 3_000
           }

    assert Dataset.sizes(:small).org_memberships == 20_000
    assert Dataset.sizes(:large).comments == 3_000_000
  end

  defp load_checksum(seed) do
    Dataset.load!(Repo, :tiny, seed)
    Dataset.checksum(Repo)
  end
end

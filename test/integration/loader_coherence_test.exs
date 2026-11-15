defmodule Authzura.Integration.LoaderCoherenceTest do
  use Authzura.CommittedCase

  alias Authzura.Adapters.Postgres
  alias Authzura.HasuraFixture
  alias Authzura.Sources.Hasura

  @refs [{"public", "articles"}]

  setup do
    metadata =
      HasuraFixture.metadata([
        %{
          table: {"public", "articles"},
          select_permissions: [%{role: "user", permission: %{columns: "*", filter: %{}}}]
        }
      ])

    HasuraFixture.put_metadata!(Repo, metadata)

    on_exit(fn ->
      for n <- 0..5,
          do: Repo.query!("ALTER TABLE public.articles DROP COLUMN IF EXISTS drift_#{n}")
    end)

    {:ok, opts: [repo: Repo, data_repo: OtherRepo]}
  end

  defp record(retries), do: send(self(), {:hook, retries})

  test "retries once when the schema changes after the data read", %{opts: opts} do
    hook = fn
      0 ->
        record(0)
        OtherRepo.query!("ALTER TABLE public.articles ADD COLUMN drift_0 int")

      retry ->
        record(retry)
    end

    assert {:ok, snapshot} = Hasura.load([before_verify: hook] ++ opts)

    assert_received {:hook, 0}
    assert_received {:hook, 1}
    refute_received {:hook, 2}

    assert {_version, fingerprint} = snapshot.version
    assert {:ok, ^fingerprint} = Postgres.fingerprint(Repo, @refs)
    assert is_map_key(snapshot.tables[{"public", "articles"}].columns, "drift_0")
  end

  test "gives up with :unstable_source after max_retries", %{opts: opts} do
    hook = fn retry ->
      record(retry)
      OtherRepo.query!("ALTER TABLE public.articles ADD COLUMN drift_#{retry} int")
    end

    assert {:error, :unstable_source} =
             Hasura.load([before_verify: hook, max_retries: 2] ++ opts)

    assert_received {:hook, 0}
    assert_received {:hook, 1}
    assert_received {:hook, 2}
    refute_received {:hook, 3}
  end

  test "different repos without drift load once", %{opts: opts} do
    assert {:ok, snapshot} = Hasura.load([before_verify: &record/1] ++ opts)
    assert_received {:hook, 0}
    refute_received {:hook, 1}
    assert {:ok, snapshot.version} == Hasura.version(opts)
  end
end

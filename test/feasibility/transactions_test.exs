defmodule Authzura.Feasibility.TransactionsTest do
  @moduledoc """
  Feasibility spike for the executor's transaction and the Store's
  publication primitives, pinned as regression tests. These need real,
  committed connections, so they run under `Authzura.CommittedCase`.

  ## Construct catalog

    * **Read-only snapshot.** Inside `Repo.transaction/1`, the first statement
      `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY` succeeds.
      A later write returns `%Postgrex.Error{postgres: %{code:
      :read_only_sql_transaction}}` (`Repo.query/1` returns it as
      `{:error, error}`; the transaction is then aborted, so end it with
      `Repo.rollback/1`).

    * **Isolation is observable.** A row committed by another connection
      (`OtherRepo`) after the first read is invisible to a second read under
      `REPEATABLE READ` and visible under the default `READ COMMITTED`. The
      Task 16 consistency test can therefore tell the two apart.

    * **Generation publication.** A generation stored with
      `:persistent_term.put({Authzura.Store, name}, generation)` can hold an
      `:atomics` ref; `:atomics.put/3` and `:atomics.add_get/3` update it in
      place, and every later `:persistent_term.get/1` sees the new value
      without the term being rewritten.
  """

  use Authzura.CommittedCase

  alias Authzura.Store
  alias Postgrex.Error

  @read_only "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
  @count "select count(*) from public.organizations"

  defp count(repo), do: repo.query!(@count).rows

  defp reads_around_foreign_commit(set_transaction) do
    {:ok, reads} =
      Repo.transaction(fn ->
        Enum.each(set_transaction, &Repo.query!/1)
        before = count(Repo)
        OtherRepo.query!("insert into public.organizations (id, name) values (2, 'later')")
        {before, count(Repo)}
      end)

    reads
  end

  setup do
    Repo.query!("insert into public.organizations (id, name) values (1, 'acme')")
    :ok
  end

  test "a read-only repeatable-read transaction refuses writes" do
    assert {:error, :refused} =
             Repo.transaction(fn ->
               Repo.query!(@read_only)

               assert {:error, %Error{postgres: %{code: :read_only_sql_transaction}}} =
                        Repo.query("insert into public.organizations (id, name) values (3, 'x')")

               Repo.rollback(:refused)
             end)

    assert count(OtherRepo) == [[1]]
  end

  test "repeatable read hides rows committed after the first read" do
    assert reads_around_foreign_commit([@read_only]) == {[[1]], [[1]]}
    assert count(OtherRepo) == [[2]]
  end

  test "read committed sees rows committed after the first read" do
    assert reads_around_foreign_commit([]) == {[[1]], [[2]]}
  end

  test "a persistent_term generation holds a mutable atomics ref" do
    key = {Store, :feasibility_spike}
    counter = :atomics.new(1, signed: false)
    on_exit(fn -> :persistent_term.erase(key) end)

    :persistent_term.put(key, %{version: 1, checked_at: counter})
    :atomics.put(:persistent_term.get(key).checked_at, 1, 41)

    assert :atomics.add_get(:persistent_term.get(key).checked_at, 1, 1) == 42
    assert %{version: 1, checked_at: ^counter} = :persistent_term.get(key)
    assert :atomics.get(counter, 1) == 42
  end
end

defmodule Authzura.CommittedCaseTest do
  use Authzura.CommittedCase

  @insert "insert into public.organizations (id, name) values (1, 'acme')"
  @count "select count(*) from public.organizations"

  test "committed rows are visible to a second connection" do
    Repo.query!(@insert)

    assert %{rows: [[1]]} = Task.async(fn -> Repo.query!(@count) end) |> Task.await()
    assert %{rows: [[1]]} = OtherRepo.query!(@count)
  end

  test "rows from the previous test were truncated" do
    assert %{rows: [[0]]} = Repo.query!(@count)
  end
end

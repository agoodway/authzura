defmodule Authzura.HarnessTest do
  use Authzura.DataCase, async: true

  test "fixture schema exists in both schemas and hdb_catalog" do
    assert %{rows: [[1]]} =
             Repo.query!("(select 1 from public.articles limit 0) union all select 1")

    assert %{num_rows: 0} = Repo.query!(~s(select * from "audit"."users"))
    assert %{num_rows: 0} = Repo.query!("select * from hdb_catalog.hdb_metadata")
  end
end

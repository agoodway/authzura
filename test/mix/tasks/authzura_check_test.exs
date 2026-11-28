defmodule Mix.Tasks.Authzura.CheckTest do
  use Authzura.CommittedCase

  import ExUnit.CaptureIO
  import ExUnit.CaptureLog

  alias Authzura.HasuraFixture
  alias Mix.Tasks.Authzura.Check

  @users {"public", "users"}
  @articles {"public", "articles"}
  @args ["--repo", "Authzura.Test.Repo"]

  defp put_metadata!(tables),
    do: HasuraFixture.put_metadata!(Repo, HasuraFixture.metadata(tables))

  defp clean do
    %{
      table: @articles,
      select_permissions: HasuraFixture.select_permissions("user", ["id", "title"])
    }
  end

  defp denied do
    %{
      table: @users,
      select_permissions:
        HasuraFixture.select_permissions("editor", ["id"], %{"nonexistent" => %{"_eq" => 1}})
    }
  end

  # A write permission with a problem is only a warning; reads are untouched.
  defp warned do
    Map.put(clean(), :insert_permissions, [
      %{role: "user", permission: %{columns: ["id"], check: %{"nonexistent" => %{"_eq" => 1}}}}
    ])
  end

  # The task's outcome (`:ok` or its exit value) and what it printed.
  defp run(args) do
    parent = self()

    errors =
      capture_io(:stderr, fn ->
        output =
          capture_io(fn -> send(parent, {:outcome, exit_of(fn -> Check.run(args) end)}) end)

        send(parent, {:output, output})
      end)

    assert_received {:outcome, outcome}
    assert_received {:output, output}
    {outcome, output <> errors}
  end

  defp exit_of(fun) do
    fun.()
    :ok
  catch
    :exit, reason -> reason
  end

  test "a denied select permission exits 1 and names the role, table and reason" do
    put_metadata!([clean(), denied()])

    assert {{:shutdown, 1}, output} = run(@args)
    assert output =~ ~r/^deny editor public\.users select filter.*nonexistent/m
    assert output =~ "1 denied"
  end

  test "clean metadata exits 0" do
    put_metadata!([clean()])

    assert {:ok, output} = run(@args)
    assert output =~ "0 denied"
    assert output =~ "1 select permissions, 0 functions"
  end

  test "warnings pass, and fail under --strict" do
    put_metadata!([warned()])

    assert {:ok, output} = run(@args)
    assert output =~ ~r/^warning user public\.articles insert .*nonexistent/m

    assert {{:shutdown, 1}, _output} = run(@args ++ ["--strict"])
  end

  test "reports the Validator's load-time checks, as an instance would" do
    put_metadata!([
      %{table: @users, select_permissions: HasuraFixture.select_permissions("user", ["id"])},
      %{
        table: {"public", "key_kinds"},
        object_relationships: [
          HasuraFixture.object_relationship("user", @users, %{code: "email"})
        ],
        select_permissions: HasuraFixture.select_permissions("user", ["id"])
      }
    ])

    assert {:ok, output} = run(@args)
    assert output =~ ~r/^warning - public\.key_kinds - user: .*incompatible_key_kinds/m
  end

  test "a function diagnostic prints fn:schema.name in the table position" do
    HasuraFixture.put_metadata!(
      Repo,
      HasuraFixture.metadata([clean()],
        functions: [%{function: %{schema: "api", name: "search"}, permissions: [%{role: 1}]}]
      )
    )

    assert {{:shutdown, 1}, output} = run(@args)

    assert output =~
             ~r/^deny - fn:api\.search - functions\.0\.permissions\.0: :invalid_function_permission/m
  end

  test "does not log the queries it runs, even when the repo logs them" do
    put_metadata!([clean()])

    log =
      capture_log(fn ->
        capture_io(fn -> Check.run(["--repo", "Authzura.Test.LogRepo"]) end)
      end)

    refute log =~ "SELECT"
  end

  test "a source that is not in the metadata fails" do
    put_metadata!([clean()])

    assert {{:shutdown, 1}, output} = run(@args ++ ["--source", "other"])
    assert output =~ "source_not_found"
  end

  test "--metadata-repo reads the metadata through another repo" do
    put_metadata!([clean()])

    assert {:ok, _output} = run(@args ++ ["--metadata-repo", "Authzura.Test.OtherRepo"])
  end

  test "--repo is required, and unknown options and repos are rejected" do
    assert_raise Mix.Error, ~r/--repo/, fn -> Check.run([]) end
    assert_raise Mix.Error, ~r/--repo/, fn -> Check.run(["--bogus", "1"]) end
    assert_raise Mix.Error, ~r/Missing.Repo/, fn -> Check.run(["--repo", "Missing.Repo"]) end
  end
end

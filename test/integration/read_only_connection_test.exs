defmodule Authzura.Integration.ReadOnlyConnectionTest do
  @moduledoc """
  `read_only: :connection` trusts connections that are read-only already
  (here every pool connection runs `SET default_transaction_read_only = on`
  on connect, as a replica or a role setting would), so a read without
  preloads is one statement. The Store verifies the setting at every load
  and poll, and refuses to serve without it.
  """

  use Authzura.CommittedCase

  import ExUnit.CaptureLog

  alias Authzura.{HasuraFixture, Store, TelemetryHelper}
  alias Authzura.Store.Generation
  alias Authzura.Test.{ReadOnlyRepo, Schemas.Organization}
  alias Postgrex.Error

  @organizations {"public", "organizations"}
  @users {"public", "users"}
  @read_only_query [:authzura, :test, :read_only_repo, :query]

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @organizations,
        array_relationships: [
          %{
            name: "users",
            using: %{foreign_key_constraint_on: %{table: @users, column: "org_id"}}
          }
        ],
        select_permissions: HasuraFixture.select_permissions("user", ["id", "name"])
      },
      %{table: @users, select_permissions: HasuraFixture.select_permissions("user", ["id"])}
    ])
  end

  setup %{test: test} = tags do
    Repo.query!("insert into public.organizations values (1, 'one')")

    Repo.query!(
      "insert into public.users (id, org_id, email, role) values (1, 1, 'a@x.com', 'r')"
    )

    start_supervised!({ReadOnlyRepo, ReadOnlyRepo.start_options(Map.get(tags, :pool_size, 1))})
    TelemetryHelper.forward!(test, [@read_only_query], caller_only: true)
    :ok
  end

  defp session, do: HasuraFixture.session!("user")

  # Polls are run by hand (`Store.poll/1`); the interval only has to exist.
  @connection_opts [read_only: :connection, poll_interval: 3_600_000, max_staleness: 3_600_000]

  defp start!(test, repo),
    do: HasuraFixture.start_instance!(test, repo, metadata(), @connection_opts)

  defp writing, do: where(Organization, [o], fragment("nextval('public.test_seq') > 0"))

  defp queries, do: TelemetryHelper.received_queries(@read_only_query)

  test "a read without preloads is one statement", %{test: test} do
    i = start!(test, ReadOnlyRepo)
    queries()

    assert {:ok, [%{id: 1, name: "one"}]} = Authzura.all(Organization, session(), instance: i)
    assert [select] = queries()
    assert select =~ ~r/^SELECT /

    assert {:ok, %{id: 1}} = Authzura.one(Organization, session(), instance: i)
    assert [_select] = queries()
  end

  test "a write is still refused, by the connection", %{test: test} do
    i = start!(test, ReadOnlyRepo)

    assert %Error{postgres: %{code: :read_only_sql_transaction}} =
             catch_error(Authzura.all(writing(), session(), instance: i))
  end

  # The only pooled connection is made writable after the load; the next
  # poll notices, and reads fall back to SET TRANSACTION READ ONLY.
  for {label, sql} <- [
        {"SET default_transaction_read_only = off", "SET default_transaction_read_only = off"},
        {"SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
         "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE"}
      ] do
    @tag :capture_log
    test "after #{label}, the next poll falls back to the transaction path", %{test: test} do
      i = start!(test, ReadOnlyRepo)
      ReadOnlyRepo.query!(unquote(sql))
      :ok = Store.poll(i)
      queries()

      assert {:ok, [_one]} = Authzura.all(Organization, session(), instance: i)
      assert ["begin", "SET TRANSACTION READ ONLY", _select, "commit"] = queries()

      assert %Error{postgres: %{code: :read_only_sql_transaction}} =
               catch_error(Authzura.all(writing(), session(), instance: i))

      # Sticky: a passing check does not restore the one-statement path;
      # only a successful load does.
      ReadOnlyRepo.query!("SET default_transaction_read_only = on")
      :ok = Store.poll(i)
      queries()

      assert {:ok, [_one]} = Authzura.all(Organization, session(), instance: i)
      assert ["begin", "SET TRANSACTION READ ONLY", _select, "commit"] = queries()

      :ok = Authzura.reload(i)
      queries()

      assert {:ok, [_one]} = Authzura.all(Organization, session(), instance: i)
      assert [_select] = queries()
    end
  end

  # With two pooled connections and one made writable, each check samples
  # one of them: once a check fails, every later read stays on the
  # transaction path, whichever connection later checks read.
  @tag :capture_log
  @tag pool_size: 2
  test "the fallback is sticky across polls that sample different connections", %{test: test} do
    i = start!(test, ReadOnlyRepo)

    # Hold both connections at once so the SET lands on exactly one.
    parent = self()

    holder =
      spawn_link(fn ->
        ReadOnlyRepo.checkout(fn ->
          send(parent, :held)
          receive do: (:release -> :ok)
        end)
      end)

    assert_receive :held
    ReadOnlyRepo.query!("SET default_transaction_read_only = off")
    send(holder, :release)

    assert Enum.find(1..50, fn _poll ->
             :ok = Store.poll(i)
             {:ok, generation} = Store.current(i)
             not Generation.connection_read_only?(generation)
           end)

    for _poll <- 1..20 do
      :ok = Store.poll(i)
      {:ok, generation} = Store.current(i)
      refute Generation.connection_read_only?(generation)

      assert %Error{postgres: %{code: :read_only_sql_transaction}} =
               catch_error(Authzura.all(writing(), session(), instance: i))
    end
  end

  test "read_only: :connection needs polling and a finite max_staleness" do
    for opts <- [[poll_interval: nil], [max_staleness: :infinity]] do
      assert_raise NimbleOptions.ValidationError, ~r/read_only: :connection requires/, fn ->
        Authzura.child_spec([name: :ro_check, repo: ReadOnlyRepo, read_only: :connection] ++ opts)
      end
    end
  end

  test "preloads keep their REPEATABLE READ, READ ONLY transaction", %{test: test} do
    i = start!(test, ReadOnlyRepo)
    queries()

    assert {:ok, [%{"users" => [%{"id" => 1}]}]} =
             Authzura.all("organizations", session(), instance: i, preload: ["users"])

    assert [
             "begin",
             "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
             _root,
             _users,
             "commit"
           ] = queries()
  end

  @tag :capture_log
  test "a repo whose connections are not read-only is refused", %{test: test} do
    log =
      capture_log(fn ->
        agent_metadata = metadata()

        assert_raise MatchError, fn ->
          HasuraFixture.start_instance!(test, Repo, agent_metadata, @connection_opts)
        end
      end)

    assert log =~ "read_only_not_enforced"
    assert {:error, :not_ready} = Authzura.all(Organization, session(), instance: test)
    assert %{ready?: false, last_error: :read_only_not_enforced} = Authzura.status(test)
  end

  test "the default mode wraps the read as before", %{test: test} do
    i = HasuraFixture.start_instance!(test, ReadOnlyRepo, metadata())
    queries()

    assert {:ok, [_one]} = Authzura.all(Organization, session(), instance: i)
    assert ["begin", "SET TRANSACTION READ ONLY", _select, "commit"] = queries()
  end
end

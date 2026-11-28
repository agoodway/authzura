defmodule Authzura.Integration.StoreReloadTest do
  use Authzura.CommittedCase

  alias Authzura.{HasuraFixture, Store}
  alias Authzura.Store.Generation

  # A table of its own, so altering it never disturbs the shared fixture.
  @probe {"public", "store_reload_probe"}

  setup %{test: instance} do
    Repo.query!("DROP TABLE IF EXISTS public.store_reload_probe")
    Repo.query!("CREATE TABLE public.store_reload_probe (id bigint PRIMARY KEY, body text NULL)")
    on_exit(fn -> Repo.query!("DROP TABLE IF EXISTS public.store_reload_probe") end)

    metadata =
      HasuraFixture.metadata([
        %{
          table: @probe,
          select_permissions: [%{role: "user", permission: %{columns: "*", filter: %{}}}]
        }
      ])

    HasuraFixture.put_metadata!(Repo, metadata)

    store = start_supervised!({Authzura, name: instance, repo: Repo, poll_interval: nil})
    # Returns once the first load (run in handle_continue) has finished.
    :sys.get_state(store)
    {:ok, instance: instance}
  end

  test "a dropped column reloads through the fingerprint alone", %{instance: instance} do
    assert %{ready?: true} = Authzura.status(instance)
    assert {:ok, %Generation{seq: seq, snapshot: before}} = Store.current(instance)
    assert is_map_key(before.tables[@probe].columns, "body")

    Repo.query!("ALTER TABLE public.store_reload_probe DROP COLUMN body")
    assert :ok = Store.poll(instance)

    assert {:ok, %Generation{seq: later, snapshot: snapshot}} = Store.current(instance)
    assert later > seq
    refute is_map_key(snapshot.tables[@probe].columns, "body")
    assert elem(snapshot.version, 0) == elem(before.version, 0)
  end

  # A restore, a blue/green switch or a manual edit can replace the metadata
  # without moving its counter; the version carries a digest of the content.
  test "metadata replaced at the same resource_version reloads", %{instance: instance} do
    Repo.query!("INSERT INTO public.store_reload_probe VALUES (1, 'b')")
    session = HasuraFixture.session!("user")

    assert {:ok, [%{"body" => "b"}]} =
             Authzura.all("store_reload_probe", session, instance: instance)

    revoked = HasuraFixture.metadata([%{table: @probe, select_permissions: []}])
    HasuraFixture.put_metadata!(Repo, revoked)
    assert :ok = Store.poll(instance)

    assert Authzura.all("store_reload_probe", session, instance: instance) == {:error, :forbidden}
  end

  test "a function grant change reloads through the metadata version", %{instance: instance} do
    session = HasuraFixture.session!("user")
    refute Authzura.function_allowed?(session, "probe_fn", instance: instance)

    granted =
      HasuraFixture.metadata([%{table: @probe}],
        functions: [HasuraFixture.function_grants("probe_fn", ["user"])]
      )

    HasuraFixture.put_metadata!(Repo, granted, 2)
    assert :ok = Store.poll(instance)
    assert Authzura.function_allowed?(session, "probe_fn", instance: instance)

    # Same resource_version, different document: the digest moves the version.
    HasuraFixture.put_metadata!(Repo, HasuraFixture.metadata([%{table: @probe}]), 2)
    assert :ok = Store.poll(instance)
    refute Authzura.function_allowed?(session, "probe_fn", instance: instance)
  end
end

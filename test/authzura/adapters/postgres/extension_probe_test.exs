defmodule Authzura.Adapters.Postgres.ExtensionProbeTest do
  # An extension type the repo cannot decode must not cost the caller its
  # connection, in the sandbox or out of it.
  use Authzura.DataCase, async: true

  alias Authzura.Adapters.Postgres.Introspection

  @refs [{"public", "extension_kinds"}]

  test "introspecting an undecodable type leaves the caller's sandboxed transaction alone" do
    Repo.query!("CREATE TEMP TABLE probe_survivor (id int)")

    assert {:ok, tables, _fks} = Introspection.introspect(Repo, @refs)
    assert tables[hd(@refs)].columns["location"].base_kind == :other
    assert Repo.query!("SELECT count(*) FROM probe_survivor").rows == [[0]]
  end

  test "it runs no query to decide whether a type decodes, on any load" do
    ref = make_ref()
    parent = self()

    :telemetry.attach(
      {__MODULE__, ref},
      [:authzura, :test, :repo, :query],
      fn _event, _measurements, %{query: query}, _config -> send(parent, {ref, query}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach({__MODULE__, ref}) end)

    for _load <- 1..2, do: Introspection.introspect(Repo, @refs)

    refute_received {^ref, "SELECT NULL::" <> _rest}
    assert_received {^ref, _introspection_query}
  end
end

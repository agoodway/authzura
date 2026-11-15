defmodule Authzura.Adapters.Postgres.ExtensionTypesTest do
  # Committed: the probe runs in its own task, on a connection of its own.
  use Authzura.CommittedCase

  alias Authzura.Adapters.Postgres
  alias Authzura.Adapters.Postgres.Introspection
  alias Authzura.HasuraFixture
  alias Authzura.Model.{Diagnostic, Snapshot, Table}
  alias Authzura.Test.{CubeRepo, SingleConnectionRepo}
  alias Authzura.Validator

  @ref {"public", "extension_kinds"}

  defp metadata(columns, filter \\ %{}) do
    HasuraFixture.metadata([
      %{
        table: @ref,
        select_permissions: HasuraFixture.select_permissions("user", columns, filter)
      }
    ])
  end

  defp snapshot(repo, metadata),
    do: repo |> HasuraFixture.snapshot!(metadata) |> Validator.validate(Postgres)

  defp table(%Snapshot{tables: tables}), do: Map.fetch!(tables, @ref)

  defp warnings(%Snapshot{diagnostics: diagnostics}),
    do: for(%Diagnostic{reason: {:other_kind_columns, names}} <- diagnostics, do: names)

  describe "with a repo whose types module decodes the type" do
    setup do
      %{snapshot: snapshot(CubeRepo, metadata(["id", "label", "location"]))}
    end

    test "an extension column is :decodable, and an array of it stays :other", %{snapshot: s} do
      assert %{"location" => %{base_kind: :decodable}, "locations" => %{base_kind: :other}} =
               table(s).columns
    end

    test "it is in the default projection, and the Validator does not warn", %{snapshot: s} do
      allowed = ["id", "label", "location", "locations"]

      assert Table.default_columns(table(s), allowed) == ["id", "label", "location"]
      assert warnings(s) == []
    end

    test "it still cannot be ordered", %{snapshot: s} do
      assert Table.orderable(table(s), ["location"]) ==
               {:error, {:invalid_input, {:order_by, :unorderable}}}
    end

    test "it still cannot be filtered on" do
      snapshot = snapshot(CubeRepo, metadata(["id"], %{"location" => %{"_eq" => "(1)"}}))

      assert %{
               {"user", @ref, :select} => %{
                 status: {:denied, [%{reason: {:invalid_literal, {:unsupported_type, "cube"}}}]}
               }
             } =
               snapshot.permissions
    end
  end

  describe "with one pooled connection, held by the load's transaction" do
    test "the type still decodes" do
      start_supervised!(SingleConnectionRepo)

      assert {:ok, {:ok, tables, _fks}} =
               SingleConnectionRepo.transaction(fn ->
                 Introspection.introspect(SingleConnectionRepo, [@ref])
               end)

      assert %{base_kind: :decodable} = tables[@ref].columns["location"]
    end
  end

  describe "with the main repo, whose types module does not" do
    setup do
      %{snapshot: snapshot(Repo, metadata(["id", "label", "location"]))}
    end

    test "the column stays :other, out of the default projection, with the warning", %{
      snapshot: s
    } do
      assert %{"location" => %{base_kind: :other}} = table(s).columns
      assert Table.default_columns(table(s), ["id", "location"]) == ["id"]
      assert warnings(s) == [["location"]]
    end
  end
end

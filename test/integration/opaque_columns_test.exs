defmodule Authzura.Integration.OpaqueColumnsTest do
  @moduledoc """
  Columns of a kind Authzura cannot compare (`base_kind: :other`, such as
  PostGIS `geography`) may need decoding support the repo lacks. They are
  left out of the default column set, stay selectable by name, and a value
  Postgrex cannot decode is `{:error, {:unsupported_column_type, column}}`.
  `opaque_values.path` (`jsonpath`) stands in for such a type, with `paths`
  (`jsonpath[]`) and `pair` (a composite); `spot` (`point`), `blob`
  (`bytea`) and `span` (`interval`) are types Postgrex decodes, and `amount`
  is a domain over `bigint`.
  """

  use Authzura.CommittedCase

  import ExUnit.CaptureLog

  @moduletag :capture_log

  alias Authzura.HasuraFixture
  alias Authzura.Model.Diagnostic
  alias Postgrex.{Interval, Point, QueryError}

  @opaque_values {"public", "opaque_values"}
  @kinds {"public", "key_kinds"}

  setup %{test: test} do
    Repo.query!("insert into public.key_kinds (id, code, rank) values (1, 'a', 1)")

    Repo.query!(
      "insert into public.opaque_values (id, label, spot, path, blob, span, paths, amount, pair) values " <>
        "(1, 'one', point(1, 2), '$.a', '\\x01', '1 day', '{$.a}', 5, row(1, 'x')), (2, 'two', null, null, null, null, null, 7, null)"
    )

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @kinds,
        array_relationships: [
          %{
            name: "opaque",
            using: %{
              manual_configuration: %{remote_table: @opaque_values, column_mapping: %{id: "id"}}
            }
          }
        ],
        select_permissions: HasuraFixture.select_permissions("user", ["id"])
      },
      %{table: @opaque_values, select_permissions: HasuraFixture.select_permissions("user", "*")}
    ])
  end

  defp session, do: HasuraFixture.session!("user")

  defp ordered, do: from(o in "opaque_values", order_by: o.id)

  test "the default column set leaves out :other columns", %{instance: i} do
    assert {:ok, [%{"id" => 1, "label" => "one"} = row, _two]} =
             Authzura.all(ordered(), session(), instance: i)

    assert Enum.sort(Map.keys(row)) == ["amount", "blob", "id", "label", "span", "spot"]
    assert %{"blob" => <<1>>, "span" => %Interval{days: 1}, "amount" => 5} = row

    assert {:ok, [%{"opaque" => [opaque]}]} =
             Authzura.all("key_kinds", session(), instance: i, preload: ["opaque"])

    assert Map.keys(opaque) == Map.keys(row)
  end

  test "an :other column stays selectable by name", %{instance: i} do
    assert {:ok, [%{"spot" => %Point{x: 1.0, y: 2.0}}, %{"spot" => nil}]} =
             Authzura.all(ordered(), session(), instance: i, columns: ["spot"])

    assert {:ok, columns} = Authzura.allowed_columns(session(), "opaque_values", instance: i)
    assert Enum.sort(columns) == ~w(amount blob id label pair path paths span spot)
  end

  test "a column the repo cannot decode is an error tuple, and the pool recovers", %{
    instance: i
  } do
    log =
      capture_log(fn ->
        assert {:error, {:unsupported_column_type, "path"}} =
                 Authzura.all(ordered(), session(), instance: i, columns: ["path"])

        assert {:error, {:unsupported_column_type, "paths"}} =
                 Authzura.all(ordered(), session(), instance: i, columns: ["id", "paths"])

        assert {:error, {:unsupported_column_type, "path"}} =
                 Authzura.one(where(ordered(), [o], o.id == 1), session(),
                   instance: i,
                   columns: ["id", "path"]
                 )

        assert {:error, {:unsupported_column_type, "path"}} =
                 Authzura.all_input("opaque_values", session(), %{"columns" => ["path"]},
                   instance: i
                 )

        assert {:error, {:unsupported_column_type, "path"}} =
                 Authzura.all("key_kinds", session(),
                   instance: i,
                   preload: [opaque: [columns: [:id, :path]]]
                 )
      end)

    assert log =~ "jsonpath"
    assert {:ok, [_one, _two]} = Authzura.all(ordered(), session(), instance: i)
  end

  test "a domain filters as its base type", %{instance: i} do
    assert {:ok, [%{"id" => 2}]} =
             Authzura.all_input(
               "opaque_values",
               session(),
               %{
                 "columns" => ["id"],
                 "filter" => %{"amount" => %{"_gt" => 6}}
               },
               instance: i
             )
  end

  # A parameter of a caller's fragment whose type Postgrex cannot encode
  # gives the same message; no `:other` column is selected, so it is raised.
  test "a types-module error from elsewhere is raised", %{instance: i} do
    query = from(o in ordered(), where: fragment("?::jsonpath IS NOT NULL", ^"$.a"))

    assert %QueryError{message: message} =
             catch_error(Authzura.all(query, session(), instance: i, columns: ["id"]))

    assert message =~ "jsonpath"
  end

  # An `:other` column is selected, but the failing type is another's: the
  # type is named, never a guessed column.
  test "a types-module error for no selected column names the type", %{instance: i} do
    query = from(o in ordered(), where: fragment("?::xml IS NOT NULL", ^"<a/>"))

    assert {:error, {:unsupported_column_type, {:type, "xml"}}} =
             Authzura.all(query, session(), instance: i, columns: ["id", "path"])
  end

  test "diagnostics warn about allowed :other columns", %{instance: i} do
    assert {:ok, diagnostics} = Authzura.diagnostics(i)

    assert %Diagnostic{severity: :warning, path: ["columns"], reason: reason} =
             Enum.find(diagnostics, &(&1.table == @opaque_values))

    assert reason == {:other_kind_columns, ["pair", "path", "paths"]}
  end
end

defmodule Authzura.PgRestExamples.EmbedsTest do
  @moduledoc """
  PgRest scopes every embedded resource through its own `scope/2`, so the
  Authzura permission of the embedded table applies at every depth.
  """
  use Authzura.PgRestExampleCase

  @moduletag :pgrest

  @owner {"owner", %{"x-hasura-user-id" => "10"}}
  @viewer {"viewer", %{"x-hasura-org-id" => "1"}}
  @member {"member", %{"x-hasura-org-id" => "1"}}

  defp item_ids(list), do: list |> Map.fetch!("todo_items") |> Enum.map(& &1["id"]) |> Enum.sort()

  test "embedded items are scoped by their own permission", ctx do
    assert {200, rows} = get(ctx, "/todo_lists?select=id,todo_items(id)&order=id.asc", @owner)
    assert Enum.map(rows, & &1["id"]) == [1, 3]
    assert Enum.map(rows, &item_ids/1) == [[11, 12], [31, 32]]
  end

  test "an embed cannot reach items of lists the role cannot read", ctx do
    assert {200, []} = get(ctx, "/todo_lists?select=id,todo_items(id)&id=eq.2", @owner)
    assert {200, rows} = get(ctx, "/todo_items?select=id&order=id.asc", @owner)
    assert Enum.map(rows, & &1["id"]) == [11, 12, 31, 32]
  end

  test "an embedded parent honors the parent's row filter and column permission", ctx do
    assert {200, rows} =
             get(ctx, "/todo_items?select=id,todo_list(id,title)&id=lt.30&order=id.asc", @viewer)

    assert Enum.map(rows, & &1["id"]) == [11, 12, 21, 22]
    assert Enum.all?(rows, &is_map(&1["todo_list"]))

    assert {status, _body} =
             get(ctx, "/todo_items?select=id,todo_list(assignee_notes)&order=id.asc", @viewer)

    assert status in [401, 403]

    assert {200, [%{"todo_list" => list} | _]} =
             get(
               ctx,
               "/todo_items?select=id,todo_list(id,org_id,owner_id,title)&order=id.asc",
               @viewer
             )

    refute Map.has_key?(list, "assignee_notes")
  end

  test "a star on an embed, spread or not, is refused where a column is hidden", ctx do
    for query <- [
          "select=id,todo_list(*)",
          "select=id,...todo_list(*)",
          "select=id,...todo_list(id,assignee_notes)",
          "select=id,l:todo_list(*)"
        ] do
      assert {status, _body} = get(ctx, "/todo_items?" <> query, @viewer)
      assert status in [401, 403], query
    end

    assert {200, [%{"assignee_notes" => "secret-1"} | _]} =
             get(ctx, "/todo_items?select=id,...todo_list(*)&order=id.asc", @member)

    assert {200, [%{"todo_list" => %{"assignee_notes" => _}} | _]} =
             get(ctx, "/todo_items?select=id,todo_list(*)&order=id.asc", @member)
  end

  test "no select reads as * and is refused; an empty select returns the trimmed rows", ctx do
    assert {status, _body} = get(ctx, "/todo_lists?order=id.asc", @viewer)
    assert status in [401, 403]

    assert {200, [_ | _] = rows} = get(ctx, "/todo_lists?select=&order=id.asc", @viewer)
    refute Enum.any?(rows, &Map.has_key?(&1, "assignee_notes"))
  end

  test "embedded filters narrow within the permission, never beyond it", ctx do
    assert {200, rows} =
             get(
               ctx,
               "/todo_lists?select=id,todo_items(id)&todo_items.id=gte.0&order=id.asc",
               @viewer
             )

    assert Enum.map(rows, &item_ids/1) == [[11, 12], [21, 22], [31, 32]]
  end

  test "hidden columns are refused inside embeds, in every position", ctx do
    for query <- [
          "select=id,todo_list!inner(id)&todo_list.assignee_notes=eq.secret-1",
          "select=id,todo_list(id)&todo_list.or=(assignee_notes.eq.secret-1)",
          "select=id,l:todo_list(id)&l.assignee_notes=not.eq.x",
          "select=id,todo_list(x:assignee_notes)",
          "select=id,todo_list(assignee_notes::text)",
          "select=id&order=todo_list(assignee_notes).asc",
          "select=id,todo_list(id,todo_items(id))&todo_list.todo_items.id=gte.0&todo_list.order=assignee_notes.asc"
        ] do
      assert {status, _body} = get(ctx, "/todo_items?" <> query, @viewer)
      assert status in [401, 403], query
    end
  end

  test "the same embed requests are allowed where the column is permitted", ctx do
    path =
      "/todo_items?select=id,todo_list!inner(id)&todo_list.assignee_notes=eq.secret-1&order=id.asc"

    assert {200, rows} = get(ctx, path, @member)
    assert Enum.map(rows, & &1["id"]) == [11, 12]
  end

  test "item requests of a member may use groups and casts", ctx do
    path = "/todo_items?select=id,body::text&or=(done.is.true,id.eq.12)&order=id.asc"

    assert {200, rows} = get(ctx, path, @member)
    assert Enum.map(rows, & &1["id"]) == [11, 12, 21, 31]
  end
end

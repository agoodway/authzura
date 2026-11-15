defmodule Authzura.PgRestExamples.EmbedsTest do
  @moduledoc """
  PgRest authorizes every embedded resource through `authorize_query/5`, so the
  Authzura permission of the embedded table applies at every depth.
  """
  use Authzura.PgRestExampleCase

  @owner {"owner", %{"x-hasura-user-id" => "10"}}
  @viewer {"viewer", %{"x-hasura-org-id" => "1"}}
  @member {"member", %{"x-hasura-org-id" => "1"}}

  defp item_ids(list), do: list |> Map.fetch!("todo_items") |> Enum.map(& &1["id"]) |> Enum.sort()

  test "embedded items are scoped by their own permission", ctx do
    assert {200, rows} = get(ctx, "/todo_lists?select=id,todo_items(id)&order=id.asc", @owner)
    assert Enum.map(rows, & &1["id"]) == [1, 3]
    assert Enum.map(rows, &item_ids/1) == [[11, 12], [31, 32]]
  end

  test "embedded aggregates need no select_aggregate root field", ctx do
    nested_analyst = {"nested_analyst", %{"x-hasura-org-id" => "1"}}
    path = "/todo_lists?select=id,todo_items(count(),id.max())&order=id.asc"

    assert {200, rows} = get(ctx, path, nested_analyst)

    assert rows == [
             %{"id" => 1, "todo_items" => [%{"count" => 2, "max" => 12}]},
             %{"id" => 2, "todo_items" => [%{"count" => 2, "max" => 22}]},
             %{"id" => 3, "todo_items" => [%{"count" => 2, "max" => 32}]}
           ]
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

    assert {403, %{"code" => "42501"}} =
             get(ctx, "/todo_items?select=id,todo_list(assignee_notes)&order=id.asc", @viewer)

    assert {200, [%{"todo_list" => list} | _]} =
             get(
               ctx,
               "/todo_items?select=id,todo_list(id,org_id,owner_id,title)&order=id.asc",
               @viewer
             )

    refute Map.has_key?(list, "assignee_notes")
  end

  test "stars narrow embedded and spread columns", ctx do
    for query <- ["select=id,todo_list(*)", "select=id,l:todo_list(*)"] do
      assert {200, rows} = get(ctx, "/todo_items?" <> query, @viewer)
      key = if String.contains?(query, "l:"), do: "l", else: "todo_list"
      assert Enum.all?(rows, &Map.has_key?(&1[key], "title"))
      refute Enum.any?(rows, &Map.has_key?(&1[key], "assignee_notes"))
    end

    assert {200, rows} = get(ctx, "/todo_items?select=id,...todo_list(*)", @viewer)
    assert Enum.all?(rows, &Map.has_key?(&1, "title"))
    refute Enum.any?(rows, &Map.has_key?(&1, "assignee_notes"))

    assert {403, %{"code" => "42501"}} =
             get(ctx, "/todo_items?select=id,...todo_list(id,assignee_notes)", @viewer)

    assert {200, [%{"assignee_notes" => "secret-1"} | _]} =
             get(ctx, "/todo_items?select=id,...todo_list(*)&order=id.asc", @member)

    assert {200, [%{"todo_list" => %{"assignee_notes" => _}} | _]} =
             get(ctx, "/todo_items?select=id,todo_list(*)&order=id.asc", @member)
  end

  test "default and empty selects return only permitted columns", ctx do
    for path <- ["/todo_lists?order=id.asc", "/todo_lists?select=&order=id.asc"] do
      assert {200, [_ | _] = rows} = get(ctx, path, @viewer)
      refute Enum.any?(rows, &Map.has_key?(&1, "assignee_notes"))
    end
  end

  test "aliased nested embed paths each retain their own narrowing", ctx do
    path =
      "/todo_items?select=id,parent:todo_list(id,children:todo_items(id))&order=id.asc"

    assert {200, rows} = get(ctx, path, @owner)
    assert Enum.map(rows, & &1["id"]) == [11, 12, 31, 32]
    assert Enum.map(rows, & &1["parent"]["id"]) == [1, 1, 3, 3]

    assert Enum.map(rows, fn row ->
             row["parent"]["children"] |> Enum.map(& &1["id"]) |> Enum.sort()
           end) == [[11, 12], [11, 12], [31, 32], [31, 32]]
  end

  test "permission limits cap each parent's embed independently", ctx do
    capped = {"capped_items", %{"x-hasura-org-id" => "1"}}

    path =
      "/todo_lists?select=id,todo_items(id)&order=id.asc&todo_items.order=id.asc&todo_items.limit=10"

    assert {200, rows} = get(ctx, path, capped)
    assert Enum.map(rows, & &1["id"]) == [1, 2, 3]
    assert Enum.map(rows, &item_ids/1) == [[11], [21], [31]]
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
          "select=id,todo_list(id)&order=todo_list(assignee_notes).asc",
          "select=id,todo_list(id,todo_items(id))&todo_list.todo_items.id=gte.0&todo_list.order=assignee_notes.asc"
        ] do
      assert {403, %{"code" => "42501"}} = get(ctx, "/todo_items?" <> query, @viewer)
    end
  end

  test "related ordering without a selected embed is rejected by PgRest", ctx do
    assert {400, %{"code" => "PGRST108"}} =
             get(ctx, "/todo_items?select=id&order=todo_list(assignee_notes).asc", @viewer)
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

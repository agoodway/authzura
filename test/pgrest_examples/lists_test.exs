defmodule Authzura.PgRestExamples.ListsTest do
  use Authzura.PgRestExampleCase

  @owner {"owner", %{"x-hasura-user-id" => "10"}}
  @member {"member", %{"x-hasura-org-id" => "1"}}
  @viewer {"viewer", %{"x-hasura-org-id" => "1"}}
  @analyst {"analyst", %{"x-hasura-org-id" => "1"}}
  @nested_analyst {"nested_analyst", %{"x-hasura-org-id" => "1"}}
  @other_org_member {"member", %{"x-hasura-org-id" => "2"}}

  defp ids({200, rows}), do: Enum.map(rows, & &1["id"])

  describe "rows" do
    test "an owner reads only their own lists", ctx do
      assert {200, rows} = get(ctx, "/todo_lists?order=id.asc", @owner)
      assert Enum.map(rows, & &1["id"]) == [1, 3]
      assert Enum.all?(rows, &(&1["owner_id"] == 10 and Map.has_key?(&1, "assignee_notes")))
    end

    test "a member reads their organization's lists", ctx do
      assert ctx |> get("/todo_lists?order=id.asc", @member) |> ids() == [1, 2, 3]
    end

    test "other tenants' rows are never returned", ctx do
      assert ctx |> get("/todo_lists", @other_org_member) |> ids() == [4]
      assert ctx |> get("/todo_lists?id=eq.4", @member) |> ids() == []
      assert ctx |> get("/todo_lists?id=eq.1", @other_org_member) |> ids() == []
    end

    test "an or filter cannot widen the permission", ctx do
      assert ctx |> get("/todo_lists?or=(org_id.eq.2,id.gte.0)&order=id.asc", @member) |> ids() ==
               [1, 2, 3]
    end
  end

  describe "columns" do
    test "a viewer never receives assignee_notes", ctx do
      assert {200, rows} =
               get(ctx, "/todo_lists?select=id,org_id,owner_id,title&order=id.asc", @viewer)

      assert Enum.map(rows, & &1["id"]) == [1, 2, 3]
      refute Enum.any?(rows, &Map.has_key?(&1, "assignee_notes"))
      assert Enum.all?(rows, &Map.has_key?(&1, "title"))
    end

    test "stars narrow to permitted columns", ctx do
      for path <- ["/todo_lists", "/todo_lists?select=*", "/todo_lists?select=id,*"] do
        assert {200, rows} = get(ctx, path, @viewer)
        assert [_, _, _] = rows
        refute Enum.any?(rows, &Map.has_key?(&1, "assignee_notes"))
        assert Enum.all?(rows, &Map.has_key?(&1, "title"))
      end

      assert {200, [%{"assignee_notes" => _} | _]} = get(ctx, "/todo_lists?select=*", @member)
      assert {200, [%{"body" => _} | _]} = get(ctx, "/todo_items?select=*", @viewer)
    end

    test "naming a hidden column is refused in select, filters and order", ctx do
      for path <- [
            "/todo_lists?select=id,assignee_notes",
            "/todo_lists?assignee_notes=eq.secret-1",
            "/todo_lists?select=id&assignee_notes=like.secret*"
          ] do
        assert {403, %{"code" => "42501"}} = get(ctx, path, @viewer)
      end
    end

    test "the same requests succeed for a role that may read the column", ctx do
      assert {200, [%{"assignee_notes" => "secret-1"}]} =
               get(
                 ctx,
                 "/todo_lists?select=id,assignee_notes&assignee_notes=eq.secret-1",
                 @member
               )
    end
  end

  describe "every way of naming a hidden column" do
    @hidden [
      "select=x:assignee_notes",
      "select=title:assignee_notes",
      "select=assignee_notes::text",
      "select=id,assignee_notes->a",
      "or=(assignee_notes.eq.secret-1)",
      "and=(assignee_notes.like.secret*,id.gt.0)",
      "not.or=(assignee_notes.eq.x,id.eq.1)",
      "or=(id.eq.1,and(title.eq.a,assignee_notes.eq.secret-1))",
      "assignee_notes=not.eq.x",
      "assignee_notes->a=eq.x",
      "order=assignee_notes.desc",
      "select=id&order=assignee_notes.asc.nullsfirst"
    ]

    test "are refused for a role that may not read the column", ctx do
      for query <- @hidden do
        assert {403, %{"code" => "42501"}} = get(ctx, "/todo_lists?" <> query, @viewer)
      end
    end

    test "never leak through a request PgRest cannot parse or resolve", ctx do
      for query <- [
            "select=id,nope(id)",
            "or=(",
            "select=id,x:todo_items(id)&nope.id=eq.1",
            "select=assignee_notes.max()"
          ] do
        assert {status, body} = get(ctx, "/todo_lists?" <> query, @viewer)
        assert status >= 400 and not is_list(body), query
      end
    end

    test "are allowed for a role that may read it", ctx do
      assert {200, [%{"id" => 1}]} =
               get(ctx, "/todo_lists?select=id&or=(assignee_notes.eq.secret-1)", @member)

      assert {200, [%{"assignee_notes" => "secret-1"} | _]} =
               get(
                 ctx,
                 "/todo_lists?select=assignee_notes::text&order=assignee_notes.asc",
                 @member
               )

      assert {200, [%{"id" => 1}]} =
               get(ctx, "/todo_lists?select=id&not.or=(assignee_notes.eq.x)&id=eq.1", @member)
    end

    test "aliases of permitted columns are preserved", ctx do
      assert {200, [row | _]} = get(ctx, "/todo_lists?select=id,x:title&order=id.asc", @member)
      assert row == %{"id" => 1, "x" => "groceries"}
    end
  end

  describe "filters and ordering stay scoped" do
    test "filters, ordering and pagination compose with the permission", ctx do
      assert ctx |> get("/todo_lists?id=gt.1&order=title.desc", @member) |> ids() == [2, 3]
      assert ctx |> get("/todo_lists?order=id.desc&limit=1", @owner) |> ids() == [3]
      assert ctx |> get("/todo_lists?title=ilike.*r*&order=id.asc", @owner) |> ids() == [1, 3]
    end
  end

  describe "denials" do
    test "a permission row limit caps reads and clamps requested limits", ctx do
      capped = {"capped", %{"x-hasura-org-id" => "1"}}

      for suffix <- ["", "&limit=10"] do
        assert {200, [%{"id" => 1}]} =
                 get(ctx, "/todo_lists?select=id&order=id.asc" <> suffix, capped)
      end
    end

    test "writes are denied and leave rows unchanged", ctx do
      assert {200, before} = get(ctx, "/todo_lists?order=id.asc", @member)

      for method <- [:post, :patch, :put, :delete] do
        assert {403, %{"code" => "42501"}} =
                 request(ctx, method, "/todo_lists?id=eq.1", @member, [], %{
                   "id" => 1,
                   "title" => "changed"
                 })
      end

      assert {200, ^before} = get(ctx, "/todo_lists?order=id.asc", @member)
    end

    test "execution plans are denied even when enabled by the endpoint", ctx do
      assert {406, %{"code" => "PGRST107"}} =
               request(ctx, :get, "/todo_lists", @member, [
                 {"accept", "application/vnd.pgrst.plan"}
               ])
    end

    test "aggregates are denied by default", ctx do
      for select <- ["count()", "id.max()"] do
        assert {403, %{"code" => "42501"}} =
                 get(ctx, "/todo_lists?select=" <> select, @member)
      end
    end

    test "counts are denied by default", ctx do
      for mode <- ["exact", "planned", "estimated"] do
        assert {403, %{"code" => "42501"}} =
                 request(ctx, :get, "/todo_lists", @member, [{"prefer", "count=" <> mode}])
      end
    end

    test "aggregates succeed when the permission grants them at the root", ctx do
      assert {200, [%{"count" => 3}]} = get(ctx, "/todo_lists?select=count()", @analyst)
      assert {200, [%{"max" => 3}]} = get(ctx, "/todo_lists?select=id.max()", @analyst)
    end

    test "counts succeed when the permission grants them at the root", ctx do
      for mode <- ["exact", "planned", "estimated"] do
        assert {status, rows} =
                 request(ctx, :get, "/todo_lists?select=id&order=id.asc", @analyst, [
                   {"prefer", "count=" <> mode}
                 ])

        assert status in [200, 206]
        assert Enum.map(rows, & &1["id"]) == [1, 2, 3]
      end
    end

    test "allow_aggregations does not grant aggregates without the root field", ctx do
      for select <- ["count()", "id.max()"] do
        assert {403, %{"code" => "42501"}} =
                 get(ctx, "/todo_lists?select=" <> select, @nested_analyst)
      end
    end

    test "allow_aggregations does not grant counts without the root field", ctx do
      for mode <- ["exact", "planned", "estimated"] do
        assert {403, %{"code" => "42501"}} =
                 request(ctx, :get, "/todo_lists", @nested_analyst, [
                   {"prefer", "count=" <> mode}
                 ])
      end
    end

    test "a role without a permission is refused", ctx do
      assert {status, _body} = get(ctx, "/todo_lists", {"stranger", %{}})
      assert status == 403
    end

    test "a missing session variable is refused by the gate, not raised", ctx do
      assert {status, _body} = get(ctx, "/todo_lists", {"owner", %{}})
      assert status == 403
    end

    test "conflicting session variables fail session construction and return no rows", ctx do
      identity = {"owner", %{"x-hasura-user-id" => "10", "X-Hasura-User-Id" => "20"}}

      assert {status, body} = get(ctx, "/todo_lists", identity)
      assert status == 401
      assert %{"code" => "42501"} = body
    end
  end
end

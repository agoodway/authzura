defmodule Authzura.Integration.FilterRowsTest do
  use Authzura.DataCase, async: true

  alias Authzura.{HasuraFixture, Store, TelemetryHelper, TestSource}
  alias Authzura.Model.Permission
  alias Authzura.Test.Schemas.Article
  alias Ecto.Query

  @articles {"public", "articles"}
  @mine %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title"], filter: @mine}},
          %{role: "capped", permission: %{columns: ["id", "title"], filter: %{}, limit: 2}},
          %{
            role: "noroot",
            permission: %{columns: ["id"], filter: %{}, query_root_fields: []}
          }
        ]
      }
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one')",
        """
        insert into public.users (id, org_id, email, role) values
          (1, 1, 'a@x.com', 'editor'), (2, 1, 'b@x.com', 'viewer')
        """,
        """
        insert into public.articles
          (id, org_id, author_id, editor_id, status, is_published, title, internal_notes)
        values
          (1, 1, 1, 2, 'draft', false, 'one', 'n1'),
          (2, 1, 1, null, 'published', true, 'two', 'n2'),
          (3, 1, 2, null, 'draft', false, 'three', null)
        """
      ],
      &Repo.query!/1
    )

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp user(id),
    do: HasuraFixture.session!("user", %{"x-hasura-user-id" => Integer.to_string(id)})

  defp ids(rows), do: rows |> Enum.map(& &1.id) |> Enum.sort()

  defp cap_to(query, nil), do: query
  defp cap_to(query, cap), do: limit(query, ^cap)

  test "ANDs the row filter and adds no select or limit", %{instance: i} do
    assert {:ok, %Query{} = filtered, %Permission{columns: ["id", "title"]}} =
             Authzura.filter_rows(Article, user(1), instance: i)

    assert {:ok, %Query{} = scoped} = Authzura.scope(Article, user(1), instance: i)

    assert filtered.select == nil
    assert filtered.limit == nil
    assert filtered.order_bys == []
    assert scoped.select != nil
    assert filtered.wheres == scoped.wheres
    assert filtered.joins == scoped.joins
    assert filtered.from == scoped.from
    assert filtered.aliases == scoped.aliases
  end

  test "keeps the caller's limit, offset and order", %{instance: i} do
    query = from(a in Article, order_by: [desc: a.id], limit: 5, offset: 1)

    assert {:ok, filtered, _permission} = Authzura.filter_rows(query, user(1), instance: i)

    assert filtered.select == nil
    assert filtered.order_bys == query.order_bys
    assert filtered.limit == query.limit
    assert filtered.offset == query.offset
    assert ids(Repo.all(filtered)) == [1]
  end

  test "rows equal scope/3's when the caller applies the columns and limit", %{instance: i} do
    for session <- [user(1), HasuraFixture.session!("capped")] do
      {:ok, scoped} = Authzura.scope(order_by(Article, :id), session, instance: i)

      {:ok, filtered, %Permission{columns: columns, limit: cap}} =
        Authzura.filter_rows(order_by(Article, :id), session, instance: i)

      fields = Enum.map(columns, &String.to_existing_atom/1)

      rows =
        filtered
        |> cap_to(cap)
        |> select([a], map(a, ^fields))
        |> Repo.all()

      assert rows == Repo.all(scoped)
    end
  end

  describe "root_field:" do
    test "defaults to requiring the select root field", %{instance: i} do
      session = HasuraFixture.session!("noroot")

      assert Authzura.filter_rows(Article, session, instance: i) == {:error, :root_field_disabled}

      assert Authzura.filter_rows(Article, session, instance: i, root_field: :select) ==
               {:error, :root_field_disabled}
    end

    test "false filters rows without a root field, keeping the permission", %{instance: i} do
      assert {:ok, %Query{} = filtered, %Permission{columns: ["id"]}} =
               Authzura.filter_rows(Article, HasuraFixture.session!("noroot"),
                 instance: i,
                 root_field: false
               )

      assert ids(Repo.all(filtered)) == [1, 2, 3]

      assert {:ok, mine, %Permission{columns: ["id", "title"]}} =
               Authzura.filter_rows(Article, user(1), instance: i, root_field: false)

      assert ids(Repo.all(mine)) == [1, 2]
    end

    test "false still denies a role without a select permission", %{instance: i} do
      assert Authzura.filter_rows(Article, HasuraFixture.session!("nobody"),
               instance: i,
               root_field: false
             ) == {:error, :forbidden}
    end

    test "rejects an invalid value", %{instance: i} do
      assert_raise NimbleOptions.ValidationError, ~r/invalid value for :root_field option/, fn ->
        Authzura.filter_rows(Article, user(1), instance: i, root_field: :select_aggregate)
      end
    end
  end

  test "unions are rejected: their branches cannot be enforced", %{instance: i} do
    branch = from(a in Article, where: a.id > 1)

    for combined <- [
          union(Article, ^branch),
          union_all(Article, ^branch),
          except(Article, ^branch),
          intersect(Article, ^branch)
        ] do
      assert Authzura.filter_rows(combined, user(1), instance: i) ==
               {:error, {:unsupported_query, :combination_requires_scope}}
    end
  end

  @tag :capture_log
  test "a stale store is refused exactly as scope/3 refuses it", %{test: test} do
    clock = :atomics.new(1, signed: true)

    {instance, agent} =
      HasuraFixture.start_instance_with_source!(Module.concat(test, Stale), Repo, metadata(),
        max_staleness: 1_000,
        clock: fn :millisecond -> :atomics.get(clock, 1) end
      )

    TestSource.put(agent, version_error: :down)
    :atomics.add(clock, 1, 1_001)
    Store.poll(instance)

    assert Authzura.scope(Article, user(1), instance: instance) == {:error, :stale_permissions}

    assert Authzura.filter_rows(Article, user(1), instance: instance) ==
             {:error, :stale_permissions}
  end

  test "an admin role gets no filter and a synthesized permission", %{test: test} do
    instance =
      HasuraFixture.start_instance!(Module.concat(test, Admin), Repo, metadata(),
        admin_role: "admin"
      )

    assert {:ok, filtered, %Permission{filter: {:and, []}, limit: nil}} =
             Authzura.filter_rows(Article, HasuraFixture.session!("admin"), instance: instance)

    assert filtered.wheres == []
    assert ids(Repo.all(filtered)) == [1, 2, 3]
  end

  test "rejects options that do not apply", %{instance: i} do
    for opts <- [[columns: ["id"]], [preload: [:author]], [repo_opts: []]] do
      assert_raise NimbleOptions.ValidationError, fn ->
        Authzura.filter_rows(Article, user(1), [instance: i] ++ opts)
      end
    end
  end

  test "keeps scope/3's denials", %{instance: i} do
    for {queryable, session, opts} <- [
          {Article, HasuraFixture.session!("noroot"), []},
          {Article, HasuraFixture.session!("nobody"), []},
          {from(t in "missing_table"), user(1), []},
          {Article, HasuraFixture.session!("user"), []},
          {Article, user(1), table: {"public", "users"}},
          {preload(Article, :author), user(1), []},
          {limit(Article, ^(-1)), user(1), []},
          {select(Article, [a], a.id), user(1), []}
        ] do
      opts = [instance: i] ++ opts

      assert {:error, _reason} = error = Authzura.filter_rows(queryable, session, opts)
      assert error == Authzura.scope(queryable, session, opts)
    end
  end

  test "an instance that is not running is not ready" do
    assert Authzura.filter_rows(Article, user(1), instance: Module.concat(__MODULE__, Missing)) ==
             {:error, :not_ready}
  end

  test "emits the scope span marked with its mode", %{instance: i, test: test} do
    TelemetryHelper.forward!(test, [[:authzura, :scope, :stop]], instance: i)

    Authzura.filter_rows(Article, user(1), instance: i)

    assert_receive {:telemetry, [:authzura, :scope, :stop],
                    %{result: :granted, role: "user", mode: :filter_rows}}
  end
end

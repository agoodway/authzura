defmodule Authzura.Integration.PreloadLoaderTest do
  use Authzura.DataCase, async: true

  alias Authzura.Adapters.Postgres
  alias Authzura.{HasuraFixture, Store, TelemetryHelper}
  alias Authzura.Model.{Snapshot, Table}
  alias Authzura.Preload.{Loader, Tree}
  alias Authzura.Store.Generation
  alias Ecto.Adapters.SQL

  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @users {"public", "users"}
  @profiles {"public", "user_profiles"}
  @memberships {"public", "org_memberships"}
  @notes {"public", "membership_notes"}
  @key_kinds {"public", "key_kinds"}

  @limits %{depth: 4, nodes: 16}
  @mine %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}
  @uuid "11111111-1111-1111-1111-111111111111"
  @repo_query [:authzura, :test, :repo, :query]

  # Every table is readable by "user" without limits and by "capped" with a
  # permission limit of 1; tables with an author_id also by "mine" through
  # @mine.
  defp permissions(columns) do
    [
      %{role: "user", permission: %{columns: columns, filter: %{}}},
      %{role: "capped", permission: %{columns: columns, filter: %{}, limit: 1}}
    ]
  end

  defp authored(columns),
    do: [%{role: "mine", permission: %{columns: columns, filter: @mine}} | permissions(columns)]

  defp self_relationship(name, column) do
    mapping = %{column => column}

    %{
      name: name,
      using: %{manual_configuration: %{remote_table: @articles, column_mapping: mapping}}
    }
  end

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        array_relationships: [
          %{
            name: "comments",
            using: %{foreign_key_constraint_on: %{table: @comments, column: "article_id"}}
          },
          self_relationship("same_status", "status"),
          self_relationship("same_ref", "external_ref")
        ],
        select_permissions: authored(["id", "title", "author_id", "status", "external_ref"])
      },
      %{
        table: @comments,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: authored(["id", "body", "article_id", "author_id"])
      },
      %{
        table: @users,
        object_relationships: [
          %{
            name: "profile",
            using: %{
              manual_configuration: %{remote_table: @profiles, column_mapping: %{id: "user_id"}}
            }
          },
          %{
            name: "same_email",
            using: %{
              manual_configuration: %{remote_table: @users, column_mapping: %{email: "email"}}
            }
          }
        ],
        select_permissions: permissions(["id", "email"])
      },
      %{table: @profiles, select_permissions: permissions(["user_id", "bio"])},
      %{
        table: @memberships,
        array_relationships: [
          %{
            name: "notes",
            using: %{
              manual_configuration: %{
                remote_table: @notes,
                column_mapping: %{org_id: "org_id", user_id: "user_id"}
              }
            }
          }
        ],
        select_permissions: permissions(["org_id", "user_id", "level"])
      },
      %{table: @notes, select_permissions: permissions(["id", "org_id", "user_id", "note"])}
    ])
  end

  # A varchar key mapped to a citext column: the Validator makes it
  # non-preloadable, with a warning diagnostic.
  defp key_kinds_metadata do
    HasuraFixture.metadata([
      %{table: @users, select_permissions: permissions(["id", "email"])},
      %{
        table: @key_kinds,
        object_relationships: [
          %{
            name: "user",
            using: %{
              manual_configuration: %{remote_table: @users, column_mapping: %{code: "email"}}
            }
          }
        ],
        select_permissions: permissions(["id", "code"])
      }
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one'), (2, 'two')",
        """
        insert into public.users (id, org_id, email, role) values
          (1, 1, 'a@x.com', 'editor'), (2, 1, 'b@x.com', 'viewer'), (3, 2, 'c@x.com', 'viewer')
        """,
        "insert into public.user_profiles values (1, 'bio one'), (3, 'bio three')",
        """
        insert into public.articles (id, org_id, author_id, status, is_published, title) values
          (1, 1, 1, 'draft', false, 'one'), (2, 1, 2, 'draft', false, 'two'),
          (3, 1, 3, 'review', false, 'three')
        """,
        "update public.articles set external_ref = '#{@uuid}' where id in (1, 3)",
        """
        insert into public.comments values
          (11, 1, 1, 'a'), (12, 1, 2, 'b'), (13, 1, 3, 'c'),
          (21, 2, 3, 'd'), (22, 2, 1, 'e'), (23, 2, 2, 'f')
        """,
        "insert into public.org_memberships values (1, 2, 5), (2, 1, 7), (1, 1, 9)",
        """
        insert into public.membership_notes values
          (1, 1, 2, 'one-two'), (2, 2, 1, 'two-one'), (3, 1, 2, 'one-two again'),
          (4, null, 2, 'orphan')
        """,
        "insert into public.key_kinds (id, code, rank) values (1, 'A@x.com', 1), (2, 'nobody', 2)"
      ],
      &Repo.query!/1
    )

    instance = HasuraFixture.start_instance!(test, Repo, metadata())
    {:ok, generation} = Store.current(instance)
    %{generation: generation}
  end

  defp session(role), do: HasuraFixture.session!(role)

  # Validates `tree` on `root`, reads the parents with a plain query, and
  # loads the preloads with their stitching keys.
  defp load(generation, root, tree, columns, role \\ "user", where \\ "true") do
    {:ok, nodes} = Tree.validate(tree, root, session(role), generation, @limits)
    keys = Tree.parent_columns(nodes)
    rows = parents(root, Enum.uniq(columns ++ keys), where)
    parent_keys = Enum.map(rows, fn row -> Enum.map(keys, &Map.fetch!(row, &1)) end)

    with {:ok, loaded} <-
           Loader.load(nodes, rows, parent_keys, Repo, Postgres),
         do:
           {:ok,
            Enum.map(loaded, &Map.take(&1, columns ++ Enum.map(nodes, fn n -> n.rel.name end)))}
  end

  defp parents({schema, name}, columns, where) do
    select = Enum.map_join(columns, ", ", &~s("#{&1}"))
    sql = "SELECT #{select} FROM #{schema}.#{name} WHERE #{where} ORDER BY 1"
    %{rows: rows, columns: names} = Repo.query!(sql)
    Enum.map(rows, &(names |> Enum.zip(&1) |> Map.new()))
  end

  defp ids(rows), do: Enum.map(rows, &Map.fetch!(&1, "id"))

  # The SQL of `tree`'s single node on `root`, for parent keys `keys`.
  defp level_sql(generation, root, tree, keys, role \\ "user") do
    {:ok, [%{rel: rel} = node]} = Tree.validate(tree, root, session(role), generation, @limits)
    %Table{columns: columns} = generation.snapshot.tables[rel.target]
    assert node.key_columns == Enum.map(rel.mapping, fn {_local, remote} -> columns[remote] end)
    {:ok, query} = Postgres.preload_level_query(node, keys)
    {sql, _params} = SQL.to_sql(:all, Repo, query)
    sql
  end

  describe "per-parent limits" do
    test "a limited array relationship gets at most the limit per parent", %{generation: g} do
      assert {:ok, [one, two, three]} = load(g, @articles, [:comments], ["id"], "capped")

      assert [%{"id" => c1}] = one["comments"]
      assert c1 in [11, 12, 13]
      assert [%{"id" => c2}] = two["comments"]
      assert c2 in [21, 22, 23]
      assert three["comments"] == []
    end

    test "order_by applies inside the per-parent limit", %{generation: g} do
      tree = [comments: [order_by: [asc: :id]]]
      assert {:ok, [one, two, _three]} = load(g, @articles, tree, ["id"], "capped")

      assert ids(one["comments"]) == [11]
      assert ids(two["comments"]) == [21]

      tree = [comments: [order_by: [desc: :id]]]
      assert {:ok, [one, two, _three]} = load(g, @articles, tree, ["id"], "capped")
      assert ids(one["comments"]) == [13]
      assert ids(two["comments"]) == [23]
    end

    test "ties in order_by break on the target's primary key", %{generation: g} do
      Repo.query!(
        "insert into public.comments values (33, 3, 3, 'same'), (31, 3, 1, 'same'), (32, 3, 2, 'same')"
      )

      tree = [comments: [order_by: [asc: :body]]]

      assert {:ok, [_one, _two, three]} = load(g, @articles, tree, ["id"], "capped")
      assert ids(three["comments"]) == [31]

      assert {:ok, [_one, _two, three]} = load(g, @articles, tree, ["id"])
      assert ids(three["comments"]) == [31, 32, 33]

      {:ok, [node]} = Tree.validate(tree, @articles, session("user"), g, @limits)
      %Table{columns: %{"article_id" => key}} = g.snapshot.tables[@comments]
      {:ok, query} = Postgres.preload_level_query(%{node | key_columns: [key]}, [[3]])
      {sql, _params} = SQL.to_sql(:all, Repo, query)

      assert sql =~ ~r/ORDER BY \w+\."idx", \w+\."body", \w+\."id"$/
    end

    test "an order_by on the primary key is not repeated", %{generation: g} do
      {:ok, [node]} =
        Tree.validate([comments: [order_by: [desc: :id]]], @articles, session("user"), g, @limits)

      %Table{columns: %{"article_id" => key}} = g.snapshot.tables[@comments]
      {:ok, query} = Postgres.preload_level_query(%{node | key_columns: [key]}, [[1]])
      {sql, _params} = SQL.to_sql(:all, Repo, query)

      assert sql =~ ~r/ORDER BY \w+\."idx", \w+\."id" DESC$/
    end

    test "an unlimited array relationship keeps every row in order", %{generation: g} do
      tree = [comments: [order_by: [desc: :id]]]
      assert {:ok, [one, two, three]} = load(g, @articles, tree, ["id"])

      assert ids(one["comments"]) == [13, 12, 11]
      assert ids(two["comments"]) == [23, 22, 21]
      assert three["comments"] == []
    end

    # The analog of Hasura's Regression/ObjectRelationshipsLimit7936Spec.hs.
    test "an object relationship ignores the target's permission limit", %{generation: g} do
      assert {:ok, rows} = load(g, @articles, [:author], ["id", "author_id"], "capped")

      for %{"author_id" => author_id, "author" => author} <- rows,
          do: assert(%{"id" => ^author_id} = author)

      assert [_, _, _] = rows
    end
  end

  describe "row filter" do
    test "each level applies the target's filter with the session", %{generation: g} do
      me = HasuraFixture.session!("mine", %{"x-hasura-user-id" => "1"})
      {:ok, nodes} = Tree.validate([:comments], @articles, me, g, @limits)

      assert {:ok, [one, two]} =
               Loader.load(nodes, [%{"id" => 1}, %{"id" => 2}], [[1], [2]], Repo, Postgres)

      assert ids(one["comments"]) == [11]
      assert ids(two["comments"]) == [22]
    end

    # Every node's filter is compiled when the tree is validated, whether or
    # not any parent row reaches it.
    test "a missing session variable is returned", %{generation: g} do
      assert Tree.validate([:comments], @articles, session("mine"), g, @limits) ==
               {:error, {:missing_session_variable, "x-hasura-user-id"}}
    end
  end

  describe "keys" do
    test "every arity up to eight key pairs builds and runs", %{generation: g} do
      {:ok, [node]} = Tree.validate([:comments], @articles, session("user"), g, @limits)
      %Table{columns: %{"article_id" => key}} = g.snapshot.tables[@comments]

      for arity <- 1..8 do
        keys = [List.duplicate(2, arity), List.duplicate(1, arity)]
        node = %{node | key_columns: List.duplicate(key, arity)}
        {:ok, query} = Postgres.preload_level_query(node, keys)

        assert {sql, params} = SQL.to_sql(:all, Repo, query)
        assert Enum.count(params) == arity
        assert sql =~ "AS p(#{Enum.map_join(1..arity, ", ", &"k#{&1}")}, idx)"

        assert query |> Repo.all() |> Enum.map(&{&1.idx, &1["id"]}) |> Enum.sort() ==
                 [{1, 21}, {1, 22}, {1, 23}, {2, 11}, {2, 12}, {2, 13}]
      end
    end

    test "enum keys compare as text", %{generation: g} do
      tree = [same_status: [columns: [:id], order_by: [asc: :id]]]
      assert {:ok, [one, _two, three]} = load(g, @articles, tree, ["id", "status"])

      assert ids(one["same_status"]) == [1, 2]
      assert ids(three["same_status"]) == [3]
    end

    test "uuid keys match, including raw values from a schemaless read", %{generation: g} do
      tree = [same_ref: [columns: [:id], order_by: [asc: :id]]]
      assert {:ok, [one, two, _three]} = load(g, @articles, tree, ["id", "external_ref"])

      assert ids(one["same_ref"]) == [1, 3]
      assert two["same_ref"] == []

      {:ok, nodes} = Tree.validate(tree, @articles, session("user"), g, @limits)

      assert {:ok, [%{"same_ref" => [%{"id" => 1}, %{"id" => 3}]}]} =
               Loader.load(nodes, [%{}], [[@uuid]], Repo, Postgres)
    end

    test "crossed composite tuples attach to the right parents", %{generation: g} do
      assert {:ok, rows} = load(g, @memberships, [:notes], ["org_id", "user_id"])

      notes = Map.new(rows, &{{&1["org_id"], &1["user_id"]}, &1["notes"] |> ids() |> Enum.sort()})
      assert notes == %{{1, 1} => [], {1, 2} => [1, 3], {2, 1} => [2]}
    end

    test "partial NULL keys attach nothing", %{generation: g} do
      {:ok, [node]} = Tree.validate([:notes], @memberships, session("user"), g, @limits)
      parents = [%{"org_id" => nil, "user_id" => 2}, %{"org_id" => 1, "user_id" => nil}]

      assert {:ok, [%{"notes" => []}, %{"notes" => []}]} =
               Loader.load([node], parents, [[nil, 2], [1, nil]], Repo, Postgres)
    end

    test "citext keys match case-insensitively", %{generation: g} do
      {:ok, nodes} = Tree.validate([:same_email], @users, session("user"), g, @limits)
      parents = [%{"email" => "A@x.com"}, %{"email" => "B@X.COM"}, %{"email" => "z@x.com"}]
      keys = Enum.map(parents, &[&1["email"]])

      assert {:ok, [alpha, beta, nobody]} =
               Loader.load(nodes, parents, keys, Repo, Postgres)

      assert alpha["same_email"] == %{"id" => 1, "email" => "a@x.com"}
      assert beta["same_email"] == %{"id" => 2, "email" => "b@x.com"}
      assert nobody["same_email"] == nil
    end

    @tag :capture_log
    test "a varchar key mapped to a citext column is not preloadable" do
      instance =
        HasuraFixture.start_instance!(:preload_loader_key_kinds, Repo, key_kinds_metadata())

      {:ok, g} = Store.current(instance)

      assert Tree.validate([:user], @key_kinds, session("user"), g, @limits) ==
               {:error, :forbidden}

      assert [%{reason: {:incompatible_key_kinds, {"code", "varchar"}, {"email", "citext"}}}] =
               g.snapshot.diagnostics
    end

    test "a reverse object relationship", %{generation: g} do
      assert {:ok, [one, two, three]} = load(g, @users, [:profile], ["id"])

      assert one["profile"] == %{"user_id" => 1, "bio" => "bio one"}
      assert two["profile"] == nil
      assert three["profile"] == %{"user_id" => 3, "bio" => "bio three"}
    end
  end

  describe "nesting and stitching" do
    test "three levels deep", %{generation: g} do
      tree = [comments: [columns: [:id], order_by: [asc: :id], preload: [author: [:profile]]]]
      assert {:ok, [one | _rest]} = load(g, @articles, tree, ["id"])

      assert one["comments"] == [
               %{
                 "id" => 11,
                 "author" => %{
                   "id" => 1,
                   "email" => "a@x.com",
                   "profile" => %{"user_id" => 1, "bio" => "bio one"}
                 }
               },
               %{"id" => 12, "author" => %{"id" => 2, "email" => "b@x.com", "profile" => nil}},
               %{
                 "id" => 13,
                 "author" => %{
                   "id" => 3,
                   "email" => "c@x.com",
                   "profile" => %{"user_id" => 3, "bio" => "bio three"}
                 }
               }
             ]
    end

    test "stitching columns the caller did not request are absent", %{generation: g} do
      tree = [
        comments: [columns: [:body], order_by: [asc: :id], preload: [author: [columns: [:email]]]]
      ]

      assert {:ok, [one | _rest]} = load(g, @articles, tree, ["id"])

      assert one["comments"] == [
               %{"body" => "a", "author" => %{"email" => "a@x.com"}},
               %{"body" => "b", "author" => %{"email" => "b@x.com"}},
               %{"body" => "c", "author" => %{"email" => "c@x.com"}}
             ]
    end

    test "no parents runs no query", %{generation: g} do
      {:ok, nodes} = Tree.validate([:comments], @articles, session("user"), g, @limits)
      assert Loader.load(nodes, [], [], Repo, Postgres) == {:ok, []}
    end
  end

  describe "object cardinality" do
    test "more than one row for an object relationship is a data-integrity error",
         %{generation: g} do
      # A "profile" whose mapping is not unique on the target: users.org_id -> users.org_id.
      %Generation{snapshot: %Snapshot{tables: tables} = snapshot} = g
      %Table{relationships: rels} = users = tables[@users]
      rel = %{rels["profile"] | name: "peer", target: @users, mapping: [{"org_id", "org_id"}]}
      users = %{users | relationships: Map.put(rels, "peer", rel)}
      g = %{g | snapshot: %{snapshot | tables: %{tables | @users => users}}}

      {:ok, [node]} = Tree.validate([:peer], @users, session("user"), g, @limits)

      assert Loader.load([node], [%{"org_id" => 1}], [[1]], Repo, Postgres) ==
               {:error, {:unsupported_query, {:object_cardinality, "peer"}}}
    end
  end

  describe "large batches" do
    setup do
      Repo.query!("""
      insert into public.articles (id, org_id, author_id, status, is_published, title)
      select n, 1, 1, 'draft', false, 'bulk' from generate_series(1000, 70999) as n
      """)

      Repo.query!("""
      insert into public.comments
      select n, n - 100000, 1, 'bulk' from generate_series(101000, 170999, 1000) as n
      """)

      :ok
    end

    test "a level query binds one parameter per key column", %{generation: g} do
      {:ok, [node]} = Tree.validate([:comments], @articles, session("user"), g, @limits)
      %Table{columns: columns} = g.snapshot.tables[@comments]
      keys = Enum.map(1000..5999, &[&1])

      {:ok, query} =
        Postgres.preload_level_query(%{node | key_columns: [columns["article_id"]]}, keys)

      {sql, params} = SQL.to_sql(:all, Repo, query)
      assert [[_ | _] = article_ids] = params
      assert Enum.count(article_ids) == 5000
      assert sql =~ "unnest($1::bigint[]) WITH ORDINALITY"
    end

    test "70,000 parents load in one query", %{generation: g} do
      assert {:ok, rows} = load(g, @articles, [:comments], ["id"], "user", "id >= 1000")

      assert Enum.count(rows) == 70_000
      attached = for %{"id" => id, "comments" => [_ | _] = comments} <- rows, do: {id, comments}
      assert Enum.count(attached) == 70

      for {id, comments} <- attached,
          do: assert([%{"article_id" => ^id, "body" => "bulk"}] = comments)
    end
  end

  describe "level shapes" do
    test "a limited array level reads each parent through a bounded lateral subquery",
         %{generation: g} do
      sql = level_sql(g, @articles, [comments: [order_by: [desc: :id]]], [[1], [2]], "capped")

      assert sql =~ "INNER JOIN LATERAL (SELECT"
      assert sql =~ ~r/ORDER BY \w+\."id" DESC LIMIT \$2\)/
      refute sql =~ "PARTITION BY"
    end

    test "without an index serving the rank order, a limited level ranks in a window",
         %{generation: g} do
      sql = level_sql(g, @articles, [comments: [order_by: [asc: :body]]], [[1]], "capped")

      refute sql =~ "LATERAL"
      assert sql =~ ~r/PARTITION BY \w+\."idx" ORDER BY \w+\."body", \w+\."id"\)/
      assert sql =~ ~r/WHERE \(\w+\."rn" <= \$2\)/
    end

    test "an object level off the primary key is bounded at two rows per key",
         %{generation: g} do
      sql = level_sql(g, @users, [:same_email], [["a@x.com"]])
      assert sql =~ ~r/WHERE \(\w+\."rn" <= \$2\)/

      %Generation{snapshot: %Snapshot{tables: tables} = snapshot} = g
      users = %{tables[@users] | indexes: [[{"email", :asc}, {"id", :asc}]]}
      g = %{g | snapshot: %{snapshot | tables: %{tables | @users => users}}}

      sql = level_sql(g, @users, [:same_email], [["a@x.com"]])
      assert sql =~ "INNER JOIN LATERAL (SELECT"
      assert sql =~ ~r/LIMIT \$2\)/
    end

    test "an object level on the target's primary key needs no bound", %{generation: g} do
      sql = level_sql(g, @articles, [:author], [[1]])

      refute sql =~ "LATERAL"
      refute sql =~ "LIMIT"
    end

    # The bench's preload-object and preload-nested-3 (bench/TRIAGE.md): the
    # target's own key column is compared bare, by equality, to the joined
    # key, so its primary key index can serve the join whenever the planner
    # prefers it to hashing the table.
    test "an object level on the primary key joins the bare key column by equality",
         %{generation: g} do
      sql = level_sql(g, @articles, [:author], [[1]])

      assert sql =~
               ~r/^SELECT .+ FROM "public"\."users" AS (\w+) INNER JOIN \(SELECT \* FROM unnest\(\$1::bigint\[\]\) WITH ORDINALITY AS p\(k1, idx\)\) AS (\w+) ON \1\."id" = \2\."k1" WHERE/
    end

    test "an unlimited array level is a plain ordered join", %{generation: g} do
      sql = level_sql(g, @articles, [comments: [order_by: [asc: :body]]], [[1], [2]])

      refute sql =~ "row_number"
      refute sql =~ "LATERAL"
      assert sql =~ ~r/ORDER BY \w+\."idx", \w+\."body", \w+\."id"$/
    end

    test "enum keys compare in the enum's own type", %{generation: g} do
      sql = level_sql(g, @articles, [:same_status], [["draft"]])

      assert sql =~ ~r/\."status" = \w+\."k1"::"public"\."article_status"/
      refute sql =~ "::text"
    end
  end

  describe "lateral and windowed levels" do
    test "load the same rows in the same order", %{generation: g} do
      Repo.query!("insert into public.comments values (14, 1, 2, 'a'), (24, 2, 1, 'a')")
      Repo.query!("insert into public.membership_notes values (5, 1, 2, 'one-two late')")

      %Generation{snapshot: %Snapshot{tables: tables} = snapshot} = g
      unindexed = Map.new(tables, fn {ref, table} -> {ref, %{table | indexes: []}} end)
      windowed = %{g | snapshot: %{snapshot | tables: unindexed}}

      cases = [
        {@articles, [comments: [order_by: [asc: :id]]], ["id"]},
        {@articles, [comments: [order_by: [desc: :id], preload: [:author]]], ["id"]},
        {@articles, [comments: [order_by: [asc: :body]]], ["id"]},
        {@articles, [:comments], ["id"]},
        {@memberships, [notes: [order_by: [desc: :id]]], ["org_id", "user_id"]},
        {@memberships, [:notes], ["org_id", "user_id"]}
      ]

      for {root, tree, columns} <- cases, role <- ["capped", "user"] do
        assert load(g, root, tree, columns, role) == load(windowed, root, tree, columns, role)
      end

      assert {:ok, [one, two, _three]} =
               load(g, @articles, [comments: [order_by: [desc: :id]]], ["id"], "capped")

      assert ids(one["comments"]) == [14]
      assert ids(two["comments"]) == [24]
    end
  end

  describe "the lateral gate" do
    @directions [
      :asc,
      :asc_nulls_first,
      :asc_nulls_last,
      :desc,
      :desc_nulls_first,
      :desc_nulls_last
    ]

    # `g` with `index` as the only index of articles (and `status` altered by `column`).
    defp with_article_index(g, index, column \\ & &1) do
      %Generation{snapshot: %Snapshot{tables: tables} = snapshot} = g
      %Table{columns: columns} = articles = tables[@articles]
      columns = Map.update!(columns, "status", column)
      articles = %{articles | indexes: [index], columns: columns}
      %{g | snapshot: %{snapshot | tables: %{tables | @articles => articles}}}
    end

    defp nulls_first?(direction),
      do: direction in [:asc_nulls_first, :desc, :desc_nulls_first]

    defp descending?(direction), do: direction in [:desc, :desc_nulls_first, :desc_nulls_last]

    test "serves an order only in the index column's direction and nulls placement, or their exact reverse",
         %{generation: g} do
      for option <- [:asc, :asc_nulls_first, :desc, :desc_nulls_last], direction <- @directions do
        g = with_article_index(g, [{"status", :asc}, {"external_ref", option}])
        tree = [same_status: [order_by: [{direction, :external_ref}]]]
        sql = level_sql(g, @articles, tree, [["draft"]], "capped")

        same = descending?(direction) == descending?(option)
        served? = nulls_first?(direction) == (nulls_first?(option) == same)

        assert sql =~ "LATERAL" == served?,
               "#{direction} against an index column #{option}: #{sql}"
      end
    end

    test "never serves an enum key compared as text", %{generation: g} do
      g = with_article_index(g, [{"status", :asc}, {"id", :asc}], &%{&1 | type_schema: nil})
      sql = level_sql(g, @articles, [same_status: [order_by: [asc: :id]]], [["draft"]], "capped")

      assert sql =~ "::text"
      refute sql =~ "LATERAL"
    end

    test "every nulls variant loads the same rows laterally and windowed", %{generation: g} do
      Repo.query!("""
      insert into public.articles (id, org_id, author_id, status, is_published, title, external_ref)
      values (4, 1, 1, 'draft', false, 'four', '00000000-0000-0000-0000-000000000004'),
             (5, 1, 2, 'draft', false, 'five', null),
             (6, 2, 2, 'review', false, 'six', '00000000-0000-0000-0000-000000000006')
      """)

      windowed = with_article_index(g, [{"id", :asc}])

      for direction <- @directions, role <- ["capped", "user"] do
        lateral = with_article_index(g, [{"status", :asc}, {"external_ref", direction}])
        tree = [same_status: [columns: [:id], order_by: [{direction, :external_ref}]]]

        assert level_sql(lateral, @articles, tree, [["draft"]], "capped") =~ "LATERAL"

        assert load(lateral, @articles, tree, ["id", "status"], role) ==
                 load(windowed, @articles, tree, ["id", "status"], role)
      end
    end
  end

  describe "deduplicated parent keys" do
    setup %{test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
    end

    test "parents sharing a key send it once and each get the rows", %{generation: g} do
      {:ok, nodes} =
        Tree.validate([comments: [order_by: [asc: :id]]], @articles, session("user"), g, @limits)

      parents = [%{"id" => 1}, %{"id" => 2}, %{"id" => 1}, %{"id" => 1}]
      keys = Enum.map(parents, &[&1["id"]])

      assert {:ok, [one, two, again, third]} =
               Loader.load(nodes, parents, keys, Repo, Postgres)

      assert_received {:telemetry, @repo_query, %{params: [[1, 2]]}}
      assert ids(one["comments"]) == [11, 12, 13]
      assert ids(two["comments"]) == [21, 22, 23]
      assert again == one and third == one
    end

    test "an object relationship sends each distinct key once", %{generation: g} do
      assert {:ok, rows} = load(g, @comments, [:author], ["id", "author_id"])
      assert_received {:telemetry, @repo_query, %{params: [[1, 2, 3]]}}

      for %{"author_id" => author_id, "author" => author} <- rows,
          do: assert(%{"id" => ^author_id} = author)
    end
  end
end

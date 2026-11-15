defmodule Authzura.Integration.InputPushdownTest do
  @moduledoc """
  `input_index_pushdown`: top-level `_eq` / `_in` input comparisons on plain,
  leakproof columns also run outside the input fence, so Postgres can use an
  index. Rows never change; the fence stays; the option is off by default.
  """

  use Authzura.DataCase, async: true
  use ExUnitProperties

  import Authzura.SqlHelper
  import StreamData

  alias Authzura.Adapters.Postgres
  alias Authzura.{Get, HasuraFixture, Options, Store}
  alias Ecto.Adapters.SQL

  @probe {"public", "pushdown_probe"}
  @view {"public", "pushdown_probe_view"}
  @columns ~w(id org_id author_id small title flag day stamp ref amount tag status doubled vdoubled vc code f4 f8 ts label)
  @fence "CASE WHEN"

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @probe,
        select_permissions: [
          %{
            role: "org",
            permission: %{
              columns: @columns,
              filter: %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}
            }
          },
          %{
            role: "either",
            permission: %{
              columns: @columns,
              filter: %{
                "_or" => [
                  %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}},
                  %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}
                ]
              }
            }
          }
        ]
      },
      %{
        table: @view,
        select_permissions: [
          %{
            role: "org",
            permission: %{
              columns: ["id", "org_id", "author_id"],
              filter: %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}
            }
          }
        ]
      }
    ])
  end

  setup %{test: test} do
    Repo.query!("""
    INSERT INTO public.pushdown_probe
      (id, org_id, author_id, small, title, flag, day, stamp, ref, amount, tag, status,
       vc, code, f4, f8, ts, label)
    SELECT n, 1 + n % 3, 1 + n % 7, n % 5, 't' || n % 4, n % 2 = 0,
           DATE '2026-01-01' + n % 3, TIMESTAMPTZ '2026-01-01 00:00:00+00' + n * interval '1 hour',
           CASE WHEN n % 4 = 0 THEN NULL ELSE ('00000000-0000-0000-0000-00000000000' || n % 4)::uuid END,
           n % 6, 'c' || n % 3, (ARRAY['draft','review','published'])[1 + n % 3]::public.article_status,
           'v' || n % 4, ('c' || n % 3)::char(2), n % 5, (n % 5)::float8,
           TIMESTAMP '2026-01-01 00:00:00' + n * interval '1 hour', ('l' || n % 3)::name
    FROM generate_series(1, 60) AS n
    """)

    metadata = metadata()
    on = HasuraFixture.start_instance!(:"#{test}_on", Repo, metadata, input_index_pushdown: true)
    off = HasuraFixture.start_instance!(:"#{test}_off", Repo, metadata)
    %{on: on, off: off}
  end

  defp session(role \\ "org"),
    do: HasuraFixture.session!(role, %{"x-hasura-org-id" => "1", "x-hasura-user-id" => "2"})

  defp query!(instance, table, filter, extra \\ %{}, role \\ "org") do
    {:ok, query} =
      Authzura.scope_input(table, session(role), Map.put(extra, :filter, filter),
        instance: instance
      )

    query
  end

  # Rows or the refusal, so a null the input refuses is compared too. A unique
  # order gives list equality; without one the rows are compared as a set.
  defp result(instance, filter, role \\ "org", extra \\ %{}) do
    with {:ok, query} <-
           Authzura.scope_input("pushdown_probe", session(role), Map.put(extra, :filter, filter),
             instance: instance
           ),
         do: Repo.all(query)
  end

  defp sorted({:ok, rows}), do: {:ok, Enum.sort(rows)}
  defp sorted(other), do: other

  # The WHERE text before the input fence: the permission and anything hoisted.
  defp outside(sql), do: outside_fence(sql, where_only: true)

  # Comparisons of `column` in the SQL: the fenced one and a hoisted (pinned) one.
  defp compares(sql, column) do
    ~r/p0\."#{column}" (=|OPERATOR\(pg_catalog\.=\))/ |> Regex.scan(sql) |> length()
  end

  describe "the SQL" do
    test "is unchanged with the option off: one fenced copy of the input", %{off: off} do
      sql = sql(query!(off, "pushdown_probe", %{"id" => %{"_eq" => 5}}))

      assert occurrences(sql, @fence) == 1
      assert compares(sql, "id") == 1

      assert sql =~
               ~s|WHERE ((p0."org_id" = $1::bigint) AND CASE WHEN (p0."org_id" = $2::bigint) THEN (p0."id" = $3::bigint) ELSE false END)|
    end

    test "the default instance option is false" do
      refute Authzura.Options.instance!(repo: Repo).input_index_pushdown
    end

    test "with the option on, a top-level _eq or _in also sits outside the fence", %{on: on} do
      for filter <- [%{"id" => %{"_eq" => 5}}, %{"id" => %{"_in" => [5, 6]}}] do
        sql = sql(query!(on, "pushdown_probe", filter))
        assert occurrences(sql, @fence) == 1
        assert compares(sql, "id") == 2
        assert outside(sql) =~ ~s|p0."id" OPERATOR(pg_catalog.=)|
      end
    end

    test "implicit and explicit _and conjuncts all move; the fence keeps the whole input",
         %{on: on} do
      filter = %{
        "_and" => [%{"id" => %{"_eq" => 5}}, %{"_and" => [%{"author_id" => %{"_in" => [1, 2]}}]}],
        "title" => %{"_eq" => "t1"}
      }

      sql = sql(query!(on, "pushdown_probe", filter))
      assert occurrences(sql, @fence) == 1
      assert compares(sql, "id") == 2
      assert compares(sql, "author_id") == 2
      assert compares(sql, "title") == 2
    end

    test "_or, _not, other operators, patterns and null checks never move", %{on: on} do
      for filter <- [
            %{"_or" => [%{"id" => %{"_eq" => 5}}, %{"id" => %{"_eq" => 6}}]},
            %{"_not" => %{"id" => %{"_eq" => 5}}},
            %{"_not" => %{"_and" => [%{"id" => %{"_eq" => 5}}, %{"title" => %{"_eq" => "t1"}}]}},
            %{"id" => %{"_gt" => 5}},
            %{"id" => %{"_neq" => 5}},
            %{"id" => %{"_nin" => [5]}},
            %{"title" => %{"_like" => "t%"}},
            %{"title" => %{"_is_null" => false}}
          ] do
        sql = sql(query!(on, "pushdown_probe", filter))
        assert occurrences(sql, @fence) == 1
        refute outside(sql) =~ ~r/"(id|title)"/, inspect(filter)
      end
    end

    test "a conjunct beside an _or moves, the _or stays inside", %{on: on} do
      filter = %{
        "id" => %{"_eq" => 5},
        "_or" => [%{"title" => %{"_eq" => "t1"}}, %{"title" => %{"_eq" => "t2"}}]
      }

      sql = sql(query!(on, "pushdown_probe", filter))
      assert compares(sql, "id") == 2
      assert compares(sql, "title") == 2
    end

    test "columns whose equality is not leakproof, and generated columns, never move",
         %{on: on} do
      for {column, value} <- [
            {"amount", 1},
            {"tag", "c1"},
            {"status", "draft"},
            {"doubled", 4},
            {"vdoubled", 4}
          ] do
        sql = sql(query!(on, "pushdown_probe", %{column => %{"_eq" => value}}))
        refute outside(sql) =~ ~s|"#{column}"|, column
      end
    end

    test "a view never moves", %{on: on} do
      sql = sql(query!(on, "pushdown_probe_view", %{"id" => %{"_eq" => 5}}))
      assert compares(sql, "id") == 1
    end

    test "every plain column whose equality is leakproof moves, whatever its operand cast", %{
      on: on
    } do
      for {column, value} <- [
            {"id", 5},
            {"small", 1},
            {"title", "t1"},
            {"flag", true},
            {"day", "2026-01-02"},
            {"ref", "00000000-0000-0000-0000-000000000001"},
            {"vc", "v1"},
            {"code", "c1"},
            {"f4", 1.5},
            {"f8", 1.5},
            {"stamp", "2026-01-01T01:00:00Z"},
            {"ts", "2026-01-01T01:00:00"},
            {"label", "l1"}
          ] do
        sql = sql(query!(on, "pushdown_probe", %{column => %{"_eq" => value}}))
        assert outside(sql) =~ ~s|p0."#{column}" OPERATOR(pg_catalog.=)|, column
      end
    end
  end

  describe "rows" do
    test "null and empty operands give the rows the option off gives", %{on: on, off: off} do
      for filter <- [
            %{"ref" => %{"_in" => []}},
            %{"ref" => %{"_in" => [nil, "00000000-0000-0000-0000-000000000001"]}},
            %{"title" => %{"_in" => [nil, "t1"]}},
            %{"title" => %{"_in" => [nil]}},
            %{"day" => %{"_eq" => "2026-01-02"}},
            %{"small" => %{"_in" => [1, 2], "_eq" => 1}}
          ] do
        assert sorted(result(on, filter)) == sorted(result(off, filter)), inspect(filter)
      end
    end

    test "an explicit null _eq is refused the same way", %{on: on, off: off} do
      filter = %{"ref" => %{"_eq" => nil}}

      assert Authzura.scope_input("pushdown_probe", session(), %{filter: filter}, instance: on) ==
               Authzura.scope_input("pushdown_probe", session(), %{filter: filter}, instance: off)
    end

    property "on and off return the same rows, for random permissions and inputs",
             %{on: on, off: off} do
      check all(
              role <- member_of(["org", "either"]),
              filter <- filter(),
              max_runs: 200
            ) do
        ordered = %{order_by: [{"id", :asc}]}

        assert result(on, filter, role, ordered) == result(off, filter, role, ordered)
        assert sorted(result(on, filter, role)) == sorted(result(off, filter, role))
      end
    end
  end

  describe "the _in cap" do
    test "an _in of at most 100 values moves, a longer one stays fenced", %{on: on, off: off} do
      at_cap = %{"id" => %{"_in" => Enum.to_list(1..100)}}
      over_cap = %{"id" => %{"_in" => Enum.to_list(1..101)}}

      assert compares(sql(query!(on, "pushdown_probe", at_cap)), "id") == 2
      assert compares(sql(query!(on, "pushdown_probe", over_cap)), "id") == 1
      assert result(on, over_cap) == result(off, over_cap)
    end
  end

  describe "operators and relations the database owner changed" do
    defp hidden_row_permission do
      %{
        "columns" => "*",
        "filter" => %{
          "_or" => [
            %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}},
            %{"id" => %{"_eq" => -1}},
            %{"id" => %{"_eq" => -2}}
          ]
        }
      }
    end

    defp instances!(test, table) do
      metadata =
        HasuraFixture.metadata([
          %{
            table: {"public", table},
            select_permissions: [%{role: "org", permission: hidden_row_permission()}]
          }
        ])

      %{
        on:
          HasuraFixture.start_instance!(:"#{test}_x_on", Repo, metadata,
            input_index_pushdown: true
          ),
        off: HasuraFixture.start_instance!(:"#{test}_x_off", Repo, metadata)
      }
    end

    # Rows, or the database error: an error on a hidden row is an oracle.
    defp outcome(instance, table, filter) do
      {:ok, query} =
        Authzura.scope_input(table, session(), %{filter: filter}, instance: instance)

      {:rows, length(Repo.all(query))}
    rescue
      error in Postgrex.Error -> {:pg_error, error.postgres.message}
    end

    # The operator raises when it matches. With the hoisted copy ahead of an
    # expensive permission it would run on rows the role cannot see.
    defp raising_operator!(left, right, function) do
      Repo.query!("""
      CREATE FUNCTION public.#{function}(#{left}, #{right}) RETURNS boolean
        LANGUAGE plpgsql IMMUTABLE COST 1 AS $$
      BEGIN
        IF $1::text = $2::text THEN RAISE EXCEPTION '#{function} matched %', $1; END IF;
        RETURN false;
      END $$
      """)

      Repo.query!(
        "CREATE OPERATOR public.= (LEFTARG = #{left}, RIGHTARG = #{right}, FUNCTION = public.#{function})"
      )
    end

    test "an owner-defined =(text, varchar) never runs on a hidden row", %{test: test} do
      Repo.query!(
        "CREATE TABLE public.pd_text (id bigint PRIMARY KEY, org_id bigint NOT NULL, t text)"
      )

      Repo.query!("INSERT INTO public.pd_text VALUES (1, 1, 'mine'), (2, 2, 'hidden-secret')")
      raising_operator!("text", "varchar", "pd_text_eq")
      %{on: on, off: off} = instances!(test, "pd_text")

      for filter <- [
            %{"t" => %{"_eq" => "hidden-secret"}},
            %{"t" => %{"_in" => ["hidden-secret"]}},
            %{"t" => %{"_eq" => "absent"}}
          ] do
        assert outcome(on, "pd_text", filter) == {:rows, 0}, inspect(filter)
        assert outcome(off, "pd_text", filter) == {:rows, 0}, inspect(filter)
      end
    end

    test "an operator declared on a domain never runs on a hidden row, and domains stay fenced",
         %{test: test} do
      Repo.query!("CREATE DOMAIN public.pd_acct AS int4")

      Repo.query!(
        "CREATE TABLE public.pd_dom (id bigint PRIMARY KEY, org_id bigint NOT NULL, a public.pd_acct)"
      )

      Repo.query!("INSERT INTO public.pd_dom VALUES (1, 1, 10), (2, 2, 777)")
      raising_operator!("public.pd_acct", "bigint", "pd_acct_eq")
      raising_operator!("public.pd_acct", "public.pd_acct", "pd_acct_eq2")
      %{on: on, off: off} = instances!(test, "pd_dom")

      for filter <- [%{"a" => %{"_eq" => 777}}, %{"a" => %{"_in" => [777]}}] do
        assert outcome(on, "pd_dom", filter) == {:rows, 0}, inspect(filter)
        assert outcome(off, "pd_dom", filter) == {:rows, 0}, inspect(filter)
        refute outside(sql(query!(on, "pd_dom", filter))) =~ ~s|"a"|
      end
    end

    test "get/4 pins its key equality, so an owner-defined operator on a domain key never runs on a hidden row",
         %{test: test} do
      Repo.query!("CREATE DOMAIN public.pd_key AS int4")

      Repo.query!(
        "CREATE TABLE public.pd_get (id public.pd_key PRIMARY KEY, org_id bigint NOT NULL)"
      )

      Repo.query!("INSERT INTO public.pd_get VALUES (10, 1), (777, 2)")
      raising_operator!("public.pd_key", "bigint", "pd_key_eq")
      %{off: instance} = instances!(test, "pd_get")
      {:ok, generation} = Store.current(instance)
      opts = Options.call!(instance: instance)

      {:ok, %{query: query}} = Get.build("pd_get", session(), 777, generation, opts)

      assert Repo.all(query) == []
      assert sql(query) =~ "OPERATOR(pg_catalog.=)"
    end

    test "get/4 qualifies a citext key's equality, so an = earlier on the search_path never runs on a hidden row",
         %{test: test} do
      Repo.query!("CREATE SCHEMA pd_evil")
      Repo.query!("CREATE TABLE public.pd_cget (id citext PRIMARY KEY, org_id bigint NOT NULL)")
      Repo.query!("INSERT INTO public.pd_cget VALUES ('mine', 1), ('hidden-secret', 2)")

      Repo.query!("""
      CREATE FUNCTION pd_evil.ci_eq(public.citext, public.citext) RETURNS boolean
        LANGUAGE plpgsql IMMUTABLE COST 1 AS $$
      BEGIN
        IF $1::text = $2::text THEN RAISE EXCEPTION 'ci_eq matched %', $1; END IF;
        RETURN false;
      END $$
      """)

      Repo.query!(
        "CREATE OPERATOR pd_evil.= (LEFTARG = public.citext, RIGHTARG = public.citext, FUNCTION = pd_evil.ci_eq)"
      )

      permission = %{
        "columns" => "*",
        "filter" => %{
          "_or" => [
            %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}},
            %{"org_id" => %{"_eq" => -1}},
            %{"org_id" => %{"_eq" => -2}}
          ]
        }
      }

      metadata =
        HasuraFixture.metadata([
          %{
            table: {"public", "pd_cget"},
            select_permissions: [%{role: "org", permission: permission}]
          }
        ])

      instance = HasuraFixture.start_instance!(:"#{test}_x", Repo, metadata)
      {:ok, generation} = Store.current(instance)
      opts = Options.call!(instance: instance)

      {:ok, %{query: query}} = Get.build("pd_cget", session(), "hidden-secret", generation, opts)

      Repo.query!("SET LOCAL search_path = pd_evil, public")

      assert Repo.all(query) == []
      assert sql(query) =~ ~S|OPERATOR("public".=)|
    end

    test "a table swapped for a view changes the fingerprint" do
      Repo.query!("CREATE TABLE public.pd_swap (id bigint, org_id bigint, score bigint)")
      refs = [{"public", "pd_swap"}]
      {:ok, before_swap} = Postgres.fingerprint(Repo, refs)

      Repo.query!("ALTER TABLE public.pd_swap RENAME TO pd_swap_raw")

      Repo.query!(
        "CREATE VIEW public.pd_swap AS SELECT id, org_id, score FROM public.pd_swap_raw"
      )

      assert {:ok, after_swap} = Postgres.fingerprint(Repo, refs)
      assert after_swap != before_swap
    end
  end

  describe "which columns are pushable" do
    test "exactly the plain stored columns whose pg_catalog equality is leakproof" do
      {:ok, tables, _fks} =
        Postgres.introspect(Repo, [@probe, @view])

      pushable = fn ref ->
        table = tables[ref]

        table.columns
        |> Enum.filter(fn {_name, column} ->
          Postgres.index_pushdown?(table, column)
        end)
        |> Enum.map(&elem(&1, 0))
        |> Enum.sort()
      end

      assert pushable.(@probe) ==
               Enum.sort(
                 ~w(id org_id author_id small title flag day stamp ref vc code f4 f8 ts label)
               )

      assert pushable.(@view) == []
    end
  end

  describe "indexes" do
    defp plan(query) do
      {sql, params} = SQL.to_sql(:all, Repo, query)
      %{rows: rows} = Repo.query!("EXPLAIN " <> sql, params)
      rows |> List.flatten() |> Enum.join("\n")
    end

    setup do
      Repo.query!("ANALYZE public.pushdown_probe")
      Repo.query!("SET LOCAL enable_seqscan = off")
      :ok
    end

    test "an id _eq uses the primary key and an author_id _in its index when on", %{on: on} do
      assert plan(query!(on, "pushdown_probe", %{"id" => %{"_eq" => 5}})) =~
               "pushdown_probe_pkey"

      assert plan(query!(on, "pushdown_probe", %{"author_id" => %{"_in" => [1, 2]}})) =~
               "pushdown_probe_author_id_idx"

      assert plan(query!(on, "pushdown_probe", %{"author_id" => %{"_eq" => 1}}, %{}, "either")) =~
               "pushdown_probe_author_id_idx"
    end

    test "varchar, uuid, timestamptz and timestamp comparisons use their indexes when on", %{
      on: on
    } do
      for {column, value, index} <- [
            {"vc", "v1", "pushdown_probe_vc_idx"},
            {"ref", "00000000-0000-0000-0000-000000000001", "pushdown_probe_ref_idx"},
            {"stamp", "2026-01-01T05:00:00Z", "pushdown_probe_stamp_idx"}
          ] do
        assert plan(query!(on, "pushdown_probe", %{column => %{"_eq" => value}})) =~ index, column

        assert plan(query!(on, "pushdown_probe", %{column => %{"_in" => [value]}})) =~ index,
               column
      end
    end

    test "neither does when off", %{off: off} do
      refute plan(query!(off, "pushdown_probe", %{"id" => %{"_eq" => 5}})) =~
               "pushdown_probe_pkey"

      refute plan(query!(off, "pushdown_probe", %{"author_id" => %{"_eq" => 1}})) =~
               "pushdown_probe_author_id_idx"
    end
  end

  defp filter do
    column =
      member_of([
        {"id", integer(1..70)},
        {"org_id", integer(1..4)},
        {"author_id", integer(1..8)},
        {"small", integer(0..5)},
        {"title", member_of(~w(t0 t1 t2 t3 zz))},
        {"flag", boolean()},
        {"ref",
         member_of([
           "00000000-0000-0000-0000-000000000001",
           "00000000-0000-0000-0000-000000000002"
         ])},
        {"amount", integer(0..6)},
        {"vc", member_of(~w(v0 v1 v2 v3 zz))},
        {"code", member_of(~w(c0 c1 c2))},
        {"f8", member_of([0.0, 1.0, 2.0, 4.5])},
        {"f4", member_of([0.0, 1.0, 2.0])},
        {"day", member_of(["2026-01-01", "2026-01-02", "2026-02-01"])},
        {"stamp", member_of(["2026-01-01T01:00:00Z", "2026-01-01T05:00:00Z"])},
        {"ts", member_of(["2026-01-01T01:00:00", "2026-01-01T02:00:00"])},
        {"label", member_of(~w(l0 l1 l9))},
        {"status", member_of(~w(draft review published))}
      ])

    comparison =
      bind(column, fn {name, present} ->
        values = one_of([present, present, present, constant(nil)])

        bind(member_of(["_eq", "_in", "_gt", "_neq", "_nin"]), fn
          op when op in ["_in", "_nin"] ->
            map(list_of(values, max_length: 3), &%{name => %{op => &1}})

          op ->
            map(values, &%{name => %{op => &1}})
        end)
      end)

    tree(comparison, fn child ->
      one_of([
        map(list_of(child, min_length: 1, max_length: 3), &%{"_and" => &1}),
        map(list_of(child, min_length: 1, max_length: 3), &%{"_or" => &1}),
        map(child, &%{"_not" => &1}),
        map({child, child}, fn {a, b} -> Map.merge(a, b) end)
      ])
    end)
  end
end

defmodule Authzura.Integration.InputHardeningTest do
  @moduledoc """
  Regression tests for the input boundary: out-of-range array elements,
  schema disclosure through filter errors, and caps on list-valued input.
  """

  use Authzura.CommittedCase, async: false

  alias Authzura.HasuraFixture

  @articles {"public", "articles"}
  @users {"public", "users"}
  @key_kinds {"public", "key_kinds"}
  @memberships {"public", "org_memberships"}

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title", "author_id"], filter: %{}}}
        ]
      },
      %{
        table: @users,
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "email"], filter: %{}}}
        ]
      },
      %{
        table: @key_kinds,
        select_permissions: [%{role: "user", permission: %{columns: "*", filter: %{}}}]
      },
      %{
        table: @memberships,
        select_permissions: [
          %{role: "user", permission: %{columns: "*", filter: %{}}},
          %{
            role: "levels",
            permission: %{columns: "*", filter: %{"level" => %{"_in" => "X-Hasura-Levels"}}}
          }
        ]
      }
    ])
  end

  setup %{test: test} do
    Repo.query!("insert into public.organizations values (1, 'one')")

    Repo.query!(
      "insert into public.users (id, org_id, email, role, salary) values (1, 1, 'a@x.com', 'editor', 100)"
    )

    Repo.query!("insert into public.key_kinds (id, code, rank) values (1, 'a', 7)")
    Repo.query!("insert into public.org_memberships values (1, 1, 5)")
    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp user, do: HasuraFixture.session!("user")

  defp all_input(table, input, instance),
    do: Authzura.all_input(table, user(), input, instance: instance)

  defp filter(table, filter, instance), do: all_input(table, %{"filter" => filter}, instance)

  defp invalid_value(path, type),
    do: {:error, {:invalid_input, [{path, {:invalid_literal, {:invalid_value, type}}}]}}

  describe "array elements out of the column's range" do
    test "are invalid for every integer and float width, never raised", %{instance: i} do
      cases = [
        {"key_kinds", "rank", "int2", [32_767, -32_768], [32_768, -32_769]},
        {"org_memberships", "level", "int4", [2_147_483_647, -2_147_483_648],
         [2_147_483_648, -2_147_483_649]},
        {"key_kinds", "id", "int8", [9_223_372_036_854_775_807],
         [9_223_372_036_854_775_808, -9_223_372_036_854_775_809]},
        {"key_kinds", "ratio", "float4", [3.4e38, -3.4e38, 1.0e-40], [3.5e38, -1.0e39, 1.0e-50]}
      ]

      for {table, column, type, edges, outside} <- cases,
          op <- ["_in", "_nin"] do
        assert {:ok, _rows} = filter(table, %{column => %{op => edges}}, i)

        for value <- outside do
          assert filter(table, %{column => %{op => [1, value]}}, i) ==
                   invalid_value([column, op], type),
                 inspect({column, op, value})
        end
      end
    end

    test "in a session array are an invalid session value", %{instance: i} do
      session = HasuraFixture.session!("levels", %{"x-hasura-levels" => "{5,2147483648}"})

      assert {:error, {:invalid_session_value, "x-hasura-levels", _reason}} =
               Authzura.all("org_memberships", session, instance: i)

      session = HasuraFixture.session!("levels", %{"x-hasura-levels" => "{5,2147483647}"})
      assert {:ok, [%{"level" => 5}]} = Authzura.all("org_memberships", session, instance: i)
    end
  end

  describe "hidden and unknown names" do
    test "are the same forbidden_columns error, whatever the operator or literal",
         %{instance: i} do
      for {name, ops} <- [
            {"salary", %{"_eq" => 1}},
            {"salry", %{"_eq" => 1}},
            {"role", %{"_eq" => 1}},
            {"is_admin", %{"_like" => "x"}},
            {"is_admin", %{"_bogus" => "x"}},
            {"manager_id", %{"_eq" => "not a number"}},
            {"nope", 1}
          ] do
        assert filter("users", %{name => ops}, i) == {:error, {:forbidden_columns, [name]}},
               name
      end
    end

    test "a hidden enum column reveals none of its labels", %{instance: i} do
      for label <- ["draft", "bogus"] do
        assert filter("articles", %{"status" => %{"_eq" => label}}, i) ==
                 {:error, {:forbidden_columns, ["status"]}}
      end
    end

    test "hidden names are reported with forbidden columns from the rest of the request",
         %{instance: i} do
      input = %{
        "columns" => ["id", "role"],
        "filter" => %{"salary" => %{"_gt" => "x"}, "nope" => 1}
      }

      assert all_input("users", input, i) ==
               {:error, {:forbidden_columns, ["role", "nope", "salary"]}}
    end

    test "a relationship-shaped key is relationship_in_input whether or not it exists",
         %{instance: i} do
      for name <- ["author", "writer"] do
        assert filter("articles", %{name => %{"id" => %{"_eq" => 1}}}, i) ==
                 {:error, {:invalid_input, [{[name], :relationship_in_input}]}},
               name
      end
    end

    # An empty object is the shape of a relationship with no condition, so
    # a relationship, a hidden column and a name that does not exist all
    # read the same. A visible column's `{}` is Hasura's "no condition".
    test "an empty object is relationship_in_input unless it names a visible column",
         %{instance: i} do
      for name <- ["author", "writer", "status"] do
        assert filter("articles", %{name => %{}}, i) ==
                 {:error, {:invalid_input, [{[name], :relationship_in_input}]}},
               name
      end

      assert {:ok, _rows} = filter("articles", %{"title" => %{}}, i)
    end
  end

  describe "caps on list-valued input" do
    test "an _in or _nin list holds at most 10_000 elements", %{instance: i} do
      for op <- ["_in", "_nin"] do
        assert {:ok, _rows} = filter("users", %{"id" => %{op => Enum.to_list(1..10_000)}}, i)

        assert filter("users", %{"id" => %{op => Enum.to_list(1..10_001)}}, i) ==
                 {:error, {:invalid_input, {:too_many, :list}}}
      end
    end

    test "columns hold at most as many distinct names as the role can see",
         %{instance: i} do
      # The role sees 2 of the table's columns ("id", "email"), so the cap
      # says nothing about how many columns the table has.
      repeated = List.duplicate("id", 100)
      assert {:ok, [%{"id" => 1}]} = all_input("users", %{"columns" => repeated}, i)

      assert all_input("users", %{"columns" => ["c1", "c2"]}, i) ==
               {:error, {:forbidden_columns, ["c1", "c2"]}}

      for n <- [3, 100] do
        assert all_input("users", %{"columns" => Enum.map(1..n, &"c#{&1}")}, i) ==
                 {:error, {:invalid_input, {:too_many, :columns}}}
      end
    end

    test "a filter holds at most 16 pattern operands", %{instance: i} do
      patterns = fn n, op ->
        %{"_and" => List.duplicate(%{"email" => %{op => "a"}}, n)}
      end

      for op <- ["_like", "_nilike", "_regex", "_nsimilar"] do
        assert {:ok, _rows} = filter("users", patterns.(16, op), i)

        assert filter("users", patterns.(17, op), i) ==
                 {:error, {:invalid_input, {:too_many, :patterns}}},
               op
      end

      mixed = %{
        "_or" =>
          List.duplicate(%{"email" => %{"_regex" => "a"}}, 9) ++
            List.duplicate(%{"email" => %{"_ilike" => "a"}}, 8)
      }

      assert filter("users", mixed, i) == {:error, {:invalid_input, {:too_many, :patterns}}}
    end

    # A backreference is what makes Postgres's regex matcher exponential: nine
    # of them hold a connection for the whole timeout on one 500-byte row.
    test "a regular expression may not hold a backreference", %{instance: i} do
      for op <- ["_regex", "_iregex", "_nregex", "_niregex"],
          pattern <- ["(a)\\1", "\\9", "x(.*)\\1y", "\\\\\\1"] do
        assert filter("users", %{"email" => %{op => pattern}}, i) ==
                 {:error, {:invalid_input, [{["email", op], {:invalid_literal, :backreference}}]}},
               "#{op} #{pattern}"
      end

      for pattern <- ["\\\\1", "a\\.1", "[0-9]\\d", "\\0"] do
        refute match?(
                 {:error, {:invalid_input, [{_path, {:invalid_literal, :backreference}}]}},
                 filter("users", %{"email" => %{"_regex" => pattern}}, i)
               ),
               pattern
      end

      # LIKE has no backreferences.
      assert {:ok, _rows} = filter("users", %{"email" => %{"_like" => "\\1"}}, i)
    end

    # SIMILAR TO does: `\"...\"` makes a capturing group, and `\1` passes
    # through to the regular expression Postgres builds from it. This
    # 31-byte pattern runs past 10 s on a 500-character row.
    test "a SIMILAR TO pattern may not hold a backreference either", %{instance: i} do
      pattern = ~S(\"%\"%\1%\1%\1%\1%\1%\1%\1%\1x%)

      for op <- ["_similar", "_nsimilar"] do
        assert filter("users", %{"email" => %{op => pattern}}, i) ==
                 {:error, {:invalid_input, [{["email", op], {:invalid_literal, :backreference}}]}},
               op
      end

      assert {:ok, _rows} = filter("users", %{"email" => %{"_similar" => ~S(%\\1%)}}, i)
    end

    test "pool-size concurrent backreference requests do not starve other reads",
         %{instance: i} do
      body = String.duplicate("x", 200) <> " " <> String.duplicate("word ", 60) <> "!"
      Repo.query!("update public.users set email = $1", [body])
      pattern = "(.*)(.*)(.*)(.*)(.*)(.*)(.*)(.*)(.*)\\1\\2\\3\\4\\5\\6\\7\\8\\9x"
      request = %{"columns" => ["id"], "filter" => %{"email" => %{"_regex" => pattern}}}

      attackers =
        for _n <- 1..10,
            do: Task.async(fn -> all_input("users", request, i) end)

      # The victim checks out a pool connection of its own, as any other
      # process would.
      victim =
        Task.async(fn ->
          Authzura.all("users", user(), instance: i, columns: ["id"], repo_opts: [timeout: 1_000])
        end)

      assert {:ok, [%{"id" => 1}]} = Task.await(victim, 5_000)

      for result <- Task.await_many(attackers, 5_000) do
        assert {:error, {:invalid_input, [{_path, {:invalid_literal, :backreference}}]}} = result
      end
    end

    test "order_by holds at most 32 terms", %{instance: i} do
      terms = Enum.map(1..33, &%{"c#{&1}" => "asc"})

      assert all_input("users", %{"order_by" => terms}, i) ==
               {:error, {:invalid_input, {:too_many, :order_by}}}
    end

    test "a preload's order_by holds at most 32 terms", %{instance: i} do
      ok = %{"author" => %{"order_by" => List.duplicate(%{"id" => "asc"}, 32)}}
      assert {:ok, _rows} = all_input("articles", %{"preload" => ok}, i)

      over = %{"author" => %{"order_by" => List.duplicate(%{"id" => "asc"}, 33)}}

      assert all_input("articles", %{"preload" => over}, i) ==
               {:error, {:invalid_input, {:too_many, :preload_order_by}}}
    end
  end

  # Every distinct request shape is a distinct SQL text. Cached, each would
  # stay in Ecto's per-repo query cache and as a named prepared statement on
  # every pool connection until a restart.
  describe "request shapes" do
    defp shapes do
      columns = [["id"], ["id", "title"], ["title", "author_id"], ["id", "title", "author_id"]]
      ops = ["_eq", "_neq", "_gt", "_lt", "_gte"]
      orders = [%{"id" => "asc"}, %{"title" => "desc_nulls_last"}, %{"author_id" => "desc"}]

      for cols <- columns, op <- ops, order <- orders do
        %{"columns" => cols, "filter" => %{"id" => %{op => 1}}, "order_by" => [order]}
      end
    end

    defp cache_size do
      %{cache: cache} = Ecto.Repo.Registry.lookup(Repo)
      :ets.info(cache, :size)
    end

    defp prepared, do: Repo.query!("select count(*) from pg_prepared_statements").rows

    test "untrusted shapes add nothing to the statement caches", %{instance: i} do
      preload = %{"author" => %{"columns" => ["id"]}}

      {:ok, {before, later}} =
        Repo.transaction(fn ->
          before = {cache_size(), prepared()}

          for shape <- shapes() do
            assert {:ok, _rows} = all_input("articles", shape, i)
          end

          {before, {cache_size(), prepared()}}
        end)

      assert later == before

      size = cache_size()

      for shape <- Enum.take(shapes(), 10) do
        assert {:ok, _rows} = all_input("articles", Map.put(shape, "preload", preload), i)
      end

      assert cache_size() == size
    end
  end

  # The pattern pre-check also sets a transaction-local statement_timeout
  # (`input_pattern_timeout`), so a pattern read cannot hold a connection
  # for the repo's whole timeout.
  describe "input_pattern_timeout" do
    setup %{test: test} do
      Repo.query!("""
      insert into public.articles (id, org_id, author_id, status, is_published, title, assignees)
      select g, 1, 1, 'draft', false, repeat('ab', 300), '{}' from generate_series(1, 50000) g
      """)

      %{
        timed:
          HasuraFixture.start_instance!(:"#{test} timed", Repo, metadata(),
            input_pattern_timeout: 1
          )
      }
    end

    test "bounds a read that carries a pattern", %{timed: timed, instance: i} do
      request = %{"columns" => ["id"], "filter" => %{"title" => %{"_regex" => "(a|b)*c"}}}

      assert all_input("articles", request, timed) ==
               {:error, {:invalid_input, :statement_timeout}}

      assert {:ok, []} = all_input("articles", request, i)
    end

    # A stricter statement_timeout the database already applies is kept:
    # the option may lower the bound, never raise it. The read takes about
    # 50 ms here, so a 20 ms session timeout must cancel it.
    test "never raises a shorter database statement_timeout", %{instance: i} do
      request = %{"columns" => ["id"], "filter" => %{"title" => %{"_regex" => "(a|b)*c"}}}

      {elapsed, result} =
        Repo.checkout(fn ->
          Repo.query!("SET statement_timeout = 20")

          try do
            :timer.tc(fn -> all_input("articles", request, i) end, :millisecond)
          after
            Repo.query!("RESET statement_timeout")
          end
        end)

      assert result == {:error, {:invalid_input, :statement_timeout}}
      assert elapsed < 1_000, "ran #{elapsed} ms under a 20 ms statement_timeout"
    end

    test "leaves reads without patterns alone", %{timed: timed} do
      request = %{"columns" => ["id"], "filter" => %{"title" => %{"_neq" => "x"}}}
      assert {:ok, rows} = all_input("articles", request, timed)
      assert Enum.count(rows) == 50_000
    end

    test "is not set in a caller's transaction", %{timed: timed} do
      request = %{"columns" => ["id"], "filter" => %{"title" => %{"_regex" => "^x"}}}

      assert {:ok, {{:ok, []}, [[before]], [[after_read]]}} =
               Repo.transaction(fn ->
                 %{rows: before} = Repo.query!("show statement_timeout")
                 result = all_input("articles", request, timed)
                 %{rows: after_read} = Repo.query!("show statement_timeout")
                 {result, before, after_read}
               end)

      assert after_read == before
    end
  end
end

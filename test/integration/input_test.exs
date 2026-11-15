defmodule Authzura.InputFixture do
  @moduledoc false

  alias Authzura.{HasuraFixture, Store, TestSource}

  @articles {"public", "articles"}
  @users {"public", "users"}

  @doc "Metadata shared by the input tests."
  def metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: [
          %{
            role: "user",
            permission: %{
              columns: ["id", "org_id", "author_id", "editor_id", "title", "assignees"],
              filter: %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}},
              limit: 3
            }
          },
          %{
            role: "noroot",
            permission: %{columns: ["id"], filter: %{}, query_root_fields: []}
          },
          %{
            role: "editor",
            permission: %{
              columns: ["id", "editor_id", "title"],
              filter: %{"editor_id" => %{"_eq" => "X-Hasura-User-Id"}}
            }
          }
        ]
      },
      %{
        table: @users,
        select_permissions: [
          %{
            role: "user",
            permission: %{
              columns: ["id", "org_id", "email"],
              filter: %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}
            }
          }
        ]
      }
    ])
  end

  @doc "Inserts the rows through `repo`."
  def seed!(repo) do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one'), (2, 'two')",
        """
        insert into public.users (id, org_id, email, role, salary) values
          (1, 1, 'a@x.com', 'editor', 100), (2, 1, 'b@x.com', 'viewer', 200),
          (3, 2, 'c@x.com', 'viewer', 300)
        """,
        """
        insert into public.articles
          (id, org_id, author_id, editor_id, status, is_published, title, internal_notes, assignees)
        values
          (1, 1, 1, 3, 'draft', false, 'one', 'n1', '{}'),
          (2, 1, 1, null, 'draft', false, 'X-Hasura-User-Id', null, '{"who": "X-Hasura-User-Id"}'),
          (3, 1, 2, 2, 'draft', false, 'x-hasura-user-id', null, '{"who": "1"}'),
          (4, 2, 3, 1, 'draft', false, 'secret-two', 'hidden', '{}'),
          (5, 1, 1, 3, 'draft', false, '1', null, '{}')
        """
      ],
      &repo.query!/1
    )
  end

  @doc "The `user` role in org 1, as user 1."
  def user,
    do: HasuraFixture.session!("user", %{"x-hasura-org-id" => "1", "x-hasura-user-id" => "1"})

  @doc "Makes the instance's TestSource return `ast` from `parse_input/2`."
  def fix_input!(instance, ast) do
    {:ok, %{config: %{source: {TestSource, opts}}}} = Store.current(instance)
    TestSource.put(Keyword.fetch!(opts, :agent), input: ast)
  end
end

defmodule Authzura.Integration.InputTest do
  use Authzura.DataCase, async: true

  import Authzura.InputFixture
  import Authzura.SqlHelper

  alias Authzura.{HasuraFixture, InputFixture}
  alias Authzura.Test.Schemas.{Article, User}

  setup %{test: test} do
    seed!(Repo)
    %{instance: HasuraFixture.start_instance!(test, Repo, InputFixture.metadata())}
  end

  defp scope(queryable, input, instance, session \\ user()),
    do: Authzura.scope_input(queryable, session, input, instance: instance)

  defp rows!(queryable, input, instance, session \\ user()) do
    {:ok, query} = scope(queryable, input, instance, session)
    Repo.all(query)
  end

  defp ids(queryable, input, instance, session \\ user()),
    do: queryable |> rows!(input, instance, session) |> Enum.map(& &1.id) |> Enum.sort()

  defp nested_not(0), do: %{"id" => %{"_eq" => 1}}
  defp nested_not(n), do: %{"_not" => nested_not(n - 1)}

  defp wide_and(n), do: %{"_and" => List.duplicate(%{"id" => %{"_eq" => 1}}, n)}

  describe "hidden columns" do
    test "filtering, sorting or selecting on a hidden column is forbidden", %{instance: i} do
      assert scope(User, %{filter: %{"salary" => %{"_gt" => 150}}}, i) ==
               {:error, {:forbidden_columns, ["salary"]}}

      assert scope(User, %{order_by: [{"salary", :desc}]}, i) ==
               {:error, {:forbidden_columns, ["salary"]}}

      assert scope(User, %{columns: ["id", "salary"]}, i) ==
               {:error, {:forbidden_columns, ["salary"]}}

      assert scope("users", %{filter: %{"salary" => 100}}, i) ==
               {:error, {:forbidden_columns, ["salary"]}}
    end

    test "every forbidden column is reported once", %{instance: i} do
      input = %{
        columns: ["id", "body"],
        filter: %{"internal_notes" => %{"_eq" => "n1"}, "body" => %{"_is_null" => true}},
        order_by: [{"status", :asc}]
      }

      assert scope(Article, input, i) ==
               {:error, {:forbidden_columns, ["body", "internal_notes", "status"]}}
    end
  end

  describe "session-looking literals" do
    test "stay literals in every casing, in _in lists and in _contains JSON", %{instance: i} do
      assert ids(Article, %{filter: %{"title" => %{"_eq" => "X-Hasura-User-Id"}}}, i) == [2]
      assert ids(Article, %{filter: %{"title" => %{"_eq" => "x-hasura-user-id"}}}, i) == [3]
      assert ids(Article, %{filter: %{"title" => "X-HASURA-USER-ID"}}, i) == []

      assert ids(
               Article,
               %{filter: %{"title" => %{"_in" => ["X-Hasura-User-Id", "x-hasura-user-id"]}}},
               i
             ) == [2, 3]

      assert ids(
               Article,
               %{filter: %{"assignees" => %{"_contains" => %{"who" => "X-Hasura-User-Id"}}}},
               i
             ) == [2]
    end
  end

  describe "rejected filters" do
    test "an explicit null operand is invalid", %{instance: i} do
      assert {:error, {:invalid_input, [{["editor_id", "_eq"], :null_operand}]}} =
               scope(Article, %{filter: %{"editor_id" => %{"_eq" => nil}}}, i)
    end

    test "relationships and _exists are invalid", %{instance: i} do
      assert {:error, {:invalid_input, [{["author"], :relationship_in_input}]}} =
               scope(Article, %{filter: %{"author" => %{"id" => %{"_eq" => 1}}}}, i)

      exists = %{"_exists" => %{"_table" => "users", "_where" => %{"id" => %{"_eq" => 3}}}}

      assert {:error, {:invalid_input, [{["_exists"], :relationship_in_input}]}} =
               scope(Article, %{filter: exists}, i)
    end

    test "unknown fields, operators and uncastable literals are invalid", %{instance: i} do
      # A name the role cannot see is a forbidden column, whether or not it
      # exists.
      assert {:error, {:forbidden_columns, ["nope"]}} =
               scope(Article, %{filter: %{"nope" => 1}}, i)

      assert {:error, {:invalid_input, [{["id", "_bogus"], {:unknown_operator, "_bogus"}}]}} =
               scope(Article, %{filter: %{"id" => %{"_bogus" => 1}}}, i)

      assert {:error, {:invalid_input, [{["id", "_eq"], {:invalid_literal, _}}]}} =
               scope(Article, %{filter: %{"id" => %{"_eq" => "abc"}}}, i)
    end
  end

  describe "probes" do
    test "a value that exists only in rows the role cannot see returns nothing", %{instance: i} do
      assert ids(Article, %{filter: %{"title" => %{"_eq" => "secret-two"}}}, i) == []
      assert ids(Article, %{filter: %{"org_id" => %{"_eq" => 2}}}, i) == []
      assert ids(User, %{filter: %{"email" => %{"_eq" => "c@x.com"}}}, i) == []
    end

    test "negative control: the same probes on permitted rows return them", %{instance: i} do
      assert ids(Article, %{filter: %{"title" => %{"_eq" => "one"}}}, i) == [1]

      assert ids(
               Article,
               %{filter: %{"org_id" => %{"_eq" => 1}}, order_by: [{"id", :asc}], limit: 10},
               i
             ) == [1, 2, 3]

      assert ids(User, %{filter: %{"email" => %{"_eq" => "b@x.com"}}}, i) == [2]
    end
  end

  describe "null modes" do
    test "the permission gates the plain input comparison", %{instance: i} do
      editor = HasuraFixture.session!("editor", %{"x-hasura-user-id" => "3"})
      {:ok, query} = scope(Article, %{filter: %{"editor_id" => %{"_eq" => 3}}}, i, editor)
      sql = sql(query)

      # The input comparison is plain. The permission compares a session
      # value, never NULL, so it is plain too, and it gates the input.
      permission = fn a -> ~s[(a0."editor_id" = $#{a}::bigint)] end

      assert sql =~
               ~s[WHERE (#{permission.(1)} AND ] <>
                 ~s[CASE WHEN #{permission.(2)} THEN (a0."editor_id" = $3::bigint) ELSE false END)]

      assert query |> Repo.all() |> Enum.map(& &1.id) |> Enum.sort() == [1, 5]

      assert ids(Article, %{filter: %{"editor_id" => %{"_neq" => 3}}}, i, editor) == []
    end
  end

  describe "limits" do
    test "101 nodes are too large, 100 are not", %{instance: i} do
      assert {:error, {:invalid_input, errors}} = scope(Article, %{filter: wide_and(100)}, i)
      assert Enum.any?(errors, &match?({_path, :too_large}, &1))
      assert {:ok, _query} = scope(Article, %{filter: wide_and(99)}, i)
    end

    test "9 levels are too deep, 8 are not", %{instance: i} do
      assert {:error, {:invalid_input, errors}} = scope(Article, %{filter: nested_not(8)}, i)
      assert Enum.any?(errors, &match?({_path, :too_deep}, &1))
      assert ids(Article, %{filter: nested_not(7)}, i) == [2, 3, 5]
    end
  end

  describe "source-neutral" do
    test "the filter is parsed by the instance's source", %{instance: i} do
      fix_input!(i, {:compare, "id", :eq, {:literal, 2}})
      assert ids(Article, %{filter: "not a bool_exp"}, i) == [2]
    end

    test "a source AST is still checked", %{instance: i} do
      fix_input!(i, {:compare, "internal_notes", :eq, {:literal, "n1"}})

      assert scope(Article, %{filter: %{}}, i) ==
               {:error, {:forbidden_columns, ["internal_notes"]}}

      fix_input!(i, {:compare, "title", :eq, {:session, "x-hasura-user-id"}})

      assert scope(Article, %{filter: %{}}, i) ==
               {:error, {:invalid_input, [{[], :session_reference}]}}

      fix_input!(i, {:relationship, "author", {:compare, "id", :eq, {:literal, 1}}})

      assert scope(Article, %{filter: %{}}, i) ==
               {:error, {:invalid_input, [{[], :relationship_in_input}]}}

      fix_input!(
        i,
        Enum.reduce(1..8, {:compare, "id", :eq, {:literal, 1}}, fn _n, ast -> {:not, ast} end)
      )

      assert scope(Article, %{filter: %{}}, i) == {:error, {:invalid_input, [{[], :too_deep}]}}
    end
  end

  describe "request shape" do
    test "only a bare schema or table is a root", %{instance: i} do
      assert scope(from(a in Article, where: a.id > 0), %{}, i) ==
               {:error, {:invalid_input, :not_a_root}}

      assert scope(Enum, %{}, i) == {:error, {:invalid_input, :not_a_root}}
      assert scope({"articles", Article}, %{}, i) == {:error, {:invalid_input, :not_a_root}}
    end

    test "string keys and string directions are accepted", %{instance: i} do
      input = %{
        "columns" => ["id", "title"],
        "filter" => %{"author_id" => %{"_eq" => 1}},
        "order_by" => [%{"id" => "desc"}],
        "limit" => nil
      }

      assert rows!(Article, input, i) == [
               %{id: 5, title: "1"},
               %{id: 2, title: "X-Hasura-User-Id"},
               %{id: 1, title: "one"}
             ]
    end

    test "columns map back to fields, or stay strings for tables", %{instance: i} do
      assert [%{"id" => 1, "title" => "one"}] =
               rows!("articles", %{columns: ["id", "title"], filter: %{"id" => 1}}, i)

      assert [%{id: 1, title: "one"}] =
               rows!(Article, %{columns: ["id", "title"], filter: %{"id" => 1}}, i)
    end

    test "order_by, limit and offset apply under the permission cap", %{instance: i} do
      input = %{order_by: [{"author_id", :desc}, {"id", :asc_nulls_last}], offset: 1, limit: 2}
      {:ok, query} = scope(Article, input, i)

      assert sql(query) =~
               ~s(ORDER BY a0."author_id" DESC, a0."id" ASC NULLS LAST LIMIT $2 OFFSET $3)

      assert query |> Repo.all() |> Enum.map(& &1.id) == [1, 2]

      # The permission caps the limit at 3.
      assert ids(Article, %{order_by: [{"id", :asc}], limit: 100}, i) == [1, 2, 3]
    end

    test "malformed requests are invalid", %{instance: i} do
      for {input, reason} <- [
            {[], :not_a_map},
            {"filter", :not_a_map},
            {%{where: %{}}, {:unknown_keys, [:where]}},
            {%{"filter" => %{}, filter: %{}}, {:duplicate_key, :filter}},
            {%{columns: []}, {:columns, :empty}},
            {%{columns: [:id]}, {:columns, :invalid}},
            {%{columns: "id"}, {:columns, :invalid}},
            {%{order_by: [{"id", :up}]}, {:order_by, :invalid}},
            {%{order_by: [{"id", "DESC"}]}, {:order_by, :invalid}},
            {%{order_by: [{:id, :asc}]}, {:order_by, :invalid}},
            {%{order_by: [%{"id" => "asc", "title" => "asc"}]}, {:order_by, :invalid}},
            {%{order_by: [{"id", :asc}, %{"id" => "desc"}]}, {:order_by, :duplicate_column}},
            {%{order_by: %{"id" => "asc"}}, {:order_by, :invalid}},
            {%{limit: -1}, :limit},
            {%{limit: "5"}, :limit},
            {%{limit: 1.0}, :limit},
            {%{limit: 9_223_372_036_854_775_808}, :limit},
            {%{offset: -1}, :offset}
          ] do
        assert scope(Article, input, i) == {:error, {:invalid_input, reason}}, inspect(input)
      end
    end

    test "preloads are executor-only", %{instance: i} do
      assert scope(Article, %{preload: ["author"]}, i) ==
               {:error, {:unsupported_query, :preload_requires_execute}}
    end

    test "access is checked as in scope/3", %{instance: i} do
      assert scope(Article, %{}, i, HasuraFixture.session!("nobody")) == {:error, :forbidden}
    end
  end

  describe "root fields" do
    test "a disabled root field is reported before columns or the filter", %{instance: i} do
      noroot = HasuraFixture.session!("noroot")

      assert scope(Article, %{filter: %{"internal_notes" => %{"_eq" => "n1"}}}, i, noroot) ==
               {:error, :root_field_disabled}

      assert scope(Article, %{filter: %{"id" => %{"_eq" => nil}}}, i, noroot) ==
               {:error, :root_field_disabled}
    end
  end

  describe "patterns" do
    test "a LIKE pattern ending in an unescaped backslash is invalid", %{instance: i} do
      for op <- ["_like", "_nlike", "_ilike", "_nilike"] do
        assert scope(Article, %{filter: %{"title" => %{op => "one\\"}}}, i) ==
                 {:error,
                  {:invalid_input, [{["title", op], {:invalid_literal, :trailing_escape}}]}}
      end

      assert ids(Article, %{filter: %{"title" => %{"_like" => "on\\e"}}}, i) == [1]
      assert ids(Article, %{filter: %{"title" => %{"_like" => "one\\\\"}}}, i) == []
    end

    test "a pattern longer than 1024 bytes is invalid", %{instance: i} do
      long = String.duplicate("a", 1025)

      for op <- ["_like", "_similar", "_regex", "_niregex"] do
        assert scope(Article, %{filter: %{"title" => %{op => long}}}, i) ==
                 {:error,
                  {:invalid_input, [{["title", op], {:invalid_literal, :pattern_too_long}}]}}
      end

      assert {:ok, _query} =
               scope(
                 Article,
                 %{filter: %{"title" => %{"_regex" => String.duplicate("a", 1024)}}},
                 i
               )
    end
  end

  describe "unorderable columns" do
    setup %{test: test} do
      Repo.query!(
        "create table public.input_docs (id bigint primary key, doc json, spot point, " <>
          "docs json[], spots point[], tags text[])"
      )

      Repo.query!(
        ~s|insert into public.input_docs values (1, '{"a": 1}', '(1,2)', | <>
          ~s|array['{"a": 1}'::json], array['(1,2)'::point], '{a}')|
      )

      metadata =
        HasuraFixture.metadata([
          %{
            table: {"public", "input_docs"},
            select_permissions: [
              %{role: "user", permission: %{columns: "*", filter: %{}}}
            ]
          }
        ])

      %{docs: HasuraFixture.start_instance!(:"#{test} docs", Repo, metadata)}
    end

    # `spot` is an `:other` column, which loads with a warning diagnostic.
    @tag :capture_log
    test "sorting on json or an unknown type is invalid", %{docs: d} do
      for column <- ["doc", "spot"] do
        assert scope("input_docs", %{order_by: [{column, :asc}]}, d) ==
                 {:error, {:invalid_input, {:order_by, :unorderable}}}
      end

      assert [%{"id" => 1}] = rows!("input_docs", %{columns: ["id"], order_by: [{"id", :asc}]}, d)
    end

    # Postgres has no ordering operator for `point[]` or `json[]`
    # (42883); an array is orderable only when its element is.
    @tag :capture_log
    test "sorting on an array of an unorderable type is invalid", %{docs: d} do
      for column <- ["docs", "spots"] do
        assert scope("input_docs", %{order_by: [{column, :asc}]}, d) ==
                 {:error, {:invalid_input, {:order_by, :unorderable}}}

        assert Authzura.all_input(
                 "input_docs",
                 HasuraFixture.session!("user"),
                 %{"columns" => ["id"], "order_by" => [%{column => "asc"}]},
                 instance: d
               ) == {:error, {:invalid_input, {:order_by, :unorderable}}}
      end

      assert [%{"id" => 1}] =
               rows!("input_docs", %{columns: ["id"], order_by: [{"tags", :asc}]}, d)
    end
  end

  describe "never raises" do
    test "hostile JSON-decoded terms return an error or a runnable query", %{instance: i} do
      hostile = [
        [1],
        "x",
        nil,
        true,
        %{"id" => %{"_eq" => 92_233_720_368_547_758_070}},
        %{"id" => %{"_in" => "1"}},
        %{"id" => %{"_in" => [1, "a", nil]}},
        %{"id" => %{"_gt" => 1.5}},
        %{"title" => %{"_like" => %{}}},
        %{"title" => %{"_regex" => ["a"]}},
        %{"title" => %{"_is_null" => "yes"}},
        %{"assignees" => %{"_has_key" => 1}},
        %{"assignees" => %{"_contains" => "not json object"}},
        %{"assignees" => %{"_jsonb_path_exists" => "$$$"}},
        %{"_and" => "x"},
        %{"_or" => [1, [], %{}]},
        %{"_not" => []},
        %{"" => 1},
        %{"x-hasura-role" => "admin"},
        %{"_eq" => 1},
        %{"id" => %{"_eq" => %{"_eq" => 1}}},
        %{"id" => %{"_cast" => %{"String" => %{"_eq" => "1"}}}},
        %{"id" => %{"_ceq" => "author_id"}},
        %{"_and" => List.duplicate(%{"_or" => List.duplicate(%{"id" => 1}, 50)}, 50)}
      ]

      for filter <- hostile do
        case scope(Article, %{filter: filter, order_by: [{"id", "asc"}]}, i) do
          {:ok, query} -> assert is_list(Repo.all(query)), inspect(filter)
          {:error, {kind, _detail}} -> assert kind in [:invalid_input, :forbidden_columns]
        end
      end
    end
  end
end

defmodule Authzura.Integration.AllInputTest do
  use Authzura.CommittedCase, async: false

  import Authzura.InputFixture

  alias Authzura.{HasuraFixture, InputFixture, TelemetryHelper}
  alias Authzura.Test.Schemas.{Article, User}

  setup %{test: test} do
    seed!(Repo)
    %{instance: HasuraFixture.start_instance!(test, Repo, InputFixture.metadata())}
  end

  test "patterns only the database can judge are rejected, not raised", %{instance: i} do
    for {op, pattern} <- [{"_regex", "("}, {"_iregex", "a{2,1}"}, {"_similar", "("}] do
      input = %{filter: %{"title" => %{op => pattern}}}

      assert {op, Authzura.all_input(Article, user(), input, instance: i)} ==
               {op, {:error, {:invalid_input, {:invalid_pattern, "title"}}}}

      assert {op, Authzura.scope_input(Article, user(), input, instance: i)} ==
               {op, {:error, {:invalid_input, {:invalid_pattern, "title"}}}}
    end
  end

  test "the first refused pattern is named, and valid ones pass", %{instance: i} do
    input = %{
      filter: %{
        "_and" => [
          %{"title" => %{"_regex" => "^o"}},
          %{"title" => %{"_nsimilar" => "x%"}},
          %{"assignees" => %{"_has_key" => "who"}},
          %{"title" => %{"_niregex" => "[z-a]"}}
        ]
      }
    }

    assert Authzura.all_input(Article, user(), input, instance: i) ==
             {:error, {:invalid_input, {:invalid_pattern, "title"}}}

    valid = put_in(input, [:filter, "_and", Access.at(3)], %{"title" => %{"_niregex" => "z"}})
    assert {:ok, []} = Authzura.all_input(Article, user(), valid, instance: i)
  end

  test "a refused pattern does not abort a caller's transaction", %{instance: i} do
    input = %{filter: %{"title" => %{"_regex" => "("}}}

    assert {:ok, :still_usable} =
             Repo.transaction(fn ->
               assert Authzura.all_input(Article, user(), input, instance: i) ==
                        {:error, {:invalid_input, {:invalid_pattern, "title"}}}

               assert %{rows: [[1]]} = Repo.query!("SELECT 1")
               :still_usable
             end)
  end

  test "input denials emit the execute span", %{instance: i, test: test} do
    TelemetryHelper.forward!(test, [[:authzura, :execute, :stop]], instance: i)

    Authzura.all_input(User, user(), %{order_by: [{"salary", :asc}]}, instance: i)

    assert_receive {:telemetry, [:authzura, :execute, :stop],
                    %{
                      instance: ^i,
                      mode: :all,
                      result: :denied,
                      reason_class: :forbidden_columns
                    }}

    Authzura.all_input(Article, user(), %{filter: %{"id" => 1}}, instance: i)

    assert_receive {:telemetry, [:authzura, :execute, :stop], %{instance: ^i, result: :granted}}
  end

  test "all_input/4 runs the scoped input", %{instance: i} do
    input = %{
      columns: ["id", "title"],
      filter: %{"title" => %{"_in" => ["X-Hasura-User-Id", "secret-two", "one"]}},
      order_by: [{"id", :desc}]
    }

    assert Authzura.all_input(Article, user(), input, instance: i) ==
             {:ok, [%{id: 2, title: "X-Hasura-User-Id"}, %{id: 1, title: "one"}]}
  end

  test "all_input/4 rejects hidden columns and invalid input", %{instance: i} do
    assert Authzura.all_input(User, user(), %{filter: %{"salary" => %{"_gte" => 0}}}, instance: i) ==
             {:error, {:forbidden_columns, ["salary"]}}

    assert {:error, {:invalid_input, _errors}} =
             Authzura.all_input(Article, user(), %{filter: %{"id" => %{"_eq" => nil}}},
               instance: i
             )
  end
end

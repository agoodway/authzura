defmodule Authzura.Integration.RowFilterTest do
  @moduledoc """
  Compiled permission filters run against seeded fixture rows. Expected IDs
  follow the SQL Hasura v2 emits for the same `bool_exp`
  (`Hasura.Backends.Postgres.Translate.BoolExp`).
  """

  use Authzura.DataCase, async: true

  alias Authzura.FilterFixture

  @articles {"public", "articles"}
  @users {"public", "users"}
  @comments {"public", "comments"}
  @notes {"public", "membership_notes"}
  @order {"public", "Order"}
  @view {"public", "published_articles"}

  setup do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one'), (2, 'two')",
        """
        insert into public.users (id, org_id, manager_id, email, role, is_admin) values
          (1, 1, null, 'a@x.com', 'editor', false),
          (2, 1, 1, 'b@x.com', 'viewer', false),
          (3, 2, null, 'c@x.com', 'admin', true)
        """,
        """
        insert into public.articles
          (id, org_id, author_id, editor_id, status, is_published, title, internal_notes, assignees)
        values
          (1, 1, 1, null, 'draft', false, 'Alpha', null, '{"1": true}'),
          (2, 1, 1, 2, 'published', true, 'beta', 'x', '{"2": true, "3": true}'),
          (3, 1, 2, null, 'review', false, 'Gamma', 'y', '{}'),
          (4, 2, 3, 3, 'published', true, 'delta', null, '{"1": true, "3": true}')
        """,
        "insert into public.comments values (1, 1, 1, 'a'), (2, 1, 2, 'b'), (3, 2, 1, 'b'), (4, 4, 3, 'c')",
        "insert into public.org_memberships values (1, 1, 5), (1, 2, 7)",
        "insert into public.membership_notes values (1, 1, 1, 'n1'), (2, 1, 2, 'n2'), (3, null, null, 'orphan')",
        ~s|insert into public."Order" ("Id", "line item") values (1, 'widget'), (2, 'gadget'), (3, null)|,
        "insert into public.key_kinds (id, code, rank, meta) values (1, 'a', 1, null), (2, 'b', 2, '{}'), (3, 'c', 3, 'null')",
        "insert into audit.users values (5, 'audited')",
        "insert into audit.article_events values (1, 1, 'edit')"
      ],
      &Repo.query!/1
    )

    %{tables: FilterFixture.tables(Repo)}
  end

  defp ids(tables, ref, json, vars \\ %{"x-hasura-user-id" => "1"}, opts \\ []) do
    pk = Keyword.get(opts, :pk, "id")
    session = FilterFixture.session(vars)
    {:ok, dynamic} = FilterFixture.compile(tables, ref, json, session)

    ref
    |> FilterFixture.scoped(dynamic, pk)
    |> then(Keyword.get(opts, :caller, & &1))
    |> Repo.all()
    |> Enum.sort()
  end

  defp me(id), do: %{"x-hasura-user-id" => Integer.to_string(id)}

  describe "row filters" do
    test "an author-only filter returns that author's articles", %{tables: t} do
      assert ids(t, @articles, %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}) == [1, 2]
      assert ids(t, @articles, %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}, me(3)) == [4]
    end

    test "_or with a caller where returns only my unpublished articles", %{tables: t} do
      filter = %{
        "_or" => [%{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}, %{"is_published" => true}]
      }

      caller = &where(&1, [a], field(a, :is_published) == false)
      assert ids(t, @articles, filter, me(1), caller: caller) == [1]
    end

    test "an empty filter returns every row", %{tables: t} do
      assert ids(t, @articles, %{}) == [1, 2, 3, 4]
    end
  end

  describe "empty forms" do
    test "_in and _nin with no values", %{tables: t} do
      assert ids(t, @articles, %{"id" => %{"_in" => []}}) == []
      assert ids(t, @articles, %{"_not" => %{"id" => %{"_in" => []}}}) == [1, 2, 3, 4]
      assert ids(t, @articles, %{"id" => %{"_nin" => []}}) == [1, 2, 3, 4]
    end

    test "_or, _and and _not with nothing inside", %{tables: t} do
      assert ids(t, @articles, %{"_or" => []}) == []
      assert ids(t, @articles, %{"_and" => []}) == [1, 2, 3, 4]
      assert ids(t, @articles, %{"_not" => %{}}) == []
    end
  end

  describe "dates and timestamps" do
    setup do
      Repo.query!("""
      update public.key_kinds set
        born_on = (date '2026-01-01' + id::int),
        seen_at = (timestamp '2026-01-01 10:00:00' + make_interval(hours => id::int))
      """)

      Repo.query!(
        "update public.articles set published_at = timestamptz '2026-01-01 00:00:00+00' + make_interval(days => id::int)"
      )

      :ok
    end

    @kinds {"public", "key_kinds"}

    test "date columns filter and compare, from literals and session values", %{tables: t} do
      assert ids(t, @kinds, %{"born_on" => %{"_eq" => "2026-01-02"}}) == [1]
      assert ids(t, @kinds, %{"born_on" => %{"_gt" => "2026-01-02"}}) == [2, 3]
      assert ids(t, @kinds, %{"born_on" => %{"_in" => ["2026-01-02", "2026-01-04"]}}) == [1, 3]

      assert ids(t, @kinds, %{"born_on" => %{"_lte" => "X-Hasura-Day"}}, %{
               "x-hasura-day" => "2026-01-03"
             }) == [1, 2]
    end

    test "_in on date and timestamp columns with session arrays", %{tables: t} do
      assert ids(t, @kinds, %{"born_on" => %{"_in" => "X-Hasura-Days"}}, %{
               "x-hasura-days" => "{2026-01-02,2026-01-04}"
             }) == [1, 3]

      assert ids(t, @kinds, %{"seen_at" => %{"_in" => "X-Hasura-Seen"}}, %{
               "x-hasura-seen" => ~s({"2026-01-01 11:00:00","2026-01-01T13:00:00"})
             }) == [1, 3]

      assert ids(t, @kinds, %{"born_on" => %{"_nin" => "X-Hasura-Days"}}, %{
               "x-hasura-days" => "{2026-01-02}"
             }) == [2, 3]
    end

    test "timestamp columns take ISO, space-separated and date-only forms", %{tables: t} do
      assert ids(t, @kinds, %{"seen_at" => %{"_eq" => "2026-01-01 12:00:00"}}) == [2]
      assert ids(t, @kinds, %{"seen_at" => %{"_eq" => "2026-01-01T12:00:00"}}) == [2]
      assert ids(t, @kinds, %{"seen_at" => %{"_gt" => "2026-01-01"}}) == [1, 2, 3]
      assert ids(t, @kinds, %{"seen_at" => %{"_lt" => "2026-01-01 11:30:00.5"}}) == [1]
    end

    test "timestamptz takes Postgres's forms with an offset", %{tables: t} do
      for form <- ["2026-01-03T00:00:00Z", "2026-01-03 02:00:00+02:00"] do
        assert ids(t, @articles, %{"published_at" => %{"_eq" => form}}) == [2], form
      end

      assert ids(t, @articles, %{"published_at" => %{"_gte" => "X-Hasura-Since"}}, %{
               "x-hasura-since" => "2026-01-04 00:00:00+00"
             }) == [3, 4]
    end

    # What Hasura returns: it sends the text, and Postgres reads it in the
    # session's TimeZone (UTC on the test database).
    @tag :hasura_divergence
    @tag skip:
           "Hasura divergence (intended): an offset-less timestamptz in a permission " <>
             "or session value is denied, since its TimeZone is the database session's"
    test "Hasura reads an offset-less timestamptz in the session TimeZone", %{tables: t} do
      assert ids(t, @articles, %{"published_at" => %{"_eq" => "2026-01-03 00:00:00"}}) == [2]
    end

    # Postgres reads an offset-less timestamptz in its session TimeZone,
    # which Authzura cannot know, so policy text without one is refused: the
    # permission at load, a session value at request time.
    test "policy timestamptz without an offset is refused", %{tables: t} do
      for form <- ["2026-01-03", "2026-01-03 00:00:00", "2026-01-03T00:00:00"] do
        assert {:error,
                [{["published_at", "_lt"], {:invalid_literal, {:invalid_value, "timestamptz"}}}]} =
                 FilterFixture.parse(t, @articles, %{"published_at" => %{"_lt" => form}}),
               form
      end

      session = FilterFixture.session(%{"x-hasura-since" => "2026-01-04 00:00:00"})

      assert {:error, {:invalid_session_value, "x-hasura-since", {:invalid_value, "timestamptz"}}} =
               FilterFixture.compile(
                 t,
                 @articles,
                 %{"published_at" => %{"_gte" => "X-Hasura-Since"}},
                 session
               )
    end
  end

  # Hasura types each operand as the column (`r <> ('0.1')::real`); a float8
  # parameter would widen the column instead, and 0.1::real is not 0.1.
  describe "real columns" do
    setup do
      Repo.query!("update public.key_kinds set ratio = (array[0.1, 0.7, 5])[id]")
      :ok
    end

    @kinds {"public", "key_kinds"}

    test "comparisons bind the operand as real, from literals and session values", %{tables: t} do
      for {op, value, expected} <- [
            {"_eq", 0.1, [1]},
            {"_neq", 0.1, [2, 3]},
            {"_gt", 0.1, [2, 3]},
            {"_gte", 0.7, [2, 3]},
            {"_lt", 0.7, [1]},
            {"_lte", 0.1, [1]},
            {"_in", [0.1], [1]}
          ] do
        assert ids(t, @kinds, %{"ratio" => %{op => value}}) == expected, op
      end

      assert ids(t, @kinds, %{"ratio" => %{"_neq" => "X-Hasura-V"}}, %{"x-hasura-v" => "0.1"}) ==
               [2, 3]

      assert ids(t, @kinds, %{"ratio" => %{"_lt" => "X-Hasura-V"}}, %{"x-hasura-v" => "0.7"}) ==
               [1]
    end

    test "a session value beyond the column's range denies the request", %{tables: t} do
      for {column, raw} <- [{"ratio", "1e300"}, {"rank", "40000"}] do
        session = FilterFixture.session(%{"x-hasura-v" => raw})

        assert {:error, {:invalid_session_value, "x-hasura-v", {:invalid_value, _type}}} =
                 FilterFixture.compile(t, @kinds, %{column => %{"_lt" => "X-Hasura-V"}}, session)
      end
    end
  end

  describe "NULL handling" do
    test "a literal null operand matches NULL rows", %{tables: t} do
      assert ids(t, @articles, %{"editor_id" => %{"_eq" => nil}}) == [1, 3]
    end

    test "null-aware _eq and _neq on a nullable column", %{tables: t} do
      assert ids(t, @articles, %{"editor_id" => %{"_eq" => "X-Hasura-User-Id"}}, me(2)) == [2]
      assert ids(t, @articles, %{"editor_id" => %{"_neq" => "X-Hasura-User-Id"}}, me(2)) == [4]
    end

    test "_not over a nullable _eq excludes NULL rows, as Hasura's form does", %{tables: t} do
      assert ids(t, @articles, %{"_not" => %{"internal_notes" => %{"_eq" => "x"}}}) == [3]
    end

    test "a json column cannot appear in a permission filter, not even with _is_null",
         %{tables: t} do
      # Hasura v2 rejects such metadata as inconsistent (see the parity suite).
      for value <- [true, false] do
        assert {:error, [{["meta"], {:unsupported, :json_column}}]} =
                 FilterFixture.parse(t, {"public", "key_kinds"}, %{
                   "meta" => %{"_is_null" => value}
                 })
      end
    end

    # Session comparisons compile to plain `=` / `<>`; with a value that is
    # never NULL they keep the null-aware form's results, negated too.
    test "session _eq and _neq on a nullable column match the null-aware form", %{tables: t} do
      for {op, session_ids, literal_ids} <- [
            {"_eq", [2], [2]},
            {"_neq", [4], [4]}
          ] do
        assert ids(t, @articles, %{"editor_id" => %{op => "X-Hasura-User-Id"}}, me(2)) ==
                 session_ids

        assert ids(t, @articles, %{"editor_id" => %{op => 2}}, me(2)) == literal_ids

        assert ids(
                 t,
                 @articles,
                 %{"_not" => %{"editor_id" => %{op => "X-Hasura-User-Id"}}},
                 me(2)
               ) ==
                 ids(t, @articles, %{"_not" => %{"editor_id" => %{op => 2}}}, me(2))
      end

      assert ids(
               t,
               @articles,
               %{"_not" => %{"editor_id" => %{"_eq" => "X-Hasura-User-Id"}}},
               me(2)
             ) ==
               [4]
    end

    test "_is_null true and false", %{tables: t} do
      assert ids(t, @articles, %{"editor_id" => %{"_is_null" => true}}) == [1, 3]
      assert ids(t, @articles, %{"editor_id" => %{"_is_null" => false}}) == [2, 4]
    end
  end

  describe "relationships" do
    test "object relationship articles.author filtered on users.org_id", %{tables: t} do
      assert ids(t, @articles, %{"author" => %{"org_id" => %{"_eq" => 1}}}) == [1, 2, 3]
    end

    test "array relationship users.articles", %{tables: t} do
      assert ids(t, @users, %{"articles" => %{"is_published" => %{"_eq" => true}}}) == [1, 3]
    end

    test "three hops comments.article.author.org", %{tables: t} do
      filter = %{"article" => %{"author" => %{"org" => %{"name" => %{"_eq" => "one"}}}}}
      assert ids(t, @comments, filter) == [1, 2, 3]
    end

    test "conditions in one node must hold on the same related row", %{tables: t} do
      same = %{"comments" => %{"author_id" => %{"_eq" => 1}, "body" => %{"_eq" => "b"}}}
      assert ids(t, @articles, same) == [2]

      siblings = %{
        "_and" => [
          %{"comments" => %{"author_id" => %{"_eq" => 1}}},
          %{"comments" => %{"body" => %{"_eq" => "b"}}}
        ]
      }

      assert ids(t, @articles, siblings) == [1, 2]
    end

    test "an empty relationship filter requires a related row, and _not inverts it", %{
      tables: t
    } do
      assert ids(t, @articles, %{"comments" => %{}}) == [1, 2, 4]
      assert ids(t, @articles, %{"_not" => %{"comments" => %{}}}) == [3]
    end

    test "multi-column membership_notes.membership", %{tables: t} do
      assert ids(t, @notes, %{"membership" => %{"level" => %{"_eq" => 7}}}) == [2]
      assert ids(t, @notes, %{"membership" => %{}}) == [1, 2]
    end

    test "self relationship users.manager", %{tables: t} do
      assert ids(t, @users, %{"manager" => %{"is_admin" => %{"_eq" => false}}}) == [2]
    end

    test "a target the role cannot read still filters (its permission is not applied)", %{
      tables: t
    } do
      assert ids(t, @articles, %{"events" => %{"kind" => %{"_eq" => "edit"}}}) == [1]
    end
  end

  describe "_exists" do
    @is_admin %{
      "_exists" => %{
        "_table" => %{"schema" => "public", "name" => "users"},
        "_where" => %{"id" => %{"_eq" => "X-Hasura-User-Id"}, "is_admin" => %{"_eq" => true}}
      }
    }

    test "the is-admin pattern: none for a non-admin, every row for an admin", %{tables: t} do
      assert ids(t, @articles, @is_admin, me(1)) == []
      assert ids(t, @articles, @is_admin, me(3)) == [1, 2, 3, 4]
    end

    test "against the root's own table with a session variable", %{tables: t} do
      filter = %{
        "author_id" => %{"_eq" => "X-Hasura-User-Id"},
        "_exists" => %{
          "_table" => "articles",
          "_where" => %{
            "is_published" => %{"_eq" => true},
            "author_id" => %{"_eq" => "X-Hasura-User-Id"}
          }
        }
      }

      assert ids(t, @articles, filter, me(1)) == [1, 2]
      assert ids(t, @articles, filter, me(2)) == []
    end

    test "inside _or and _not", %{tables: t} do
      either = %{"_or" => [%{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}, @is_admin]}
      assert ids(t, @articles, either, me(2)) == [3]
      assert ids(t, @articles, either, me(3)) == [1, 2, 3, 4]

      audited = fn id ->
        %{
          "_not" => %{
            "_exists" => %{
              "_table" => %{"schema" => "audit", "name" => "users"},
              "_where" => %{"id" => %{"_eq" => id}}
            }
          }
        }
      end

      assert ids(t, @articles, audited.(5)) == []
      assert ids(t, @articles, audited.(6)) == [1, 2, 3, 4]
    end

    test "public.users and audit.users never cross", %{tables: t} do
      exists = fn schema ->
        %{
          "_exists" => %{
            "_table" => %{"schema" => schema, "name" => "users"},
            "_where" => %{"id" => %{"_eq" => 5}}
          }
        }
      end

      assert ids(t, @articles, exists.("audit")) == [1, 2, 3, 4]
      assert ids(t, @articles, exists.("public")) == []
    end
  end

  describe "operators" do
    test "comparisons", %{tables: t} do
      assert ids(t, @articles, %{"id" => %{"_gt" => 1}}) == [2, 3, 4]
      assert ids(t, @articles, %{"id" => %{"_lt" => 3}}) == [1, 2]
      assert ids(t, @articles, %{"id" => %{"_gte" => 3}}) == [3, 4]
      assert ids(t, @articles, %{"id" => %{"_lte" => 1}}) == [1]
      assert ids(t, @articles, %{"id" => %{"_neq" => 2}}) == [1, 3, 4]
      assert ids(t, @articles, %{"id" => %{"_in" => [1, 4]}}) == [1, 4]
      assert ids(t, @articles, %{"id" => %{"_nin" => [1, 4]}}) == [2, 3]
      assert ids(t, @articles, %{"status" => %{"_gt" => "draft"}}) == [2, 3, 4]
    end

    test "pattern families", %{tables: t} do
      title = &ids(t, @articles, %{"title" => &1}, &2)
      vars = %{"x-hasura-user-id" => "1", "x-hasura-pattern" => "^GAM"}

      assert title.(%{"_like" => "A%"}, vars) == [1]
      assert title.(%{"_nlike" => "A%"}, vars) == [2, 3, 4]
      assert title.(%{"_ilike" => "a%"}, vars) == [1]
      assert title.(%{"_nilike" => "a%"}, vars) == [2, 3, 4]
      assert title.(%{"_similar" => "(Alpha|beta)"}, vars) == [1, 2]
      assert title.(%{"_nsimilar" => "(Alpha|beta)"}, vars) == [3, 4]
      assert title.(%{"_regex" => "^[A-Z]"}, vars) == [1, 3]
      assert title.(%{"_nregex" => "^[A-Z]"}, vars) == [2, 4]
      assert title.(%{"_iregex" => "X-Hasura-Pattern"}, vars) == [3]
      assert title.(%{"_niregex" => "X-Hasura-Pattern"}, vars) == [1, 2, 4]
    end

    test "jsonb operators", %{tables: t} do
      assignees = &ids(t, @articles, %{"assignees" => &1}, &2)

      assert assignees.(%{"_contains" => %{"1" => true}}, me(1)) == [1, 4]
      assert assignees.(%{"_contained_in" => %{"1" => true, "3" => true}}, me(1)) == [1, 3, 4]
      assert assignees.(%{"_has_key" => "X-Hasura-User-Id"}, me(3)) == [2, 4]
      assert assignees.(%{"_has_keys_any" => []}, me(1)) == []
      assert assignees.(%{"_has_keys_any" => ["2", "1"]}, me(1)) == [1, 2, 4]
      assert assignees.(%{"_has_keys_all" => ["1", "3"]}, me(1)) == [4]
    end
  end

  describe "quoting, schemas and views" do
    test ~s("Order" filters on "line item"), %{tables: t} do
      order = &ids(t, @order, %{"line item" => &1}, me(1), pk: "Id")
      assert order.(%{"_eq" => "widget"}) == [1]
      assert order.(%{"_neq" => "widget"}) == [2]
    end

    test "a view filters with null-aware forms and a manual relationship", %{tables: t} do
      assert ids(t, @view, %{"author_id" => %{"_eq" => "X-Hasura-User-Id"}}) == [2]
      assert ids(t, @view, %{"author" => %{"org_id" => %{"_eq" => 2}}}) == [4]
    end
  end
end

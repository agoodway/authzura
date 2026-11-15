defmodule Authzura.Adapters.PostgresTest do
  use Authzura.DataCase, async: true

  import Authzura.SqlHelper

  alias Authzura.Adapters.Postgres
  alias Authzura.Model.Column
  alias Ecto.Adapters.SQL

  doctest Postgres

  @root :__authzura_0
  @uuid "11111111-1111-1111-1111-111111111111"

  setup do
    Enum.each(
      [
        "insert into public.organizations values (1, 'o')",
        """
        insert into public.users (id, org_id, email, role, is_admin, salary)
        values (1, 1, 'A@x.com', 'editor', true, 10.5), (2, 1, 'b@x.com', 'viewer', false, null)
        """,
        """
        insert into public.articles
          (id, org_id, author_id, status, is_published, title, body, assignees, external_ref, published_at)
        values
          (1, 1, 1, 'draft', false, 'Alpha one', 'x', '{"7": true, "8": true}', '#{@uuid}', '2026-01-01T00:00:00Z'),
          (2, 1, 2, 'published', true, 'beta two', null, '{"9": true}', null, '2026-02-01T00:00:00Z'),
          (3, 1, 2, 'review', false, 'gamma', 'y', '{}', null, null)
        """,
        "insert into public.key_kinds values (1, 'alpha', 2, 'a', 1.5), (2, 'beta', 3, 'bb', null)"
      ],
      &Repo.query!/1
    )

    refs = [{"public", "articles"}, {"public", "users"}, {"public", "key_kinds"}]
    {:ok, tables, _fks} = Postgres.introspect(Repo, refs)
    %{tables: Map.new(tables, fn {{_schema, name}, table} -> {name, table.columns} end)}
  end

  # Casts `operand` for the operator's right side, compiles it, and returns the
  # matching ids together with the SQL.
  defp run(tables, table, column_name, op, operand, mode \\ :permission) do
    column = tables[table][column_name]
    {:ok, %{rhs: rhs}} = Postgres.operator_signature(op)
    {:ok, value} = Postgres.cast_value(operand, rhs, column)
    lhs = dynamic(field(as(^@root), ^column_name))
    condition = Postgres.compile_operator(op, lhs, value, column, mode)
    {ids(table, condition), sql(table, condition)}
  end

  defp query(table, condition),
    do: from(t in table, prefix: "public", as: ^@root, where: ^condition, select: field(t, ^"id"))

  defp ids(table, condition), do: table |> query(condition) |> Repo.all() |> Enum.sort()

  defp sql(table, condition), do: table |> query(condition) |> sql()

  defp negated(tables, table, column_name, op, operand, mode \\ :permission) do
    column = tables[table][column_name]
    {:ok, %{rhs: rhs}} = Postgres.operator_signature(op)
    {:ok, value} = Postgres.cast_value(operand, rhs, column)
    lhs = dynamic(field(as(^@root), ^column_name))
    condition = Postgres.compile_operator(op, lhs, value, column, mode)
    ids(table, dynamic(not (^condition)))
  end

  # The EXPLAIN output of the query `run/6` would execute.
  defp explain(tables, table, column_name, op, operand) do
    column = tables[table][column_name]
    {:ok, %{rhs: rhs}} = Postgres.operator_signature(op)
    {:ok, value} = Postgres.cast_value(operand, rhs, column)
    lhs = dynamic(field(as(^@root), ^column_name))
    condition = Postgres.compile_operator(op, lhs, value, column, :permission)
    {sql, params} = SQL.to_sql(:all, Repo, query(table, condition))
    %{rows: rows} = Repo.query!("EXPLAIN " <> sql, params)
    Enum.map_join(rows, "\n", &hd/1)
  end

  describe "operator_signature/1" do
    test "follows the signature table" do
      assert Postgres.operator_signature(:eq) == {:ok, %{lhs: :any, rhs: :column}}
      assert Postgres.operator_signature(:nin) == {:ok, %{lhs: :any, rhs: :column_array}}
      assert Postgres.operator_signature(:is_null) == {:ok, %{lhs: :any, rhs: :boolean}}
      assert Postgres.operator_signature(:niregex) == {:ok, %{lhs: :text, rhs: :text}}
      assert Postgres.operator_signature(:contained_in) == {:ok, %{lhs: :jsonb, rhs: :jsonb}}
      assert Postgres.operator_signature(:has_key) == {:ok, %{lhs: :jsonb, rhs: :text}}
      assert Postgres.operator_signature(:has_keys_any) == {:ok, %{lhs: :jsonb, rhs: :text_array}}
      assert Postgres.operator_signature(:has_keys_all) == {:ok, %{lhs: :jsonb, rhs: :text_array}}
    end

    test "everything else is unsupported" do
      for op <- [:ceq, :st_within, :_eq, "eq", nil] do
        assert Postgres.operator_signature(op) == :unsupported
      end
    end
  end

  describe "supported_key_kind?/1" do
    test "integer, text, citext, uuid and enum columns are key kinds", %{tables: tables} do
      for {table, column} <- [
            {"articles", "id"},
            {"key_kinds", "rank"},
            {"users", "role"},
            {"key_kinds", "code"},
            {"users", "email"},
            {"articles", "external_ref"},
            {"articles", "status"}
          ] do
        assert Postgres.supported_key_kind?(tables[table][column]), column
      end
    end

    test "bpchar, boolean, numeric, jsonb and timestamptz are not", %{tables: tables} do
      for {table, column} <- [
            {"key_kinds", "grade"},
            {"users", "is_admin"},
            {"users", "salary"},
            {"articles", "assignees"},
            {"articles", "published_at"}
          ] do
        refute Postgres.supported_key_kind?(tables[table][column]), column
      end
    end
  end

  describe "session strings against non-text columns (Review Focus 3)" do
    test "uuid", %{tables: t} do
      assert {[1], sql} =
               run(t, "articles", "external_ref", :eq, {:session, String.upcase(@uuid)})

      assert sql =~ "::uuid"
      assert {[1], _} = run(t, "articles", "external_ref", :in, {:session, "{#{@uuid}}"})
    end

    test "timestamptz", %{tables: t} do
      assert {[1], sql} =
               run(t, "articles", "published_at", :eq, {:session, "2026-01-01T02:00:00+02:00"})

      assert sql =~ "::timestamptz"

      assert {[2], _} =
               run(t, "articles", "published_at", :gt, {:session, "2026-01-15T00:00:00Z"})
    end

    test "enum equality, membership and ordering", %{tables: t} do
      assert {[3], _} = run(t, "articles", "status", :eq, {:session, "review"})
      assert {[1, 2], _} = run(t, "articles", "status", :neq, {:session, "review"})
      assert {[1, 3], _} = run(t, "articles", "status", :in, {:session, "{draft,review}"})
      assert {[2], _} = run(t, "articles", "status", :nin, {:literal, ["draft", "review"]})
      # Enum order (draft < review < published), not text order.
      assert {[2, 3], _} = run(t, "articles", "status", :gte, {:session, "review"})
    end

    test "citext compares case-insensitively", %{tables: t} do
      assert {[1], sql} = run(t, "users", "email", :eq, {:session, "a@X.COM"})
      assert sql =~ "::citext"
      assert {[1, 2], _} = run(t, "users", "email", :in, {:session, "{A@X.COM,B@x.com}"})
      assert {[2], _} = run(t, "users", "email", :like, {:session, "B@%"})
    end

    test "numeric, boolean, integer and float", %{tables: t} do
      assert {[1], _} = run(t, "users", "salary", :eq, {:session, "10.50"})
      assert {[1], _} = run(t, "users", "is_admin", :eq, {:session, "Yes"})
      assert {[2], _} = run(t, "users", "is_admin", :eq, {:session, "0"})
      assert {[2, 3], _} = run(t, "articles", "author_id", :eq, {:session, "2"})
      assert {[2], _} = run(t, "key_kinds", "rank", :gt, {:session, "2"})
      assert {[1], _} = run(t, "key_kinds", "score", :lte, {:session, "1.5"})
      assert {[1, 2, 3], _} = run(t, "articles", "id", :in, {:session, "{1,2,3}"})
    end
  end

  test "bpchar compares with its own padding semantics in _eq and _in", %{tables: t} do
    assert {[1], sql} = run(t, "key_kinds", "grade", :eq, {:session, "a "})
    assert sql =~ "::bpchar"
    assert {[1], _} = run(t, "key_kinds", "grade", :eq, {:session, "a"})
    assert {[1], _} = run(t, "key_kinds", "grade", :in, {:session, ~s({"a "})})
    assert {[1], _} = run(t, "key_kinds", "grade", :in, {:literal, ["a"]})
  end

  describe "empty membership" do
    test "_in [] matches no rows and _nin [] matches all rows", %{tables: t} do
      assert {[], _} = run(t, "articles", "id", :in, {:session, "{}"})
      assert {[1, 2, 3], _} = run(t, "articles", "id", :nin, {:literal, []})
      assert negated(t, "articles", "id", :in, {:literal, []}) == [1, 2, 3]
      assert negated(t, "articles", "id", :nin, {:literal, []}) == []
    end
  end

  describe "null-aware equality" do
    test "nullable columns use the null-aware forms in :permission mode", %{tables: t} do
      assert {[1], sql} = run(t, "articles", "body", :eq, {:literal, "x"})
      assert sql =~ ~s|."body" IS NULL) AND ($2::varchar IS NULL)|
      assert {[3], sql} = run(t, "articles", "body", :neq, {:literal, "x"})

      assert sql =~
               ~s|."body" != $1::varchar) OR (NOT (a0."body" IS NULL) AND ($2::varchar IS NULL)|
    end

    test "non-null columns and :input mode use plain forms", %{tables: t} do
      assert {[1], sql} = run(t, "articles", "title", :eq, {:literal, "Alpha one"})
      refute sql =~ "IS NULL"
      assert {[1], sql} = run(t, "articles", "body", :eq, {:literal, "x"}, :input)
      refute sql =~ "IS NULL"
    end

    test "a nil literal matches NULL rows and stays unknown otherwise", %{tables: t} do
      assert {[2], _} = run(t, "articles", "body", :eq, {:literal, nil})
      assert {[1, 3], _} = run(t, "articles", "body", :neq, {:literal, nil})
      # `col = NULL OR (col IS NULL AND NULL IS NULL)` is never false, so its
      # negation matches nothing, exactly as in Hasura.
      assert negated(t, "articles", "body", :eq, {:literal, nil}) == []
      assert negated(t, "articles", "body", :neq, {:literal, nil}) == []
    end

    test "a nil literal on a non-null column or in :input mode matches nothing", %{tables: t} do
      assert {[], _} = run(t, "articles", "title", :eq, {:literal, nil})
      assert negated(t, "articles", "title", :eq, {:literal, nil}) == []
      assert {[], _} = run(t, "articles", "body", :eq, {:literal, nil}, :input)
      assert negated(t, "articles", "body", :neq, {:literal, nil}, :input) == []
      assert {[], _} = run(t, "articles", "id", :gt, {:literal, nil})
    end
  end

  test "_is_null", %{tables: t} do
    assert {[2, 3], _} = run(t, "articles", "external_ref", :is_null, {:session, "true"})
    assert {[1], _} = run(t, "articles", "external_ref", :is_null, {:literal, false})
  end

  describe "text operators" do
    test "like, ilike, similar and regex families", %{tables: t} do
      assert {[1], _} = run(t, "articles", "title", :like, {:literal, "Alpha%"})
      assert {[2, 3], _} = run(t, "articles", "title", :nlike, {:literal, "Alpha%"})
      assert {[1], _} = run(t, "articles", "title", :ilike, {:literal, "alpha%"})
      assert {[2, 3], _} = run(t, "articles", "title", :nilike, {:literal, "alpha%"})
      assert {[2], _} = run(t, "articles", "title", :similar, {:literal, "(beta|delta)%"})
      assert {[1, 3], _} = run(t, "articles", "title", :nsimilar, {:literal, "(beta|delta)%"})
      assert {[3], _} = run(t, "articles", "title", :regex, {:literal, "^gam"})
      assert {[1], _} = run(t, "articles", "title", :iregex, {:literal, "^ALPHA"})
      assert {[1, 2], _} = run(t, "articles", "title", :nregex, {:literal, "^gam"})
      assert {[2, 3], _} = run(t, "articles", "title", :niregex, {:literal, "^ALPHA"})
    end
  end

  describe "jsonb operators" do
    test "contains and contained_in", %{tables: t} do
      assert {[1], _} = run(t, "articles", "assignees", :contains, {:session, ~s({"7": true})})

      assert {[2, 3], _} =
               run(t, "articles", "assignees", :contained_in, {:literal, %{"9" => true}})

      # A string literal stays a string: it is not decoded into an object.
      assert {[], _} = run(t, "articles", "assignees", :contains, {:literal, ~s({"7": true})})
    end

    test "has_key with a session variable, has_keys_any and has_keys_all", %{tables: t} do
      assert {[1], sql} = run(t, "articles", "assignees", :has_key, {:session, "8"})
      assert sql =~ ~s|."assignees" ? $1|
      assert {[1, 2], _} = run(t, "articles", "assignees", :has_keys_any, {:session, "{8,9}"})
      assert {[1], _} = run(t, "articles", "assignees", :has_keys_all, {:literal, ["7", "8"]})
      assert {[], _} = run(t, "articles", "assignees", :has_keys_all, {:session, "{7,9}"})
    end
  end

  test "an operator applied to a column it cannot compare raises before any SQL" do
    column = %Column{name: "id", pg_type: "int8", base_kind: :bigint, ecto_type: :integer}
    lhs = dynamic(field(as(^@root), ^"id"))

    assert_raise ArgumentError, ~r/:like/, fn ->
      Postgres.compile_operator(:like, lhs, "x", column, :permission)
    end
  end

  describe "enum comparisons in the enum's own type" do
    test "equality and membership cast the value, never the column", %{tables: t} do
      assert {[3], sql} = run(t, "articles", "status", :eq, {:session, "review"})
      assert sql =~ ~s|."status" = $1::"public"."article_status"|
      refute sql =~ "::text"

      assert {[1, 3], sql} = run(t, "articles", "status", :in, {:literal, ["draft", "review"]})
      assert sql =~ ~s|."status" = ANY($1::"public"."article_status"[])|

      nullable = %{t["articles"]["status"] | nullable?: true}
      t = put_in(t, ["articles", "status"], nullable)
      assert {[3], sql} = run(t, "articles", "status", :eq, {:session, "review"})
      assert sql =~ ~s|AND ($2::"public"."article_status" IS NULL)|
      assert {[1, 2], _} = run(t, "articles", "status", :neq, {:session, "review"})
    end

    test "an index on the enum column serves equality and membership", %{tables: t} do
      Repo.query!("CREATE INDEX articles_status_idx ON public.articles (status)")
      Repo.query!("SET LOCAL enable_seqscan = off")

      for {op, operand} <- [eq: {:session, "review"}, in: {:literal, ["draft", "review"]}] do
        assert explain(t, "articles", "status", op, operand) =~
                 ~r/Index Cond: \(status = (ANY \()?/
      end
    end

    test "an enum column without a quotable type compares as text", %{tables: t} do
      untyped = %{t["articles"]["status"] | type_schema: nil}
      t = put_in(t, ["articles", "status"], untyped)

      assert {[3], sql} = run(t, "articles", "status", :eq, {:session, "review"})
      assert sql =~ ~s|."status"::text = $1::varchar|
      assert {[1, 3], _} = run(t, "articles", "status", :in, {:literal, ["draft", "review"]})
      assert {[2], _} = run(t, "articles", "status", :nin, {:literal, ["draft", "review"]})
    end
  end
end

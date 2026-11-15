defmodule Authzura.Adapters.Postgres.IntrospectionTest do
  use Authzura.DataCase, async: true

  alias Authzura.Adapters.Postgres.Introspection

  @refs [
    {"public", "users"},
    {"audit", "users"},
    {"public", "articles"},
    {"public", "published_articles"},
    {"public", "Order"},
    {"public", "membership_notes"},
    {"public", "org_memberships"},
    {"public", "key_kinds"}
  ]

  setup do
    {:ok, tables, fks} = Introspection.introspect(Repo, @refs)
    %{tables: tables, fks: fks}
  end

  test "reads citext columns as non-null citext", %{tables: tables} do
    email = tables[{"public", "users"}].columns["email"]
    assert email.base_kind == :citext
    refute email.nullable?
  end

  test "reads enum labels in sort order", %{tables: tables} do
    status = tables[{"public", "articles"}].columns["status"]
    assert status.base_kind == :enum
    assert status.enum_labels == ["draft", "review", "published"]
  end

  test "reads the schema of an enum column's type, and only for enums", %{tables: tables} do
    columns = tables[{"public", "articles"}].columns

    assert %{base_kind: :enum, pg_type: "article_status", type_schema: "public"} =
             columns["status"]

    assert columns["title"].type_schema == nil
  end

  test "reads btree index key columns with their order, leaving out partial, expression, INCLUDE, non-default opclass and collation parts" do
    Enum.each(
      [
        "CREATE INDEX ON public.articles (org_id, title) INCLUDE (body)",
        "CREATE INDEX ON public.articles (author_id) WHERE editor_id IS NULL",
        "CREATE INDEX ON public.articles (lower(title))",
        "CREATE INDEX ON public.articles USING hash (status)",
        "CREATE INDEX ON public.articles (org_id, published_at DESC NULLS LAST, id)",
        "CREATE INDEX ON public.articles (author_id, published_at NULLS FIRST)",
        "CREATE INDEX ON public.articles (org_id, title text_pattern_ops)",
        ~s|CREATE INDEX ON public.articles (org_id, title COLLATE "C")|
      ],
      &Repo.query!/1
    )

    {:ok, tables, _fks} = Introspection.introspect(Repo, [{"public", "articles"}])

    assert Enum.sort(tables[{"public", "articles"}].indexes) == [
             [{"author_id", :asc}, {"published_at", :asc_nulls_first}],
             [{"id", :asc}],
             [{"org_id", :asc}, {"published_at", :desc_nulls_last}, {"id", :asc}],
             [{"org_id", :asc}, {"title", :asc}]
           ]
  end

  test "reads uuid, jsonb and timestamptz kinds", %{tables: tables} do
    columns = tables[{"public", "articles"}].columns
    assert columns["external_ref"].base_kind == :uuid
    assert columns["assignees"].base_kind == :jsonb
    assert columns["published_at"].base_kind == :timestamptz
    assert columns["id"].base_kind == :bigint
  end

  test "maps varchar, smallint and bpchar per the base_kind ruling", %{tables: tables} do
    columns = tables[{"public", "key_kinds"}].columns
    assert %{base_kind: :text, ecto_type: :string} = columns["code"]
    assert %{base_kind: :integer, ecto_type: :integer} = columns["rank"]
    assert %{base_kind: :text, pg_type: "bpchar"} = columns["grade"]
    assert %{base_kind: :text, pg_type: "varchar"} = columns["code"]
    assert %{base_kind: :float, pg_type: "float8", ecto_type: :float} = columns["score"]
  end

  # information_schema.sql_identifier is a domain over `name`.
  test "a domain over name resolves to name and compares as text" do
    ref = {"hasura_boolexp", "table_with_sql_identifier"}
    {:ok, %{^ref => %{columns: columns}}, _fks} = Introspection.introspect(Repo, [ref])
    assert %{base_kind: :text, pg_type: "name", ecto_type: :string} = columns["sql_id"]
  end

  test "views are tracked with all columns nullable", %{tables: tables} do
    view = tables[{"public", "published_articles"}]
    assert view.kind == :view
    assert Enum.all?(Map.values(view.columns), & &1.nullable?)
    assert view.primary_key == []
  end

  test "handles quoted identifiers", %{tables: tables} do
    order = tables[{"public", "Order"}]
    assert Map.has_key?(order.columns, "line item")
    assert order.primary_key == ["Id"]
  end

  test "pairs composite foreign key columns by position", %{fks: fks} do
    assert %{
             columns: ["org_id", "user_id"],
             ref_table: {"public", "org_memberships"},
             ref_columns: ["org_id", "user_id"]
           } = Enum.find(fks, &(&1.table == {"public", "membership_notes"}))
  end

  test "keeps same-named tables in different schemas apart", %{tables: tables} do
    assert Map.keys(tables[{"audit", "users"}].columns) == ["id", "note"]
    assert Map.has_key?(tables[{"public", "users"}].columns, "email")
    assert tables[{"audit", "users"}].schema == "audit"
  end

  test "reads whether each column is generated and whether its equality is leakproof" do
    {:ok, tables, _fks} = Introspection.introspect(Repo, [{"public", "pushdown_probe"}])
    columns = tables[{"public", "pushdown_probe"}].columns

    assert columns["doubled"].generated?
    refute columns["id"].generated?

    for name <- ~w(id small title flag day stamp ref),
        do: assert(columns[name].eq_leakproof?, name)

    for name <- ~w(amount tag status), do: refute(columns[name].eq_leakproof?, name)
  end

  test "returns only requested tables" do
    {:ok, tables, _fks} = Introspection.introspect(Repo, [{"public", "users"}])
    assert Map.keys(tables) == [{"public", "users"}]
  end

  test "omits tables that do not exist" do
    {:ok, tables, _fks} = Introspection.introspect(Repo, [{"public", "nope"}])
    assert tables == %{}
  end
end

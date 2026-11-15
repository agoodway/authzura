defmodule Authzura.Parity.SelectParityTest do
  @moduledoc """
  Permission semantics against a real Hasura v2.51.6: each case runs the
  same read through Hasura GraphQL (admin-secret impersonation of one
  fixture role, see `Authzura.Parity.Fixture`) and through Authzura, and
  compares every returned key and value, or the errors.
  """

  use Authzura.ParityCase

  alias Authzura.HasuraFixture
  alias Authzura.Model.Diagnostic
  alias Authzura.Parity.{Compare, Hasura}
  alias Authzura.Test.ParityRepo
  alias Ecto.UUID

  @articles Fixture.table(:articles)
  @users Fixture.table(:users)
  @comments Fixture.table(:comments)
  @kinds Fixture.table(:kinds)

  defp articles(fields \\ []),
    do: Read.new(@articles, [columns: Fixture.article_columns()] ++ fields)

  defp ids_of(table, fields \\ []), do: Read.new(table, [columns: ["id"]] ++ fields)
  defp me(id), do: %{"x-hasura-user-id" => Integer.to_string(id)}

  describe "row filters" do
    test "an author sees only their own articles" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("author", me(1)))
      assert ids(rows) == [1, 2]
      assert {:ok, [%{"id" => 4}]} = assert_parity(articles(), impersonate("author", me(3)))
    end

    test "a published-only role, with the bare-value shorthand" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("published"))
      assert ids(rows) == [2, 4]
    end

    test "a reviewer sees in-review plus published" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("reviewer"))
      assert ids(rows) == [2, 3, 4]
    end

    test "$or with a bare upper-case session variable" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("author_or_published", me(2)))
      assert ids(rows) == [2, 3, 4]
    end

    test "{} returns every row" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("everyone"))
      assert ids(rows) == [1, 2, 3, 4]
    end
  end

  describe "empty forms" do
    for {role, expected} <- [
          {"in_empty", []},
          {"nin_empty", [1, 2, 3, 4]},
          {"not_in_empty", [1, 2, 3, 4]},
          {"or_empty", []},
          {"and_empty", [1, 2, 3, 4]},
          {"not_empty", []}
        ] do
      test "#{role}" do
        assert {:ok, rows} = assert_parity(articles(), impersonate(unquote(role)))
        assert ids(rows) == unquote(expected)
      end
    end
  end

  describe "NULL handling" do
    test "null-aware _eq and _neq against a session variable on a nullable column" do
      assert {:ok, [%{"id" => 2}]} = assert_parity(articles(), impersonate("editor_eq_me", me(2)))

      assert {:ok, [%{"id" => 4}]} =
               assert_parity(articles(), impersonate("editor_neq_me", me(2)))
    end

    test "a literal null operand" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("editor_eq_null"))
      assert ids(rows) == [1, 3]
    end

    test "_neq with a literal and _not over _eq on a nullable column" do
      assert {:ok, [%{"id" => 3}]} = assert_parity(articles(), impersonate("notes_neq_literal"))
      assert {:ok, [%{"id" => 3}]} = assert_parity(articles(), impersonate("notes_not_eq"))
    end

    test "_is_null true and false" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("editor_is_null"))
      assert ids(rows) == [1, 3]
      assert {:ok, rows} = assert_parity(articles(), impersonate("editor_not_null"))
      assert ids(rows) == [2, 4]
    end
  end

  describe "relationships in filters" do
    test "an object relationship with a session variable" do
      assert {:ok, rows} =
               assert_parity(articles(), impersonate("rel_object", %{"x-hasura-org-id" => "1"}))

      assert ids(rows) == [1, 2, 3]
    end

    test "array, three-hop, self and reverse object relationships" do
      assert {:ok, [_ | _]} = assert_parity(ids_of(@users), impersonate("rel_array"))
      assert {:ok, [_ | _]} = assert_parity(ids_of(@comments), impersonate("rel_3hop"))
      assert {:ok, [%{"id" => 2}]} = assert_parity(ids_of(@users), impersonate("rel_self"))

      assert {:ok, [%{"id" => 1}]} =
               assert_parity(ids_of(@users), impersonate("rel_reverse_object"))
    end

    test "conditions in one node match the same related row; siblings are independent" do
      assert {:ok, []} = assert_parity(ids_of(@users), impersonate("rel_same_row"))
      assert {:ok, [%{"id" => 1}]} = assert_parity(ids_of(@users), impersonate("rel_siblings"))
    end

    test "relationship: {} requires a related row, and its negation" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("rel_exists"))
      assert ids(rows) == [1, 2, 4]
      assert {:ok, [%{"id" => 3}]} = assert_parity(articles(), impersonate("rel_negated"))
    end

    test "a multi-column mapping" do
      read = Read.new({"public", "membership_notes"}, columns: ["id", "note"])
      assert {:ok, [%{"id" => 2}]} = assert_parity(read, impersonate("rel_composite"))
    end

    test "the target table's own permission is not applied inside a filter" do
      assert {:ok, rows} = assert_parity(ids_of(@comments), impersonate("rel_no_target_perm"))
      assert ids(rows) |> Enum.sort() == [3, 5, 6]
    end

    test "manual relationships, from a table and from a view" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("rel_manual"))
      assert ids(rows) == [1, 4]

      view = Read.new({"public", "published_articles"}, columns: ["id", "title"])
      assert {:ok, [%{"id" => 4}]} = assert_parity(view, impersonate("rel_view"))
    end
  end

  describe "_exists" do
    test "uncorrelated, true and false" do
      assert {:ok, [_, _, _, _]} = assert_parity(articles(), impersonate("exists_uncorrelated"))
      assert {:ok, []} = assert_parity(articles(), impersonate("exists_none"))
    end

    test "against the root table with a session variable" do
      assert {:ok, [_, _, _, _]} =
               assert_parity(articles(), impersonate("exists_same_table", me(2)))

      assert {:ok, []} = assert_parity(articles(), impersonate("exists_same_table", me(1)))
    end

    test "inside _or and _not" do
      assert {:ok, [%{"id" => 1}]} = assert_parity(articles(), impersonate("exists_or", me(2)))
      assert {:ok, [_, _, _, _]} = assert_parity(articles(), impersonate("exists_or", me(5)))
      assert {:ok, []} = assert_parity(articles(), impersonate("exists_not", me(1)))
      assert {:ok, [_, _, _, _]} = assert_parity(articles(), impersonate("exists_not", me(2)))
    end

    test "the same table name in another schema" do
      read = Read.new({"audit", "users"}, columns: ["id", "note"])
      assert {:ok, [%{"id" => 5}]} = assert_parity(read, impersonate("audit_only", me(5)))

      assert {:error, _code, :forbidden} =
               assert_parity(ids_of(@users), impersonate("audit_only", me(5)))
    end
  end

  describe "operators" do
    # Titles: 1 "Alpha", 2 "beta", 3 "Gamma", 4 "delta".
    for {role, expected} <- [
          {"op_like", [2, 4]},
          {"op_nlike", [1, 3]},
          {"op_ilike", [1]},
          {"op_nilike", [2, 3, 4]},
          {"op_similar", [1, 2]},
          {"op_nsimilar", [3, 4]},
          {"op_regex", [1, 3]},
          {"op_nregex", [2, 4]},
          {"op_iregex", [3]},
          {"op_niregex", [1, 2, 4]},
          {"op_contains", [1, 4]},
          {"op_contained_in", [1, 2, 3]},
          {"op_has_key", [2]},
          {"op_has_keys_any", [2]},
          {"op_has_keys_all", [4]},
          {"op_enum", [3]}
        ] do
      test "#{role} on articles" do
        assert {:ok, rows} = assert_parity(articles(), impersonate(unquote(role)))
        assert ids(rows) == unquote(expected)
      end
    end

    for {role, expected} <- [
          {"op_cmp", [2, 3, 4]},
          {"op_neq", [1, 3, 4, 5]},
          {"op_range", [2, 3, 4]},
          {"op_in", [1, 2]},
          {"op_nin", [2, 3, 4, 5]},
          {"op_float", [1, 2]},
          {"op_real", [1, 5]},
          {"op_char", [1]}
        ] do
      test "#{role} on key_kinds" do
        assert {:ok, rows} = assert_parity(ids_of(@kinds), impersonate(unquote(role)))
        assert ids(rows) == unquote(expected)
      end
    end

    test "citext and numeric comparisons" do
      assert {:ok, [%{"id" => 3}]} = assert_parity(ids_of(@users), impersonate("op_citext"))
      assert {:ok, rows} = assert_parity(ids_of(@users), impersonate("op_numeric"))
      assert ids(rows) == [1, 3]
    end

    test "_has_key with a session variable" do
      assert {:ok, rows} = assert_parity(articles(), impersonate("op_has_key_session", me(1)))
      assert ids(rows) == [1, 4]
    end

    test "session variables cast to boolean, uuid and timestamptz" do
      assert {:ok, [%{"id" => 3}]} =
               assert_parity(
                 ids_of(@users),
                 impersonate("op_bool", %{"x-hasura-is-admin" => "true"})
               )

      ref = %{"x-hasura-ref" => "7d0e0a3c-6b0f-4e55-8a77-000000000004"}
      assert {:ok, [%{"id" => 4}]} = assert_parity(articles(), impersonate("op_uuid", ref))

      since = %{"x-hasura-since" => "2024-06-01T00:00:00Z"}

      assert {:ok, [%{"id" => 4}]} =
               assert_parity(articles(), impersonate("op_timestamptz", since))
    end
  end

  describe "session variables" do
    test "names are case-insensitive" do
      vars = %{"X-Hasura-User-Id" => "1"}
      assert {:ok, rows} = assert_parity(articles(), impersonate("author", vars))
      assert ids(rows) == [1, 2]
    end

    test "a missing variable is an error" do
      assert {:error, "not-found", {:missing_session_variable, _name}} =
               assert_parity(articles(), impersonate("author"))
    end

    test "a value that does not cast to the column type is an error" do
      assert {:error, "data-exception", {:invalid_session_value, "x-hasura-user-id", _reason}} =
               assert_parity(articles(), impersonate("author", %{"x-hasura-user-id" => "abc"}))
    end

    test "array variables, including the empty array" do
      ids = %{"x-hasura-article-ids" => "{1,3}"}

      assert {:ok, [%{"id" => 1}, %{"id" => 3}]} =
               assert_parity(articles(), impersonate("sv_array", ids))

      empty = %{"x-hasura-article-ids" => "{}"}
      assert {:ok, []} = assert_parity(articles(), impersonate("sv_array", empty))
    end

    test "quoted and comma elements in an array variable" do
      read = Read.new(@kinds, columns: ["id", "code"])
      codes = %{"x-hasura-codes" => ~s|{"a,b","\\"q\\"",c}|}
      assert {:ok, rows} = assert_parity(read, impersonate("sv_codes", codes))
      assert ids(rows) == [3, 4]
    end

    test "a value longer than a varchar column is not truncated" do
      read = Read.new(@kinds, columns: ["id", "code"])
      long = %{"x-hasura-code" => "abcdefghijklmnopXYZ"}
      assert {:ok, []} = assert_parity(read, impersonate("sv_long", long))

      exact = %{"x-hasura-code" => "abcdefghijklmnop"}
      assert {:ok, [%{"id" => 5}]} = assert_parity(read, impersonate("sv_long", exact))
    end
  end

  describe "columns" do
    test "every column of every fixture type compares by value" do
      for table <- [@articles, @users, @kinds, {"public", "user_profiles"}] do
        read = Read.new(table, columns: all_columns(table))
        assert {:ok, [_ | _]} = assert_parity(read, impersonate("everyone"))
      end
    end

    test "a quoted table and column" do
      read = Read.new({"public", "Order"}, columns: ["Id"], order_by: [desc: :Id])

      assert {:ok, [%{"Id" => 3}, %{"Id" => 2}, %{"Id" => 1}]} =
               assert_parity(read, impersonate("everyone"))
    end

    test "only the requested allowed columns, under a filter on a hidden column" do
      read = Read.new(@articles, columns: ["id", "title"])
      assert {:ok, rows} = assert_parity(read, impersonate("cols"))
      assert ids(rows) == [2, 3]
    end

    test "a hidden column is refused" do
      read = Read.new(@articles, columns: ["id", "internal_notes"])

      assert {:error, "validation-failed", {:forbidden_columns, ["internal_notes"]}} =
               assert_parity(read, impersonate("cols"))
    end

    test "a caller filter is ANDed with the permission; a hidden column in it is refused" do
      read =
        Read.new(@articles, columns: ["id", "title"], where: %{"title" => %{"_ilike" => "%a%"}})

      assert {:ok, rows} = assert_parity(read, impersonate("cols"))
      assert ids(rows) == [2, 3]

      hidden = Read.new(@articles, columns: ["id"], where: %{"internal_notes" => %{"_eq" => "x"}})

      assert {:error, "validation-failed", {:forbidden_columns, ["internal_notes"]}} =
               assert_parity(hidden, impersonate("cols"))
    end

    test "a role without a permission on the table" do
      read = Read.new({"public", "organizations"}, columns: ["id"])

      assert {:error, "validation-failed", :forbidden} =
               assert_parity(read, impersonate("author", me(1)))
    end
  end

  describe "limits" do
    test "the permission limit caps the result" do
      read = Read.new(@articles, columns: ["id", "title"], order_by: [asc: :id])
      assert {:ok, [%{"id" => 1}, %{"id" => 2}]} = assert_parity(read, impersonate("lim"))
    end

    test "min(caller, permission)" do
      lower = Read.new(@articles, columns: ["id"], order_by: [desc: :id], limit: 1)
      assert {:ok, [%{"id" => 4}]} = assert_parity(lower, impersonate("lim"))

      higher = Read.new(@articles, columns: ["id"], order_by: [desc: :id], limit: 3)
      assert {:ok, [%{"id" => 4}, %{"id" => 3}]} = assert_parity(higher, impersonate("lim"))
    end
  end

  describe "root fields" do
    test "query_root_fields: [] disables the list root field" do
      assert {:error, "validation-failed", :root_field_disabled} =
               assert_parity(ids_of(@articles), impersonate("rf_none"))
    end

    test "a by-pk-only permission disables the list root field" do
      assert {:error, "validation-failed", :root_field_disabled} =
               assert_parity(ids_of(@articles), impersonate("rf_pk"))
    end
  end

  describe "preloads" do
    test "object and ordered array relationships" do
      read =
        articles(
          relationships: [
            {"author", Read.nested(columns: ["id", "email"])},
            {"comments", Read.nested(columns: ["id", "body"], order_by: [asc: :id])}
          ]
        )

      assert {:ok, [_, _, _, _]} = assert_parity(read, impersonate("everyone"))
    end

    test "an unordered array relationship compares as a set" do
      read = articles(relationships: [{"comments", Read.nested(columns: ["id", "author_id"])}])
      assert {:ok, [_, _, _, _]} = assert_parity(read, impersonate("everyone"))
    end

    test "three levels, a null object relationship and a reverse object relationship" do
      read =
        Read.new(@users,
          columns: ["id"],
          relationships: [
            {"profile", Read.nested(columns: ["bio"])},
            {"manager", Read.nested(columns: ["id", "email"])},
            {"org", Read.nested(columns: ["name"])},
            {"articles",
             Read.nested(
               columns: ["id", "status"],
               order_by: [desc: :id],
               relationships: [{"comments", Read.nested(columns: ["id"])}]
             )}
          ]
        )

      assert {:ok, [_, _, _]} = assert_parity(read, impersonate("everyone"))
    end

    test "a composite-key relationship with a NULL key, and manual relationships" do
      notes =
        Read.new({"public", "membership_notes"},
          columns: ["id"],
          relationships: [{"membership", Read.nested(columns: ["org_id", "user_id", "level"])}]
        )

      assert {:ok, [_, _, _]} = assert_parity(notes, impersonate("everyone"))

      events = articles(relationships: [{"events", Read.nested(columns: ["id", "kind"])}])
      assert {:ok, [_, _, _, _]} = assert_parity(events, impersonate("everyone"))

      view =
        Read.new({"public", "published_articles"},
          columns: ["id"],
          relationships: [{"author", Read.nested(columns: ["email"])}]
        )

      assert {:ok, [_, _]} = assert_parity(view, impersonate("everyone"))
    end

    test "each level applies its target's row filter" do
      read =
        Read.new(@users,
          columns: ["id"],
          relationships: [
            {"articles",
             Read.nested(
               columns: ["id"],
               relationships: [{"comments", Read.nested(columns: ["id"])}]
             )}
          ]
        )

      assert {:ok, [_, _, _]} = assert_parity(read, impersonate("author", me(1)))
    end

    test "a relationship to a table whose root fields are disabled" do
      read =
        Read.new(@users,
          columns: ["id"],
          relationships: [{"articles", Read.nested(columns: ["id", "title"])}]
        )

      assert {:ok, [_, _, _]} = assert_parity(read, impersonate("rf_rel"))
    end

    test "a limited relationship without order_by: cardinality and membership" do
      comments =
        Read.nested(
          columns: ["id", "article_id", "body"],
          sample: {@comments, %{"id" => "article_id"}}
        )

      read = articles(relationships: [{"comments", comments}])
      assert {:ok, [_, _, _, _]} = assert_parity(read, impersonate("lim_rel"))
    end

    test "a limited relationship with order_by" do
      comments = Read.nested(columns: ["id", "body"], order_by: [desc: :id])
      read = articles(relationships: [{"comments", comments}])
      assert {:ok, [_, _, _, _]} = assert_parity(read, impersonate("lim_rel"))
    end

    test "a caller filter with a preload goes through the input path" do
      read =
        articles(
          where: %{"is_published" => %{"_eq" => true}},
          relationships: [{"comments", Read.nested(columns: ["id"], order_by: [asc: :id])}]
        )

      assert {:ok, [_, _]} = assert_parity(read, impersonate("everyone"))
    end
  end

  describe "metadata Hasura rejects" do
    test "a json column in a permission filter is denied at load" do
      {table, %{role: role}} = entry = Fixture.json_filter_permission()
      metadata = Fixture.metadata([entry])

      # Inconsistent metadata leaves Hasura's current metadata untouched.
      assert {:error, {400, %{"error" => "cannot continue due to inconsistent metadata"}}} =
               Hasura.replace_metadata(metadata)

      %{permissions: permissions, diagnostics: diagnostics} =
        HasuraFixture.snapshot!(ParityRepo, metadata)

      assert %{status: {:denied, _diagnostics}} = Map.fetch!(permissions, {role, table, :select})

      assert [%Diagnostic{severity: :deny, reason: {:unsupported, :json_column}}] =
               Enum.filter(diagnostics, &match?(%Diagnostic{role: ^role, table: ^table}, &1))
    end
  end

  describe "comparison by declared column type" do
    test "the fixture columns have the kinds the comparison relies on" do
      kinds =
        for {ref, column} <- [
              {@articles, "external_ref"},
              {@articles, "published_at"},
              {@articles, "title"},
              {@users, "salary"}
            ],
            do:
              tables()
              |> Map.fetch!(ref)
              |> Map.fetch!(:columns)
              |> Map.fetch!(column)
              |> Map.fetch!(:base_kind)

      assert kinds == [:uuid, :timestamptz, :text, :numeric]
    end

    test "each side's representation agrees only under the declared type" do
      uuid = "7d0e0a3c-6b0f-4e55-8a77-000000000004"
      binary = UUID.dump!(uuid)
      assert Compare.value(binary, :uuid) == Compare.value(uuid, :uuid)
      refute Compare.value(binary, :text) == Compare.value(uuid, :text)

      at = ~U[2024-03-01 10:00:00.500000Z]

      assert Compare.value(at, :timestamptz) ==
               Compare.value("2024-03-01T10:00:00.5+00:00", :timestamptz)

      assert Compare.value("2024-03-01T10:00:00.5+00:00", :text) == "2024-03-01T10:00:00.5+00:00"

      assert Compare.value(Decimal.new("1000.50"), :numeric) == Compare.value(1000.5, :numeric)
      refute Compare.value("1000.5", :numeric) == Compare.value(1000.5, :numeric)
    end
  end

  defp all_columns(@articles),
    do:
      ~w(id org_id author_id editor_id status is_published title body internal_notes assignees external_ref published_at)

  defp all_columns(@users), do: ~w(id org_id manager_id email role is_admin salary)
  defp all_columns(@kinds), do: ~w(id code rank grade score meta ratio)
  defp all_columns({"public", "user_profiles"}), do: ~w(user_id bio)
end

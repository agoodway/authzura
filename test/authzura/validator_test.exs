defmodule Authzura.ValidatorTest do
  use ExUnit.Case, async: true

  alias Authzura.Adapters.Postgres
  alias Authzura.Model.{Column, Diagnostic, Permission, Relationship, Snapshot, Table}
  alias Authzura.Validator

  @things {"public", "things"}
  @grades {"public", "grades"}

  defp column(name, pg_type, base_kind, nullable? \\ false),
    do: %Column{
      name: name,
      pg_type: pg_type,
      base_kind: base_kind,
      ecto_type: :integer,
      nullable?: nullable?
    }

  defp snapshot(permissions) do
    things = %Table{
      schema: "public",
      name: "things",
      primary_key: ["id"],
      columns: %{
        "id" => column("id", "int8", :bigint),
        "owner_id" => column("owner_id", "int8", :bigint),
        "grade" => column("grade", "bpchar", :text, true),
        "span" => column("span", "interval", :other, true)
      },
      relationships: %{
        "grade" => %Relationship{
          name: "grade",
          kind: :object,
          target: @grades,
          mapping: [{"grade", "code"}]
        },
        "self" => %Relationship{
          name: "self",
          kind: :object,
          target: @things,
          mapping: [{"id", "id"}]
        }
      }
    }

    grades = %Table{
      schema: "public",
      name: "grades",
      primary_key: ["code"],
      columns: %{"code" => column("code", "bpchar", :text)}
    }

    %Snapshot{
      version: 1,
      tables: %{@things => things, @grades => grades},
      permissions: Map.new(permissions, &{{&1.role, &1.table, &1.operation}, &1})
    }
  end

  defp select(filter),
    do: %Permission{role: "user", table: @things, operation: :select, filter: filter}

  defp owner_filter, do: {:compare, "owner_id", :eq, {:session, "x-hasura-user-id"}}

  test "a relationship key of an unsupported kind is not preloadable, with a warning" do
    %Snapshot{tables: tables, diagnostics: diagnostics} =
      [select({:relationship, "grade", {:and, []}})] |> snapshot() |> Validator.validate(Postgres)

    assert %Relationship{preloadable?: false} = tables[@things].relationships["grade"]
    assert %Relationship{preloadable?: true} = tables[@things].relationships["self"]

    assert [
             %Diagnostic{
               severity: :warning,
               table: @things,
               path: ["grade"],
               reason: {:unsupported_key_kind, "grade", "bpchar"}
             }
           ] = diagnostics
  end

  describe "key compatibility" do
    @keys {"public", "keys"}

    # Each relationship maps the named pair of columns of `keys` to itself.
    defp keys_snapshot(pairs) do
      columns = [
        column("i4", "int4", :integer),
        column("i8", "int8", :bigint),
        column("vc", "varchar", :text),
        column("tx", "text", :text),
        column("ci", "citext", :citext),
        column("id", "uuid", :uuid),
        column("st", "article_status", :enum),
        column("st2", "article_status", :enum),
        column("mood", "mood", :enum),
        %{column("other_st", "article_status", :enum) | type_schema: "audit"}
      ]

      relationships =
        Map.new(pairs, fn {local, remote} = pair ->
          name = "#{local}_#{remote}"
          {name, %Relationship{name: name, kind: :array, target: @keys, mapping: [pair]}}
        end)

      keys = %Table{
        schema: "public",
        name: "keys",
        columns: Map.new(columns, &{&1.name, &1}),
        relationships: relationships
      }

      Validator.validate(%Snapshot{version: 1, tables: %{@keys => keys}}, Postgres)
    end

    defp preloadable?(%Snapshot{tables: %{@keys => %Table{relationships: rels}}}, name),
      do: rels[name].preloadable?

    test "pairs of compatible kinds stay preloadable" do
      pairs = [
        {"i4", "i8"},
        {"i8", "i4"},
        {"vc", "tx"},
        {"ci", "ci"},
        {"id", "id"},
        {"st", "st2"}
      ]

      snapshot = keys_snapshot(pairs)

      for {local, remote} <- pairs, do: assert(preloadable?(snapshot, "#{local}_#{remote}"))
      assert snapshot.diagnostics == []
    end

    test "pairs of incompatible kinds are not preloadable, with a warning" do
      pairs = [
        {"vc", "ci"},
        {"ci", "tx"},
        {"tx", "id"},
        {"i8", "tx"},
        {"st", "mood"},
        {"st", "tx"}
      ]

      %Snapshot{diagnostics: diagnostics} = snapshot = keys_snapshot(pairs)

      for {local, remote} <- pairs, do: refute(preloadable?(snapshot, "#{local}_#{remote}"))

      assert %Diagnostic{
               severity: :warning,
               table: @keys,
               path: ["vc_ci"],
               reason: {:incompatible_key_kinds, {"vc", "varchar"}, {"ci", "citext"}}
             } = Enum.find(diagnostics, &(&1.path == ["vc_ci"]))

      assert length(diagnostics) == length(pairs)
    end

    test "enum types of the same name in different schemas are incompatible" do
      %Snapshot{diagnostics: [diagnostic]} = snapshot = keys_snapshot([{"st", "other_st"}])

      refute preloadable?(snapshot, "st_other_st")

      assert diagnostic.reason ==
               {:incompatible_key_kinds, {"st", "article_status"}, {"other_st", "article_status"}}
    end
  end

  test "filters through an unsupported key kind stay enforceable" do
    %Snapshot{permissions: permissions} =
      [select({:relationship, "grade", {:and, []}})] |> snapshot() |> Validator.validate(Postgres)

    assert %Permission{status: :ok} = permissions[{"user", @things, :select}]
  end

  test "an uncompilable filter denies the permission" do
    bad = select({:compare, "no_such_col", :eq, {:session, "x-hasura-user-id"}})

    %Snapshot{permissions: permissions, diagnostics: diagnostics} =
      [bad] |> snapshot() |> Validator.validate(Postgres)

    diagnostic = %Diagnostic{
      severity: :deny,
      role: "user",
      table: @things,
      operation: :select,
      path: ["filter"],
      reason: {:unknown_column, @things, "no_such_col"}
    }

    assert %Permission{status: {:denied, [^diagnostic]}} = permissions[{"user", @things, :select}]
    assert diagnostic in diagnostics
  end

  describe "select_by_pk root fields" do
    defp by_pk(columns, root_fields \\ [:select_by_pk]),
      do: %{select({:and, []}) | columns: columns, root_fields: root_fields}

    defp status(snapshot),
      do: Validator.validate(snapshot, Postgres).permissions[{"user", @things, :select}].status

    test "a role that cannot select the whole primary key is denied, as Hasura refuses it" do
      %Snapshot{permissions: permissions, diagnostics: diagnostics} =
        [by_pk(["owner_id"])] |> snapshot() |> Validator.validate(Postgres)

      diagnostic = %Diagnostic{
        severity: :deny,
        role: "user",
        table: @things,
        operation: :select,
        path: ["query_root_fields"],
        reason: {:select_by_pk_without_primary_key, ["id"]}
      }

      assert %Permission{status: {:denied, [^diagnostic]}} =
               permissions[{"user", @things, :select}]

      assert diagnostic in diagnostics
    end

    test "a table without a primary key is denied too" do
      snapshot =
        [by_pk(["owner_id"], [:select, :select_by_pk])]
        |> snapshot()
        |> put_in([Access.key!(:tables), @things, Access.key!(:primary_key)], [])

      assert {:denied, [%Diagnostic{reason: {:select_by_pk_without_primary_key, []}}]} =
               status(snapshot)
    end

    test "the key visible, or no select_by_pk named, stays enforceable" do
      assert :ok = [by_pk(["id", "owner_id"])] |> snapshot() |> status()
      assert :ok = [by_pk(["owner_id"], :all)] |> snapshot() |> status()
      assert :ok = [by_pk(["owner_id"], [:select])] |> snapshot() |> status()
    end
  end

  test "a session compare on a column kind that cannot be bound denies" do
    %Snapshot{permissions: permissions} =
      [select({:compare, "span", :eq, {:session, "x-hasura-user-id"}})]
      |> snapshot()
      |> Validator.validate(Postgres)

    assert %Permission{
             status: {:denied, [%Diagnostic{reason: {:unsupported_type, "interval"}}]}
           } = permissions[{"user", @things, :select}]
  end

  test "a malformed literal denies instead of crashing the load" do
    %Snapshot{permissions: permissions} =
      [select({:compare, "id", :in, {:literal, nil}})]
      |> snapshot()
      |> Validator.validate(Postgres)

    assert %Permission{status: {:denied, [%Diagnostic{reason: :invalid_filter}]}} =
             permissions[{"user", @things, :select}]
  end

  test "a filter on an unknown table denies the permission" do
    perm = %{select({:and, []}) | table: {"public", "gone"}}

    %Snapshot{permissions: permissions} = [perm] |> snapshot() |> Validator.validate(Postgres)

    assert %Permission{
             status: {:denied, [%Diagnostic{reason: {:unknown_table, {"public", "gone"}}}]}
           } =
             permissions[{"user", {"public", "gone"}, :select}]
  end

  test "denied and non-select permissions are left alone" do
    denied = %{select({:compare, "nope", :eq, {:literal, 1}}) | status: {:denied, []}}
    write = %{select({:compare, "nope", :eq, {:literal, 1}}) | role: "w", operation: :update}
    snapshot = %{snapshot([denied, write]) | tables: %{}}

    assert Validator.validate(snapshot, Postgres) == snapshot
  end

  test "a valid snapshot comes back unchanged but for the preloads it grants" do
    snapshot =
      [select({:and, [owner_filter(), {:relationship, "self", {:not, owner_filter()}}]})]
      |> snapshot()
      |> update_in(
        [Access.key!(:tables), @things, Access.key!(:relationships)],
        &Map.delete(&1, "grade")
      )

    granted =
      put_in(snapshot.tables[@things].relationships["self"].preloadable?, true)

    assert Validator.validate(snapshot, Postgres) == granted
  end
end

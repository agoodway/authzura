defmodule Authzura.Feasibility.EctoConstructsTest do
  @moduledoc """
  Feasibility spike: every Ecto/Postgres query construct the compiler, scope
  and preload loader rely on, pinned as regression tests (Ecto 3.14, Ecto SQL
  3.14, Postgrex 0.22, Postgres 16). Later tasks use the forms below verbatim.

  ## Construct catalog

  All names are runtime strings; aliases come from the fixed atom pool.

    * **Root alias.** `from(q in query, as: ^alias)` attaches a runtime alias
      to an unaliased query (schema or string source). The alias is visible
      in `query.aliases` and `query.from.as`.

    * **Correlated `EXISTS`.** Build the subquery separately and wrap it with
      `exists(subquery(sub))`:

          sub =
            from(c in table, prefix: ^schema, as: ^alias,
              where: field(c, ^col) == field(parent_as(^parent_alias), ^parent_col),
              select: 1)

          where(root, [], exists(subquery(sub)))

      A runtime string is the source as-is (`from c in table`, no `^`);
      `prefix: ^schema` and `as: ^alias` take pinned values. The subquery needs
      an explicit `select` (`select: 1`), because a schemaless source has no
      default selection (omitting it raises `Ecto.SubQueryError`). Emits
      `exists((SELECT 1 FROM "public"."comments" AS sc0 WHERE (sc0."article_id" = a0."id")))`.

    * **Quoting.** Ecto quotes every source, prefix and column:
      `from(o in "Order", prefix: ^"public")` with `field(o, ^"line item")`
      emits `"public"."Order"` and `"line item"`. The generated table alias is
      unquoted (`O0`), which is harmless because Postgres folds it the same way
      at every use.

    * **Prefixes.** The same runtime table name under `prefix: ^"audit"` and
      `prefix: ^"public"` hits different tables.

    * **`unnest` join source (preload keys), ruling 13b form.** One array
      parameter per key column. Each parameter is `type(^values, ^ecto_type)`
      with a runtime Ecto type, so `key_array_param/2` returns
      `{values, ecto_type}` and the arity-generated macro only interpolates
      `type(^v_i, ^t_i)`. The fragment SQL depends on arity alone:

          join: p in fragment("SELECT * FROM unnest(?, ?) WITH ORDINALITY AS p(k1, k2, idx)",
                              type(^v1, ^t1), type(^v2, ^t2)),
          on: field(t, ^c1) == p.k1 and field(t, ^c2) == p.k2

      Supported key kinds (each proven single-column and in a composite pair):

      | key kind | `ecto_type` | emitted SQL | `on` clause for column `c` |
      | --- | --- | --- | --- |
      | `bigint`, `integer`, `smallint` | `{:array, :integer}` | `$n::bigint[]` | `field(t, ^c) == p.kN` |
      | `text`, `varchar` | `{:array, :string}` | `$n::varchar[]` | `field(t, ^c) == p.kN` |
      | `uuid` | `{:array, Ecto.UUID}` (string values; Ecto dumps) | `$n::uuid[]` | `field(t, ^c) == p.kN` |
      | `citext` | `{:array, CitextType}` (an `Ecto.Type` whose `type/0` is `:citext`) | `$n::citext[]` | `field(t, ^c) == p.kN` |
      | enum | `{:array, :string}` | `$n::varchar[]` | `fragment("?::text", field(t, ^c)) == p.kN` |

      - `integer` (int4) and `smallint` columns compare to `bigint[]` elements
        directly.
      - `citext = citext` is case-insensitive: keys `"a@X.com"` and `"B@X.COM"`
        match the stored `"A@x.com"` and `"b@x.com"`. A `{:array, :string}`
        (`varchar[]`) parameter compares case-sensitively against citext and
        does **not** match, so citext keys must use the citext type.
      - Enum keys are sent as `varchar[]`. The column cast to text (below)
        works but defeats an index on it, so the preload query casts the key
        to the enum type instead, with the type name passed through
        `identifier/1` (see "Enum comparisons in the enum's own type"); the
        text form remains the fallback for a type Ecto cannot quote.
      - `bpchar` (`char(n)`) is **not** a supported preload key kind (padding
        semantics; filters bind it as `?::bpchar`, see below). It and every
        other kind not in this table are denied at load.
      - A `dynamic/2` interpolated into a fragment argument is rejected when
        the query is planned (`Ecto.QueryError`, "invalid dynamic
        expression"), which is why per-column casts are Ecto types, not query
        expressions.

    * **Lateral per-parent limit.** The `unnest` fragment as the `from`
      source, named with `as: ^keys`, joined with
      `join(:inner_lateral, [p], s in subquery(target), on: true)`; the
      target subquery correlates with `field(parent_as(^keys), :k1)` and
      carries its own `order_by` and `limit: ^n`. Emits
      `INNER JOIN LATERAL (SELECT ... WHERE (sc0."article_id" = f0."k1") ... LIMIT $2)`.

    * **Enum comparisons in the enum's own type.** The schema and type name
      go through `identifier/1`, which quotes them (and refuses a name
      containing `"`): `fragment("?::?.?", ^v, identifier(^schema),
      identifier(^type))` emits `$1::"public"."article_status"`, and
      `fragment("? = ANY(?::?.?[])", col, ^list, ...)` binds the labels as
      the enum array type. Each distinct type is its own cached statement.

    * **Window ranking (per-parent limits).**
      `over(row_number(), partition_by: field(c, ^fk), order_by: field(c, ^pk))`
      selected as `rn` in an inner query, wrapped in
      `from(s in subquery(inner), where: s.rn <= ^n, order_by: [s.idx, s.rn])`.

    * **Enum comparison with a session string.** An untyped parameter,
      `field(a, ^"status") == ^"draft"`, works: Postgres infers the enum type.
      `type(^"draft", :string)` emits `::varchar` and fails with
      `undefined_function` (no `enum = varchar` operator). An invalid label
      fails in Postgres with `invalid_text_representation`, so labels must be
      checked in Elixir against the introspected labels before the query runs.
      `fragment("?::text", field(a, ^"status")) == type(^v, :string)` also works.

    * **Scalar citext comparison.** `field(u, ^"email") == fragment("?::citext", ^v)`
      or an untyped `^v`; never `type(^v, :string)` (case-sensitive).

    * **Scalar uuid comparison.** `field(a, ^"external_ref") == type(^v, Ecto.UUID)`.

    * **Scalar varchar, smallint and bpchar comparisons.**
      `field(k, ^c) == type(^v, :string)` for `varchar` (emits `$n::varchar`);
      `field(k, ^c) == fragment("?::bpchar", ^v)` for `bpchar`, so the column's
      own padding rules apply (stored `char(2)` `'a'` matches `"a"` and
      `"a "`, as `_in` does with its inferred `bpchar[]`);
      `field(k, ^c) == type(^v, :integer)` for `smallint` (emits
      `$n::bigint`). `Authzura.Adapters.Postgres` is the source of truth.

    * **Null-aware `_eq`/`_neq` with a nil literal.** `field(a, ^c) == ^nil`
      raises `ArgumentError` when the query is built, so a nil literal is
      compiled to the three-valued result of Hasura's SQL with `v` = `NULL`
      (never plain `is_nil`/`false`, which would turn true under `NOT`):
      `:eq` on a nullable column is `is_nil(col) or fragment("NULL::boolean")`,
      `:neq` is `not is_nil(col) or fragment("NULL::boolean")`, and every other
      nil comparison (non-null columns, `:input` mode) is
      `fragment("NULL::boolean")`. None of them is ever FALSE, so their
      negation matches no rows. `Authzura.Adapters.Postgres.compile_operator/5`
      is the source of truth for these forms.
  """

  use Authzura.DataCase, async: true

  import Authzura.SqlHelper

  alias Authzura.Test.Schemas.Article
  alias Ecto.{QueryError, UUID}
  alias Postgrex.Error

  defmodule CitextType do
    @moduledoc false
    use Ecto.Type

    alias Ecto.Type

    @impl Type
    def type, do: :citext

    @impl Type
    def cast(value), do: {:ok, value}

    @impl Type
    def load(value), do: {:ok, value}

    @impl Type
    def dump(value), do: {:ok, value}
  end

  @root :__authzura_0
  @child :__authzura_1
  @keys :__authzura_keys
  @uuid "11111111-1111-1111-1111-111111111111"
  @unnest1 "SELECT * FROM unnest(?) WITH ORDINALITY AS p(k1, idx)"
  @unnest2 "SELECT * FROM unnest(?, ?) WITH ORDINALITY AS p(k1, k2, idx)"

  setup do
    Enum.each(
      [
        "insert into public.organizations values (1, 'o')",
        "insert into public.users (id, org_id, email, role) values (1, 1, 'A@x.com', 'editor'), (2, 1, 'b@x.com', 'viewer')",
        """
        insert into public.articles (id, org_id, author_id, status, is_published, title, external_ref)
        values (1, 1, 1, 'draft', false, 'one', '#{@uuid}'), (2, 1, 2, 'published', true, 'two', null),
               (3, 1, 2, 'review', false, 'three', null)
        """,
        "insert into public.comments values (1, 1, 1, 'a'), (2, 1, 2, 'b'), (3, 2, 1, 'c')",
        "insert into public.org_memberships values (1, 1, 5), (1, 2, 7)",
        ~s|insert into public."Order" ("Id", "line item") values (1, 'widget')|,
        "insert into audit.users values (1, 'audit row')",
        "insert into public.key_kinds values (1, 'alpha', 2, 'a'), (2, 'beta', 3, 'bb')"
      ],
      &Repo.query!/1
    )
  end

  defp sorted_rows(query), do: query |> Repo.all() |> Enum.sort()

  defp table(name, schema \\ "public"), do: from(t in name, prefix: ^schema)

  defp unnest_join(table_name, column, values, ecto_type, select_column \\ "id") do
    from(t in table(table_name),
      join: p in fragment(@unnest1, type(^values, ^ecto_type)),
      on: field(t, ^column) == p.k1,
      select: {field(t, ^select_column), p.idx}
    )
  end

  defp unnest_enum_join(table_name, column, labels) do
    from(t in table(table_name),
      join: p in fragment(@unnest1, type(^labels, {:array, :string})),
      on: fragment("?::text", field(t, ^column)) == p.k1,
      select: {field(t, ^"id"), p.idx}
    )
  end

  defp unnest2_join(table_name, {c1, v1, t1}, {c2, v2, t2}) do
    from(t in table(table_name),
      join: p in fragment(@unnest2, type(^v1, ^t1), type(^v2, ^t2)),
      on: field(t, ^c1) == p.k1 and field(t, ^c2) == p.k2,
      select: {field(t, ^"id"), p.idx}
    )
  end

  describe "aliases and correlation" do
    test "root alias attaches to an unaliased schema query" do
      query = from(a in Article)
      aliased = from(q in query, as: ^@root)

      assert %{@root => 0} = aliased.aliases
      assert aliased.from.as == @root
    end

    test "correlated exists against the runtime root alias" do
      {schema, child_table, fk, pk} = {"public", "comments", "article_id", "id"}
      root = from(q in from(a in Article, prefix: ^schema), as: ^@root)

      sub =
        from(c in child_table,
          prefix: ^schema,
          as: ^@child,
          where: field(c, ^fk) == field(parent_as(^@root), ^pk),
          select: 1
        )

      query = from(a in root, where: exists(subquery(sub)), select: a.id)

      assert sql(query) =~
               ~s|exists((SELECT 1 FROM "public"."comments" AS sc0 WHERE (sc0."article_id" = a0."id")))|

      assert sorted_rows(query) == [1, 2]
    end
  end

  describe "identifiers and prefixes" do
    test "mixed-case tables and columns with spaces are quoted" do
      query = from(o in table("Order"), select: {field(o, ^"Id"), field(o, ^"line item")})

      assert sql(query) =~ ~s|FROM "public"."Order"|
      assert sql(query) =~ ~s|."line item"|
      assert Repo.all(query) == [{1, "widget"}]
    end

    test "the same runtime table name resolves per prefix" do
      email = fn schema -> from(u in table("users", schema), select: field(u, ^"id")) end
      note = from(u in table("users", "audit"), select: field(u, ^"note"))

      assert sql(email.("audit")) =~ ~s|FROM "audit"."users"|
      assert sql(email.("public")) =~ ~s|FROM "public"."users"|
      assert sorted_rows(email.("public")) == [1, 2]
      assert Repo.all(note) == ["audit row"]
    end
  end

  describe "unnest join source per key kind (runtime Ecto type)" do
    test "bigint keys with ordinality" do
      query = unnest_join("articles", "id", [2, 1], {:array, :integer})

      assert sql(query) =~ "unnest($1::bigint[])"
      assert sorted_rows(query) == [{1, 2}, {2, 1}]
    end

    test "integer (int4) columns compare to bigint[] keys" do
      query = unnest_join("org_memberships", "level", [7], {:array, :integer}, "user_id")

      assert sorted_rows(query) == [{2, 1}]
    end

    test "smallint columns compare to bigint[] keys" do
      query = unnest_join("key_kinds", "rank", [3, 2], {:array, :integer})

      assert sql(query) =~ "unnest($1::bigint[])"
      assert sorted_rows(query) == [{1, 2}, {2, 1}]
    end

    test "text keys" do
      query = unnest_join("users", "role", ["viewer"], {:array, :string})

      assert sql(query) =~ "unnest($1::varchar[])"
      assert sorted_rows(query) == [{2, 1}]
    end

    test "varchar keys" do
      query = unnest_join("key_kinds", "code", ["beta"], {:array, :string})

      assert sql(query) =~ "unnest($1::varchar[])"
      assert sorted_rows(query) == [{2, 1}]
    end

    test "uuid keys from strings" do
      query = unnest_join("articles", "external_ref", [@uuid], {:array, UUID})

      assert sql(query) =~ "unnest($1::uuid[])"
      assert sorted_rows(query) == [{1, 1}]
    end

    test "citext keys match case-insensitively only with the citext type" do
      citext = unnest_join("users", "email", ["a@x.com"], {:array, CitextType})
      varchar = unnest_join("users", "email", ["a@x.com"], {:array, :string})

      assert sql(citext) =~ "unnest($1::citext[])"
      assert sorted_rows(citext) == [{1, 1}]
      assert sorted_rows(varchar) == []
    end

    test "enum keys as varchar[] joined on the column cast to text" do
      query = unnest_enum_join("articles", "status", ["review", "draft"])

      assert sql(query) =~ "unnest($1::varchar[])"
      assert sql(query) =~ ~s|."status"::text = |
      assert sorted_rows(query) == [{1, 2}, {3, 1}]
    end
  end

  describe "mixed-type composite keys (runtime Ecto type per column)" do
    test "bigint + citext, matching mixed-case keys" do
      query =
        unnest2_join(
          "users",
          {"id", [2, 1], {:array, :integer}},
          {"email", ["B@X.COM", "a@X.com"], {:array, CitextType}}
        )

      assert sql(query) =~ "unnest($1::bigint[], $2::citext[])"
      assert sorted_rows(query) == [{1, 2}, {2, 1}]
    end

    test "bigint + uuid" do
      query =
        unnest2_join(
          "articles",
          {"id", [1, 2], {:array, :integer}},
          {"external_ref", [@uuid, @uuid], {:array, UUID}}
        )

      assert sql(query) =~ "unnest($1::bigint[], $2::uuid[])"
      assert sorted_rows(query) == [{1, 1}]
    end

    test "smallint + varchar" do
      query =
        unnest2_join(
          "key_kinds",
          {"rank", [3, 2], {:array, :integer}},
          {"code", ["beta", "alpha"], {:array, :string}}
        )

      assert sql(query) =~ "unnest($1::bigint[], $2::varchar[])"
      assert sorted_rows(query) == [{1, 2}, {2, 1}]
    end

    test "bigint + enum, the enum column compared as text" do
      {ids, id_type} = {[3, 1, 2], {:array, :integer}}
      {labels, label_type} = {["review", "draft", "draft"], {:array, :string}}
      {id_column, status_column} = {"id", "status"}

      query =
        from(t in table("articles"),
          join: p in fragment(@unnest2, type(^ids, ^id_type), type(^labels, ^label_type)),
          on:
            field(t, ^id_column) == p.k1 and fragment("?::text", field(t, ^status_column)) == p.k2,
          select: {field(t, ^id_column), p.idx}
        )

      assert sql(query) =~ "unnest($1::bigint[], $2::varchar[])"
      assert sorted_rows(query) == [{1, 2}, {3, 1}]
    end

    test "a dynamic cannot be a fragment argument" do
      cast = dynamic(fragment("?::citext[]", ^["a@x.com"]))

      query =
        from(t in table("users"),
          join: p in fragment(@unnest1, ^cast),
          on: field(t, ^"email") == p.k1,
          select: p.idx
        )

      assert_raise QueryError, ~r/invalid dynamic expression/, fn -> sql(query) end
    end
  end

  test "window ranking limits rows per parent" do
    parents = [2, 1]

    inner =
      from(c in table("comments"),
        join: p in fragment(@unnest1, type(^parents, {:array, :integer})),
        on: field(c, ^"article_id") == p.k1,
        select: %{
          id: field(c, ^"id"),
          idx: p.idx,
          rn: over(row_number(), partition_by: field(c, ^"article_id"), order_by: field(c, ^"id"))
        }
      )

    query = from(s in subquery(inner), where: s.rn <= ^1, order_by: [s.idx, s.rn], select: s.id)

    assert sql(query) =~ "row_number() OVER (PARTITION BY"
    assert sql(query) =~ ~s|ORDER BY s0."idx", s0."rn"|
    assert Repo.all(query) == [3, 1]
  end

  describe "lateral per-parent limit" do
    test "unnest source with a lateral subquery correlated through parent_as" do
      parents = [2, 1, 2]

      target =
        from(c in table("comments"),
          as: ^@root,
          where: field(c, ^"article_id") == field(parent_as(^@keys), :k1),
          order_by: [desc: field(c, ^"id")],
          limit: ^1,
          select: %{
            id: field(c, ^"id"),
            rn: over(row_number(), order_by: [desc: field(c, ^"id")])
          }
        )

      query =
        from(p in fragment(@unnest1, type(^parents, {:array, :integer})),
          as: ^@keys,
          inner_lateral_join: s in subquery(target),
          on: true,
          order_by: [p.idx, s.rn],
          select: {p.idx, s.id}
        )

      assert sql(query) =~ "INNER JOIN LATERAL (SELECT"
      assert sql(query) =~ ~s|WHERE (sc0."article_id" = f0."k1")|
      assert Repo.all(query) == [{1, 3}, {2, 2}, {3, 3}]
    end
  end

  describe "enum comparisons in the enum's own type" do
    test "a parameter cast to the schema-qualified enum type" do
      query =
        from(a in table("articles"),
          where:
            field(a, ^"status") ==
              fragment("?::?.?", ^"review", identifier(^"public"), identifier(^"article_status")),
          select: field(a, ^"id")
        )

      assert sql(query) =~ ~s|."status" = $1::"public"."article_status"|
      assert Repo.all(query) == [3]
    end

    test "membership against an array cast to the enum array type" do
      query =
        from(a in table("articles"),
          where:
            fragment(
              "? = ANY(?::?.?[])",
              field(a, ^"status"),
              ^["draft", "review"],
              identifier(^"public"),
              identifier(^"article_status")
            ),
          select: field(a, ^"id")
        )

      assert sql(query) =~ ~s|= ANY($1::"public"."article_status"[])|
      assert sorted_rows(query) == [1, 3]
    end
  end

  describe "scalar comparisons with session strings" do
    test "enum column against an untyped parameter" do
      status = "draft"

      query =
        from(a in table("articles"),
          where: field(a, ^"status") == ^status,
          select: field(a, ^"id")
        )

      assert sql(query) =~ ~s|."status" = $1)|
      assert sorted_rows(query) == [1]
    end

    test "enum column against a text-cast column" do
      status = "review"

      query =
        from(a in table("articles"),
          where: fragment("?::text", field(a, ^"status")) == type(^status, :string),
          select: field(a, ^"id")
        )

      assert sorted_rows(query) == [3]
    end

    test "enum column against a varchar parameter fails in Postgres" do
      status = "draft"

      query =
        from(a in table("articles"),
          where: field(a, ^"status") == type(^status, :string),
          select: field(a, ^"id")
        )

      assert %Error{postgres: %{code: :undefined_function}} =
               catch_error(Repo.all(query))
    end

    test "invalid enum labels fail in Postgres, so Elixir must reject them first" do
      status = "nope"

      query =
        from(a in table("articles"),
          where: field(a, ^"status") == ^status,
          select: field(a, ^"id")
        )

      assert %Error{postgres: %{code: :invalid_text_representation}} =
               catch_error(Repo.all(query))
    end

    test "citext column against a citext-cast parameter" do
      email = "a@x.com"

      citext =
        from(u in table("users"),
          where: field(u, ^"email") == fragment("?::citext", ^email),
          select: field(u, ^"id")
        )

      varchar =
        from(u in table("users"),
          where: field(u, ^"email") == type(^email, :string),
          select: field(u, ^"id")
        )

      assert sorted_rows(citext) == [1]
      assert sorted_rows(varchar) == []
    end

    test "uuid column against a string parameter" do
      ref = @uuid

      query =
        from(a in table("articles"),
          where: field(a, ^"external_ref") == type(^ref, UUID),
          select: field(a, ^"id")
        )

      assert sql(query) =~ "$1::uuid"
      assert sorted_rows(query) == [1]
    end
  end

  describe "scalar comparisons on varchar, smallint and bpchar" do
    test "varchar column against a string parameter" do
      code = "beta"

      query =
        from(k in table("key_kinds"),
          where: field(k, ^"code") == type(^code, :string),
          select: field(k, ^"id")
        )

      assert sql(query) =~ ~s|."code" = $1::varchar|
      assert sorted_rows(query) == [2]
    end

    test "smallint column against an integer parameter" do
      rank = 2

      query =
        from(k in table("key_kinds"),
          where: field(k, ^"rank") == type(^rank, :integer),
          select: field(k, ^"id")
        )

      assert sql(query) =~ ~s|."rank" = $1::bigint|
      assert sorted_rows(query) == [1]
    end

    test "bpchar column against a bpchar parameter uses padding semantics" do
      query = fn grade ->
        from(k in table("key_kinds"),
          where: field(k, ^"grade") == fragment("?::bpchar", ^grade),
          select: field(k, ^"id")
        )
      end

      assert sql(query.("a")) =~ ~s|."grade" = $1::bpchar|
      assert sorted_rows(query.("a")) == [1]
      assert sorted_rows(query.("a ")) == [1]
    end
  end

  describe "null-aware _eq/_neq with a nil literal" do
    test "== ^nil raises" do
      value = nil

      assert_raise ArgumentError, fn ->
        from(a in table("articles"), where: field(a, ^"external_ref") == ^value) |> sql()
      end
    end

    test "three-valued forms on nullable columns never turn true under NOT" do
      unknown = dynamic(fragment("NULL::boolean"))
      eq = dynamic([a], is_nil(field(a, ^"external_ref")) or ^unknown)
      neq = dynamic([a], not is_nil(field(a, ^"external_ref")) or ^unknown)

      query = fn condition ->
        from(a in table("articles"), where: ^condition, select: field(a, ^"id"))
      end

      assert sql(query.(eq)) =~ ~s|."external_ref" IS NULL) OR NULL::boolean)|
      assert sorted_rows(query.(eq)) == [2, 3]
      assert sorted_rows(query.(neq)) == [1]
      assert sorted_rows(query.(dynamic(not (^eq)))) == []
      assert sorted_rows(query.(dynamic(not (^neq)))) == []
    end

    test "NULL::boolean on non-null columns matches nothing, negated or not" do
      unknown = dynamic(fragment("NULL::boolean"))

      query = fn condition ->
        from(a in table("articles"), where: ^condition, select: field(a, ^"id"))
      end

      assert sql(query.(unknown)) =~ "WHERE (NULL::boolean)"
      assert sorted_rows(query.(unknown)) == []
      assert sorted_rows(query.(dynamic(not (^unknown)))) == []
    end
  end
end

defmodule Authzura.Parity.VerdictTest do
  @moduledoc """
  The differential suite's verdict (`Authzura.Parity.Verdict`) and saved
  cases (`Authzura.Gen.Save`), against hand-built results: no database and
  no Hasura. Every planted leak here must classify as `:leak`.
  """

  use ExUnit.Case, async: true

  alias Authzura.Gen.Save
  alias Authzura.Model.{Column, Relationship, Table}
  alias Authzura.Parity.{Compare, Read, Verdict}
  alias Authzura.Test.CoverageMap

  @articles {"public", "articles"}
  @users {"public", "users"}
  @comments {"public", "comments"}
  @replies {"public", "replies"}
  @likes {"public", "likes"}
  @tags {"public", "tags"}
  @order {"public", "Order"}

  @tables %{
    @articles => %Table{
      schema: "public",
      name: "articles",
      primary_key: ["id"],
      columns: %{
        "id" => %Column{name: "id", base_kind: :integer, pg_type: "t", ecto_type: :any},
        "title" => %Column{name: "title", base_kind: :text, pg_type: "t", ecto_type: :any},
        "author_id" => %Column{
          name: "author_id",
          base_kind: :integer,
          pg_type: "t",
          ecto_type: :any
        }
      },
      relationships: %{
        "author" => %Relationship{
          name: "author",
          kind: :object,
          target: @users,
          mapping: [{"author_id", "id"}]
        },
        "comments" => %Relationship{
          name: "comments",
          kind: :array,
          target: @comments,
          mapping: [{"id", "article_id"}]
        }
      }
    },
    @users => %Table{
      schema: "public",
      name: "users",
      primary_key: ["id"],
      columns: %{
        "id" => %Column{name: "id", base_kind: :integer, pg_type: "t", ecto_type: :any},
        "salary" => %Column{name: "salary", base_kind: :numeric, pg_type: "t", ecto_type: :any}
      }
    },
    @comments => %Table{
      schema: "public",
      name: "comments",
      primary_key: ["id"],
      columns: %{
        "id" => %Column{name: "id", base_kind: :integer, pg_type: "t", ecto_type: :any},
        "body" => %Column{name: "body", base_kind: :text, pg_type: "t", ecto_type: :any}
      },
      relationships: %{
        "replies" => %Relationship{
          name: "replies",
          kind: :array,
          target: @replies,
          mapping: [{"id", "comment_id"}]
        }
      }
    },
    @replies => %Table{
      schema: "public",
      name: "replies",
      primary_key: ["id"],
      columns: %{"id" => %Column{name: "id", base_kind: :integer, pg_type: "t", ecto_type: :any}},
      relationships: %{
        "likes" => %Relationship{
          name: "likes",
          kind: :array,
          target: @likes,
          mapping: [{"id", "reply_id"}]
        }
      }
    },
    @likes => %Table{
      schema: "public",
      name: "likes",
      primary_key: ["id"],
      columns: %{"id" => %Column{name: "id", base_kind: :integer, pg_type: "t", ecto_type: :any}}
    },
    @tags => %Table{
      schema: "public",
      name: "tags",
      columns: %{"t" => %Column{name: "t", base_kind: :text, pg_type: "t", ecto_type: :any}}
    },
    @order => %Table{
      schema: "public",
      name: "Order",
      primary_key: ["Id"],
      columns: %{
        "Id" => %Column{name: "Id", base_kind: :integer, pg_type: "t", ecto_type: :any},
        "line item" => %Column{name: "line item", base_kind: :text, pg_type: "t", ecto_type: :any}
      }
    }
  }

  describe "classify/3: leaks" do
    test "Hasura denies, Authzura grants (even []) is a leak" do
      assert {:leak, _} =
               Verdict.classify(ctx(), {:error, "validation-failed"}, {:ok, [%{"id" => 1}]})

      assert {:leak, _} = Verdict.classify(ctx(), {:error, "validation-failed"}, {:ok, []})
      assert {:leak, "LEAK" <> _} = Verdict.classify(ctx(), {:error, "x", "m"}, {:ok, []})
    end

    test "nested leaks at every shape" do
      assert {:leak, _} =
               Verdict.classify(
                 ctx(),
                 ok([%{"id" => 1, "author" => nil}]),
                 ok([%{"id" => 1, "author" => %{"id" => 2}}])
               )

      assert {:leak, _} = Verdict.classify(ctx(), ok([deep3([])]), ok([deep3([%{"id" => 9}])]))

      assert {:leak, _} =
               Verdict.classify(
                 ctx(),
                 ok([%{"id" => 1, "author" => %{"id" => 2}}]),
                 ok([%{"id" => 1, "author" => %{"id" => 2, "salary" => 1}}])
               )

      assert {:leak, _} =
               Verdict.classify(
                 ctx(pk: :none),
                 ok([%{"t" => "a"}]),
                 ok([%{"t" => "a"}, %{"t" => "a"}])
               )
    end

    test "an extra root row, a duplicated key or a value Hasura nulls is a leak" do
      assert {:leak, _} =
               Verdict.classify(ctx(), ok([article(1)]), ok([article(1), article(2)]))

      assert {:leak, _} = Verdict.classify(ctx(), ok([article(1)]), ok([article(1), article(1)]))

      assert {:leak, _} =
               Verdict.classify(
                 salary_ctx(),
                 ok([%{article(1) | "author" => %{"id" => 2, "salary" => nil}}]),
                 ok([%{article(1) | "author" => %{"id" => 2, "salary" => 10}}])
               )

      assert {:leak, _} = Verdict.classify(ctx(), ok([]), ok([article(1)]))

      assert {:leak, _} =
               Verdict.classify(
                 ctx(),
                 ok([%{article(1) | "comments" => nil}]),
                 ok([%{article(1) | "comments" => [%{"id" => 3, "replies" => []}]}])
               )
    end

    test "a leak beats a mismatch found first" do
      hasura = ok([%{article(1) | "title" => "x"}, article(2)])
      authzura = ok([article(1), %{article(2) | "author" => %{"id" => 5}}])
      assert {:leak, _} = Verdict.classify(ctx(), hasura, authzura)
    end
  end

  describe "classify/3: matches and mismatches" do
    test "equal results match, whatever each side's number encoding" do
      assert :match = Verdict.classify(ctx(), ok([article(1)]), ok([article(1)]))

      assert :match =
               Verdict.classify(
                 salary_ctx(),
                 ok([%{article(1) | "author" => %{"id" => 2, "salary" => 1.5}}]),
                 ok([%{article(1) | "author" => %{"id" => 2, "salary" => Decimal.new("1.50")}}])
               )
    end

    test "a changed value, nil vs [], or a sampling ctx is a mismatch" do
      assert {:mismatch, _} =
               Verdict.classify(ctx(), ok([article(1)]), ok([%{article(1) | "title" => "other"}]))

      assert {:mismatch, _} =
               Verdict.classify(
                 ctx(),
                 ok([%{article(1) | "comments" => []}]),
                 ok([%{article(1) | "comments" => nil}])
               )

      assert {:mismatch, _} =
               Verdict.classify(
                 ctx(),
                 ok([%{article(1) | "comments" => nil}]),
                 ok([%{article(1) | "comments" => []}])
               )

      assert {:mismatch, _} = Verdict.classify(ctx(), ok([article(1)]), ok([]))

      assert {:mismatch, _} =
               Verdict.classify(ctx(sample: true), ok([article(1)]), ok([article(1)]))
    end

    test "an ordered read in another order is a mismatch" do
      ctx = ctx(order_by: [asc: :id])

      assert {:mismatch, _} =
               Verdict.classify(ctx, ok([article(1), article(2)]), ok([article(2), article(1)]))

      assert :match =
               Verdict.classify(ctx, ok([article(1), article(2)]), ok([article(1), article(2)]))
    end

    test "rows without a visible key compare as a multiset" do
      ctx = ctx(pk: :none)

      assert :match =
               Verdict.classify(
                 ctx,
                 ok([%{"t" => "a"}, %{"t" => "b"}, %{"t" => "a"}]),
                 ok([%{"t" => "b"}, %{"t" => "a"}, %{"t" => "a"}])
               )

      assert {:mismatch, _} =
               Verdict.classify(ctx, ok([%{"t" => "a"}, %{"t" => "a"}]), ok([%{"t" => "a"}]))

      assert {:leak, _} = Verdict.classify(ctx, ok([%{"t" => "a"}]), ok([%{"t" => "b"}]))
    end
  end

  describe "classify/3: the twin rule" do
    test "a limited level with a hidden key is checked against the no-limit twin" do
      ctx = ctx(pk: :none, limits: %{[] => 2})
      twin = ok([%{"t" => "a"}, %{"t" => "b"}, %{"t" => "c"}])

      assert Verdict.twin?(ctx)
      assert {:mismatch, _} = Verdict.classify(ctx, ok([%{"t" => "a"}]), ok([%{"t" => "b"}]))

      ctx = Verdict.put_twin(ctx, twin)
      assert :match = Verdict.classify(ctx, ok([%{"t" => "a"}]), ok([%{"t" => "b"}]))
      assert {:leak, _} = Verdict.classify(ctx, ok([%{"t" => "a"}]), ok([%{"t" => "z"}]))

      assert {:leak, _} =
               Verdict.classify(ctx, ok([%{"t" => "a"}]), ok([%{"t" => "b"}, %{"t" => "c"}]))

      assert {:mismatch, _} =
               Verdict.classify(ctx, ok([%{"t" => "a"}, %{"t" => "b"}]), ok([%{"t" => "c"}]))
    end

    # Containment and counts alone pass a page from the wrong place; on an
    # ordered level the order columns pin it (ties agree on them).
    test "an ordered limited level with a hidden key must show Hasura's page" do
      read = Read.new(@tags, columns: ["t"], order_by: [asc: :t], limit: 2, offset: 1)
      ctx = read |> Verdict.context(@tables) |> Verdict.put_twin(ok(tags(["a", "b", "c"])))

      assert :match = Verdict.classify(ctx, ok(tags(["b", "c"])), ok(tags(["b", "c"])))

      # Offset ignored, then the page read backwards.
      assert {:mismatch, _} = Verdict.classify(ctx, ok(tags(["b", "c"])), ok(tags(["a", "b"])))
      assert {:mismatch, _} = Verdict.classify(ctx, ok(tags(["b", "c"])), ok(tags(["c", "b"])))
    end

    test "a limited level with a visible key needs no twin" do
      refute Verdict.twin?(ctx(limits: %{[] => 2}))
    end

    test "a nested level above its limit is a leak, also below a loose level" do
      comments = Read.nested(columns: ["id"], order_by: [asc: :id])
      read = Read.new(@articles, columns: ["title"], relationships: [{"comments", comments}])
      ctx = Verdict.context(read, @tables, limits: %{[] => 5, ["comments"] => 2})
      row = fn ids -> %{"title" => "t", "comments" => Enum.map(ids, &%{"id" => &1})} end

      assert Verdict.twin?(ctx)
      ctx = Verdict.put_twin(ctx, ok([row.([1, 2, 3])]))
      assert :match = Verdict.classify(ctx, ok([row.([1, 2])]), ok([row.([1, 2])]))
      assert {:leak, _} = Verdict.classify(ctx, ok([row.([1, 2])]), ok([row.([1, 2, 3])]))
    end

    test "a null object on both sides matches whatever the twin row holds" do
      author = Read.nested(columns: ["id"])
      comments = Read.nested(columns: ["body"])

      read =
        Read.new(@articles,
          columns: ["id"],
          relationships: [{"author", author}, {"comments", comments}]
        )

      ctx = Verdict.context(read, @tables, limits: %{["comments"] => 1})

      row = fn author, bodies ->
        %{"id" => 1, "author" => author, "comments" => tags_of(bodies)}
      end

      assert Verdict.twin?(ctx)
      ctx = Verdict.put_twin(ctx, ok([row.(%{"id" => 9}, ["a", "b"])]))
      both = ok([row.(nil, ["a"])])
      assert :match = Verdict.classify(ctx, both, both)

      assert {:leak, _} =
               Verdict.classify(ctx, both, ok([row.(%{"id" => 9}, ["a"])]))
    end

    test "a keyed level above its limit is a leak" do
      ctx = ctx(limits: %{["comments"] => 1})
      comments = [%{"id" => 1, "replies" => []}, %{"id" => 2, "replies" => []}]
      both = ok([%{article(1) | "comments" => comments}])

      assert {:leak, "LEAK: comments: 2 rows, above the limit 1"} =
               Verdict.classify(ctx, both, both)
    end
  end

  describe "classify/3: errors" do
    test "Hasura grants, Authzura denies: an over-deny" do
      assert {:over_deny, _} = Verdict.classify(ctx(), ok([]), {:error, :forbidden})
    end

    test "a reviewed divergence needs both the case and the reason to match" do
      reason = {:invalid_session_value, "x-hasura-user-id", {:invalid_value, :integer}}

      assert {:reviewed_divergence, "session-cast-eager"} =
               Verdict.classify(cast_ctx("abc"), ok([]), {:error, reason})

      assert {:over_deny, _} = Verdict.classify(cast_ctx("abc"), ok([]), {:error, :forbidden})
      assert {:over_deny, _} = Verdict.classify(cast_ctx("7"), ok([]), {:error, reason})
      assert {:over_deny, _} = Verdict.classify(ctx(), ok([]), {:error, reason})
    end

    test "a reviewed divergence holds for the very variable the reason names" do
      ctx = cast_ctx("abc", %{"x-hasura-org-id" => "1"})
      on_org = {:invalid_session_value, "x-hasura-org-id", {:invalid_value, "int8"}}
      on_user = {:invalid_session_value, "x-hasura-user-id", {:invalid_value, "int8"}}

      assert {:over_deny, _} = Verdict.classify(ctx, ok([]), {:error, on_org})

      assert {:reviewed_divergence, "session-cast-eager"} =
               Verdict.classify(ctx, ok([]), {:error, on_user})

      strict = cast_ctx(" 1", %{"x-hasura-org-id" => "abc"})

      assert {:reviewed_divergence, "session-text-strict"} =
               Verdict.classify(strict, ok([]), {:error, on_user})

      assert {:reviewed_divergence, "session-cast-eager"} =
               Verdict.classify(strict, ok([]), {:error, on_org})
    end

    test "validation-failed matches only when the message names the expected field" do
      hidden = {:error, {:forbidden_columns, ["salary"]}}
      message = "field 'salary' not found in type: 'users'"

      assert :match = Verdict.classify(ctx(), {:error, "validation-failed", message}, hidden)

      assert {:mismatch, _} =
               Verdict.classify(
                 ctx(),
                 {:error, "validation-failed", "field 'title' not found in type: 'articles'"},
                 hidden
               )

      assert {:mismatch, _} = Verdict.classify(ctx(), {:error, "validation-failed"}, hidden)

      root = "field 'articles' not found in type: 'query_root'"

      assert :match =
               Verdict.classify(ctx(), {:error, "validation-failed", root}, {:error, :forbidden})

      relationship = "field 'author' not found in type: 'articles'"

      assert :match =
               Verdict.classify(
                 ctx(),
                 {:error, "validation-failed", relationship},
                 {:error, :forbidden}
               )
    end

    test "a field is named by its GraphQL name" do
      ctx = Verdict.context(Read.new(@order, columns: ["Id"]), @tables)
      message = "field 'line_item' not found in type: 'Order'"

      assert :match =
               Verdict.classify(
                 ctx,
                 {:error, "validation-failed", message},
                 {:error, {:forbidden_columns, ["line item"]}}
               )
    end

    test "an unknown column must be denied like a hidden one" do
      ctx = ctx(tags: [:unknown_column])
      message = "field 'no_such_column' not found in type: 'articles'"

      assert :match =
               Verdict.classify(
                 ctx,
                 {:error, "validation-failed", message},
                 {:error, {:forbidden_columns, ["no_such_column"]}}
               )

      assert {:mismatch, _} =
               Verdict.classify(
                 ctx,
                 {:error, "validation-failed", message},
                 {:error, {:invalid_input, {:unknown_column, "no_such_column"}}}
               )
    end

    test "mapped codes need a reason of an allowed class; unmapped codes mismatch" do
      assert :match =
               Verdict.classify(
                 ctx(),
                 {:error, "not-found", "missing session variable"},
                 {:error, {:missing_session_variable, "x-hasura-user-id"}}
               )

      assert {:mismatch, _} =
               Verdict.classify(ctx(), {:error, "not-found", "m"}, {:error, :forbidden})

      assert {:mismatch, _} =
               Verdict.classify(ctx(), {:error, "unexpected", "m"}, {:error, :forbidden})
    end

    test "the code table accepts every pairing Compare.equivalent?/2 makes" do
      for {code, reason} <- [
            {"not-found", {:missing_session_variable, "x"}},
            {"access-denied", {:invalid_session, :role_not_allowed, "r"}},
            {"data-exception", {:invalid_session_value, "x", {:invalid_value, :integer}}},
            {"invalid-jwt", {:invalid_jwt, :signature}},
            {"jwt-missing-role-claims", {:jwt_missing_role_claims, "x-hasura-default-role"}},
            {"jwt-invalid-claims", {:jwt_invalid_claims, :allowed_roles}}
          ] do
        assert :match = Verdict.classify(ctx(), {:error, code, "m"}, {:error, reason})
      end
    end
  end

  describe "Compare.value/2 for timestamps" do
    test "a timestamp compares by value, whatever its precision; an offset never matches" do
      assert Compare.value(~N[2024-02-07 06:30:00.000000], :timestamp) ==
               Compare.value("2024-02-07T06:30:00", :timestamp)

      assert {:type_mismatch, :timestamp, _} = Compare.value("2024-02-07T06:30:00Z", :timestamp)

      assert {:type_mismatch, :timestamp, _} =
               Compare.value("2024-02-07T06:30:00+02:00", :timestamp)
    end
  end

  describe "reviewed divergences" do
    test "each names a Divergences row of the coverage map and both predicates" do
      rows = "docs/hasura-test-coverage.md" |> CoverageMap.parse!() |> Map.fetch!(:divergences)
      cells = MapSet.new(rows, & &1.test)

      for %{id: id, coverage_row: row, case?: case?, reason?: reason?} <- Verdict.divergences() do
        assert row in cells, "#{id}: no Divergences row #{row}"
        assert is_function(case?, 2) and is_function(reason?, 1)
      end
    end
  end

  describe "Gen.Save.write!/3" do
    @tag :tmp_dir
    test "ids hash canonical JSON; a different payload under an existing id raises",
         %{tmp_dir: dir} do
      payload = payload(%{"b" => 1, "a" => [1, 2]})
      path = Save.write!(payload, "mismatch: x", %{batch: 1, request: 2}, dir: dir)

      assert Path.basename(path) =~ ~r/^gen-[0-9a-f]{16}\.json$/

      assert %{"payload" => saved, "reason" => "mismatch: x"} =
               path |> File.read!() |> Jason.decode!()

      assert saved["read"]["order_by"] == [["asc", "id"]]
      assert saved["read"]["table"] == ["public", "articles"]

      reordered = payload(%{"a" => [1, 2], "b" => 1})
      assert Save.write!(reordered, "again", %{batch: 1, request: 3}, dir: dir) == path

      File.write!(path, Jason.encode!(%{"payload" => %{"other" => true}}))
      assert_raise RuntimeError, ~r/differs/, fn -> Save.write!(payload, "x", %{}, dir: dir) end
    end
  end

  # Helpers.

  defp ok(rows), do: {:ok, rows}

  defp article(id), do: %{"id" => id, "title" => "t#{id}", "author" => nil, "comments" => []}

  defp deep3(likes),
    do: %{
      "id" => 1,
      "title" => "t",
      "author" => nil,
      "comments" => [%{"id" => 1, "replies" => [%{"id" => 1, "likes" => likes}]}]
    }

  # Articles with their author and comments (replies, likes), or the
  # keyless `tags` with `pk: :none`.
  defp tags(values), do: Enum.map(values, &%{"t" => &1})

  defp tags_of(bodies), do: Enum.map(bodies, &%{"body" => &1})

  defp ctx(opts \\ []), do: ctx(Keyword.get(opts, :pk), opts)

  defp ctx(:none, opts), do: @tags |> Read.new(columns: ["t"]) |> context(opts)

  defp ctx(_pk, opts) do
    likes = Read.nested(columns: ["id"])
    replies = Read.nested(columns: ["id"], relationships: [{"likes", likes}])
    comments = Read.nested(columns: ["id"], relationships: [{"replies", replies}])
    author = Read.nested(columns: ["id"])

    @articles
    |> Read.new(
      columns: ["id", "title"],
      order_by: opts[:order_by],
      relationships: [{"author", author}, {"comments", comments}]
    )
    |> context(opts)
  end

  defp context(read, opts) do
    read = if opts[:sample], do: %{read | sample: {@tags, %{}}}, else: read
    case = if opts[:tags], do: %{tags: opts[:tags], auth: {:jwt, %{}, nil}}
    Verdict.context(read, @tables, limits: Keyword.get(opts, :limits, %{}), case: case)
  end

  # The author selects `salary` too.
  defp salary_ctx do
    author = Read.nested(columns: ["id", "salary"])

    @articles
    |> Read.new(
      columns: ["id", "title"],
      relationships: [{"author", author}, {"comments", Read.nested(columns: ["id"])}]
    )
    |> Verdict.context(@tables)
  end

  defp cast_ctx(user_id, vars \\ %{}) do
    session = %{
      "x-hasura-user-id" => user_id,
      "x-hasura-default-role" => "gen_1",
      "x-hasura-allowed-roles" => ["gen_1"]
    }

    claims = %{"https://hasura.io/jwt/claims" => Map.merge(session, vars)}

    case = %{tags: [:uncastable_value], auth: {:jwt, claims, nil}}
    Verdict.context(Read.new(@articles, columns: ["id"]), @tables, case: case)
  end

  defp payload(permission) do
    %{
      read: Read.new(@articles, columns: ["id"], order_by: [asc: :id]),
      auth: {:jwt, %{"sub" => "1"}, "gen_1"},
      permissions: %{"gen_1" => %{@articles => permission}},
      relationships: []
    }
  end
end

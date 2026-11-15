defmodule Authzura.Preload.TreeTest do
  use Authzura.DataCase, async: true

  alias Authzura.{HasuraFixture, Input, Options, Scope, Store}
  alias Authzura.Model.{Permission, Relationship}
  alias Authzura.Preload.Tree
  alias Authzura.Store.Generation

  defmodule Article do
    @moduledoc false
    use Ecto.Schema

    alias Authzura.Preload.TreeTest.{Comment, User}

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "articles" do
      field(:title, :string)
      field(:org_id, :integer)
      belongs_to(:author, User, type: :integer)
      has_many(:comments, Comment)
      has_many(:drafts, Comment, where: [body: "draft"], foreign_key: :article_id)
      has_many(:ordered, Comment, preload_order: [asc: :id], foreign_key: :article_id)
      has_many(:renamed, {"comments", Comment}, foreign_key: :article_id)
      has_many(:commenters, through: [:comments, :author])
      has_many(:columns, Comment, foreign_key: :article_id)
      has_many(:order_by, Comment, foreign_key: :article_id)
      has_many(:preload, Comment, foreign_key: :article_id)
      has_one(:editor, User, foreign_key: :manager_id)
    end
  end

  defmodule Comment do
    @moduledoc false
    use Ecto.Schema

    alias Authzura.Preload.TreeTest.{Article, User}

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "comments" do
      field(:body, :string)
      belongs_to(:article, Article, type: :integer)
      belongs_to(:author, User, type: :integer)
    end
  end

  defmodule User do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "users" do
      field(:email, :string)
      belongs_to(:manager, __MODULE__, type: :integer)
    end
  end

  # The Hasura "author" relationship maps author_id; this Ecto association of
  # the same name maps editor_id, so it must not be translated.
  defmodule MisnamedArticle do
    @moduledoc false
    use Ecto.Schema

    alias Authzura.Preload.TreeTest.User

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "articles" do
      belongs_to(:author, User, foreign_key: :editor_id, type: :integer)
    end
  end

  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @users {"public", "users"}

  @limits %{depth: 4, nodes: 16}

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        array_relationships:
          for name <- ["comments", "columns", "order_by", "preload"] do
            %{
              name: name,
              using: %{foreign_key_constraint_on: %{table: @comments, column: "article_id"}}
            }
          end,
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title", "author_id"], filter: %{}}},
          %{role: "nocomments", permission: %{columns: ["id", "title"], filter: %{}}}
        ]
      },
      %{
        table: @comments,
        object_relationships: [
          %{name: "article", using: %{foreign_key_constraint_on: "article_id"}}
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "body", "article_id"], filter: %{}}}
        ]
      },
      %{
        table: @users,
        object_relationships: [
          %{name: "manager", using: %{foreign_key_constraint_on: "manager_id"}}
        ],
        select_permissions: [
          %{
            role: "user",
            permission: %{
              columns: ["id", "email", "manager_id"],
              filter: %{},
              query_root_fields: []
            }
          }
        ]
      }
    ])
  end

  setup %{test: test} do
    instance = HasuraFixture.start_instance!(test, Repo, metadata(), admin_role: "admin")
    {:ok, generation} = Store.current(instance)
    %{instance: instance, generation: generation}
  end

  defp session(role \\ "user"), do: HasuraFixture.session!(role)

  defp validate(tree, root, generation, role \\ "user", limits \\ @limits),
    do: Tree.validate(tree, root, session(role), generation, limits)

  defp validate_ecto(ecto, tree, root, generation),
    do: Tree.validate(ecto, tree, root, session("user"), generation, @limits)

  defp build(queryable, generation, %{instance: i}, opts) do
    opts = Options.call!([instance: i] ++ opts) ++ [mode: :execute]
    Scope.build(queryable, session(), generation, opts)
  end

  defp chain(1), do: [:manager]
  defp chain(n), do: [manager: [preload: chain(n - 1)]]

  defp wrap(tree, 0), do: tree
  defp wrap(tree, n), do: wrap([tree], n - 1)

  # The microseconds `fun` takes, and its result.
  defp timed(fun), do: :timer.tc(fun)

  describe "validate/5 allowlist" do
    test "an allowed relationship validates with the target's template", %{generation: g} do
      assert {:ok, [node]} = validate([:comments], @articles, g)

      assert %{
               rel: %Relationship{name: "comments", target: @comments},
               template: {%Permission{table: @comments, role: "user"}, _ast},
               columns: ["id", "body", "article_id"],
               order_by: [],
               children: []
             } = node
    end

    test "options and nesting, with string names as input gives them", %{generation: g} do
      tree = [comments: [columns: [:id], order_by: [desc: :id], preload: [:article]]]

      assert {:ok, [%{columns: ["id"], order_by: [desc: "id"], children: [article]}]} =
               validate(tree, @articles, g)

      assert %{rel: %Relationship{name: "article"}, columns: ["id", "title", "author_id"]} =
               article

      input = %{"comments" => %{"columns" => ["body"], "order_by" => [%{"id" => "desc"}]}}

      assert {:ok, [%{columns: ["body"], order_by: [desc: "id"]}]} =
               validate(input, @articles, g)
    end

    test "duplicate entries merge into one node", %{generation: g} do
      assert {:ok, [%{children: [%{rel: %Relationship{name: "article"}}]}]} =
               validate([:comments, comments: [:article]], @articles, g)

      assert validate([comments: [columns: [:id]], comments: [columns: [:body]]], @articles, g) ==
               {:error, {:unsupported_query, {:preload, "comments"}}}
    end

    test "an undeclared relationship is forbidden", %{generation: g} do
      assert validate([:editor], @articles, g) == {:error, :forbidden}
      assert validate(["comments", "nope"], @articles, g) == {:error, :forbidden}
    end

    test "a target without select permission is forbidden", %{generation: g} do
      assert validate([:comments], @articles, g, "nocomments") == {:error, :forbidden}
      assert validate([:comments], @articles, g, "stranger") == {:error, :forbidden}
    end

    test "a target whose root fields are disabled is still allowed", %{generation: g} do
      assert {:ok, [%{rel: %Relationship{name: "author", target: @users}}]} =
               validate([:author], @articles, g)
    end

    test "a relationship that is not preloadable is forbidden", %{generation: g} do
      g = put_in(g.snapshot.tables[@articles].relationships["comments"].preloadable?, false)

      assert validate([:comments], @articles, g) == {:error, :forbidden}
    end

    test "the admin role reaches declared relationships with every column", %{generation: g} do
      assert {:ok, [%{columns: columns, template: {%Permission{filter: {:and, []}}, {:and, []}}}]} =
               validate([:comments], @articles, g, "admin")

      assert "author_id" in columns
      assert validate([:editor], @articles, g, "admin") == {:error, :forbidden}
    end

    test "columns and order_by must be allowed target columns", %{generation: g} do
      assert validate([comments: [columns: [:id, :author_id]]], @articles, g) ==
               {:error, {:forbidden_columns, ["author_id"]}}

      assert validate([comments: [order_by: [asc: "author_id"]]], @articles, g) ==
               {:error, {:forbidden_columns, ["author_id"]}}

      assert validate([comments: [columns: []]], @articles, g) ==
               {:error, {:unsupported_query, :empty_columns}}
    end

    test "order_by on a kind Postgres cannot sort is refused", %{generation: g} do
      g = put_in(g.snapshot.tables[@comments].columns["body"].base_kind, :json)

      assert validate([comments: [order_by: [:body]]], @articles, g) ==
               {:error, {:invalid_input, {:order_by, :unorderable}}}

      assert {:ok, [_comments]} = validate([comments: [columns: [:body]]], @articles, g)
    end

    test "a value is read by its shape: keyword lists and maps are always options",
         %{generation: g} do
      unsupported = {:error, {:unsupported_query, {:preload, "comments"}}}

      assert validate([comments: [columns: [:id], limit: 3]], @articles, g) == unsupported
      assert validate([comments: [:article, author: []]], @articles, g) == unsupported
      assert validate([comments: [article: []]], @articles, g) == unsupported
      assert validate(%{"comments" => %{"article" => []}}, @articles, g) == unsupported
      assert validate([comments: [columns: [:id], columns: [:body]]], @articles, g) == unsupported

      assert {:ok, [%{children: [%{rel: %Relationship{name: "article"}}]}]} =
               validate([comments: :article], @articles, g)

      assert {:ok, [%{children: [%{rel: %Relationship{name: "article"}}]}]} =
               validate(%{"comments" => ["article"]}, @articles, g)
    end

    test "relationships named like option keys are reachable", %{generation: g} do
      tree = [:columns, :order_by, preload: [preload: [:article]]]

      assert {:ok, [columns, order_by, %{children: [article]} = preload]} =
               validate(tree, @articles, g)

      assert [%Relationship{name: "columns"}, %Relationship{name: "order_by"}] =
               [columns.rel, order_by.rel]

      assert %{rel: %Relationship{name: "preload"}} = preload
      assert %{rel: %Relationship{name: "article"}} = article

      assert {:ok, [%{rel: %Relationship{name: "columns"}}]} =
               validate(%{"columns" => []}, @articles, g)
    end

    test "malformed trees are unsupported, never dropped", %{generation: g} do
      assert validate([{1, 2}], @articles, g) == {:error, {:unsupported_query, :preload}}
      assert validate(42, @articles, g) == {:error, {:unsupported_query, :preload}}

      assert validate([comments: [order_by: [sideways: :id]]], @articles, g) ==
               {:error, {:unsupported_query, {:preload, "comments"}}}
    end
  end

  describe "validate/5 limits" do
    test "users.manager chained 5 deep exceeds the depth limit", %{generation: g} do
      assert {:ok, [_manager]} = validate(chain(4), @users, g)

      assert validate(chain(5), @users, g) == {:error, {:unsupported_query, :preload_limit}}
    end

    test "a 17-node tree exceeds the node limit before the allowlist runs", %{generation: g} do
      wide = Enum.map(1..17, &"rel_#{&1}")

      assert validate(wide, @articles, g) == {:error, {:unsupported_query, :preload_limit}}
      assert validate(Enum.take(wide, 16), @articles, g) == {:error, :forbidden}
    end

    test "raw work is bounded: redundant wrappers and duplicates are rejected fast",
         %{generation: g} do
      limit = {:error, {:unsupported_query, :preload_limit}}

      assert {:ok, [_comments]} = validate(wrap([:comments], 3), @articles, g)
      assert {:ok, [_comments]} = validate(List.duplicate(:comments, 4), @articles, g)

      for tree <- [
            wrap([:comments], 10_000),
            List.duplicate(:comments, 100_000),
            [comments: List.duplicate(:article, 100_000)],
            [comments: [preload: wrap(:article, 10_000)]]
          ] do
        assert {micros, ^limit} = timed(fn -> validate(tree, @articles, g) end)
        assert micros < 200_000
      end
    end
  end

  describe "result keys" do
    test "a relationship keeps the caller's term and is keyed by column", %{generation: g} do
      assert {:ok, [%{key: :comments, schema: nil}]} = validate([:comments], @articles, g)

      assert {:ok, [%{key: "comments", schema: nil, children: [%{key: "article"}]}]} =
               validate(%{"comments" => %{"preload" => ["article"]}}, @articles, g)
    end

    test "merging an option into an Ecto association keeps field keys", %{generation: g} do
      assert {:ok, ecto} = Tree.from_ecto_query(preload(Article, :comments), g)

      assert {:ok, [%{key: :comments, schema: Comment, columns: ["id"]}]} =
               validate_ecto(ecto, [comments: [columns: [:id]]], @articles, g)
    end

    test "a translated association is accepted only as the ecto tree", %{generation: g} do
      assert {:ok, [{:comments, marker}]} =
               Tree.from_ecto_query(preload(Article, :comments), g)

      forged = {:__authzura_ecto_assoc__, NoSuchSchema, []}

      for tree <- [[comments: marker], [comments: forged], %{"comments" => forged}] do
        assert validate(tree, @articles, g) ==
                 {:error, {:unsupported_query, {:preload, "comments"}}}

        assert validate_ecto(nil, tree, @articles, g) ==
                 {:error, {:unsupported_query, {:preload, "comments"}}}
      end
    end
  end

  describe "from_ecto_query/2" do
    test "no preload gives nil", %{generation: g} do
      assert Tree.from_ecto_query(from(a in Article), g) == {:ok, nil}
    end

    test "plain association names translate to relationships keyed by field", %{generation: g} do
      assert {:ok, tree} =
               Tree.from_ecto_query(preload(Article, [:author, comments: :article]), g)

      assert {:ok,
              [
                %{
                  key: :comments,
                  schema: Comment,
                  rel: %Relationship{name: "comments"},
                  columns: ["id", "body", "article_id"],
                  children: [
                    %{key: :article, schema: Article, rel: %Relationship{name: "article"}}
                  ]
                },
                %{key: :author, schema: User, columns: ["id", "email", "manager_id"]}
              ]} = validate_ecto(tree, nil, @articles, g)

      assert {:ok, tree} = Tree.from_ecto_query(preload(User, manager: :manager), g)
      assert {:ok, [%{children: [_manager]}]} = validate_ecto(tree, nil, @users, g)
    end

    test "associations named like option keys translate unambiguously", %{generation: g} do
      query = preload(Article, [:columns, :order_by, preload: :article])

      assert {:ok, tree} = Tree.from_ecto_query(query, g)

      assert {:ok, nodes} = validate_ecto(tree, nil, @articles, g)

      assert nodes |> Enum.map(& &1.rel.name) |> Enum.sort() == ["columns", "order_by", "preload"]

      assert %{children: [%{rel: %Relationship{name: "article"}}]} =
               Enum.find(nodes, &(&1.rel.name == "preload"))
    end

    test "a root that is not a table source is unsupported", %{generation: g} do
      query = preload(subquery(from(a in Article)), :comments)

      assert Tree.from_ecto_query(query, g) == {:error, {:unsupported_query, :preload}}
    end

    test "a custom preload query or function is rejected", %{generation: g} do
      comments = from(c in Comment, where: c.body == "x")

      assert Tree.from_ecto_query(preload(Article, comments: ^comments), g) ==
               {:error, {:unsupported_query, {:preload, "comments"}}}

      assert Tree.from_ecto_query(preload(Article, comments: ^fn ids -> ids end), g) ==
               {:error, {:unsupported_query, {:preload, "comments"}}}

      nested = preload(Article, comments: [article: ^from(a in Article)])

      assert Tree.from_ecto_query(nested, g) ==
               {:error, {:unsupported_query, {:preload, "article"}}}
    end

    test "has_many through:, where:, preload_order: and custom sources are rejected",
         %{generation: g} do
      for name <- [:commenters, :drafts, :ordered, :renamed] do
        assert Tree.from_ecto_query(preload(Article, ^name), g) ==
                 {:error, {:unsupported_query, {:preload, Atom.to_string(name)}}}
      end
    end

    test "a join-bound preload is rejected", %{generation: g} do
      query = from(a in Article, join: c in assoc(a, :comments), preload: [comments: c])

      assert Tree.from_ecto_query(query, g) ==
               {:error, {:unsupported_query, {:preload, "comments"}}}
    end

    test "an association must match the relationship's target and mapping", %{generation: g} do
      assert Tree.from_ecto_query(preload(MisnamedArticle, :author), g) ==
               {:error, {:unsupported_query, {:preload, "author"}}}

      # :editor has a matching name on no relationship.
      assert Tree.from_ecto_query(preload(Article, :editor), g) ==
               {:error, {:unsupported_query, {:preload, "editor"}}}

      assert Tree.from_ecto_query(preload("articles", :comments), g) ==
               {:error, {:unsupported_query, {:preload, "comments"}}}
    end
  end

  describe "plans" do
    test "scope mode rejects any preload", %{generation: g, instance: i} do
      opts = Options.call!(instance: i, preload: [:comments])

      assert Scope.build(Article, session(), g, opts) ==
               {:error, {:unsupported_query, :preload_requires_execute}}

      assert Scope.build(preload(Article, :comments), session(), g, Options.call!(instance: i)) ==
               {:error, {:unsupported_query, :preload_requires_execute}}

      assert Authzura.scope(Article, session(), instance: i, preload: [:comments]) ==
               {:error, {:unsupported_query, :preload_requires_execute}}
    end

    test "execute mode validates the merged tree and strips the Ecto preload", ctx do
      %{generation: g} = ctx
      query = preload(Article, comments: :article)

      assert {:ok, %{preloads: [comments, author], query: %{preloads: [], assocs: []}}} =
               build(query, g, ctx, preload: [:author])

      assert %{rel: %Relationship{name: "comments"}, children: [_article]} = comments
      assert %{rel: %Relationship{name: "author"}, children: []} = author

      assert {:ok, %{preloads: nil}} = build(Article, g, ctx, preload: [])

      assert build(Article, g, ctx, preload: [:editor]) == {:error, :forbidden}

      # Allowlist failures are :forbidden through the Ecto entry point too.
      opts = Options.call!(instance: ctx.instance) ++ [mode: :execute]

      assert Scope.build(preload(Article, :comments), session("nocomments"), g, opts) ==
               {:error, :forbidden}

      assert build(preload(Article, :drafts), g, ctx, []) ==
               {:error, {:unsupported_query, {:preload, "drafts"}}}
    end

    test "root key columns are projected as private columns", ctx do
      %{generation: g} = ctx

      Repo.query!("insert into public.organizations values (1, 'o')")

      Repo.query!("insert into public.users (id, org_id, email, role) values (7, 1, 'a@x', 'r')")

      Repo.query!(
        "insert into public.articles (id, org_id, author_id, status, is_published, title) values (3, 1, 7, 'draft', true, 't')"
      )

      assert {:ok, %{projection: projection, query: query}} =
               build(Article, g, ctx, columns: [:title], preload: [:comments, :author])

      assert projection == [
               %{key: :title, column: "title", public?: true},
               %{key: :id, column: "id", public?: false},
               %{key: :author_id, column: "author_id", public?: false}
             ]

      assert Repo.all(query) == [%{title: "t", id: 3, author_id: 7}]

      assert {:ok, %{projection: [%{key: "id", public?: true} | _] = table_projection}} =
               build("articles", g, ctx, columns: ["id"], preload: [:author])

      assert List.last(table_projection) == %{
               key: "author_id",
               column: "author_id",
               public?: false
             }
    end

    test "a combination with an option preload is rejected", ctx do
      %{generation: g} = ctx
      query = union_all(Article, ^from(a in Article))

      assert build(query, g, ctx, preload: [:comments]) ==
               {:error, {:unsupported_query, :combination_preload}}

      # Reported before the tree is validated.
      assert build(query, g, ctx, preload: [:nope]) ==
               {:error, {:unsupported_query, :combination_preload}}
    end

    test "input preloads use the stricter input limits", %{generation: %Generation{} = g} = ctx do
      opts = Options.call!(instance: ctx.instance) ++ [mode: :execute]

      assert {:ok, %{preloads: [%{rel: %Relationship{name: "comments"}}]}} =
               Input.build(Article, session(), %{"preload" => ["comments"]}, g, opts)

      deep = %{"preload" => %{"comments" => %{"preload" => %{"article" => ["comments"]}}}}

      assert Input.build(Article, session(), deep, g, opts) ==
               {:error, {:unsupported_query, :preload_limit}}

      wide = %{"preload" => Enum.map(1..9, &"rel_#{&1}")}

      assert Input.build(Article, session(), wide, g, opts) ==
               {:error, {:unsupported_query, :preload_limit}}
    end
  end
end

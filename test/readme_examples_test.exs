defmodule Authzura.ReadmeExamplesTest do
  @moduledoc """
  Runs every Elixir example of README.md and docs/guides/*.md against the
  fixture database.

  The examples are written for `MyApp`; `@names` maps them onto the test
  fixtures, and the blocks run in document order (the README, then the guides
  in `@guides` order), sharing their bindings.
  Blocks that are configuration, not code to run, are listed in `@static`
  and checked on their own. A block in neither list fails the test, so a new
  example cannot be added without being run here.
  """

  use Authzura.CommittedCase

  alias Authzura.{HasuraFixture, Options}
  alias Authzura.Test.Schemas.Article

  @guides ~w(configuration querying security compatibility)
  @guide_paths Enum.map(@guides, &"docs/guides/#{&1}.md")
  @configuration File.read!("docs/guides/configuration.md")
  @documents Enum.map(["README.md" | @guide_paths], &File.read!/1)

  @instance Authzura.ReadmeExamples
  @handler Authzura.ReadmeExamples.Telemetry

  @names [
    {"MyApp.Repo", "Authzura.Test.Repo"},
    {"MyApp.Authz", inspect(@instance)},
    {"MyApp.Article", "Authzura.Test.Schemas.Article"},
    {"MyApp.Telemetry", inspect(@handler)}
  ]

  # Blocks that configure the host application, by their first line.
  @static ["def deps do", "children = [", "config :my_app"]

  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @users {"public", "users"}

  @blocks Enum.flat_map(@documents, fn document ->
            ~r/```elixir\n(.*?)```/s
            |> Regex.scan(document, capture: :all_but_first)
            |> List.flatten()
          end)

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        array_relationships: [
          %{
            name: "comments",
            using: %{foreign_key_constraint_on: %{table: @comments, column: "article_id"}}
          }
        ],
        select_permissions:
          HasuraFixture.select_permissions(
            "user",
            ["id", "title", "status", "author_id", "org_id"],
            %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}
          )
      },
      %{
        table: @users,
        select_permissions: HasuraFixture.select_permissions("user", ["id", "email"])
      },
      %{
        table: @comments,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions:
          HasuraFixture.select_permissions("user", ["id", "body", "article_id", "author_id"])
      }
    ])
  end

  setup do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one'), (2, 'two')",
        "insert into public.users (id, org_id, email, role) values (1, 1, 'a@x.com', 'editor')",
        """
        insert into public.articles (id, org_id, author_id, status, is_published, title) values
          (1, 1, 1, 'draft', false, 'one'),
          (2, 1, 1, 'published', true, 'two'),
          (3, 2, 1, 'draft', false, 'three')
        """,
        """
        insert into public.comments (id, article_id, author_id, body) values
          (10, 1, 1, 'first'), (11, 1, 1, 'second')
        """
      ],
      &Repo.query!/1
    )

    HasuraFixture.put_metadata!(Repo, metadata())
    start_supervised!({Authzura, name: @instance, repo: Repo, poll_interval: nil})
    :ok = Authzura.reload(@instance)
    on_exit(fn -> :telemetry.detach("authzura-log") end)
  end

  defp substitute(block),
    do: Enum.reduce(@names, block, fn {from, to}, code -> String.replace(code, from, to) end)

  defp static?(block), do: Enum.any?(@static, &String.starts_with?(block, &1))

  defp signed_token(secret) do
    claims = %{
      "https://hasura.io/jwt/claims" => %{
        "x-hasura-allowed-roles" => ["user"],
        "x-hasura-default-role" => "user",
        "x-hasura-org-id" => "1"
      }
    }

    {_header, token} =
      secret
      |> JOSE.JWK.from_oct()
      |> JOSE.JWT.sign(%{"alg" => "HS256"}, claims)
      |> JOSE.JWS.compact()

    token
  end

  defp run_blocks(binding) do
    @blocks
    |> Enum.reject(&static?/1)
    |> Enum.reduce(binding, fn block, binding ->
      {_result, binding} = block |> substitute() |> Code.eval_string(binding)
      binding
    end)
  end

  test "every example is either run here or a known static one" do
    assert Enum.count(@blocks) > Enum.count(@static)

    for prefix <- @static do
      assert Enum.any?(@blocks, &String.starts_with?(&1, prefix)), prefix
    end
  end

  test "every guide is listed here, so none escapes the examples run" do
    on_disk = "docs/guides/*.md" |> Path.wildcard() |> Enum.sort()
    assert on_disk == Enum.sort(@guide_paths)
  end

  test "the supervision and config examples make a valid child spec" do
    [config_block] = Enum.filter(@blocks, &String.starts_with?(&1, "config :my_app"))
    path = Path.join(System.tmp_dir!(), "authzura_readme_config.exs")
    File.write!(path, "import Config\n" <> substitute(config_block))
    on_exit(fn -> File.rm(path) end)

    [my_app: [{@instance, host_config}]] = Config.Reader.read!(path)
    assert host_config != []

    assert %{id: @instance, start: {Authzura.Store, :start_link, [config]}} =
             Authzura.child_spec([name: @instance, repo: Repo] ++ host_config)

    for {key, value} <- host_config, do: assert(config[key] == value)
  end

  test "the documented option defaults are the real ones" do
    defaults = Options.instance!(repo: Repo)

    rows =
      ~r/^\| `(\w+)`(?:, `(\w+)`)? \| `([^`]+)`(?:, `([^`]+)`)? \|/m
      |> Regex.scan(@configuration, capture: :all_but_first)
      |> Enum.flat_map(fn [name, other, value | rest] ->
        Enum.zip([name, other], [value | rest]) |> Enum.reject(fn {n, _} -> n == "" end)
      end)

    assert Enum.map(rows, &elem(&1, 0)) ==
             ~w(poll_interval max_staleness admin_role default_prefix max_preload_depth max_preload_nodes read_only input_pattern_timeout input_index_pushdown)

    for {name, documented} <- rows do
      {value, _binding} = Code.eval_string(documented)
      assert Map.fetch!(defaults, String.to_existing_atom(name)) == value, name
    end
  end

  test "the examples run, in order, and return what the guide says" do
    secret = String.duplicate("k", 32)
    binding = run_blocks(token: signed_token(secret), secret: secret)

    assert %Authzura.Session{role: "user"} = binding[:session]
    assert binding[:session].vars["x-hasura-org-id"] == "1"

    assert [
             %{
               id: 1,
               title: "one",
               author: %{"id" => 1},
               comments: [%{"id" => 11, "body" => "second"}, %{"id" => 10, "body" => "first"}]
             }
           ] = binding[:articles]

    assert %{id: 1} = binding[:article]
    assert binding[:by_pk] == %{id: 2}
    assert Enum.map(binding[:rows], & &1[:id]) == [1]
    assert %Authzura.Model.Permission{role: "user"} = binding[:permission]
    assert "title" in binding[:columns]
    refute "internal_notes" in binding[:columns]

    assert [%{:id => 1, :title => "one", "comments" => [_, _]}] = binding[:input_rows]
    assert %Ecto.Query{} = binding[:input_query]

    assert Enum.any?(
             :telemetry.list_handlers([:authzura, :execute, :stop]),
             &(&1.id == "authzura-log")
           )

    # The handler survives a real event.
    assert {:ok, [_org_one_a, _org_one_b]} =
             Authzura.all(Article, binding[:session], instance: @instance)

    assert Enum.any?(
             :telemetry.list_handlers([:authzura, :execute, :stop]),
             &(&1.id == "authzura-log")
           )
  end
end

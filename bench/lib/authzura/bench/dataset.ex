defmodule Authzura.Bench.Dataset do
  @moduledoc """
  The benchmark's deterministic dataset. Test harness only.

  `load!/3` replaces the rows of the fixture tables `organizations`,
  `users`, `org_memberships`, `articles` and `comments` with
  `generate_series` inserts. Every pseudo-random choice is
  `hashint8extended(i, seed + salt)`, so the same scale and seed give the
  same rows on any server of the same major version, and `checksum/1`
  proves it. Numerics are multiples of 0.25, exact in a float.

  | scale | organizations | users | org_memberships | articles | comments |
  |---|---|---|---|---|---|
  | `:tiny` (tests) | 5 | 100 | 150 | 1 000 | 3 000 |
  | `:small` | 100 | 10 000 | 20 000 | 100 000 | 300 000 |
  | `:large` | 1 000 | 100 000 | 200 000 | 1 000 000 | 3 000 000 |

  The data is consistent: an article belongs to its author's organization,
  and at `:small` and `:large` every user has a membership in their own
  organization and in the next one. `:tiny` stops at 150 memberships: the
  first 75 users have both and the other 25 none (see `sizes/1`).
  """

  alias Authzura.Bench.Env

  @type scale :: :tiny | :small | :large
  @type sizes :: %{
          organizations: pos_integer(),
          users: pos_integer(),
          org_memberships: pos_integer(),
          articles: pos_integer(),
          comments: pos_integer()
        }

  @default_seed 20_261_114
  @non_negative 9_223_372_036_854_775_807

  @sizes %{
    tiny: %{organizations: 5, users: 100, articles: 1_000, comments: 3_000},
    small: %{organizations: 100, users: 10_000, articles: 100_000, comments: 300_000},
    large: %{organizations: 1_000, users: 100_000, articles: 1_000_000, comments: 3_000_000}
  }

  @tables ~w(organizations users org_memberships articles comments)

  @doc "The seed `mix authzura.bench.seed` uses."
  @spec default_seed() :: integer()
  def default_seed, do: @default_seed

  @doc """
  The row counts of `scale`. Memberships are two per user, except at
  `:tiny`, where only the first 75 users have any.
  """
  @spec sizes(scale()) :: sizes()
  def sizes(scale) do
    %{users: users} = counts = Map.fetch!(@sizes, scale)
    Map.put(counts, :org_memberships, membership_count(scale, users))
  end

  defp membership_count(:tiny, _users), do: 150
  defp membership_count(_scale, users), do: 2 * users

  @doc """
  Replaces the five tables' rows with the rows of `scale` and `seed`, in one
  transaction. Raises before writing anything unless `repo` is connected to
  the `authzura_bench` database (`Authzura.Bench.Env.check_connected!/1`).
  Run `VACUUM (ANALYZE)` afterwards (it cannot run in a transaction).
  """
  @spec load!(module(), scale(), integer()) :: :ok
  def load!(repo, scale, seed) when is_integer(seed) do
    :ok = Env.check_connected!(repo)
    sizes = sizes(scale)

    {:ok, :ok} =
      repo.transaction(
        fn ->
          sizes |> statements(seed) |> Enum.each(&repo.query!(&1, [], timeout: :infinity))
        end,
        timeout: :infinity
      )

    :ok
  end

  @doc """
  A checksum per table, `%{table => md5}`, over its row count and an
  order-independent sum of its rows' text hashes.
  """
  @spec checksum(module()) :: %{String.t() => String.t()}
  def checksum(repo) do
    Map.new(@tables, fn table ->
      %{rows: [[digest]]} =
        repo.query!(
          """
          SELECT md5(count(*)::text || ':' || coalesce(sum(hashtextextended(t::text, 0)::numeric), 0)::text)
          FROM public.#{table} t
          """,
          [],
          timeout: :infinity
        )

      {table, digest}
    end)
  end

  @doc "The row count of each table, `%{table => count}`."
  @spec counts(module()) :: %{String.t() => non_neg_integer()}
  def counts(repo) do
    Map.new(@tables, fn table ->
      %{rows: [[count]]} = repo.query!("SELECT count(*) FROM public.#{table}")
      {table, count}
    end)
  end

  defp statements(sizes, seed) do
    [
      "TRUNCATE public.comments, public.org_memberships, public.articles, public.users, public.organizations CASCADE",
      insert_organizations(sizes),
      insert_users(sizes, seed),
      insert_memberships(sizes, seed),
      insert_articles(sizes, seed),
      insert_comments(sizes, seed)
    ]
  end

  # `hashint8extended` is a stable internal Postgres function; the `&` mask
  # keeps the hash non-negative, so `%` stays in range.
  defp h(expr, seed, salt, modulus),
    do: "((hashint8extended(#{expr}::bigint, #{seed + salt}) & #{@non_negative}) % #{modulus})"

  defp insert_organizations(%{organizations: n}),
    do: "INSERT INTO public.organizations SELECT i, 'org-' || i FROM generate_series(1, #{n}) i"

  defp insert_users(%{users: n, organizations: orgs}, seed) do
    """
    INSERT INTO public.users (id, org_id, manager_id, email, role, is_admin, salary)
    SELECT i, 1 + #{h("i", seed, 1, orgs)}, NULL, 'user' || i || '@bench.test',
           (ARRAY['member', 'editor', 'admin'])[1 + #{h("i", seed, 2, 3)}],
           #{h("i", seed, 3, 50)} = 0,
           round(#{h("i", seed, 4, 40_000)}::numeric / 4, 2)
    FROM generate_series(1, #{n}) i
    """
  end

  defp insert_memberships(%{org_memberships: n, users: users, organizations: orgs}, seed) do
    """
    INSERT INTO public.org_memberships (org_id, user_id, level)
    SELECT CASE WHEN k = 0 THEN own_org ELSE own_org % #{orgs} + 1 END,
           u, 1 + #{h("(u * 2 + k)", seed, 5, 10)}
    FROM (SELECT u, 1 + #{h("u", seed, 1, orgs)} AS own_org FROM generate_series(1, #{users}) u) x,
         generate_series(0, 1) k
    WHERE (u - 1) * 2 + k < #{n}
    """
  end

  defp insert_articles(%{articles: n, users: users, organizations: orgs}, seed) do
    """
    INSERT INTO public.articles
      (id, org_id, author_id, editor_id, status, is_published, title, body, internal_notes,
       assignees, external_ref, published_at)
    SELECT i, 1 + #{h("a", seed, 1, orgs)}, a, NULL, s::public.article_status, s = 'published',
           'article ' || i, 'body ' || i, NULL, '{}'::jsonb, NULL, NULL
    FROM (SELECT i, 1 + #{h("i", seed, 6, users)} AS a,
                 (ARRAY['draft', 'review', 'published'])[1 + #{h("i", seed, 7, 3)}] AS s
          FROM generate_series(1, #{n}) i) x
    """
  end

  defp insert_comments(%{comments: n, articles: articles, users: users}, seed) do
    """
    INSERT INTO public.comments (id, article_id, author_id, body)
    SELECT i, 1 + #{h("i", seed, 8, articles)}, 1 + #{h("i", seed, 9, users)}, 'comment ' || i
    FROM generate_series(1, #{n}) i
    """
  end
end

defmodule Authzura.Test.Seed do
  @moduledoc """
  The property and differential suites' data: `Authzura.Parity.Fixture`'s
  seed rows plus deterministic extra rows, so every tracked table holds 20
  to 50 rows.

  The extra rows put a NULL in every nullable column, give
  `membership_notes` partial-NULL composite keys (one key column set, the
  other NULL), chain `users.manager_id` up to three levels, and use only
  numerics a float represents exactly (`0.125`, `1000.5`, ...), so values
  compare equal after any float round trip. `users.email` is `citext` with
  a `UNIQUE` constraint, so no two emails differ only by case (see the
  hardening pre-flight ruling F6).

  `ids/0` gives the id pools session variables draw from, and `values/0`
  the literal pools filter generators draw from, keyed by
  `{schema, table, column}`. `ParityCase`'s own seed is untouched.
  """

  alias Authzura.Parity.Fixture

  @titles ~w(Alpha beta Gamma delta Epsilon zeta)
  @statuses ~w(draft review published)
  @roles ~w(editor viewer admin)
  @kinds ~w(edit view share)
  @bodies ~w(a b c d e f)

  @doc "Commits the parity seed rows plus the extra rows below."
  @spec insert!(module()) :: :ok
  def insert!(repo) do
    :ok = Fixture.seed!(repo)
    Enum.each(tables(), fn {table, rows} -> repo.query!(insert_sql(table, rows)) end)
  end

  @doc """
  The id pools session variables draw from: `:user`, `:org` and `:article`
  ids, plus the `key_kinds.code` values.
  """
  @spec ids() :: %{atom() => [term()]}
  def ids do
    %{
      user: Enum.to_list(1..40),
      org: Enum.to_list(1..20),
      article: Enum.to_list(1..45),
      code: Enum.uniq(["a", "b", "a,b" | Enum.map(key_kinds(), &Map.fetch!(&1, "code"))])
    }
  end

  @doc """
  The literal pools for filter generators: up to 8 distinct non-NULL values
  per `{schema, table, column}`, as JSON-encodable terms (timestamps, dates
  and uuids as strings). `published_articles` draws from `articles`.
  """
  @spec values() :: %{{String.t(), String.t(), String.t()} => [term()]}
  def values do
    articles = Map.fetch!(Map.new(tables()), {"public", "articles"})
    view = Enum.map(articles, &Map.take(&1, ["id", "org_id", "author_id", "title"]))

    [{{"public", "published_articles"}, view} | tables()]
    |> Enum.flat_map(fn {{schema, table}, rows} ->
      rows
      |> Enum.flat_map(&Map.keys/1)
      |> Enum.uniq()
      |> Enum.map(&{{schema, table, &1}, pool(rows, &1)})
    end)
    |> Map.new()
  end

  # Evenly spaced over the distinct values, so a pool spans the data.
  defp pool(rows, column) do
    distinct = rows |> Enum.map(&Map.fetch!(&1, column)) |> Enum.reject(&is_nil/1) |> Enum.uniq()
    distinct |> Enum.take_every(max(div(length(distinct), 8), 1)) |> Enum.take(8)
  end

  defp tables do
    [
      {{"public", "organizations"}, for(i <- 3..20, do: %{"id" => i, "name" => "org#{i}"})},
      {{"public", "users"}, users()},
      {{"public", "user_profiles"}, profiles()},
      {{"public", "articles"}, articles()},
      {{"public", "comments"}, comments()},
      {{"public", "org_memberships"}, memberships()},
      {{"public", "membership_notes"}, notes()},
      {{"public", "Order"}, orders()},
      {{"public", "key_kinds"}, key_kinds()},
      {{"audit", "users"}, audit_users()},
      {{"audit", "article_events"}, events()}
    ]
  end

  # Every fourth user starts a manager chain; the others report to the
  # previous id, so chains are up to three managers long.
  defp users do
    for i <- 4..40 do
      %{
        "id" => i,
        "org_id" => rem(i, 20) + 1,
        "manager_id" => if(rem(i, 4) == 0, do: nil, else: i - 1),
        "email" => if(rem(i, 2) == 0, do: "user#{i}@x.com", else: "User#{i}@X.com"),
        "role" => cycle(@roles, i),
        "is_admin" => rem(i, 5) == 0,
        "salary" => if(rem(i, 4) == 1, do: nil, else: i * 100 + 0.5)
      }
    end
  end

  defp profiles do
    for i <- 4..30,
        rem(i, 3) != 0,
        do: %{"user_id" => i, "bio" => if(rem(i, 5) == 0, do: nil, else: "bio #{i}")}
  end

  defp articles do
    for i <- 5..45 do
      %{
        "id" => i,
        "org_id" => rem(i, 20) + 1,
        "author_id" => rem(i, 25) + 1,
        "editor_id" => if(rem(i, 3) == 0, do: nil, else: rem(i * 7, 40) + 1),
        "status" => cycle(@statuses, i),
        "is_published" => rem(i, 2) == 0,
        "title" => "#{cycle(@titles, i)}#{i}",
        "body" => if(rem(i, 4) == 0, do: nil, else: cycle(@bodies, i)),
        "internal_notes" => cycle([nil, "x", "y"], i),
        "assignees" => assignees(i),
        "external_ref" => if(rem(i, 2) == 0, do: nil, else: uuid(i)),
        "published_at" =>
          if(rem(i, 3) == 0, do: nil, else: "2024-01-#{pad(rem(i, 28) + 1)} 10:00:00+00")
      }
    end
  end

  defp assignees(i) when rem(i, 5) == 0, do: %{}
  defp assignees(i), do: %{"#{rem(i, 4) + 1}" => true, "#{rem(i, 3) + 5}" => rem(i, 2) == 0}

  defp comments do
    for i <- 7..80,
        do: %{
          "id" => i,
          "article_id" => rem(i, 45) + 1,
          "author_id" => rem(i * 3, 40) + 1,
          "body" => cycle(@bodies, i)
        }
  end

  defp memberships do
    for u <- 3..25, do: %{"org_id" => membership_org(u), "user_id" => u, "level" => rem(u, 10)}
  end

  defp membership_org(user), do: rem(user, 20) + 1

  # Notes 4, 8, ... keep only `org_id` and 5, 9, ... only `user_id`: a
  # partial-NULL key matches no membership.
  defp notes do
    for i <- 4..35 do
      user = rem(i, 23) + 3

      {org, user} =
        case rem(i, 4) do
          0 -> {membership_org(user), nil}
          1 -> {nil, user}
          _ -> {membership_org(user), user}
        end

      %{
        "id" => i,
        "org_id" => org,
        "user_id" => user,
        "note" => if(rem(i, 5) == 0, do: nil, else: "note #{i}")
      }
    end
  end

  defp orders do
    for i <- 4..25,
        do: %{"Id" => i, "line item" => if(rem(i, 4) == 0, do: nil, else: "item #{i}")}
  end

  defp key_kinds do
    for i <- 6..40 do
      %{
        "id" => i,
        "code" => "c#{rem(i, 7)}",
        "rank" => i,
        "grade" => cycle([nil, "A", "B", "C"], i),
        "score" => if(rem(i, 4) == 0, do: nil, else: i * 0.25 - 3),
        "meta" => cycle([nil, "{}", "[1]"], i),
        "ratio" => if(rem(i, 3) == 0, do: nil, else: i * 0.125),
        "born_on" =>
          if(rem(i, 5) == 0, do: nil, else: "2024-#{pad(rem(i, 12) + 1)}-#{pad(rem(i, 28) + 1)}"),
        "seen_at" =>
          if(rem(i, 4) == 0, do: nil, else: "2024-02-#{pad(rem(i, 28) + 1)} 0#{rem(i, 10)}:30:00")
      }
    end
  end

  defp audit_users do
    for i <- 2..30, i != 5, do: %{"id" => i, "note" => if(rem(i, 3) == 0, do: nil, else: "n#{i}")}
  end

  defp events do
    for i <- 4..70, do: %{"id" => i, "article_id" => rem(i, 45) + 1, "kind" => cycle(@kinds, i)}
  end

  defp cycle(list, i), do: Enum.at(list, rem(i, length(list)))

  defp pad(n), do: n |> Integer.to_string() |> String.pad_leading(2, "0")

  defp uuid(i),
    do: "00000000-0000-4000-8000-#{i |> Integer.to_string() |> String.pad_leading(12, "0")}"

  # The rows are this module's own literals, never input.
  defp insert_sql({schema, table}, [first | _] = rows) do
    columns = Map.keys(first)

    values =
      Enum.map_join(rows, ", ", fn row ->
        "(" <> Enum.map_join(columns, ", ", &literal(Map.fetch!(row, &1))) <> ")"
      end)

    ~s|INSERT INTO "#{schema}"."#{table}" (#{Enum.map_join(columns, ", ", &~s|"#{&1}"|)}) VALUES #{values}|
  end

  defp literal(nil), do: "NULL"
  defp literal(value) when is_boolean(value) or is_number(value), do: to_string(value)
  defp literal(value) when is_binary(value), do: "'" <> String.replace(value, "'", "''") <> "'"
  defp literal(value) when is_map(value), do: value |> Jason.encode!() |> literal()
end

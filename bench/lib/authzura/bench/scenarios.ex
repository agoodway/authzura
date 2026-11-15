defmodule Authzura.Bench.Scenarios do
  @moduledoc """
  The 17 benchmark scenarios. Test harness only.

  Each is `%{id, read, auth, preload_levels}`:

    * `read` - an `Authzura.Parity.Read`, run unchanged on both engines
    * `auth` - always a JWT (`{:jwt, claims, role}`), so both engines resolve
      the role and session the same way
    * `preload_levels` - `L`, the number of preload nodes of the read. The
      target number of data statements is `1 + L`

  Every root and array level is ordered by its primary key, and selects it:
  the order is total, so both engines return the same rows in the same
  order. (An object relationship has at most one row and takes no order.)
  The roles are those of `Authzura.Bench.Metadata`.
  """

  alias Authzura.Parity.{Hasura, Read}

  @type scenario :: %{
          id: String.t(),
          read: Read.t(),
          auth: Hasura.auth(),
          preload_levels: non_neg_integer()
        }

  @namespace "https://hasura.io/jwt/claims"
  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @by_id [asc: :id]

  @doc "The scenario ids, in order."
  @spec ids() :: [String.t()]
  def ids,
    do: ~w(
      flat-tenant author-or-published exists-member rel-filter-3hop session-array-in
      columns-narrow input-filter input-regex limit-permission page-1000
      preload-object preload-array-limited preload-nested-3
      input-selective input-pk input-rel-permission preload-large-batch
    )

  @doc """
  The session variables every scenario uses: user 17, organization 3 and
  the organizations 1, 2 and 3 as an array variable.
  """
  @spec session_vars() :: %{String.t() => String.t()}
  def session_vars,
    do: %{
      "x-hasura-user-id" => "17",
      "x-hasura-org-id" => "3",
      "x-hasura-org-ids" => "{1,2,3}"
    }

  @doc "A JWT for `role` (its only allowed and default role) carrying `vars`."
  @spec auth(String.t(), %{String.t() => String.t()}) :: Hasura.auth()
  def auth(role, vars \\ session_vars()) when is_binary(role) do
    session =
      Map.merge(vars, %{"x-hasura-default-role" => role, "x-hasura-allowed-roles" => [role]})

    {:jwt, %{@namespace => session}, role}
  end

  @doc "Every scenario, in `ids/0` order."
  @spec all() :: [scenario()]
  def all do
    [
      scenario(
        "flat-tenant",
        "tenant",
        articles(~w(id org_id author_id status is_published title), limit: 100)
      ),
      scenario(
        "author-or-published",
        "author",
        articles(~w(id author_id is_published title), limit: 100)
      ),
      scenario("exists-member", "member", articles(~w(id author_id title), limit: 100)),
      scenario(
        "rel-filter-3hop",
        "deep",
        Read.new(@comments, columns: ~w(id article_id body), order_by: @by_id, limit: 100)
      ),
      scenario("session-array-in", "arr", articles(~w(id org_id title), limit: 100)),
      scenario("columns-narrow", "tenant", articles(~w(id title), limit: 100)),
      scenario(
        "input-filter",
        "tenant",
        articles(~w(id title status), where: %{"status" => %{"_eq" => "published"}}, limit: 100)
      ),
      scenario(
        "input-regex",
        "tenant",
        articles(~w(id title),
          where: %{"title" => %{"_regex" => "^article [0-9]*7$"}},
          limit: 100
        )
      ),
      scenario("limit-permission", "limited", articles(~w(id title status), [])),
      scenario(
        "page-1000",
        "author",
        articles(~w(id author_id title), limit: 1000, offset: 1000)
      ),
      scenario(
        "preload-object",
        "tenant",
        articles(~w(id title author_id),
          limit: 100,
          relationships: [{"author", object(~w(id email role))}]
        )
      ),
      scenario(
        "preload-array-limited",
        "limited",
        articles(~w(id title), relationships: [{"comments", comments(~w(id article_id body))}])
      ),
      scenario(
        "preload-nested-3",
        "tenant",
        articles(~w(id title),
          limit: 100,
          relationships: [
            {"comments",
             comments(~w(id author_id), [
               {"author", object(~w(id email), [{"org", object(~w(id name))}])}
             ])}
          ]
        )
      ),
      # Regression pins: an input filter on a selective, indexed column; a
      # primary-key lookup through the input path (the statement shape a
      # `get/4` would need fenced); an input filter under a relationship
      # permission; and a preload over about a thousand parents.
      scenario(
        "input-selective",
        "author",
        articles(~w(id author_id title), where: %{"author_id" => %{"_eq" => 17}}, limit: 100)
      ),
      scenario(
        "input-pk",
        "author",
        articles(~w(id title), where: %{"id" => %{"_in" => Enum.to_list(300..309)}})
      ),
      scenario(
        "input-rel-permission",
        "deep",
        Read.new(@comments,
          columns: ~w(id article_id body),
          where: %{"body" => %{"_like" => "%7"}},
          order_by: @by_id,
          limit: 100
        )
      ),
      scenario(
        "preload-large-batch",
        "tenant",
        articles(~w(id title author_id),
          limit: 1_000,
          relationships: [{"author", object(~w(id email role))}]
        )
      )
    ]
  end

  defp scenario(id, role, read),
    do: %{id: id, read: read, auth: auth(role), preload_levels: levels(read)}

  # The preload nodes of a read: its relationships, at every depth.
  defp levels(%Read{relationships: relationships}),
    do: Enum.sum_by(relationships, fn {_name, nested} -> 1 + levels(nested) end)

  defp articles(columns, fields),
    do: Read.new(@articles, [columns: columns, order_by: @by_id] ++ fields)

  defp comments(columns, relationships \\ []),
    do: Read.nested(columns: columns, order_by: @by_id, relationships: relationships)

  defp object(columns, relationships \\ []),
    do: Read.nested(columns: columns, relationships: relationships)
end

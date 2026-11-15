defmodule Authzura.Gen.Catalog do
  @moduledoc """
  The fixture schema as `Authzura.Gen` sees it: each tracked table's
  primary key and columns (with a coarse kind), the relationships of
  `Authzura.Parity.Fixture.metadata/0`, the column atoms `order_by` may
  hold, the session variables filters reference, and the literal and id
  pools of `Authzura.Test.Seed`.

  Column kinds: `:int`, `:float`, `:text`, `:char`, `:enum`, `:bool`,
  `:uuid`, `:time` (dates and timestamps), `:jsonb` and `:json`.
  Everything here is a compile-time literal; nothing creates an atom at
  run time.
  """

  alias Authzura.Parity.Fixture
  alias Authzura.Test.Seed

  @organizations {"public", "organizations"}
  @users {"public", "users"}
  @profiles {"public", "user_profiles"}
  @articles {"public", "articles"}
  @comments {"public", "comments"}
  @memberships {"public", "org_memberships"}
  @notes {"public", "membership_notes"}
  @order {"public", "Order"}
  @kinds {"public", "key_kinds"}
  @view {"public", "published_articles"}
  @audit_users {"audit", "users"}
  @events {"audit", "article_events"}

  @tables %{
    @organizations => {["id"], id: :int, name: :text},
    @users =>
      {["id"],
       id: :int,
       org_id: :int,
       manager_id: :int,
       email: :text,
       role: :text,
       is_admin: :bool,
       salary: :float},
    @profiles => {["user_id"], user_id: :int, bio: :text},
    @articles =>
      {["id"],
       id: :int,
       org_id: :int,
       author_id: :int,
       editor_id: :int,
       status: :enum,
       is_published: :bool,
       title: :text,
       body: :text,
       internal_notes: :text,
       assignees: :jsonb,
       external_ref: :uuid,
       published_at: :time},
    @comments => {["id"], id: :int, article_id: :int, author_id: :int, body: :text},
    @memberships => {["org_id", "user_id"], org_id: :int, user_id: :int, level: :int},
    @notes => {["id"], id: :int, org_id: :int, user_id: :int, note: :text},
    @order => {["Id"], Id: :int, "line item": :text},
    @kinds =>
      {["id"],
       id: :int,
       code: :text,
       rank: :int,
       grade: :char,
       score: :float,
       meta: :json,
       ratio: :float,
       born_on: :time,
       seen_at: :time},
    @view => {[], id: :int, org_id: :int, author_id: :int, title: :text},
    @audit_users => {["id"], id: :int, note: :text},
    @events => {["id"], id: :int, article_id: :int, kind: :text}
  }

  @columns Map.new(@tables, fn {table, {_pk, columns}} ->
             {table, Enum.map(columns, fn {atom, kind} -> {Atom.to_string(atom), atom, kind} end)}
           end)

  @atoms for {_table, columns} <- @columns,
             {name, atom, _kind} <- columns,
             into: %{},
             do: {name, atom}

  # name => {kind, target, %{parent column => target column}}.
  @relationships %{
    @articles => %{
      "author" => {:object, @users, %{"author_id" => "id"}},
      "editor" => {:object, @users, %{"editor_id" => "id"}},
      "comments" => {:array, @comments, %{"id" => "article_id"}},
      "events" => {:array, @events, %{"id" => "article_id"}}
    },
    @users => %{
      "org" => {:object, @organizations, %{"org_id" => "id"}},
      "manager" => {:object, @users, %{"manager_id" => "id"}},
      "articles" => {:array, @articles, %{"id" => "author_id"}},
      "profile" => {:object, @profiles, %{"id" => "user_id"}}
    },
    @comments => %{"article" => {:object, @articles, %{"article_id" => "id"}}},
    @notes => %{
      "membership" => {:object, @memberships, %{"org_id" => "org_id", "user_id" => "user_id"}}
    },
    @view => %{"author" => {:object, @users, %{"author_id" => "id"}}},
    @organizations => %{"users" => {:array, @users, %{"id" => "org_id"}}}
  }

  # {name, kind, spellings filters use}.
  @variables [
    {"x-hasura-user-id", :int, ["X-Hasura-User-Id", "x-hasura-user-id", "X-HASURA-USER-ID"]},
    {"x-hasura-org-id", :int, ["X-Hasura-Org-Id", "x-HASURA-org-ID"]},
    {"x-hasura-article-ids", :int_array, ["X-Hasura-Article-Ids", "X-HASURA-ARTICLE-IDS"]},
    {"x-hasura-codes", :text_array, ["X-Hasura-Codes", "x-hasura-codes"]},
    {"x-hasura-code", :text, ["X-Hasura-Code"]},
    {"x-hasura-flag", :bool, ["X-Hasura-Flag", "x-hasura-flag"]}
  ]

  @variable_kinds Map.new(@variables, fn {name, kind, _spellings} -> {name, kind} end)

  @values Seed.values()
  @ids Seed.ids()

  @type table :: {String.t(), String.t()}
  @type kind :: :int | :float | :text | :char | :enum | :bool | :uuid | :time | :jsonb | :json
  @type relationship :: {:object | :array, table(), %{String.t() => String.t()}}

  @doc "Every tracked table, in the fixture's order."
  @spec tracked() :: [table()]
  def tracked, do: Fixture.tracked()

  @doc "The `published_articles` view."
  @spec view() :: table()
  def view, do: @view

  @doc "`org_memberships`, the composite-key target."
  @spec memberships() :: table()
  def memberships, do: @memberships

  @doc "The column names of `table`, in order."
  @spec names(table()) :: [String.t()]
  def names(table), do: @columns |> Map.fetch!(table) |> Enum.map(&elem(&1, 0))

  @doc "The kind of `column` on `table`."
  @spec kind(table(), String.t()) :: kind()
  def kind(table, column),
    do: @columns |> Map.fetch!(table) |> List.keyfind!(column, 0) |> elem(2)

  @doc "The primary key of `table` (`[]` for the view)."
  @spec pk(table()) :: [String.t()]
  def pk(table), do: @tables |> Map.fetch!(table) |> elem(0)

  @doc "A column that identifies a row: the single-column key, or the view's `id`."
  @spec key(table()) :: String.t()
  def key(table) do
    case pk(table) do
      [key] -> key
      [] -> "id"
    end
  end

  @doc "The fixed atom of a column name."
  @spec atom(String.t()) :: atom()
  def atom(column), do: Map.fetch!(@atoms, column)

  @doc "Every column atom."
  @spec atoms() :: [atom()]
  def atoms, do: @atoms |> Map.values() |> Enum.uniq()

  @doc "The relationships of `table`, sorted by name."
  @spec relationships(table()) :: [{String.t(), relationship()}]
  def relationships(table), do: @relationships |> Map.get(table, %{}) |> Enum.sort()

  @doc "The relationship `name` of `table`, or `nil` when `name` is not one."
  @spec relationship(table(), String.t()) :: relationship() | nil
  def relationship(table, name), do: @relationships |> Map.get(table, %{}) |> Map.get(name)

  @doc "Columns a filter may name: every one but `json`."
  @spec filterable(table(), [String.t()]) :: [String.t()]
  def filterable(table, names), do: Enum.reject(names, &(kind(table, &1) == :json))

  @doc "Whether Postgres (and Authzura) can order by `column`."
  @spec orderable?(table(), String.t()) :: boolean()
  def orderable?(table, column), do: kind(table, column) not in [:json, :jsonb]

  @doc "Whether `table` may be the root of an `all_input` read."
  @spec where_root?(table()) :: boolean()
  def where_root?({"public", _name} = table), do: table != @view
  def where_root?(_table), do: false

  @doc "The session variables as `{name, kind, spellings}`."
  @spec variables() :: [{String.t(), atom(), [String.t()]}]
  def variables, do: @variables

  @doc "The kind of the session variable `name` (lowercase)."
  @spec variable_kind(String.t()) :: atom() | nil
  def variable_kind(name), do: Map.get(@variable_kinds, name)

  @doc "The literal pool of a column (`Authzura.Test.Seed.values/0`)."
  @spec pool(table(), String.t()) :: [term()]
  def pool({schema, name}, column), do: Map.fetch!(@values, {schema, name, column})

  @doc "The id pools session values draw from (`Authzura.Test.Seed.ids/0`)."
  @spec ids() :: %{atom() => [term()]}
  def ids, do: @ids
end

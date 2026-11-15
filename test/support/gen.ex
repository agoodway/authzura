defmodule Authzura.Gen do
  @moduledoc """
  StreamData generators for the property and differential suites: batches
  of Hasura select permissions and `Authzura.Parity.Read` cases against
  them, over the fixture schema (`Authzura.Gen.Catalog`) and
  `Authzura.Test.Seed`'s rows.

  ## Batches

  `batch/2` draws, with seed `AUTHZURA_PROP_SEED + i` (default
  `20261114`), a select permission per tracked table for each of sixteen
  roles, `"gen_0"` to `"gen_15"` (about one table in ten has none). A
  permission has `"columns"` (`"*"` or a non-empty subset, so primary and
  foreign keys are sometimes hidden), a `"filter"`
  (`Authzura.Gen.Filter.permission/1`) and optionally `"limit"` (1 to 4)
  and `"query_root_fields"` (`[]`, or `["select_by_pk"]` on a table with
  a primary key: the list root is then disabled). Each role with a limit
  also gets a no-limit twin, `"gen_<n>_twin"`, which does not count toward
  the sixteen. `limits: false` drops every limit, and with it every twin.

  ## Cases

  `request/2` generates cases:

      %{id:, role:, read: %Read{}, auth: {:jwt, claims, requested_role},
        allowed_roles:, denial: nil | atom(), twin: nil | role,
        tags: [atom()], input_tags: [atom()]}

  Every case authenticates with an HS256 JWT (`Authzura.Parity.Hasura`'s
  key), the only way to reach `:role_not_allowed`. A case with `where` runs
  through `Authzura.all_input/4`, so its root is a `public` table (never
  the view) and its preload tree is at most 2 deep and 8 nodes; any other
  through `Authzura.all/3`, at most 3 deep and 16 nodes. There is no nested
  limit (Authzura has none); the root may carry `limit` (sometimes 0, often
  below the permission's) and `offset`. Every root and array level is
  totally ordered (`total_order?/4`).

  `denial` is the class a case is built to be denied with (`denials/0`);
  `expected_denial?/2` matches a reason to it. Cases tagged
  `:session_boundary` send a boundary form (`boundary_forms/0`) for a
  referenced variable of its kind, with no expectation either way.
  `mutation: m` builds only cases of mutation `m`, where `m` applies
  (`sweep/0` has one per denial class).

  `tags` are what the case exercises (`must_appear/0`, `operators/0`);
  `input_tags` the operators of its input filter alone
  (`input_operators/0`). `oracle/1` is the same read as the admin role
  `"gen_admin"` without `limit` and `offset`; `as_role/2` the same case as
  another role.

  `degenerate:` (on `batch/2`: `:no_filters`, `:all_columns`; on
  `request/2`: `:no_preloads`, `:no_input_filter`) switches off one source
  of variety; only the vacuity guards' self-tests use it.

  Generated names stay strings; `order_by` holds atoms from the fixed
  column map (`Authzura.Gen.Catalog.atom/1`).
  """

  import StreamData, except: [filter: 2, filter: 3]

  import Authzura.Gen.Access, only: [level_columns: 2, root_enabled?: 1, visible_columns: 2]

  alias Authzura.Gen.{Batch, Catalog, Filter, Mutation, Tags}
  alias Authzura.Parity.{Fixture, Hasura, Read}

  @default_seed 20_261_114
  @size 50
  @roles Enum.map(0..15, &"gen_#{&1}")
  @admin "gen_admin"
  @namespace "https://hasura.io/jwt/claims"
  @role_claims ["x-hasura-default-role", "x-hasura-allowed-roles"]

  @directions [
    :asc,
    :desc,
    :asc_nulls_first,
    :asc_nulls_last,
    :desc_nulls_first,
    :desc_nulls_last
  ]

  # `:partial_null_key` is counted at run time (see the metamorphic suite).
  @must_appear ~w(hidden_in_columns hidden_in_filter hidden_in_order hidden_in_preload_columns
                  hidden_in_preload_order unknown_column hidden_pk_role hidden_fk_role
                  preload_target_without_permission preload_target_root_disabled rel_object
                  rel_array rel_composite rel_self partial_null_key view_root offset limit_zero
                  session_boundary missing_variable uncastable_value root_disabled
                  role_not_allowed)a

  @mutations [
    {40, :none},
    {4, :hidden_in_columns},
    {4, :hidden_in_filter},
    {4, :hidden_in_order},
    {4, :hidden_in_preload_columns},
    {5, :hidden_in_preload_order},
    {3, :unknown_column},
    {6, :preload_target_without_permission},
    {6, :missing_variable},
    {6, :uncastable_value},
    {6, :root_disabled},
    {6, :role_not_allowed},
    {6, :session_boundary}
  ]

  @denials ~w(missing_variable uncastable_value root_disabled role_not_allowed forbidden_columns
              forbidden)a
  @sweep ~w(missing_variable uncastable_value root_disabled role_not_allowed hidden_in_columns
            preload_target_without_permission)a

  @type role :: String.t()
  @type table :: Catalog.table()
  @type permission :: %{String.t() => term()}
  @type batch :: %{role() => %{table() => permission()}}
  @type denial ::
          :missing_variable
          | :uncastable_value
          | :root_disabled
          | :role_not_allowed
          | :forbidden_columns
          | :forbidden
  @type case_t :: %{
          id: String.t(),
          role: role(),
          read: Read.t(),
          auth: Hasura.auth(),
          allowed_roles: [role()],
          denial: denial() | nil,
          twin: role() | nil,
          tags: [atom()],
          input_tags: [atom()]
        }
  @typedoc "A level of a read: `{path, :root | :object | :array, table, parent table, read}`."
  @type level :: {[String.t()], :root | :object | :array, table(), table() | nil, Read.t()}

  @doc "`AUTHZURA_PROP_SEED`, default `20261114`."
  @spec seed() :: integer()
  def seed, do: env_integer("AUTHZURA_PROP_SEED", @default_seed)

  @doc "The integer environment variable `name`, or `default`."
  @spec env_integer(String.t(), integer()) :: integer()
  def env_integer(name, default), do: name |> System.get_env("#{default}") |> String.to_integer()

  @doc "The sixteen generated roles."
  @spec roles() :: [role()]
  def roles, do: @roles

  @doc "The admin role the properties configure as Authzura's `admin_role`."
  @spec admin_role() :: role()
  def admin_role, do: @admin

  @doc "The must-appear coverage tags."
  @spec must_appear() :: [atom()]
  def must_appear, do: @must_appear

  @doc "The must-appear tags a generated case carries (all but the run-time ones)."
  @spec static_must_appear() :: [atom()]
  def static_must_appear, do: @must_appear -- [:partial_null_key]

  @doc "The permission-filter operator and form tags."
  @spec operators() :: [atom()]
  def operators, do: Filter.operators()

  @doc "The input-filter operator tags."
  @spec input_operators() :: [atom()]
  def input_operators, do: Filter.input_operators()

  @doc "Every session boundary form."
  @spec boundary_forms() :: [String.t()]
  def boundary_forms, do: Mutation.boundary_forms()

  @doc "The denial classes a case can be built with."
  @spec denials() :: [denial()]
  def denials, do: @denials

  @doc "One mutation per denial class, in `denials/0`'s order."
  @spec sweep() :: [atom()]
  def sweep, do: @sweep

  @doc "Every atom a batch or a case may hold besides struct and case keys."
  @spec fixed_atoms() :: [atom()]
  def fixed_atoms,
    do: Catalog.atoms() ++ @directions ++ @must_appear ++ operators() ++ @denials ++ @sweep

  @doc "What `c` exercises."
  @spec coverage_tags(case_t()) :: [atom()]
  def coverage_tags(%{tags: tags}), do: tags

  @doc "The batch permissions as `Authzura.Parity.Fixture.metadata/1`."
  @spec metadata(batch()) :: map()
  def metadata(batch) do
    for(
      {role, permissions} <- batch,
      {table, permission} <- permissions,
      do: {table, %{role: role, permission: permission}}
    )
    |> Enum.sort()
    |> Fixture.metadata()
  end

  @doc "`permissions` without their limits."
  @spec unlimited(%{table() => permission()}) :: %{table() => permission()}
  def unlimited(permissions), do: Batch.unlimited(permissions)

  @doc "`role`'s permission on `table` in `batch`, or `nil`."
  @spec permission(batch(), role(), table()) :: permission() | nil
  def permission(batch, role, table), do: batch |> Map.get(role, %{}) |> Map.get(table)

  @doc "The columns `role` may select on `table` (all for the admin, none without permission)."
  @spec visible(batch(), role(), table()) :: [String.t()]
  def visible(_batch, @admin, table), do: Catalog.names(table)
  def visible(batch, role, table), do: batch |> permission(role, table) |> visible_columns(table)

  @doc "Every level of `read`, root first (see `t:level/0`)."
  @spec levels(Read.t()) :: [level()]
  def levels(%Read{table: table} = read),
    do: [{[], :root, table, nil, read} | nested(read, table, [])]

  @doc """
  Whether `order` totally orders a level on `table` for the case's role:
  it holds the primary key when the role sees it, otherwise every column
  the role sees that Postgres can order.
  """
  @spec total_order?(batch(), case_t(), table(), keyword(atom()) | nil) :: boolean()
  def total_order?(batch, %{role: role}, table, order) do
    have = Enum.map(order || [], fn {_direction, column} -> column end)

    batch
    |> permission(role, table)
    |> level_columns(table)
    |> order_columns(table)
    |> Enum.all?(&(Catalog.atom(&1) in have))
  end

  @doc "Depth and node count of a filter (`Authzura.Gen.Filter.stats/1`)."
  @spec stats(map()) :: %{depth: non_neg_integer(), nodes: non_neg_integer()}
  def stats(filter), do: Filter.stats(filter)

  @doc "Whether `reason` is a denial of class `denial`."
  @spec expected_denial?(denial(), term()) :: boolean()
  def expected_denial?(:missing_variable, {:missing_session_variable, _name}), do: true
  def expected_denial?(:uncastable_value, {:invalid_session_value, _name, _why}), do: true
  def expected_denial?(:root_disabled, :root_field_disabled), do: true
  def expected_denial?(:role_not_allowed, {:invalid_session, :role_not_allowed, _role}), do: true
  def expected_denial?(:forbidden_columns, {:forbidden_columns, [_ | _]}), do: true
  # Input refuses more distinct columns than the role may select before it
  # names any (`Authzura.Input`, step 3).
  def expected_denial?(:forbidden_columns, {:invalid_input, {:too_many, :columns}}), do: true
  def expected_denial?(:forbidden, :forbidden), do: true
  def expected_denial?(_denial, _reason), do: false

  @doc "The same case as `role`: same session variables, `role` its only allowed role."
  @spec as_role(case_t(), role()) :: case_t()
  def as_role(%{auth: {:jwt, claims, _requested}} = c, role) do
    vars = claims |> Map.fetch!(@namespace) |> Map.drop(@role_claims)
    %{c | role: role, auth: jwt(vars, role, [role], role), allowed_roles: [role]}
  end

  @doc "The same read as the admin role, without the root `limit` and `offset`."
  @spec oracle(case_t()) :: case_t()
  def oracle(%{read: %Read{} = read} = c) do
    %{as_role(c, @admin) | read: %{read | limit: nil, offset: nil}, denial: nil, twin: nil}
  end

  @doc "The session variables of `c`, keyed by lowercase name."
  @spec variables(case_t()) :: %{String.t() => String.t()}
  def variables(%{auth: {:jwt, claims, _requested}}),
    do: claims |> Map.fetch!(@namespace) |> Map.drop(@role_claims)

  @doc """
  `n` values of `generator` drawn deterministically from `seed` (one
  seeded draw of a list: a seeded generator in `Enum.take/2` would
  repeat one value).
  """
  @spec take(StreamData.t(a), integer(), non_neg_integer()) :: [a] when a: term()
  def take(generator, seed, n),
    do: generator |> list_of(length: n) |> resize(@size) |> seeded(seed) |> Enum.at(0)

  @doc """
  The batch drawn for index `i` with seed `seed() + i`. `limits: false`
  drops every limit (and the twins); `degenerate:` is for guard
  self-tests only. `join_lift: true` opts into object-chain weighting for
  the join-lift property; other properties retain the default distribution.
  """
  @spec batch(integer(), keyword()) :: batch()
  def batch(i, opts \\ []), do: Batch.build(seed() + i, opts)

  @doc """
  What `batch` lacks: permission operators no filter uses, and boundary
  variable kinds no list-root permission references. `batch/2` makes it
  `[]` by placing, for each, `Authzura.Gen.Filter.feature/1`'s filter on
  the first role whose permission on that table has an enabled list root
  and was not used for another feature (the degenerate batches excepted).
  """
  @spec missing_coverage(batch()) :: [atom()]
  def missing_coverage(batch), do: Batch.missing_coverage(batch)

  @doc "Cases against `batch` (see the moduledoc)."
  @spec request(batch(), keyword()) :: StreamData.t(case_t())
  def request(batch, opts \\ []) do
    degenerate = Keyword.get(opts, :degenerate)

    {roles, mutation} =
      case Keyword.fetch(opts, :mutation) do
        {:ok, mutation} -> {applicable(batch, mutation, degenerate), constant(mutation)}
        :error -> {@roles, @mutations |> weighted() |> frequency()}
      end

    # A fixed size: StreamData's ramp from size 0 would make the first
    # runs' list literals (and so their filters) degenerate.
    {member_of(roles), mutation}
    |> tuple()
    |> bind(fn {role, mutation} ->
      env = env(batch, role, degenerate)
      env |> draft(mutation) |> map(&finish(&1, env))
    end)
    |> resize(@size)
  end

  defp env(batch, role, degenerate),
    do: %{batch: batch, role: role, permissions: Map.fetch!(batch, role), degenerate: degenerate}

  # The roles `mutation` applies to; every role when none does, so the
  # property's denial check reports it.
  defp applicable(batch, mutation, degenerate) do
    case Enum.filter(@roles, &(batch |> env(&1, degenerate) |> roots(mutation) != [])) do
      [] -> @roles
      roles -> roles
    end
  end

  defp weighted(pairs), do: Enum.map(pairs, fn {weight, value} -> {weight, constant(value)} end)

  # Cases. A draft is a case before `finish/2`: its session is still
  # `vars`, `allowed` and `requested`.

  defp draft(env, :none), do: base(env, enabled_roots(env))

  defp draft(env, mutation) do
    case roots(env, mutation) do
      [] -> draft(env, :none)
      roots -> env |> base(roots) |> bind(&Mutation.mutate(mutation, &1, env))
    end
  end

  defp roots(env, :root_disabled), do: disabled_roots(env)

  defp roots(env, mutation),
    do: env |> enabled_roots() |> Enum.filter(&Mutation.applies?(mutation, env, &1))

  defp enabled_roots(%{permissions: permissions}),
    do: for({table, permission} <- permissions, root_enabled?(permission), do: table)

  defp disabled_roots(%{permissions: permissions}),
    do: for({table, permission} <- permissions, not root_enabled?(permission), do: table)

  # A role with no readable table at all reads one it has no permission
  # on, or one whose root is disabled.
  defp base(env, []) do
    case Catalog.tracked() -- Map.keys(env.permissions) do
      [] -> base(env, disabled_roots(env), :root_disabled)
      tables -> base(env, tables, :forbidden)
    end
  end

  defp base(env, roots), do: base(env, roots, nil)

  defp base(%{role: role} = env, roots, denial) do
    where_roots = Enum.filter(roots, &Catalog.where_root?/1)
    modes = if where_roots == [], do: [:all], else: [:where, :all]

    bind(member_of(modes), fn mode ->
      bind(root(if mode == :where, do: where_roots, else: roots), fn table ->
        fixed_map(%{
          role: constant(role),
          read: read(env, table, mode),
          vars: variables(),
          allowed: map(list_of(member_of(@roles), max_length: 2), &Enum.uniq([role | &1])),
          requested: member_of([nil, role]),
          denial: constant(denial),
          mutation: constant(:none)
        })
      end)
    end)
  end

  # Roots with array relationships are drawn most, then those with object
  # relationships, so preloads are common.
  defp root(tables), do: tables |> Enum.map(&{root_weight(&1), constant(&1)}) |> frequency()

  defp root_weight(table) do
    case for({_name, {kind, _target, _mapping}} <- Catalog.relationships(table), do: kind) do
      [] -> 1
      kinds -> if :array in kinds, do: 4, else: 2
    end
  end

  defp read(env, table, mode) do
    visible = level_columns(env.permissions[table], table)
    {depth, width} = bounds(mode)

    fixed_map(%{
      columns: Batch.subset(visible),
      where: where(env, table, visible, mode),
      order_by: order(table, visible),
      limit: request_limit(get_in(env.permissions, [table, "limit"])),
      offset: frequency([{7, constant(nil)}, {3, integer(0..3)}]),
      relationships: preloads(env, table, depth, width)
    })
    |> map(&struct!(Read, Map.put(&1, :table, table)))
  end

  defp bounds(:where), do: {2, 2}
  defp bounds(:all), do: {3, 2}

  defp where(_env, _table, _visible, :all), do: constant(nil)
  defp where(%{degenerate: :no_input_filter}, _table, _visible, :where), do: constant(%{})
  defp where(_env, table, visible, :where), do: Filter.input(table, visible)

  # Often below the permission's own limit, so both caps are exercised.
  defp request_limit(cap) when is_integer(cap) and cap > 1,
    do:
      frequency([
        {8, constant(nil)},
        {1, constant(0)},
        {6, integer(1..(cap - 1))},
        {2, integer(cap..8)}
      ])

  defp request_limit(_cap),
    do: frequency([{12, constant(nil)}, {1, constant(0)}, {5, integer(1..8)}])

  defp order(table, visible) do
    case order_columns(visible, table) do
      [] -> constant(nil)
      columns -> columns |> Enum.map(&direction/1) |> fixed_list()
    end
  end

  defp direction(column), do: map(member_of(@directions), &{&1, Catalog.atom(column)})

  defp order_columns(visible, table) do
    pk = Catalog.pk(table)

    if pk != [] and pk -- visible == [],
      do: pk,
      else: Enum.filter(visible, &Catalog.orderable?(table, &1))
  end

  defp preloads(%{degenerate: :no_preloads}, _table, _depth, _width), do: constant([])
  defp preloads(_env, _table, 0, _width), do: constant([])

  defp preloads(%{permissions: permissions} = env, table, depth, width) do
    case for(
           {name, {kind, target, _m}} <- Catalog.relationships(table),
           Map.has_key?(permissions, target),
           do: {if(kind == :array, do: 2, else: 1), constant(name)}
         ) do
      [] ->
        constant([])

      names ->
        [{2, constant(0)}, {3, constant(1)}, {2, constant(width)}]
        |> frequency()
        |> bind(&map(list_of(frequency(names), length: &1), fn picked -> Enum.uniq(picked) end))
        |> bind(&preload_list(env, table, depth, &1))
    end
  end

  defp preload_list(env, table, depth, names) do
    names
    |> Enum.map(fn name -> map(nested_read(env, table, name, depth), &{name, &1}) end)
    |> fixed_list()
  end

  defp nested_read(env, table, name, depth) do
    {kind, target, _mapping} = Catalog.relationship(table, name)
    visible = level_columns(env.permissions[target], target)

    fixed_map(%{
      columns: Batch.subset(visible),
      order_by: if(kind == :array, do: order(target, visible), else: constant(nil)),
      relationships: preloads(env, target, depth - 1, 2)
    })
    |> map(&struct!(Read, &1))
  end

  defp variables do
    ids = Catalog.ids()

    fixed_map(%{
      "x-hasura-user-id" => map(member_of(ids.user), &Integer.to_string/1),
      "x-hasura-org-id" => map(member_of(ids.org), &Integer.to_string/1),
      "x-hasura-article-ids" => map(distinct(ids.article, 0, 4), &array_literal/1),
      "x-hasura-codes" => map(distinct(ids.code, 0, 3), &array_literal/1),
      "x-hasura-code" => member_of(ids.code),
      "x-hasura-flag" => member_of(["true", "false"])
    })
  end

  defp distinct(values, min, max),
    do: map(list_of(member_of(values), min_length: min, max_length: max), &Enum.uniq/1)

  defp array_literal(elements), do: "{" <> Enum.map_join(elements, ",", &element/1) <> "}"

  defp element(n) when is_integer(n), do: Integer.to_string(n)

  defp element(text),
    do: ~s|"| <> (text |> String.replace("\\", "\\\\") |> String.replace(~s|"|, ~s|\\"|)) <> ~s|"|

  defp nested(%Read{relationships: relationships}, table, path) do
    Enum.flat_map(relationships, fn {name, child} ->
      {kind, target, _mapping} = Catalog.relationship(table, name)
      here = path ++ [name]
      [{here, kind, target, table, child} | nested(child, target, here)]
    end)
  end

  # Finishing: the JWT, the twin, the tags and the id.

  defp finish(draft, %{batch: batch} = env) do
    %{role: role, read: read, vars: vars, allowed: allowed, requested: requested} = draft
    default = if requested == role and role not in allowed, do: hd(allowed), else: role

    c = %{
      role: role,
      read: read,
      auth: jwt(vars, default, allowed, requested),
      allowed_roles: allowed,
      denial: draft.denial,
      twin: twin(batch, env, read)
    }

    tags = Tags.tags(c, draft, env)
    input_tags = Filter.tags(read.where, read.table)
    Map.merge(c, %{tags: tags, input_tags: input_tags, id: id(c)})
  end

  defp jwt(vars, default, allowed, requested) do
    claims =
      Map.merge(vars, %{"x-hasura-default-role" => default, "x-hasura-allowed-roles" => allowed})

    {:jwt, %{"sub" => "1", @namespace => claims}, requested}
  end

  defp twin(batch, %{role: role, permissions: permissions}, read) do
    twin = "#{role}_twin"
    tables = for {_path, _kind, table, _parent, _read} <- levels(read), do: table
    limited? = Enum.any?(tables, &(get_in(permissions, [&1, "limit"]) != nil))
    if limited? and Map.has_key?(batch, twin), do: twin
  end

  defp id(c), do: c |> :erlang.phash2() |> Integer.to_string(16) |> String.downcase()
end

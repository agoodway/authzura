defmodule Authzura.Parity.Verdict do
  @moduledoc """
  Classifies one differential result pair, Hasura's and Authzura's, for
  one `Authzura.Parity.Read`:

    * `:match`
    * `{:leak, message}` - anything only Authzura returns, at any depth: a
      grant where Hasura denies (even `[]`), a row, an extra key, an object
      or array where Hasura has `null`, a value where Hasura has `null`.
      The message always begins `"LEAK"`
    * `{:over_deny, message}` - Hasura grants, Authzura denies, and no
      reviewed divergence (`test/parity/reviewed_divergences.exs`) matches
      both the case and Authzura's reason
    * `{:reviewed_divergence, id}` - such an entry matched
    * `{:mismatch, message}` - anything else: a changed value, `nil` vs
      `[]`, a missing row, another order, two errors that are not
      equivalent, an unmapped Hasura code, or a read that samples

  ## The context

  `context/3` derives, for each level of the read (keyed by its path of
  relationship names, the root is `[]`): its table, its key (the primary
  key when every key column is selected, else `:none`), its selected
  columns, its relationships' kinds, whether it is ordered, and its
  *bound*: the most rows it may hold per parent (the root's caller `limit`
  and the permission limits given as `limits:`, the smaller of the two).
  A level is *limited* when it has a bound, or is a root with an
  `offset`. `for_case/3` builds the context of a generated case, its
  limits taken from the batch, and keeps the case for the divergence
  predicates and the unknown-column rule.

  ## Rows

  Both sides go through `Authzura.Parity.Compare.normalize/3` first, so
  values compare by declared column type and every key, missing or
  unexpected, is kept. Then each level is compared:

    * keyed - rows match by key; a key only Authzura has (or has more
      often) is a leak, one only Hasura has a mismatch; an ordered level
      must list its keys in Hasura's order
    * no visible key - rows match as a multiset of whole rows (columns
      first, then the nested levels); an Authzura row with no counterpart
      is a leak, a Hasura row without one a mismatch
    * limited with no visible key (the twin rule) - which tied rows a
      limit keeps is not determined, so Authzura's rows must be a
      sub-multiset of the rows Hasura returns for the no-limit twin
      (`twin/1`, `put_twin/2`; else a leak) and their count must equal
      Hasura's (else a mismatch). When the level is ordered by columns it
      selects, its rows projected on those columns must also equal
      Hasura's, in order (ties agree on them), so an ignored `offset` or a
      page read backwards is a mismatch. Below such a level only the
      twin's rows bound Authzura's

  At every level with a bound, a parent with more rows than the bound is a
  leak, whatever else matches (also below a limited level, against the
  twin).

  Within a matched row every column and relationship is compared: `nil`
  is never `[]`, and `nil` where Authzura has a value or a row is a leak.

  ## Errors

  Two errors match when `@codes` maps Hasura's code to the class of
  Authzura's reason (it holds every pairing of
  `Authzura.Parity.Compare.equivalent?/2`). For `validation-failed`,
  Hasura's message must also name, by its GraphQL name, a field the reason
  implies: a forbidden column, or the root field or a relationship for
  `:forbidden` and `:root_field_disabled`. A case built with an unknown
  column must be denied exactly as a hidden one (`{:forbidden_columns, _}`).
  """

  alias Authzura.Gen
  alias Authzura.Parity.{Compare, Fixture, Read}

  @enforce_keys [:read, :tables, :levels]
  defstruct [:read, :tables, :levels, :case, twin: nil, divergences: []]

  @type level :: %{
          table: {String.t(), String.t()},
          kind: :root | :object | :array,
          key: [String.t()] | :none,
          columns: [String.t()],
          relationships: %{String.t() => :object | :array},
          ordered?: boolean(),
          order: [String.t()],
          bound: non_neg_integer() | nil,
          loose?: boolean()
        }
  @typedoc """
  A reviewed divergence. `case?` takes the case and Authzura's reason, so
  it can check the very value the reason names.
  """
  @type divergence :: %{
          id: String.t(),
          coverage_row: String.t(),
          case?: (map(), term() -> boolean()),
          reason?: (term() -> boolean())
        }
  @type t :: %__MODULE__{
          read: Read.t(),
          tables: Compare.tables(),
          levels: %{[String.t()] => level()},
          case: map() | nil,
          twin: {:ok, [map()]} | {:error, term()} | nil,
          divergences: [divergence()]
        }
  @type hasura :: {:ok, [map()]} | {:error, String.t()} | {:error, String.t(), String.t()}
  @type verdict ::
          :match
          | {:reviewed_divergence, String.t()}
          | {:leak | :over_deny | :mismatch, String.t()}

  # The classes a hidden column is denied with; an unknown one must get
  # one of them too.
  @hidden_classes [:forbidden_columns, :too_many_columns]

  @divergences_file "test/parity/reviewed_divergences.exs"

  # Hasura code => the Authzura reason classes it may pair with.
  @codes %{
    "not-found" => [:missing_session_variable],
    "validation-failed" => [
      :forbidden_columns,
      :too_many_columns,
      :forbidden,
      :root_field_disabled
    ],
    "access-denied" => [:role_not_allowed],
    "data-exception" => [:invalid_session_value],
    "invalid-jwt" => [:invalid_jwt],
    "jwt-missing-role-claims" => [:jwt_missing_role_claims],
    "jwt-invalid-claims" => [:jwt_invalid_claims]
  }

  @doc """
  The context of `read` against `tables`. Options: `limits:` (the
  permission limit of each limited level, `%{path => limit}`; the root is
  also bounded by its own `limit`), `case:` (a generated case, for the
  divergence predicates) and `divergences:` (default `divergences/0`).
  """
  @spec context(Read.t(), Compare.tables(), keyword()) :: t()
  def context(%Read{} = read, tables, opts \\ []) do
    %__MODULE__{
      read: read,
      tables: tables,
      levels: levels(read, tables, Keyword.get(opts, :limits, %{})),
      case: Keyword.get(opts, :case),
      divergences: Keyword.get_lazy(opts, :divergences, &divergences/0)
    }
  end

  @doc "The context of generated case `c` of `batch`, its permission limits from `batch`."
  @spec for_case(Gen.case_t(), Gen.batch(), Compare.tables()) :: t()
  def for_case(%{read: %Read{} = read, role: role} = c, batch, tables) do
    limits =
      for {path, kind, table, _parent, _read} <- Gen.levels(read),
          kind in [:root, :array],
          limit = batch |> Gen.permission(role, table) |> limit(),
          limit != nil,
          into: %{},
          do: {path, limit}

    context(read, tables, limits: limits, case: c)
  end

  @doc "Whether `ctx` needs the no-limit twin's Hasura rows (see the moduledoc)."
  @spec twin?(t()) :: boolean()
  def twin?(%__MODULE__{levels: levels}), do: Enum.any?(levels, fn {_path, l} -> l.loose? end)

  @doc """
  The case whose Hasura result `put_twin/2` takes: the context's case as
  its no-limit twin role (or as itself when only the caller limits), with
  no root `limit` or `offset`. `nil` when `twin?/1` is false.
  """
  @spec twin(t()) :: Gen.case_t() | nil
  def twin(%__MODULE__{case: %{read: %Read{} = read} = c} = ctx) do
    if twin?(ctx) do
      c = c |> Map.get(:twin) |> as_twin(c)
      %{c | read: %{read | limit: nil, offset: nil}}
    end
  end

  def twin(%__MODULE__{}), do: nil

  defp as_twin(nil, c), do: c
  defp as_twin(role, c), do: Gen.as_role(c, role)

  @doc "`ctx` with the twin's Hasura result."
  @spec put_twin(t(), hasura()) :: t()
  def put_twin(%__MODULE__{} = ctx, result), do: %{ctx | twin: result}

  @doc """
  The reviewed divergences of `#{@divergences_file}`, evaluated once per
  VM.
  """
  @spec divergences() :: [divergence()]
  def divergences do
    case :persistent_term.get({__MODULE__, :divergences}, nil) do
      nil ->
        {entries, _binding} = Code.eval_file(@divergences_file)
        :persistent_term.put({__MODULE__, :divergences}, entries)
        entries

      entries ->
        entries
    end
  end

  @doc "The verdict on Hasura's and Authzura's results under `ctx`."
  @spec classify(t(), hasura(), {:ok, [map()]} | {:error, term()}) :: verdict()
  def classify(%__MODULE__{} = ctx, hasura, authzura),
    do: ctx |> verdict(hasura_error(hasura), authzura) |> sampled(ctx)

  defp hasura_error({:error, code}), do: {:error, code, nil}
  defp hasura_error(other), do: other

  defp verdict(_ctx, {:error, code, _message}, {:ok, rows}),
    do: {:leak, "LEAK: Hasura denied (#{code}), Authzura granted #{length(rows)} row(s)"}

  defp verdict(ctx, {:ok, hasura}, {:ok, authzura}), do: rows(ctx, hasura, authzura)

  defp verdict(ctx, {:ok, _rows}, {:error, reason}) do
    case Enum.find(ctx.divergences, &reviewed?(&1, ctx.case, reason)) do
      %{id: id} -> {:reviewed_divergence, id}
      nil -> {:over_deny, "Hasura granted, Authzura denied with #{inspect(reason)}"}
    end
  end

  defp verdict(ctx, {:error, code, message}, {:error, reason}),
    do: errors(ctx, code, message, reason)

  defp reviewed?(_entry, nil, _reason), do: false

  defp reviewed?(%{case?: case?, reason?: reason?}, c, reason),
    do: reason?.(reason) and case?.(c, reason)

  defp sampled({:leak, _message} = leak, _ctx), do: leak

  defp sampled(verdict, %__MODULE__{read: read}) do
    if sample?(read),
      do: {:mismatch, "the read samples a relationship; nothing is sampled"},
      else: verdict
  end

  defp sample?(%Read{sample: nil, relationships: relationships}),
    do: Enum.any?(relationships, fn {_name, child} -> sample?(child) end)

  defp sample?(%Read{}), do: true

  # Levels.

  defp levels(%Read{table: table} = read, tables, limits) do
    bound = smaller(read.limit, Map.get(limits, []))
    walk(read, [], :root, table, {bound, read.offset != nil}, tables, limits)
  end

  defp walk(read, path, kind, table_ref, {bound, offset?}, tables, limits) do
    table = Map.fetch!(tables, table_ref)
    key = key(table.primary_key, read.columns)

    level = %{
      table: table_ref,
      kind: kind,
      key: key,
      columns: read.columns,
      relationships: Map.new(read.relationships, fn {name, _} -> {name, kind(table, name)} end),
      ordered?: read.order_by != nil,
      order: order_columns(read.order_by, read.columns),
      bound: bound,
      loose?: (bound != nil or offset?) and key == :none
    }

    read.relationships
    |> Enum.reduce(%{path => level}, fn {name, child}, acc ->
      relationship = Map.fetch!(table.relationships, name)
      here = path ++ [name]
      bound = if relationship.kind == :array, do: Map.get(limits, here)

      Map.merge(
        acc,
        walk(child, here, relationship.kind, relationship.target, {bound, false}, tables, limits)
      )
    end)
  end

  # The columns a level is ordered by, when it selects every one of them.
  defp order_columns(nil, _columns), do: []

  defp order_columns(order_by, columns) do
    order = Enum.map(order_by, fn {_direction, column} -> to_string(column) end)
    if order -- columns == [], do: order, else: []
  end

  defp key([], _columns), do: :none
  defp key(pk, columns), do: if(pk -- columns == [], do: pk, else: :none)

  defp kind(table, name), do: Map.fetch!(table.relationships, name).kind

  defp limit(%{"limit" => limit}), do: limit
  defp limit(_permission), do: nil

  defp smaller(nil, b), do: b
  defp smaller(a, nil), do: a
  defp smaller(a, b), do: min(a, b)

  # Rows.

  defp rows(ctx, hasura, authzura) do
    normalize = &Compare.normalize(&1, ctx.read, ctx.tables)
    twin = twin_rows(ctx)

    ctx
    |> level([], normalize.(authzura), normalize.(hasura), twin)
    |> conclude()
  end

  defp twin_rows(%__MODULE__{twin: {:ok, rows}} = ctx),
    do: Compare.normalize(rows, %{ctx.read | limit: nil, offset: nil}, ctx.tables)

  defp twin_rows(%__MODULE__{}), do: nil

  defp conclude(findings) do
    case {Keyword.get(findings, :leak), Keyword.get(findings, :mismatch)} do
      {nil, nil} -> :match
      {nil, message} -> {:mismatch, message}
      {message, _mismatch} -> {:leak, "LEAK: " <> message}
    end
  end

  defp level(ctx, path, authzura, hasura, twin) do
    info = Map.fetch!(ctx.levels, path)

    findings =
      cond do
        info.loose? -> loose(ctx, path, info, authzura, hasura, twin)
        info.key == :none -> keyless(ctx, path, info, authzura, hasura, twin)
        true -> keyed(ctx, path, info, authzura, hasura, twin)
      end

    over_bound(path, info.bound, length(authzura)) ++ findings
  end

  defp over_bound(path, bound, count) when is_integer(bound) and count > bound,
    do: [{:leak, "#{at(path)}#{count} rows, above the limit #{bound}"}]

  defp over_bound(_path, _bound, _count), do: []

  defp keyed(ctx, path, info, authzura, hasura, twin) do
    key = &key_of(&1, info.key)
    a_keys = Enum.map(authzura, key)
    h_keys = Enum.map(hasura, key)
    by_key = Map.new(hasura, &{key.(&1), &1})
    twin_by_key = twin && Map.new(twin, &{key.(&1), &1})

    extra = Enum.map(a_keys -- h_keys, &{:leak, "#{at(path)}row #{inspect(&1)} only in Authzura"})
    missing = Enum.map(h_keys -- a_keys, &{:mismatch, "#{at(path)}row #{inspect(&1)} missing"})

    order =
      if info.ordered? and extra == [] and missing == [] and a_keys != h_keys,
        do: [{:mismatch, "#{at(path)}order #{inspect(a_keys)}, Hasura #{inspect(h_keys)}"}],
        else: []

    pairs =
      for row <- Enum.uniq_by(authzura, key),
          {:ok, other} <- [Map.fetch(by_key, key.(row))],
          finding <- row(ctx, path, info, row, other, twin_by_key && twin_by_key[key.(row)]),
          do: finding

    extra ++ pairs ++ missing ++ order
  end

  defp keyless(ctx, path, info, authzura, hasura, twin) do
    {pairs, extra, missing} = pair(ctx, path, info, authzura, hasura)

    order =
      if info.ordered? and extra == [] and missing == [] and
           columns(authzura, info) != columns(hasura, info),
         do: [{:mismatch, "#{at(path)}rows in another order"}],
         else: []

    findings =
      for {row, other, findings} <- pairs,
          finding <- with_twin(ctx, path, info, row, other, findings, twin),
          do: finding

    Enum.map(extra, &{:leak, "#{at(path)}row #{inspect(&1)} only in Authzura (no visible key)"}) ++
      findings ++
      Enum.map(missing, &{:mismatch, "#{at(path)}row #{inspect(&1)} missing (no visible key)"}) ++
      order
  end

  # A twin row is needed only below a loose level; recompare with it then.
  defp with_twin(_ctx, _path, _info, _row, _other, findings, nil), do: findings

  defp with_twin(ctx, path, info, row, other, _findings, twin) do
    twin_row = Enum.find(twin, &(same_columns?(&1, row, info) and subsumed?(ctx, path, row, &1)))
    row(ctx, path, info, row, other, twin_row)
  end

  defp loose(_ctx, path, _info, authzura, _hasura, nil) when authzura != [],
    do: [{:mismatch, "#{at(path)}a limited level without a visible key needs the twin's rows"}]

  defp loose(ctx, path, info, authzura, hasura, twin) do
    leaks =
      ctx
      |> take_subsumed(path, authzura, twin || [])
      |> Enum.map(&{:leak, "#{at(path)}row #{inspect(&1)} outside the no-limit twin's rows"})

    leaks ++ count(path, length(authzura), length(hasura)) ++ page(path, info, authzura, hasura)
  end

  # The page itself, on the order columns: the same values in the same order.
  defp page(_path, %{order: []}, _authzura, _hasura), do: []

  defp page(path, %{order: order}, authzura, hasura) do
    project = fn rows -> Enum.map(rows, &Map.take(&1, order)) end

    if project.(authzura) == project.(hasura),
      do: [],
      else: [{:mismatch, "#{at(path)}another page than Hasura's on #{inspect(order)}"}]
  end

  # The rows of `rows` (Authzura's, at `path`) that no distinct row of
  # `twin` subsumes, plus every row beyond the level's bound: `[]` when
  # Authzura holds nothing the no-limit twin does not, within the limit.
  defp take_subsumed(ctx, path, rows, twin) do
    {within, beyond} = split_bound(rows, Map.fetch!(ctx.levels, path).bound)

    {_left, outside} =
      Enum.reduce(within, {twin, []}, fn row, {left, outside} ->
        case Enum.split_with(left, &(not subsumed?(ctx, path, row, &1))) do
          {before, [_used | rest]} -> {before ++ rest, outside}
          {_all, []} -> {left, [row | outside]}
        end
      end)

    Enum.reverse(outside) ++ beyond
  end

  defp split_bound(rows, nil), do: {rows, []}
  defp split_bound(rows, bound), do: Enum.split(rows, bound)

  # More rows than Hasura's under the same limit is a leak; fewer, a
  # mismatch.
  defp count(_path, same, same), do: []

  defp count(path, authzura, hasura) when authzura > hasura,
    do: [{:leak, "#{at(path)}#{authzura} rows, Hasura #{hasura} under the same limit"}]

  defp count(path, authzura, hasura),
    do: [{:mismatch, "#{at(path)}#{authzura} rows, Hasura #{hasura}"}]

  # Pairs each Authzura row with an unused Hasura row of the same columns,
  # preferring one whose nested levels match too, then one with no leak.
  defp pair(ctx, path, info, authzura, hasura) do
    {pairs, left, extra} =
      Enum.reduce(authzura, {[], hasura, []}, fn row, {pairs, left, extra} ->
        candidates =
          left
          |> Enum.with_index()
          |> Enum.filter(fn {other, _i} -> same_columns?(row, other, info) end)
          |> Enum.map(fn {other, i} -> {i, other, row(ctx, path, info, row, other, nil)} end)

        case best(candidates) do
          nil ->
            {pairs, left, [row | extra]}

          {i, other, findings} ->
            {[{row, other, findings} | pairs], List.delete_at(left, i), extra}
        end
      end)

    {Enum.reverse(pairs), Enum.reverse(extra), left}
  end

  defp best([]), do: nil

  defp best(candidates) do
    Enum.find(candidates, &match?({_i, _other, []}, &1)) ||
      Enum.find(candidates, fn {_i, _other, findings} -> not Keyword.has_key?(findings, :leak) end) ||
      hd(candidates)
  end

  defp same_columns?(row, other, info),
    do: Map.take(row, info.columns) == Map.take(other, info.columns)

  defp columns(rows, info), do: Enum.map(rows, &Map.take(&1, info.columns))

  defp key_of(row, key), do: Enum.map(key, &Map.get(row, &1))

  # One matched row: every key, column and relationship.
  defp row(ctx, path, info, row, other, twin_row) do
    unexpected(path, row, other) ++
      Enum.flat_map(info.columns, &value(path, &1, Map.get(row, &1), Map.get(other, &1))) ++
      Enum.flat_map(info.relationships, fn {name, kind} ->
        here = path ++ [name]
        twin = twin_row && Map.get(twin_row, name)
        related(ctx, here, kind, Map.get(row, name), Map.get(other, name), twin)
      end)
  end

  defp unexpected(path, row, other) do
    case {Map.get(row, :unexpected), Map.get(other, :unexpected)} do
      {nil, nil} -> []
      {nil, keys} -> [{:mismatch, "#{at(path)}Hasura returned unexpected keys #{inspect(keys)}"}]
      {keys, _other} -> [{:leak, "#{at(path)}keys only in Authzura: #{inspect(Map.keys(keys))}"}]
    end
  end

  defp value(_path, _column, same, same), do: []

  defp value(path, column, value, nil) when value != :missing,
    do: [{:leak, "#{at(path)}#{column} is #{inspect(value)}, Hasura null"}]

  defp value(path, column, value, other),
    do: [{:mismatch, "#{at(path)}#{column} is #{inspect(value)}, Hasura #{inspect(other)}"}]

  # Equal arrays still go through `level/5`, which checks their bound. A
  # null object on both sides holds nothing, whatever the twin row holds.
  defp related(_ctx, _path, :object, nil, nil, _twin), do: []
  defp related(_ctx, _path, _kind, same, same, nil) when not is_list(same), do: []
  defp related(_ctx, _path, _kind, {:sample, _n}, {:sample, _m}, _twin), do: []

  defp related(_ctx, path, _kind, :missing, _other, _twin),
    do: [{:mismatch, "#{at(path)}missing in Authzura"}]

  defp related(_ctx, path, _kind, _value, :missing, _twin),
    do: [{:mismatch, "#{at(path)}missing in Hasura"}]

  defp related(_ctx, path, :object, %{} = object, nil, _twin),
    do: [{:leak, "#{at(path)}object #{inspect(object)} only in Authzura"}]

  defp related(_ctx, path, :array, [_ | _] = rows, nil, _twin),
    do: [{:leak, "#{at(path)}#{length(rows)} row(s) only in Authzura, Hasura null"}]

  defp related(ctx, path, :object, %{} = object, %{} = other, twin) do
    info = Map.fetch!(ctx.levels, path)
    row(ctx, path, info, object, other, twin)
  end

  defp related(ctx, path, :array, rows, others, twin) when is_list(rows) and is_list(others),
    do: level(ctx, path, rows, others, twin)

  defp related(_ctx, path, _kind, value, other, _twin),
    do: [{:mismatch, "#{at(path)}#{inspect(value)}, Hasura #{inspect(other)}"}]

  # Whether Authzura's `row` holds nothing the twin's `twin_row` does not:
  # the same columns and no unexpected key, each object within the twin's,
  # each array's rows within the twin's.
  defp subsumed?(ctx, path, row, twin_row) do
    info = Map.fetch!(ctx.levels, path)

    not Map.has_key?(row, :unexpected) and same_columns?(row, twin_row, info) and
      Enum.all?(info.relationships, fn {name, _kind} ->
        within?(ctx, path ++ [name], Map.get(row, name), Map.get(twin_row, name))
      end)
  end

  defp within?(_ctx, _path, empty, _twin) when empty in [nil, []], do: true
  defp within?(ctx, path, %{} = row, %{} = twin), do: subsumed?(ctx, path, row, twin)

  defp within?(ctx, path, rows, twin) when is_list(rows) and is_list(twin),
    do: take_subsumed(ctx, path, rows, twin) == []

  defp within?(_ctx, _path, _value, _twin), do: false

  defp at([]), do: ""
  defp at(path), do: Enum.join(path, ".") <> ": "

  # Errors.

  defp errors(ctx, code, message, reason) do
    with {:ok, classes} <- fetch_code(code),
         :ok <- allowed_class(classes, reason),
         :ok <- field_named(ctx, code, message, reason) do
      unknown_like_hidden(ctx, reason)
    end
  end

  defp fetch_code(code) do
    case Map.fetch(@codes, code) do
      {:ok, classes} -> {:ok, classes}
      :error -> {:mismatch, "unmapped Hasura code #{inspect(code)}"}
    end
  end

  defp allowed_class(classes, reason) do
    if reason_class(reason) in classes,
      do: :ok,
      else: {:mismatch, "Hasura's code allows #{inspect(classes)}, Authzura #{inspect(reason)}"}
  end

  defp field_named(ctx, "validation-failed", message, reason) do
    fields = expected_fields(ctx, reason)

    if is_binary(message) and Enum.any?(fields, &String.contains?(message, "'#{&1}'")),
      do: :ok,
      else: {:mismatch, "validation-failed #{inspect(message)} names none of #{inspect(fields)}"}
  end

  defp field_named(_ctx, _code, _message, _reason), do: :ok

  defp unknown_like_hidden(%__MODULE__{case: %{tags: tags}}, reason) do
    if :unknown_column in tags and reason_class(reason) not in @hidden_classes,
      do: {:mismatch, "an unknown column was denied with #{inspect(reason)}, not as hidden"},
      else: :match
  end

  defp unknown_like_hidden(_ctx, _reason), do: :match

  defp expected_fields(ctx, {:forbidden_columns, columns}) do
    names =
      ctx.levels
      |> Map.values()
      |> Enum.map(&Fixture.graphql_names(&1.table))
      |> Enum.reduce(%{}, &Map.merge/2)

    Enum.map(columns, &Map.get(names, &1, &1))
  end

  defp expected_fields(%__MODULE__{read: %Read{table: table}, levels: levels}, reason)
       when reason in [:forbidden, :root_field_disabled],
       do: [
         Read.root_field(table)
         | Enum.flat_map(levels, fn {_path, l} -> Map.keys(l.relationships) end)
       ]

  # More distinct columns than the role may select (`Authzura.Input`,
  # step 3): a hidden one is among them.
  defp expected_fields(ctx, {:invalid_input, {:too_many, :columns}}),
    do:
      expected_fields(
        ctx,
        {:forbidden_columns, Enum.flat_map(ctx.levels, fn {_p, l} -> l.columns end)}
      )

  defp expected_fields(_ctx, _reason), do: []

  defp reason_class({:missing_session_variable, _name}), do: :missing_session_variable
  defp reason_class({:forbidden_columns, _columns}), do: :forbidden_columns
  defp reason_class({:invalid_input, {:too_many, :columns}}), do: :too_many_columns
  defp reason_class(:forbidden), do: :forbidden
  defp reason_class(:root_field_disabled), do: :root_field_disabled
  defp reason_class({:invalid_session, :role_not_allowed, _role}), do: :role_not_allowed
  defp reason_class({:invalid_session_value, _name, _why}), do: :invalid_session_value
  defp reason_class({:invalid_jwt, _why}), do: :invalid_jwt
  defp reason_class({:jwt_missing_role_claims, _claim}), do: :jwt_missing_role_claims
  defp reason_class({:jwt_invalid_claims, _why}), do: :jwt_invalid_claims
  defp reason_class(_reason), do: :other
end

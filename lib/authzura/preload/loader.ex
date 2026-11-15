defmodule Authzura.Preload.Loader do
  @moduledoc """
  Loads validated preload nodes (`Authzura.Preload.Tree`) level by level.

  Each node is **one query** for all of its parents, built by the adapter's
  `preload_level_query/2`: the parent keys travel as one array parameter
  per key column, the target's row filter and allowed columns apply, and
  limits are per parent. The rows come back ordered by parent and rank and
  are grouped by parent here:

    * an **object relationship** gets its row or `nil`. More than one row
      breaks the relationship's cardinality, which is a data-integrity
      error: `{:unsupported_query, {:object_cardinality, name}}`.
    * an **array relationship** gets a list in rank order (the node's
      `order_by`, applied inside the per-parent limit).

  Children load from the rows of their parent level, the same way.

  Parents that share a key tuple (compared exactly, so `citext` keys that
  differ in case stay distinct and Postgres still decides equality) send it
  once; every such parent gets the same value.

  ## Keys and stitching

  Loaded rows are maps of **column name strings**, and each relationship
  nests under its name as a string. Re-keying to the caller's terms (field
  atoms for Ecto associations, the caller's relationship key) belongs to
  the executor.

  At every loaded level the stitching columns (the children's local keys)
  are read but kept only when the node's `columns` asked for them; the
  parent rows passed in are returned with only the relationships added.

  This module runs queries but never opens a transaction: the caller pins
  one snapshot for the whole tree.
  """

  alias Authzura.Model.Relationship
  alias Authzura.Preload.Tree
  alias Authzura.{Telemetry, Util}

  @type reason :: {:unsupported_query, {:object_cardinality, String.t()}}

  @doc """
  Loads `nodes` for `parent_rows` and returns the rows with each
  relationship attached under its name.

  `parent_keys` holds, for each parent row in order, the values of
  `Authzura.Preload.Tree.parent_columns(nodes)` in that order. Each level's
  query comes from `adapter`, and `repo_opts` are passed to every level's
  `repo.all/2`. The nodes already carry their compiled row filters
  (`Authzura.Preload.Tree.validate/5`), so loading needs no generation or
  session.

  `finish` is called as `finish.(node, value)` once per distinct key tuple
  of each node, after the value's own children are attached and finished;
  what it returns is what every parent sharing the tuple gets. The executor
  re-keys rows there, so parents keep sharing one term (the default keeps
  the value as loaded).
  """
  @spec load(
          [Tree.preload_node()],
          [map()],
          [[term()]],
          module(),
          module(),
          keyword(),
          (Tree.preload_node(), term() -> term()),
          map()
        ) :: {:ok, [map()]} | {:error, reason() | term()}
  def load(
        nodes,
        parent_rows,
        parent_keys,
        repo,
        adapter,
        repo_opts \\ [],
        finish \\ &as_loaded/2,
        telemetry \\ %{}
      )
      when is_list(nodes) and length(parent_rows) == length(parent_keys) and
             is_function(finish, 2) do
    env = %{
      repo: repo,
      repo_opts: repo_opts,
      adapter: adapter,
      finish: finish,
      depth: 1,
      telemetry: telemetry
    }

    columns = Tree.parent_columns(nodes)
    keyed = Enum.map(parent_keys, &(columns |> Enum.zip(&1) |> Map.new()))
    level(nodes, parent_rows, keyed, env)
  end

  # `keyed` holds, per parent row, a map of its stitching columns to values.
  defp level(nodes, rows, keyed, env) do
    with {:ok, loaded} <- Util.map_ok(nodes, &node(&1, keyed, env)),
         do: {:ok, attach(rows, names(nodes), loaded)}
  end

  # One value per parent, in parent order. Parents that share a key tuple
  # send it once and share its value.
  defp node(_node, [], _env), do: {:ok, []}

  defp node(
         %{rel: %Relationship{name: name}} = node,
         keyed,
         %{depth: depth, telemetry: telemetry} = env
       ) do
    metadata = Map.merge(telemetry, %{relationship: name, depth: depth, parents: length(keyed)})
    Telemetry.span(:preload, metadata, fn -> load_node(node, keyed, env) end, &loaded/1)
  end

  # The rows this level attached to its parents.
  defp loaded({:ok, values}), do: %{rows: values |> Enum.map(&attached/1) |> Enum.sum()}
  defp loaded(_error), do: %{rows: nil}

  defp attached(nil), do: 0
  defp attached(rows) when is_list(rows), do: length(rows)
  defp attached(_row), do: 1

  defp load_node(
         %{rel: %Relationship{mapping: mapping}, children: children, table: table} = node,
         keyed,
         %{repo: repo, repo_opts: repo_opts, adapter: adapter, finish: finish} = env
       ) do
    {positions, unique} = positions(keyed, Enum.map(mapping, &elem(&1, 0)))

    with {:ok, query} <- adapter.preload_level_query(node, unique),
         rows = statement(table, env, fn -> repo.all(query, repo_opts) end),
         {:ok, rows} <- children(children, rows, env),
         {:ok, values} <- per_key(rows, node, length(unique)) do
      values = values |> Enum.map(&finish.(node, &1)) |> List.to_tuple()
      {:ok, Enum.map(positions, &elem(values, &1 - 1))}
    end
  end

  defp statement(%{name: name}, %{telemetry: telemetry}, fun),
    do: Telemetry.query(:data, :preload, Map.put(telemetry, :table, name), fun)

  defp as_loaded(_node, value), do: value

  # Each parent's 1-based key tuple position, and the distinct key tuples
  # (compared exactly) in first-seen order, in one pass.
  defp positions(keyed, locals) do
    {_seen, positions, unique} =
      Enum.reduce(keyed, {%{}, [], []}, fn keys, acc ->
        locals |> Enum.map(&Map.fetch!(keys, &1)) |> position(acc)
      end)

    {Enum.reverse(positions), Enum.reverse(unique)}
  end

  defp position(key, {seen, positions, unique}) when is_map_key(seen, key),
    do: {seen, [Map.fetch!(seen, key) | positions], unique}

  defp position(key, {seen, positions, unique}) do
    position = map_size(seen) + 1
    {Map.put(seen, key, position), [position | positions], [key | unique]}
  end

  defp children([], rows, _env), do: {:ok, rows}
  # Loaded rows carry their stitching columns, so they are their own keys.
  defp children(nodes, rows, %{depth: depth} = env),
    do: level(nodes, rows, rows, %{env | depth: depth + 1})

  # One value per key tuple, in position order, from rows numbered by it.
  # The rows arrive ordered by position (`c:Authzura.Adapter.preload_level_query/2`),
  # so one pass groups them; a position without rows gets none.
  defp per_key(
         rows,
         %{rel: %Relationship{kind: kind, name: name}, columns: columns, children: children},
         count
       ) do
    group = %{keep: columns ++ names(children), kind: kind, name: name, count: count}
    rows |> Enum.chunk_by(& &1.idx) |> grouped(1, group, [])
  end

  defp grouped([], position, %{count: count}, acc) when position > count,
    do: {:ok, Enum.reverse(acc)}

  defp grouped(
         [[%{idx: position} | _rows] = chunk | rest],
         position,
         %{keep: keep, kind: kind, name: name} = group,
         acc
       ) do
    with {:ok, value} <- value(kind, Enum.map(chunk, &Map.take(&1, keep)), name),
         do: grouped(rest, position + 1, group, [value | acc])
  end

  defp grouped(chunks, position, %{kind: kind, name: name, count: count} = group, acc)
       when position <= count do
    {:ok, value} = value(kind, [], name)
    grouped(chunks, position + 1, group, [value | acc])
  end

  defp value(:array, rows, _name), do: {:ok, rows}
  defp value(:object, [], _name), do: {:ok, nil}
  defp value(:object, [row], _name), do: {:ok, row}

  defp value(:object, [_first, _second | _rest], name),
    do: {:error, {:unsupported_query, {:object_cardinality, name}}}

  defp names(nodes), do: Enum.map(nodes, fn %{rel: %Relationship{name: name}} -> name end)

  # Each relationship's values, one per row in row order, go under its name.
  defp attach(rows, names, loaded) do
    names
    |> Enum.zip(loaded)
    |> Enum.reduce(rows, fn {name, values}, rows ->
      Enum.zip_with(rows, values, &Map.put(&1, name, &2))
    end)
  end
end

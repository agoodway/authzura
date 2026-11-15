defmodule Authzura.Validator do
  @moduledoc """
  Load-time enforceability check. The Store runs it on every snapshot a
  source loads, before publishing it, and `mix authzura.check` runs it on
  what it loads, so every `Authzura.Source` gets the same checks.

    * **Filters.** Every `:select` permission whose status is `:ok` has its
      filter compiled with `Authzura.Compiler` in validation mode
      (`session: :validate`), which type-checks session references without
      binding values. A failure denies the permission
      (`{:denied, [diagnostic]}`) and adds the same `:deny` diagnostic, with
      path `["filter"]`, to the snapshot.
    * **Root fields.** A permission whose `query_root_fields` name
      `select_by_pk` while the role cannot select every primary key column
      (or the table has none) is denied, path `["query_root_fields"]`,
      reason `{:select_by_pk_without_primary_key, missing_columns}`: Hasura
      refuses such metadata as inconsistent.
    * **Relationship keys.** A relationship whose mapping uses a column the
      adapter cannot batch as a preload key (`supported_key_kind?/1`) stays
      `preloadable?: false` (the struct default) and is recorded as a
      `:warning` naming the first such column. So is one with a pair whose two columns are not
      key-compatible (`{:incompatible_key_kinds, {local, pg_type}, {remote,
      pg_type}}`): both must share a `base_kind` (`smallint`, `integer` and
      `bigint` count as one; `text` and `varchar` are both `:text`), so
      `citext` pairs only with `citext` and `uuid` only with `uuid`, and enum
      columns must have the same enum type (name and schema). Otherwise the parent's values
      would be coerced, or fail to cast, against the target's key type.
      Every other relationship is granted `preloadable?: true`. Filters
      through a relationship that is not preloadable are still enforced
      faithfully, because `EXISTS` correlation needs no array parameters.

    * **Undecodable columns.** A table whose enforceable select
      permissions allow columns of base kind `:other` (an extension type such
      as PostGIS `geography` that the data repo's Postgrex types cannot
      decode, a composite, an array) gets one `:warning` with path
      `["columns"]` and reason `{:other_kind_columns, columns}`, the sorted
      names of those columns: the repo's Postgrex types must be able to
      decode them. They are left out of default column sets and read only
      when named. An extension type the repo does decode is not `:other`
      (introspection asks the repo's types module), so it gets no warning and is selected by
      default.

  Everything else is returned unchanged. Diagnostics are appended in table,
  relationship and permission-key order, so the result is deterministic.
  """

  alias Authzura.Compiler
  alias Authzura.Model.{Column, Diagnostic, Permission, Relationship, Snapshot, Table}

  # smallint, integer and bigint all bind as `bigint[]`.
  @integer_kinds Column.integer_kinds()

  @doc "Validates a snapshot as its source loaded it, denying what cannot be compiled."
  @spec validate(Snapshot.t(), module()) :: Snapshot.t()
  def validate(
        %Snapshot{tables: tables, permissions: permissions, diagnostics: existing} = snapshot,
        adapter
      ) do
    {checked, warnings} = collect(tables, &check_table(&1, tables, adapter))
    {permissions, denials} = collect(permissions, &check_permission(&1, checked, adapter))

    %{
      snapshot
      | tables: checked,
        permissions: permissions,
        diagnostics: existing ++ warnings ++ denials ++ other_kind_warnings(permissions, checked)
    }
  end

  # Allowed columns of base kind `:other`, one warning per table.
  defp other_kind_warnings(permissions, tables) do
    allowed =
      for {_key, %Permission{operation: :select, status: :ok, table: ref, columns: columns}} <-
            permissions,
          reduce: %{} do
        acc -> Map.update(acc, ref, MapSet.new(columns), &MapSet.union(&1, MapSet.new(columns)))
      end

    for {ref, columns} <- Enum.sort(allowed),
        {:ok, table} <- [Table.fetch(tables, ref)],
        names =
          for({name, _pg_type} <- Table.other_kind_columns(table, Enum.sort(columns)), do: name),
        names != [] do
      %Diagnostic{
        severity: :warning,
        table: ref,
        path: ["columns"],
        reason: {:other_kind_columns, names}
      }
    end
  end

  # Maps every entry to `{entry, diagnostics}`, in key order.
  defp collect(map, check) do
    {entries, diagnostics} = map |> Enum.sort() |> Enum.map(check) |> Enum.unzip()
    {Map.new(entries), List.flatten(diagnostics)}
  end

  # Relationship keys.

  defp check_table({ref, %Table{relationships: relationships} = table}, tables, adapter) do
    {relationships, warnings} =
      collect(relationships, &check_relationship(&1, ref, table, tables, adapter))

    {{ref, %{table | relationships: relationships}}, warnings}
  end

  defp check_relationship({name, %Relationship{} = rel}, ref, table, tables, adapter) do
    rel |> unsupported_key(table, tables, adapter) |> key_warning(name, rel, ref)
  end

  defp key_warning(nil, name, rel, _ref), do: {{name, %{rel | preloadable?: true}}, []}

  defp key_warning(reason, name, rel, ref) do
    warning = %Diagnostic{severity: :warning, table: ref, path: [name], reason: reason}
    {{name, %{rel | preloadable?: false}}, [warning]}
  end

  defp unsupported_key(%Relationship{target: target, mapping: mapping}, table, tables, adapter) do
    remote = Map.get(tables, target)

    pairs =
      Enum.map(mapping, fn {local, name} ->
        {key_column(table, local), key_column(remote, name)}
      end)

    Enum.find_value(pairs, &unsupported_pair(&1, adapter)) ||
      Enum.find_value(pairs, &incompatible_pair/1)
  end

  defp unsupported_pair({local, remote}, adapter),
    do: unsupported_kind(local, adapter) || unsupported_kind(remote, adapter)

  # Both sides of a pair must bind as the same key type, or the parent's
  # values would be coerced (or fail to cast) against the target's.
  defp incompatible_pair({local, remote}),
    do: local |> key_compatible?(remote) |> incompatibility(local, remote)

  defp incompatibility(true, _local, _remote), do: nil

  defp incompatibility(false, %Column{name: local, pg_type: local_type}, %Column{
         name: remote,
         pg_type: remote_type
       }),
       do: {:incompatible_key_kinds, {local, local_type}, {remote, remote_type}}

  defp key_compatible?(%Column{base_kind: :enum, pg_type: type, type_schema: schema}, %Column{
         base_kind: :enum,
         pg_type: type,
         type_schema: schema
       }),
       do: true

  defp key_compatible?(%Column{base_kind: :enum}, %Column{}), do: false
  defp key_compatible?(%Column{base_kind: kind}, %Column{base_kind: kind}), do: true

  defp key_compatible?(%Column{base_kind: local}, %Column{base_kind: remote}),
    do: local in @integer_kinds and remote in @integer_kinds

  defp key_column(%Table{columns: %{} = columns}, name),
    do: Map.get(columns, name, {:missing, name})

  defp key_column(nil, name), do: {:missing, name}

  defp unsupported_kind({:missing, name}, _adapter), do: {:unknown_key_column, name}

  defp unsupported_kind(%Column{} = column, adapter),
    do: column |> adapter.supported_key_kind?() |> key_kind(column)

  defp key_kind(true, %Column{}), do: nil

  defp key_kind(false, %Column{name: name, pg_type: pg_type}),
    do: {:unsupported_key_kind, name, pg_type}

  # Permission filters.

  defp check_permission(
         {key, %Permission{operation: :select, status: :ok, role: role, table: ref} = perm},
         tables,
         adapter
       ) do
    with :ok <- by_pk_root(perm, tables),
         :ok <- filter_compiles(perm, tables, adapter) do
      {{key, perm}, []}
    else
      {:error, path, reason} ->
        diagnostic = %Diagnostic{
          severity: :deny,
          role: role,
          table: ref,
          operation: :select,
          path: path,
          reason: reason
        }

        {{key, %{perm | status: {:denied, [diagnostic]}}}, [diagnostic]}
    end
  end

  defp check_permission({key, %Permission{} = perm}, _tables, _adapter), do: {{key, perm}, []}

  # Hasura refuses, as inconsistent metadata, a `select_by_pk` root field
  # for a role that cannot select every primary key column (or on a table
  # without one).
  defp by_pk_root(%Permission{root_fields: fields, table: ref, columns: columns}, tables)
       when is_list(fields) do
    with true <- :select_by_pk in fields,
         {:ok, %Table{primary_key: pk}} <- Table.fetch(tables, ref) do
      missing_key(pk, pk -- columns)
    else
      _no_by_pk_root -> :ok
    end
  end

  defp by_pk_root(%Permission{}, _tables), do: :ok

  # A primary key the role can select whole is enforceable; no key, or a
  # key column it cannot select, is not.
  defp missing_key([_ | _], []), do: :ok

  defp missing_key(_pk, missing),
    do: {:error, ["query_root_fields"], {:select_by_pk_without_primary_key, missing}}

  defp filter_compiles(perm, tables, adapter) do
    with {:error, reason} <- compile_filter(perm, tables, adapter),
         do: {:error, ["filter"], reason}
  end

  defp compile_filter(%Permission{table: ref, filter: filter}, tables, adapter) do
    with {:ok, table} <- Table.fetch(tables, ref),
         ctx = Compiler.root_ctx(table, tables, :validate, adapter, :permission),
         {:ok, _dynamic} <- Compiler.compile(filter, ctx) do
      :ok
    end
  end
end

defmodule Authzura.Sources.Hasura.Metadata do
  @moduledoc """
  Pure translation of a Hasura v2 metadata document (format v3) into
  Authzura's model.

  Nothing here raises on metadata: anything malformed, unknown or
  unsupported becomes a `%Diagnostic{}` and, for permissions, a
  `{:denied, diagnostics}` status. Names stay strings.

  ## Relationships

  `resolve_relationships/4` reads `object_relationships` and
  `array_relationships`. The section decides the cardinality. Supported
  `using` forms:

    * `foreign_key_constraint_on: "col"` or `["col", ...]` - the FK on the
      local table whose column set matches (object relationships only, as
      in Hasura)
    * `foreign_key_constraint_on: %{table, column | columns}` - the FK on the
      remote table whose column set matches and that references this table
    * `manual_configuration: %{remote_table, column_mapping}`

  FK mappings follow the constraint's column order. A relationship that
  cannot be resolved (no or several matching FKs, an untracked target, an
  unknown column, more than 8 column pairs, a duplicate name, or a name
  that is also a column) is left out of `Table.relationships` with a
  `:deny` diagnostic, so a filter that names it fails to parse and denies.

  ## Permissions

  `translate/4` builds one `%Permission{}` per role, table and operation.
  Select permissions deny on any problem (`:deny` diagnostics). Insert,
  update and delete permissions are parsed and stored for later stages; a
  problem there denies only that write permission, with `:warning`
  diagnostics, and never touches a read. Roles listed in `inherited_roles`
  are denied with a diagnostic and get no permission.

  ## Function permissions

  `translate_functions/2` reads `sources[].functions[]` into explicit execute
  grants per function and role. Only grants written in the metadata count;
  Hasura's `infer_function_permissions` is not in the metadata and is not
  applied, so Authzura follows the stricter rule. An inherited role is never
  granted, and a function listed twice is granted to no role.

  A grant is only the execute gate. The caller must still scope the rows a
  function returns with the return table's select permission (for example
  `Authzura.filter_rows/3`) and supply session arguments itself. A function
  tracked with `exposed_as: "mutation"` is reported like any other; the
  library is read-only and does not record how a function is exposed.

  Computed fields are not implemented. A select permission's
  `computed_fields` grant (a list of names) is ignored with a `:warning`
  diagnostic, `{:unsupported, :computed_fields}`, and the rest of the
  permission (filter, columns, limit, root fields) is enforced as usual. A
  computed field is never exposed: `columns` holds table columns only. A
  filter that references a computed field still fails to parse, so that
  permission is denied.
  """

  alias Authzura.Model.{Diagnostic, Permission, Relationship, Snapshot, Table}
  alias Authzura.Sources.Hasura.BoolExp
  alias Authzura.Util

  @max_pairs 8
  @sections [{"object_relationships", :object}, {"array_relationships", :array}]
  @operations [
    {"select_permissions", :select},
    {"insert_permissions", :insert},
    {"update_permissions", :update},
    {"delete_permissions", :delete}
  ]
  @fields %{
    select: [:filter, :columns, :limit, :allow_aggregations, :root_fields, :computed_fields],
    insert: [:check, :presets, :write_columns, :backend_only],
    update: [:filter, :optional_check, :presets, :write_columns, :backend_only],
    delete: [:filter, :backend_only]
  }
  @root_fields %{
    "select" => :select,
    "select_by_pk" => :select_by_pk,
    "select_aggregate" => :select_aggregate
  }
  @limits %{binding_depth: 15, syntactic_depth: 32, nodes: 1000}

  @typedoc "Introspected tables keyed by reference."
  @type tables :: %{Table.table_ref() => Table.t()}

  @doc false
  # The bounds every permission filter is parsed under, shared with test
  # fixtures so they parse exactly as a load does.
  @spec permission_limits() :: BoolExp.limits()
  def permission_limits, do: @limits

  @doc """
  Returns the `kind` of the source named `source_name`. A source without a
  `kind` is a Postgres source, as in Hasura.
  """
  @spec source_kind(term(), String.t()) :: {:ok, term()} | {:error, :source_not_found}
  def source_kind(metadata, source_name),
    do:
      with_source(metadata, source_name, {:error, :source_not_found}, fn source ->
        {:ok, Map.get(source, "kind", "postgres")}
      end)

  @doc """
  Lists the tables tracked in the source named `source_name`, in metadata
  order. Malformed table entries are skipped (`translate/4` reports them).
  """
  @spec tracked_tables(term(), String.t()) ::
          {:ok, [Table.table_ref()]} | {:error, :source_not_found}
  def tracked_tables(metadata, source_name),
    do:
      with_source(metadata, source_name, {:error, :source_not_found}, fn source ->
        {:ok, Enum.uniq(for {ref, _entry} <- entries(source), do: ref)}
      end)

  @doc """
  Resolves the relationships declared in `source_name` against introspected
  `tables` and foreign keys (`Authzura.Adapter.fk()`).

  Returns `tables` with `relationships` filled in, plus a `:deny` diagnostic
  for every relationship left out. An unknown source resolves nothing.
  """
  @spec resolve_relationships(term(), String.t(), tables(), [map()]) ::
          {tables(), [Diagnostic.t()]}
  def resolve_relationships(metadata, source_name, tables, fks)
      when is_map(tables) and is_list(fks) do
    metadata
    |> source_entries(source_name)
    |> Enum.filter(fn {ref, _entry} -> is_map_key(tables, ref) end)
    |> Enum.group_by(fn {ref, _entry} -> ref end, fn {_ref, entry} -> entry end)
    |> Enum.map_reduce(tables, fn {ref, entries}, tables ->
      {relationships, denied} = table_relationships(ref, entries, tables, fks)
      {denied, Map.update!(tables, ref, &%{&1 | relationships: relationships})}
    end)
    |> resolved()
  end

  defp resolved({denied, tables}), do: {tables, List.flatten(denied)}

  @doc """
  Translates every permission in `source_name` into `%Permission{}` structs,
  given `tables` whose relationships are already resolved.

  Returns the permissions (denied ones included) and every diagnostic. An
  unknown source translates nothing.
  """
  @spec translate(term(), String.t(), tables(), module()) ::
          {[Permission.t()], [Diagnostic.t()]}
  def translate(metadata, source_name, tables, adapter)
      when is_map(tables) and is_atom(adapter) do
    with_source(metadata, source_name, {[], []}, &translate_source(metadata, &1, tables, adapter))
  end

  @doc """
  Translates the `functions` of `source_name` into explicit execute grants:
  a map from function reference `{schema, name}` to the `MapSet` of roles
  listed in its `permissions`, plus the diagnostics.

  A function is a string name or a `%{"schema", "name"}` object (schema
  defaults to `"public"`). Every tracked function appears, with an empty set
  when nothing is granted. Anything malformed becomes a `:deny` diagnostic
  naming the function, and its grant is left out. An unknown source
  translates nothing. See the module doc, "Function permissions".
  """
  @spec translate_functions(term(), String.t()) ::
          {%{Snapshot.function_ref() => MapSet.t(String.t())}, [Diagnostic.t()]}
  def translate_functions(metadata, source_name) do
    {inherited, _diagnostics} = inherited_roles(metadata)

    with_source(metadata, source_name, {%{}, []}, fn source ->
      indexed =
        source |> list("functions") |> Enum.map(&entry(&1, "function")) |> Enum.with_index()

      refs = for {{ref, _entry}, _index} <- indexed, do: ref
      counts = Enum.frequencies(refs)

      {functions, diagnostics} =
        Enum.reduce(indexed, {%{}, []}, &function_entry(&1, &2, counts, inherited))

      {functions, Enum.reverse(diagnostics)}
    end)
  end

  # A function listed twice is ambiguous: it gets no grants (a `:deny`
  # diagnostic at each repeat), as a table listed twice gets no permission.
  defp function_entry({:invalid, index}, {functions, denied}, _counts, _inherited),
    do: {functions, [function_deny(:invalid_function, ["functions", "#{index}"]) | denied]}

  defp function_entry({{ref, entry}, index}, {functions, denied}, counts, inherited) do
    path = ["functions", "#{index}"]
    {granted, diagnostics} = function_grants(entry, ref, path, inherited)

    case counts do
      %{^ref => 1} ->
        {Map.put(functions, ref, granted), diagnostics ++ denied}

      _repeated ->
        {Map.put(functions, ref, MapSet.new()),
         diagnostics ++ duplicate_function(functions, ref, path) ++ denied}
    end
  end

  defp duplicate_function(functions, ref, path) when is_map_key(functions, ref),
    do: [function_deny(:duplicate_function, path, ref)]

  defp duplicate_function(_functions, _ref, _path), do: []

  # Grants and the diagnostics (newest first) of one function entry.
  defp function_grants(%{"permissions" => permissions}, ref, path, inherited)
       when is_list(permissions) do
    permissions
    |> Enum.with_index()
    |> Enum.reduce({MapSet.new(), []}, fn {permission, index}, {granted, denied} ->
      case function_role(permission, inherited) do
        {:ok, role} ->
          {MapSet.put(granted, role), denied}

        {:error, role, reason} ->
          diagnostic = function_deny(reason, path ++ ["permissions", "#{index}"], ref, role)
          {granted, [diagnostic | denied]}
      end
    end)
  end

  defp function_grants(%{"permissions" => _permissions}, ref, path, _inherited),
    do:
      {MapSet.new(), [function_deny(:invalid_function_permissions, path ++ ["permissions"], ref)]}

  defp function_grants(_entry, _ref, _path, _inherited), do: {MapSet.new(), []}

  defp function_deny(reason, path, ref \\ nil, role \\ nil),
    do: %{deny(reason, path) | function: ref, role: role}

  defp function_role(%{"role" => role}, inherited) when is_binary(role) do
    if MapSet.member?(inherited, role),
      do: {:error, role, {:unsupported, :inherited_role}},
      else: {:ok, role}
  end

  defp function_role(_permission, _inherited), do: {:error, nil, :invalid_function_permission}

  # Source and table entries.

  defp source(%{"sources" => sources}, name) when is_list(sources) do
    case Enum.find(sources, &match?(%{"name" => ^name}, &1)) do
      nil -> :error
      source -> {:ok, source}
    end
  end

  defp source(_metadata, _name), do: :error

  # Runs `fun` on the named source, or returns `missing` when there is none.
  defp with_source(metadata, name, missing, fun) do
    case source(metadata, name) do
      {:ok, source} -> fun.(source)
      :error -> missing
    end
  end

  defp source_entries(metadata, name),
    do: with_source(metadata, name, [], &valid_entries(entries(&1)))

  defp valid_entries(entries), do: for({_ref, _entry} = valid <- entries, do: valid)

  defp entries(%{"tables" => tables}) when is_list(tables),
    do: Enum.map(tables, &entry(&1, "table"))

  defp entries(_source), do: []

  # An entry whose `key` holds a valid reference: `{ref, entry}`, else `:invalid`.
  defp entry(%{} = entry, key) do
    case BoolExp.table_ref(Map.get(entry, key)) do
      {:ok, ref} -> {ref, entry}
      :error -> :invalid
    end
  end

  defp entry(_entry, _key), do: :invalid

  defp list(map, key) do
    case Map.get(map, key) do
      list when is_list(list) -> list
      _missing -> []
    end
  end

  # Relationships.

  defp table_relationships(ref, entries, tables, fks) do
    declared =
      for entry <- entries,
          {section, kind} <- @sections,
          {rel, index} <- entry |> list(section) |> Enum.with_index(),
          do: {section, kind, rel, index}

    counts = declared |> Enum.flat_map(&declared_name/1) |> Enum.frequencies()
    table = Map.fetch!(tables, ref)

    {relationships, denied} =
      Enum.reduce(declared, {%{}, []}, fn {section, _kind, _rel, _index} = decl, acc ->
        decl
        |> relationship(table, counts, tables, fks)
        |> add_relationship(ref, section, acc)
      end)

    {relationships, Enum.reverse(denied)}
  end

  defp add_relationship(
         {:ok, %Relationship{name: name} = resolved},
         _ref,
         _section,
         {rels, denied}
       ),
       do: {Map.put(rels, name, resolved), denied}

  defp add_relationship({:error, path, reason}, ref, section, {rels, denied}) do
    diagnostic = %Diagnostic{severity: :deny, table: ref, path: [section | path], reason: reason}
    {rels, [diagnostic | denied]}
  end

  defp declared_name({_section, _kind, %{"name" => name}, _index}) when is_binary(name),
    do: [name]

  defp declared_name(_decl), do: []

  defp relationship(
         {_section, kind, %{"name" => name, "using" => using}, _index},
         table,
         counts,
         tables,
         fks
       )
       when is_binary(name) and is_map(using) do
    with :ok <- unique_name(name, counts, table),
         {:ok, target, mapping} <- definition(using, kind, table, tables, fks),
         :ok <- check_mapping(mapping, table, Map.fetch!(tables, target)) do
      {:ok, %Relationship{name: name, kind: kind, target: target, mapping: mapping}}
    else
      {:error, reason} -> {:error, [name], reason}
    end
  end

  defp relationship({_section, _kind, %{"name" => name}, _index}, _table, _counts, _tables, _fks)
       when is_binary(name),
       do: {:error, [name], :invalid_relationship}

  defp relationship({_section, _kind, _rel, index}, _table, _counts, _tables, _fks),
    do: {:error, [Integer.to_string(index)], :invalid_relationship}

  defp unique_name(name, counts, %Table{columns: columns}) do
    cond do
      Map.fetch!(counts, name) > 1 -> {:error, :duplicate_relationship}
      is_map_key(columns, name) -> {:error, :conflicting_field}
      true -> :ok
    end
  end

  # FK on the remote table: `%{table, column | columns}`.
  defp definition(
         %{"foreign_key_constraint_on" => %{"table" => remote} = spec},
         _kind,
         table,
         tables,
         fks
       ) do
    with {:ok, target} <- target_ref(remote, tables),
         {:ok, key_set} <- spec |> Map.get("columns", Map.get(spec, "column")) |> key_columns(),
         {:ok, %{columns: columns, ref_columns: ref_columns}} <-
           fks |> Enum.filter(&remote_fk?(&1, target, Table.ref(table), key_set)) |> single_fk() do
      {:ok, target, Enum.zip(ref_columns, columns)}
    end
  end

  # Hasura's array relationships take only the remote-table form.
  defp definition(%{"foreign_key_constraint_on" => _columns}, :array, _table, _tables, _fks),
    do: {:error, :invalid_relationship}

  # FK on the local table: `"col"` or `["col", ...]`.
  defp definition(%{"foreign_key_constraint_on" => columns}, :object, table, tables, fks) do
    with {:ok, key_set} <- key_columns(columns),
         {:ok, %{columns: columns, ref_table: ref_table, ref_columns: ref_columns}} <-
           fks |> Enum.filter(&local_fk?(&1, Table.ref(table), key_set)) |> single_fk(),
         {:ok, target} <- tracked(ref_table, tables) do
      {:ok, target, Enum.zip(columns, ref_columns)}
    end
  end

  defp definition(
         %{"manual_configuration" => %{"remote_table" => remote, "column_mapping" => mapping}},
         _kind,
         _table,
         tables,
         _fks
       )
       when is_map(mapping) and map_size(mapping) > 0 do
    with {:ok, target} <- target_ref(remote, tables),
         :ok <- string_mapping(mapping) do
      {:ok, target, Enum.to_list(mapping)}
    end
  end

  defp definition(_using, _kind, _table, _tables, _fks), do: {:error, :invalid_relationship}

  defp target_ref(remote, tables) do
    case BoolExp.table_ref(remote) do
      {:ok, target} -> tracked(target, tables)
      :error -> {:error, :invalid_relationship}
    end
  end

  defp tracked(ref, tables) when is_map_key(tables, ref), do: {:ok, ref}
  defp tracked(ref, _tables), do: {:error, {:unknown_table, ref}}

  defp key_columns(column) when is_binary(column), do: {:ok, MapSet.new([column])}

  defp key_columns([_ | _] = columns),
    do: columns |> Enum.all?(&is_binary/1) |> key_set(columns)

  defp key_columns(_columns), do: {:error, :invalid_relationship}

  defp key_set(true, columns), do: {:ok, MapSet.new(columns)}
  defp key_set(false, _columns), do: {:error, :invalid_relationship}

  defp string_mapping(mapping),
    do:
      mapping
      |> Enum.all?(fn {local, remote} -> is_binary(local) and is_binary(remote) end)
      |> mapping_result()

  defp mapping_result(true), do: :ok
  defp mapping_result(false), do: {:error, :invalid_relationship}

  defp local_fk?(%{table: table, columns: columns}, ref, set),
    do: table == ref and MapSet.new(columns) == set

  defp remote_fk?(%{table: table, ref_table: ref_table, columns: columns}, target, ref, set),
    do: table == target and ref_table == ref and MapSet.new(columns) == set

  defp single_fk([fk]), do: {:ok, fk}
  defp single_fk([]), do: {:error, :no_foreign_key}
  defp single_fk([_ | _]), do: {:error, :ambiguous_foreign_key}

  defp check_mapping(mapping, _table, _target) when length(mapping) > @max_pairs,
    do: {:error, {:too_many_column_pairs, length(mapping)}}

  defp check_mapping(mapping, table, target) do
    Util.first_error(mapping, fn {local, remote} ->
      with :ok <- column_present(table, local), do: column_present(target, remote)
    end)
  end

  defp column_present(%Table{columns: columns}, column) when is_map_key(columns, column), do: :ok
  defp column_present(table, column), do: {:error, {:unknown_column, Table.ref(table), column}}

  # Permissions.

  defp translate_source(metadata, source, tables, adapter) do
    {inherited, inherited_diagnostics} = inherited_roles(metadata)
    entries = entries(source)
    valid = valid_entries(entries)

    duplicates =
      valid
      |> Enum.frequencies_by(fn {ref, _entry} -> ref end)
      |> Map.filter(fn {_ref, count} -> count > 1 end)

    ctx = %{
      tables: tables,
      adapter: adapter,
      inherited: inherited,
      duplicates: duplicates,
      unsupported: Map.new(valid, &unsupported_fields/1)
    }

    invalid = for :invalid <- entries, do: deny(:invalid_table, [])

    {permissions, diagnostics} =
      valid
      |> Enum.map(&table_permissions(&1, ctx))
      |> Enum.unzip()

    {List.flatten(permissions), inherited_diagnostics ++ invalid ++ List.flatten(diagnostics)}
  end

  defp inherited_roles(metadata) do
    entries = inherited_entries(metadata)

    roles =
      for %{"role_name" => role} when is_binary(role) <- entries, into: MapSet.new(), do: role

    {roles, Enum.map(entries, &inherited_diagnostic/1)}
  end

  defp inherited_diagnostic(%{"role_name" => role}) when is_binary(role),
    do: %{deny({:unsupported, :inherited_role}, []) | role: role}

  defp inherited_diagnostic(_entry), do: deny(:invalid_inherited_role, [])

  defp inherited_entries(%{"inherited_roles" => roles}) when is_list(roles), do: roles
  defp inherited_entries(_metadata), do: []

  defp unsupported_fields({ref, entry}) do
    fields =
      Map.new(
        names(entry, "computed_fields", :computed_field) ++
          names(entry, "remote_relationships", :remote_relationship)
      )

    {ref, fields}
  end

  defp names(entry, key, kind),
    do: for(%{"name" => name} when is_binary(name) <- list(entry, key), do: {name, kind})

  defp table_permissions({ref, entry}, ctx) do
    {permissions, diagnostics} =
      @operations
      |> Enum.map(fn {section, operation} ->
        entry |> list(section) |> section_permissions(ref, operation, ctx)
      end)
      |> Enum.unzip()

    {List.flatten(permissions), List.flatten(diagnostics)}
  end

  defp section_permissions(grants, ref, operation, %{inherited: inherited} = ctx) do
    {valid, invalid} = Enum.split_with(grants, &role_grant?/1)

    invalid =
      Enum.map(invalid, fn _grant ->
        severity(%{deny(:invalid_permission, []) | table: ref, operation: operation}, operation)
      end)

    grouped =
      valid
      |> Enum.group_by(fn %{"role" => role} -> role end)
      |> Enum.reject(fn {role, _grants} -> MapSet.member?(inherited, role) end)
      |> Enum.sort_by(&elem(&1, 0))

    permissions =
      Enum.map(grouped, fn {role, grants} -> permission(role, grants, ref, operation, ctx) end)

    warnings =
      Enum.flat_map(grouped, fn {role, grants} -> ignored(role, grants, ref, operation) end)

    {permissions, invalid ++ Enum.flat_map(permissions, &denials/1) ++ warnings}
  end

  # Grants that are read but not enforced: a select permission's computed
  # fields.
  defp ignored(role, grants, ref, :select) do
    for %{"permission" => %{"computed_fields" => [_ | _]}} <- grants do
      %Diagnostic{
        severity: :warning,
        reason: {:unsupported, :computed_fields},
        path: ["computed_fields"],
        role: role,
        table: ref,
        operation: :select
      }
    end
  end

  defp ignored(_role, _grants, _ref, _operation), do: []

  defp role_grant?(%{"role" => role}) when is_binary(role), do: true
  defp role_grant?(_grant), do: false

  defp denials(%Permission{status: {:denied, diagnostics}}), do: diagnostics
  defp denials(%Permission{status: :ok}), do: []

  defp permission(role, grants, ref, operation, ctx) do
    base = %Permission{role: role, table: ref, operation: operation}

    base
    |> build(grants, ctx)
    |> finish(base)
  end

  # A role granted twice, a table tracked twice or a table missing from the
  # database denies the permission before its fields are read.
  defp build(%Permission{}, [_, _ | _], _ctx), do: {:error, [{[], :duplicate_permission}]}

  defp build(%Permission{table: ref}, _grants, %{duplicates: duplicates})
       when is_map_key(duplicates, ref),
       do: {:error, [{[], :duplicate_table}]}

  defp build(%Permission{table: ref}, _grants, %{tables: tables})
       when not is_map_key(tables, ref),
       do: {:error, [{[], {:unknown_table, ref}}]}

  defp build(
         %Permission{operation: operation, table: ref} = base,
         [%{"permission" => spec}],
         %{tables: tables} = ctx
       )
       when is_map(spec) do
    table = Map.fetch!(tables, ref)

    @fields
    |> Map.fetch!(operation)
    |> Enum.reduce({base, []}, fn field, {permission, errors} ->
      case field(field, spec, table, ctx) do
        {:ok, updates} -> {struct!(permission, updates), errors}
        {:error, field_errors} -> {permission, [field_errors | errors]}
      end
    end)
    |> built()
  end

  defp build(%Permission{}, _grants, _ctx), do: {:error, [{[], :invalid_permission}]}

  # An accumulated value with its reversed (possibly nested) error lists.
  defp built({value, []}), do: {:ok, value}
  defp built({_value, errors}), do: {:error, errors |> Enum.reverse() |> List.flatten()}

  defp finish({:ok, permission}, _base), do: permission

  defp finish(
         {:error, errors},
         %Permission{role: role, table: table, operation: operation} = base
       ) do
    diagnostics =
      Enum.map(errors, fn {path, reason} ->
        %{deny(reason, path) | role: role, table: table, operation: operation}
        |> severity(operation)
      end)

    %{base | status: {:denied, diagnostics}}
  end

  defp deny(reason, path), do: %Diagnostic{severity: :deny, reason: reason, path: path}

  defp severity(diagnostic, :select), do: diagnostic
  defp severity(diagnostic, _write), do: %{diagnostic | severity: :warning}

  # Permission fields. Each returns {:ok, struct updates} or {:error, [{path, reason}]}.

  defp field(:filter, spec, table, ctx),
    do: required_bool_exp(spec, "filter", :filter, :missing_filter, table, ctx)

  defp field(:check, spec, table, ctx),
    do: required_bool_exp(spec, "check", :check, :missing_check, table, ctx)

  defp field(:optional_check, %{"check" => json}, table, ctx) when not is_nil(json),
    do: bool_exp(json, "check", :check, table, ctx)

  defp field(:optional_check, _spec, _table, _ctx), do: {:ok, check: nil}

  defp field(:columns, spec, table, _ctx) do
    case Map.fetch(spec, "columns") do
      {:ok, columns} -> columns(columns, table)
      :error -> {:error, [{["columns"], :missing_columns}]}
    end
  end

  defp field(:write_columns, spec, table, _ctx),
    do: spec |> Map.get("columns", []) |> columns(table)

  defp field(:limit, spec, _table, _ctx) do
    case Map.get(spec, "limit") do
      limit when is_nil(limit) or (is_integer(limit) and limit >= 0) -> {:ok, limit: limit}
      limit -> {:error, [{["limit"], {:invalid_limit, limit}}]}
    end
  end

  defp field(:allow_aggregations, spec, _table, _ctx),
    do: boolean(spec, "allow_aggregations", :allow_aggregations, :invalid_allow_aggregations)

  defp field(:backend_only, spec, _table, _ctx),
    do: boolean(spec, "backend_only", :backend_only, :invalid_backend_only)

  defp field(:root_fields, spec, _table, _ctx),
    do: spec |> Map.get("query_root_fields") |> root_fields()

  # The grant itself is ignored (see the moduledoc); only its shape is checked.
  defp field(:computed_fields, spec, _table, _ctx) do
    case Map.get(spec, "computed_fields") do
      fields when is_nil(fields) or is_list(fields) -> {:ok, []}
      fields -> {:error, [{["computed_fields"], {:invalid_computed_fields, fields}}]}
    end
  end

  defp field(:presets, spec, table, ctx), do: spec |> Map.get("set", %{}) |> presets(table, ctx)

  defp required_bool_exp(spec, key, field, missing, table, ctx) do
    case Map.fetch(spec, key) do
      {:ok, json} -> bool_exp(json, key, field, table, ctx)
      :error -> {:error, [{[key], missing}]}
    end
  end

  defp bool_exp(json, key, field, table, %{
         tables: tables,
         adapter: adapter,
         unsupported: unsupported
       }) do
    parse_ctx = %{
      table: table,
      tables: tables,
      adapter: adapter,
      limits: @limits,
      unsupported: unsupported
    }

    case BoolExp.parse(json, :permission, parse_ctx) do
      {:ok, ast} ->
        {:ok, [{field, ast}]}

      {:error, errors} ->
        {:error, Enum.map(errors, fn {path, reason} -> {[key | path], reason} end)}
    end
  end

  defp columns("*", %Table{columns: columns}),
    do: {:ok, columns: columns |> Map.keys() |> Enum.sort()}

  defp columns(names, %Table{columns: columns}) when is_list(names) do
    case Enum.reject(names, &(is_binary(&1) and is_map_key(columns, &1))) do
      [] -> {:ok, columns: Enum.uniq(names)}
      unknown -> {:error, Enum.map(unknown, &{["columns"], {:unknown_column, &1}})}
    end
  end

  defp columns(names, _table), do: {:error, [{["columns"], {:invalid_columns, names}}]}

  defp boolean(spec, key, field, invalid) do
    case Map.get(spec, key, false) do
      value when is_boolean(value) -> {:ok, [{field, value}]}
      value -> {:error, [{[key], {invalid, value}}]}
    end
  end

  defp root_fields(nil), do: {:ok, root_fields: :all}

  defp root_fields(names) when is_list(names) do
    case Enum.reject(names, &is_map_key(@root_fields, &1)) do
      [] -> {:ok, root_fields: names |> Enum.map(&Map.fetch!(@root_fields, &1)) |> Enum.uniq()}
      unknown -> {:error, Enum.map(unknown, &{["query_root_fields"], {:invalid_root_field, &1}})}
    end
  end

  defp root_fields(names), do: {:error, [{["query_root_fields"], {:invalid_root_field, names}}]}

  defp presets(set, %Table{columns: columns}, %{adapter: adapter}) when is_map(set) do
    {presets, errors} =
      Enum.reduce(set, {%{}, []}, fn {name, raw}, {presets, errors} ->
        case preset(Map.fetch(columns, name), name, raw, adapter) do
          {:ok, value} -> {Map.put(presets, name, value), errors}
          {:error, reason} -> {presets, [{["set", name], reason} | errors]}
        end
      end)

    built({[presets: presets], errors})
  end

  defp presets(set, _table, _ctx), do: {:error, [{["set"], {:invalid_presets, set}}]}

  defp preset({:ok, column}, _name, raw, adapter),
    do: BoolExp.operand(raw, :column, column, adapter)

  defp preset(:error, name, _raw, _adapter), do: {:error, {:unknown_column, name}}
end

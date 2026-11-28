defmodule Mix.Tasks.Authzura.Check do
  @shortdoc "Checks Hasura select permissions against the database"

  @moduledoc """
  Loads a Hasura v2 project's permissions and reports what Authzura denies.

      mix authzura.check --repo MyApp.Repo [--metadata-repo MyApp.MetadataRepo] [--source default] [--strict]

  The task starts the repo (and the metadata repo, when given), then runs
  `Authzura.Sources.Hasura.load/1` and `Authzura.Validator`, exactly as an
  instance does at boot. It only reads.

  Every diagnostic is printed on one line:

      severity role schema.table operation path: reason

  A function diagnostic prints `fn:schema.name` in the table position.

  Parts a diagnostic does not carry print as `-`. The last line counts the
  tables, select permissions, denials and warnings. No metadata is printed.

  A `deny` means that role, table and operation is refused at runtime. A
  `warning` is a narrower loss, such as a relationship that cannot be
  preloaded or a write permission Authzura cannot parse.

  The task exits 1 when any permission or relationship is denied (a `deny`
  diagnostic), or when the load itself fails (only a bounded error kind is
  printed, never the raw reason), and 0 otherwise. `--strict`
  also exits 1 on warnings.

  Example output:

      deny editor public.users select filter.nonexistent: {:unknown_field, "nonexistent"}
      2 tables, 2 select permissions, 0 functions, 1 denied, 0 warnings

  Run it against your real metadata before you depend on it, and in CI after
  every metadata change.

  ## Options

    * `--repo` (required) - the data repo, as the instance's `:repo`: the repo
      holding the data tables
    * `--metadata-repo` - the repo holding `hdb_catalog.hdb_metadata`
      (default: `--repo`)
    * `--source` - the Hasura source name (default `default`)
    * `--strict` - fail on warnings too
  """

  # `test/fixtures/host_app` is a tiny host project this task is run from
  # (`mix test --only host_app`, excluded by default because it compiles the
  # dependencies); it guards that `--repo` resolves in an app whose modules the
  # task itself compiles.
  use Mix.Task

  alias Authzura.Adapters.Postgres
  alias Authzura.Model.{Diagnostic, Permission, Snapshot}
  alias Authzura.Sources.Hasura
  alias Authzura.{Store, Validator}

  @switches [repo: :string, metadata_repo: :string, source: :string, strict: :boolean]
  @hint "Check the repo's connection settings and that hdb_catalog exists."
  @usage "usage: mix authzura.check --repo MyApp.Repo [--metadata-repo R] [--source default] [--strict]"

  @doc "Runs the check; see the moduledoc."
  @impl Mix.Task
  @spec run([String.t()]) :: :ok
  def run(args) do
    opts = parse(args)

    # Compiles and configures the host app, so its repo modules can be found.
    Mix.Task.run("app.config")

    {repo, metadata_repo, source, strict?} = settings(opts)

    start([repo, metadata_repo])

    [repo: metadata_repo, data_repo: repo, source_name: source]
    |> Hasura.load()
    |> validated()
    |> report(strict?)
    |> finish()
  end

  # The Store validates what a source loads; the task does the same.
  defp validated({:ok, %Snapshot{} = snapshot}), do: {:ok, Validator.validate(snapshot, Postgres)}
  defp validated(error), do: error

  defp parse(args) do
    case OptionParser.parse(args, strict: @switches) do
      {opts, [], []} -> opts
      _invalid -> Mix.raise("invalid arguments. #{@usage}")
    end
  end

  defp settings(opts) do
    repo = opts |> Keyword.get(:repo) |> repo!()
    metadata_repo = opts |> Keyword.get(:metadata_repo) |> metadata_repo(repo)

    {repo, metadata_repo, Keyword.get(opts, :source, "default"),
     Keyword.get(opts, :strict, false)}
  end

  defp repo!(nil), do: Mix.raise("--repo is required. #{@usage}")
  defp repo!(name), do: name |> String.split(".") |> Module.concat() |> loaded!()

  defp metadata_repo(nil, repo), do: repo
  defp metadata_repo(name, _repo), do: repo!(name)

  defp loaded!(repo) do
    case Code.ensure_loaded(repo) do
      {:module, ^repo} -> repo
      {:error, _reason} -> Mix.raise("Missing repo #{inspect(repo)}: module is not available")
    end
  end

  defp start(repos) do
    {:ok, _apps} = Application.ensure_all_started([:ecto_sql, :postgrex])
    repos |> Enum.uniq() |> Enum.each(&start_repo/1)
  end

  defp start_repo(repo) do
    case repo.start_link(pool_size: 2, log: false) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, reason} -> Mix.raise("could not start #{inspect(repo)}: #{kind(reason)}. #{@hint}")
    end
  end

  # Reporting.

  defp report({:ok, %Snapshot{diagnostics: diagnostics} = snapshot}, strict?) do
    Enum.each(diagnostics, &Mix.shell().info(line(&1)))
    Mix.shell().info(summary(snapshot))
    Enum.any?(diagnostics, &fails?(&1, strict?))
  end

  defp report({:error, reason}, _strict?) do
    Mix.shell().error("load failed: #{kind(reason)}. #{@hint}")
    true
  end

  defp fails?(%Diagnostic{severity: :deny}, _strict?), do: true
  defp fails?(%Diagnostic{severity: :warning}, strict?), do: strict?

  defp finish(false), do: :ok
  defp finish(true), do: exit({:shutdown, 1})

  defp kind(reason), do: reason |> Store.error_kind() |> inspect()

  defp line(%Diagnostic{
         severity: severity,
         role: role,
         table: table,
         function: function,
         operation: operation,
         path: path,
         reason: reason
       }) do
    "#{severity} #{part(role)} #{target(table, function)} #{part(operation)} #{path(path)}: #{inspect(reason)}"
  end

  defp part(nil), do: "-"
  defp part(value), do: to_string(value)

  # A table prints as `schema.name`, a function as `fn:schema.name`.
  defp target(nil, nil), do: "-"
  defp target(nil, function), do: "fn:" <> ref(function)
  defp target(table, _function), do: ref(table)

  defp ref({schema, name}), do: "#{schema}.#{name}"

  defp path([]), do: "-"
  defp path(path), do: Enum.join(path, ".")

  defp summary(%Snapshot{
         tables: tables,
         permissions: permissions,
         functions: functions,
         diagnostics: diagnostics
       }) do
    selects =
      permissions |> Map.values() |> Enum.filter(&match?(%Permission{operation: :select}, &1))

    denied = Enum.count(selects, &match?(%Permission{status: {:denied, _}}, &1))
    warnings = Enum.count(diagnostics, &match?(%Diagnostic{severity: :warning}, &1))

    "#{map_size(tables)} tables, #{length(selects)} select permissions, " <>
      "#{map_size(functions)} functions, #{denied} denied, #{warnings} warnings"
  end
end

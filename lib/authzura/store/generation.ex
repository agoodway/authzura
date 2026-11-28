defmodule Authzura.Store.Generation do
  @moduledoc """
  One complete, immutable policy generation of an instance.

  It is published under a single `:persistent_term` key. Only `freshness` is
  mutable: an `:atomics` ref whose slot 1 holds `last_confirmed_current_at`
  in monotonic milliseconds, so renewing freshness never rewrites the term,
  and whose slot 2 is 1 until a check finds the instance's connections not
  read-only (for `read_only: :connection`; see `connection_read_only?/1`).

  `admin` holds the configured admin role's template for every table
  (`Authzura.Model.Permission.admin/2` with an empty filter), built once
  with the generation; it is empty without an admin role.
  """

  alias Authzura.AST
  alias Authzura.Model.{Permission, Snapshot, Table}
  alias Authzura.Options

  @enforce_keys [
    :instance,
    :owner,
    :incarnation,
    :seq,
    :version,
    :snapshot,
    :templates,
    :config,
    :freshness
  ]
  defstruct @enforce_keys ++ [admin: %{}]

  @type t :: %__MODULE__{
          instance: atom(),
          owner: pid(),
          incarnation: reference(),
          seq: pos_integer(),
          version: term(),
          snapshot: Snapshot.t(),
          templates: %{{String.t(), Table.table_ref()} => {Permission.t(), AST.t()}},
          config: map(),
          freshness: :atomics.atomics_ref(),
          admin: %{Table.table_ref() => {Permission.t(), AST.t()}}
        }

  @doc """
  Whether reads may rely on the connections being read-only: the instance
  is configured `read_only: :connection`, the load that published this
  generation verified them, and no poll check has failed since (a failure
  is sticky until the next successful load). Otherwise reads use
  `SET TRANSACTION READ ONLY`.
  """
  @spec connection_read_only?(t()) :: boolean()
  def connection_read_only?(%__MODULE__{config: %{read_only: :connection}, freshness: ref}),
    do: :atomics.get(ref, 2) == 1

  def connection_read_only?(%__MODULE__{}), do: false

  @typedoc "A role's select access to one table; see `access/3`."
  @type access :: %{
          template: {Permission.t(), AST.t()},
          table: Table.t(),
          admin?: boolean()
        }

  @doc """
  Whether `role` is the configured admin role: the one role that bypasses
  permissions. `nil` never is, and neither is any role without one configured.
  """
  @spec admin_role?(Options.instance(), String.t() | nil) :: boolean()
  def admin_role?(%{admin_role: role}, role) when is_binary(role), do: true
  def admin_role?(_config, _role), do: false

  @doc """
  Whether `role` may execute the function `ref`: a role granted in the
  snapshot, or the configured admin role on any tracked function. An untracked
  function is never executable.
  """
  @spec function_allowed?(t(), String.t() | nil, Snapshot.function_ref()) :: boolean()
  def function_allowed?(
        %__MODULE__{config: config, snapshot: %Snapshot{functions: functions}},
        role,
        ref
      ) do
    case functions do
      %{^ref => roles} -> admin_role?(config, role) or MapSet.member?(roles, role)
      _untracked -> false
    end
  end

  @doc """
  The roles granted execute on the tracked function `ref`, sorted (the admin
  role is not listed), or `:error` when `ref` is not tracked.
  """
  @spec function_roles(t(), Snapshot.function_ref()) :: {:ok, [String.t()]} | :error
  def function_roles(%__MODULE__{snapshot: %Snapshot{functions: functions}}, ref) do
    case functions do
      %{^ref => roles} -> {:ok, roles |> MapSet.to_list() |> Enum.sort()}
      _untracked -> :error
    end
  end

  @doc """
  Returns `role`'s select access to the table `ref`: its non-denied
  template, the table, and whether `role` is the configured admin role. The
  admin role gets its prebuilt template from `admin` (every column, an
  empty filter) on any known table. Anything else is
  `{:error, :forbidden}`.
  """
  @spec access(t(), String.t(), Table.table_ref()) :: {:ok, access()} | {:error, :forbidden}
  def access(%__MODULE__{config: config} = generation, role, ref) do
    admin? = admin_role?(config, role)

    with {:ok, template} <- template(generation, role, ref, admin?),
         {:ok, table} <- Table.fetch(generation.snapshot.tables, ref) do
      {:ok, %{template: template, table: table, admin?: admin?}}
    else
      _missing -> {:error, :forbidden}
    end
  end

  defp template(%__MODULE__{admin: admin}, _role, ref, true), do: Map.fetch(admin, ref)

  defp template(%__MODULE__{templates: templates}, role, ref, false) do
    key = {role, ref}

    case templates do
      %{^key => {%Permission{}, _filter} = template} -> {:ok, template}
      _missing -> :error
    end
  end
end

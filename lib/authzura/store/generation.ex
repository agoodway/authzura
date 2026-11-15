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
  Returns `role`'s select access to the table `ref`: its non-denied
  template, the table, and whether `role` is the configured admin role. The
  admin role gets its prebuilt template from `admin` (every column, an
  empty filter) on any known table. Anything else is
  `{:error, :forbidden}`.
  """
  @spec access(t(), String.t(), Table.table_ref()) :: {:ok, access()} | {:error, :forbidden}
  def access(
        %__MODULE__{
          config: %{admin_role: role},
          admin: admin,
          snapshot: %Snapshot{tables: tables}
        },
        role,
        ref
      )
      when is_binary(role) do
    with %{^ref => template} <- admin,
         {:ok, table} <- Table.fetch(tables, ref) do
      {:ok, %{template: template, table: table, admin?: true}}
    else
      _missing -> {:error, :forbidden}
    end
  end

  def access(%__MODULE__{templates: templates, snapshot: %Snapshot{tables: tables}}, role, ref) do
    key = {role, ref}

    with %{^key => {%Permission{}, _filter} = template} <- templates,
         {:ok, table} <- Table.fetch(tables, ref) do
      {:ok, %{template: template, table: table, admin?: false}}
    else
      _missing -> {:error, :forbidden}
    end
  end
end

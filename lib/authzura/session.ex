defmodule Authzura.Session do
  @moduledoc """
  A normalized Hasura session: one resolved role plus its `x-hasura-*` variables.

  Build one with `new/2`. Variable names are lowercase, and `vars` always
  carries the effective role under `"x-hasura-role"`.
  """

  @enforce_keys [:role, :vars]
  defstruct [:role, :vars]

  @typedoc "A session: `role` is the effective role, `vars` the lowercase `x-hasura-*` map."
  @type t :: %__MODULE__{role: String.t(), vars: %{String.t() => String.t()}}

  @typedoc """
  Why a session was refused: `:conflicting_keys` (keys differing only in case
  carry different values), `:invalid_key` (a non-string key),
  `:role_not_allowed` (the role is not in `:allowed_roles`) or `:no_role`
  (no requested, claimed or default role). All are bad input.
  """
  @type kind :: :conflicting_keys | :invalid_key | :role_not_allowed | :no_role

  @typedoc "`{:invalid_session, kind, term}`; the term is the offending key or role, or `nil`."
  @type error :: {:invalid_session, kind(), term()}

  @prefix "x-hasura-"
  @role_key "x-hasura-role"
  @dropped ["x-hasura-admin-secret", "x-hasura-allowed-roles", "x-hasura-default-role"]

  @doc """
  Normalizes raw session variables and resolves the effective role.

  Options: `:allowed_roles`, `:default_role` and `:requested_role`.
  The requested role (option, then the map's `x-hasura-role`) falls back to
  the default role. An empty string counts as absent. When `:allowed_roles`
  is given, the effective role must be a member. `x-hasura-admin-secret`,
  `x-hasura-allowed-roles` and `x-hasura-default-role` are dropped from `vars`.

  Returns `{:ok, session}` or `{:error, {:invalid_session, kind, term}}`.

      iex> {:ok, session} =
      ...>   Authzura.Session.new(%{"X-Hasura-User-Id" => "42"},
      ...>     allowed_roles: ["user"],
      ...>     default_role: "user"
      ...>   )
      iex> session
      %Authzura.Session{
        role: "user",
        vars: %{"x-hasura-user-id" => "42", "x-hasura-role" => "user"}
      }

      iex> Authzura.Session.new(%{"x-hasura-role" => "admin"}, allowed_roles: ["user"])
      {:error, {:invalid_session, :role_not_allowed, "admin"}}
  """
  @spec new(map(), keyword()) :: {:ok, t()} | {:error, error()}
  def new(raw, opts) when is_map(raw) and is_list(opts) do
    with {:ok, folded} <- normalize_vars(raw),
         vars = Map.drop(folded, @dropped),
         {:ok, role} <- resolve_role(vars, opts) do
      {:ok, %__MODULE__{role: role, vars: Map.put(vars, @role_key, role)}}
    end
  end

  @doc """
  Folds a raw variable map to lowercase `x-hasura-*` keys.

  Keys outside the `x-hasura-` namespace are ignored. Unlike `new/2` this
  keeps the role-claim keys (`x-hasura-allowed-roles`, `x-hasura-default-role`,
  `x-hasura-admin-secret`). Keys that fold to the same name must carry equal
  values, and every key must be a string.
  """
  @spec normalize_vars(map()) :: {:ok, map()} | {:error, error()}
  def normalize_vars(raw) when is_map(raw), do: Enum.reduce_while(raw, {:ok, %{}}, &put_var/2)

  defp put_var({key, _value}, _acc) when not is_binary(key),
    do: {:halt, {:error, {:invalid_session, :invalid_key, key}}}

  defp put_var({key, value}, acc), do: key |> String.downcase() |> put_folded(value, acc)

  defp put_folded(@prefix <> _ = key, value, {:ok, vars}),
    do: vars |> Map.get(key, value) |> merge(key, value, vars)

  defp put_folded(_key, _value, acc), do: {:cont, acc}

  defp merge(value, key, value, vars), do: {:cont, {:ok, Map.put(vars, key, value)}}

  defp merge(_existing, key, _value, _vars),
    do: {:halt, {:error, {:invalid_session, :conflicting_keys, key}}}

  defp resolve_role(vars, opts) do
    role =
      present(opts[:requested_role]) || present(vars[@role_key]) || present(opts[:default_role])

    with {:ok, role} <- require_role(role) do
      check_allowed(role, opts[:allowed_roles])
    end
  end

  defp present(""), do: nil
  defp present(value), do: value

  defp require_role(nil), do: {:error, {:invalid_session, :no_role, nil}}
  defp require_role(role), do: {:ok, role}

  defp check_allowed(role, nil), do: {:ok, role}

  defp check_allowed(role, allowed) when is_list(allowed),
    do: allowed |> Enum.member?(role) |> allowed(role)

  defp allowed(true, role), do: {:ok, role}
  defp allowed(false, role), do: {:error, {:invalid_session, :role_not_allowed, role}}
end

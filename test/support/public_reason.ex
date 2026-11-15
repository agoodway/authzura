defmodule Authzura.Test.PublicReason do
  @moduledoc """
  The oracle for "every error is a public reason": `public_reason?/1`
  accepts exactly the shapes of the documented reason types and nothing
  else, so a leaked internal error (an exception struct, a raw
  `Postgrex.Error`, a compiler term) fails it.

  It enumerates `t:Authzura.Scope.reason/0`, `t:Authzura.Input.reason/0`,
  `t:Authzura.Executor.reason/0`, `t:Authzura.Get.reason/0`,
  `t:Authzura.Preload.Tree.reason/0`, `t:Authzura.Preload.Loader.reason/0`,
  `t:Authzura.QueryShape.reason/0` (as `{:unsupported_query, reason}`),
  `t:Authzura.Store.unavailable/0`, `t:Authzura.Session.error/0` and
  `t:Authzura.JWT.reason/0`. Keep it in step with those types.
  """

  @plain [:forbidden, :root_field_disabled, :multiple_results, :stale_permissions, :not_ready]

  @unsupported_query ~w(fragment_source subquery_source modifying_cte fragment_cte existing_select
                        aggregate lock distinct with_ties limit preload_requires_execute
                        combination_tables combination_preload combination_shape reserved_alias
                        dynamic_repo preload_in_transaction get_requires_bare_root no_primary_key
                        preload preload_limit empty_columns)a

  @invalid_input [:not_a_root, :not_a_map, :limit, :offset, :rejected_by_database]
  @too_many [:list, :patterns, :columns, :order_by, :preload_order_by]
  @bool_exp_plain [
    :invalid_expression,
    :null_operand,
    :relationship_in_input,
    :too_deep,
    :too_large
  ]
  @bool_exp_unsupported [
    :column_comparison,
    :cast,
    :json_column,
    :computed_field,
    :remote_relationship
  ]
  @session_kinds [:conflicting_keys, :invalid_key, :role_not_allowed, :no_role]
  @invalid_jwt [
    :algorithm,
    :signature,
    :expired,
    :not_yet_valid,
    :issued_in_future,
    :invalid_time_claim,
    :issuer,
    :audience
  ]
  @jwt_config [
    :missing_key,
    :invalid_key,
    :weak_secret,
    :invalid_algorithms,
    :key_algorithm_mismatch
  ]

  @doc "Whether `reason` is one of the public denial reasons."
  @spec public_reason?(term()) :: boolean()
  def public_reason?(reason) when reason in @plain, do: true
  def public_reason?({:forbidden_columns, [_ | _] = columns}), do: strings?(columns)
  def public_reason?({:missing_session_variable, name}), do: is_binary(name)

  def public_reason?({:invalid_session_value, name, why}),
    do: is_binary(name) and cast_reason?(why)

  def public_reason?({:unsupported_query, reason}), do: unsupported_query?(reason)
  def public_reason?({:invalid_input, reason}), do: invalid_input?(reason)
  def public_reason?({:unsupported_column_type, {:type, type}}), do: is_binary(type)
  def public_reason?({:unsupported_column_type, column}), do: is_binary(column)

  def public_reason?({:invalid_session, :no_role, nil}), do: true

  def public_reason?({:invalid_session, kind, detail}),
    do: kind in @session_kinds and is_binary(detail)

  def public_reason?({:invalid_jwt, why}), do: why in @invalid_jwt
  def public_reason?({:invalid_jwt_config, {:unknown_algorithm, alg}}), do: is_binary(alg)
  def public_reason?({:invalid_jwt_config, why}), do: why in @jwt_config
  def public_reason?({:jwt_missing_role_claims, claim}), do: is_binary(claim)
  def public_reason?({:jwt_invalid_claims, {:claims_map, path}}), do: is_binary(path)

  def public_reason?({:jwt_invalid_claims, why}),
    do: why in [:allowed_roles_not_list, :invalid_claim_value]

  def public_reason?({:invalid_headers, :missing_token}), do: true
  def public_reason?({:unsupported_option, option}), do: is_atom(option)
  def public_reason?(_reason), do: false

  defp cast_reason?({:invalid_value, type}), do: is_binary(type)
  defp cast_reason?({:unsupported_type, type}), do: is_binary(type)
  defp cast_reason?(:invalid_array_literal), do: true
  defp cast_reason?(_why), do: false

  defp unsupported_query?(reason) when reason in @unsupported_query, do: true
  defp unsupported_query?({:preload, name}), do: is_binary(name)
  defp unsupported_query?({:option, option}), do: is_atom(option)
  defp unsupported_query?({:object_cardinality, name}), do: is_binary(name)
  defp unsupported_query?(_reason), do: false

  defp invalid_input?(reason) when reason in @invalid_input, do: true
  defp invalid_input?({:unknown_keys, [_ | _] = keys}), do: strings?(keys)
  defp invalid_input?({:duplicate_key, key}), do: is_atom(key)
  defp invalid_input?({:columns, why}), do: why in [:invalid, :empty]
  defp invalid_input?({:order_by, why}), do: why in [:invalid, :duplicate_column, :unorderable]
  defp invalid_input?({:preload, :invalid}), do: true
  defp invalid_input?({:too_many, what}), do: what in @too_many
  defp invalid_input?({:invalid_pattern, column}), do: is_binary(column)
  defp invalid_input?({:primary_key, :invalid}), do: true

  defp invalid_input?([_ | _] = errors), do: Enum.all?(errors, &parse_error?/1)

  defp invalid_input?(_reason), do: false

  # `{path, reason}` with a `t:Authzura.Sources.Hasura.BoolExp.reason/0`.
  defp parse_error?({path, why}) when is_list(path), do: strings?(path) and bool_exp_reason?(why)
  defp parse_error?(_error), do: false

  defp bool_exp_reason?(why) when why in @bool_exp_plain, do: true
  defp bool_exp_reason?({:unknown_field, name}), do: is_binary(name)
  defp bool_exp_reason?({:unknown_operator, op}), do: is_binary(op)
  defp bool_exp_reason?({:unknown_table, {schema, name}}), do: strings?([schema, name])
  defp bool_exp_reason?({:unsupported, what}), do: what in @bool_exp_unsupported

  defp bool_exp_reason?({:operator_type_mismatch, op, type}), do: strings?([op, type])
  defp bool_exp_reason?({:invalid_literal, why}), do: literal_reason?(why)
  defp bool_exp_reason?(_why), do: false

  defp literal_reason?(why) when is_atom(why), do: true
  defp literal_reason?(why), do: cast_reason?(why)

  defp strings?(list), do: Enum.all?(list, &is_binary/1)
end

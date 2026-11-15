defmodule Authzura.JWTUnsecuredTest do
  # Toggles a global JOSE setting, so it must not run concurrently.
  use ExUnit.Case, async: false

  alias Authzura.JWT

  @secret String.duplicate("s3cret-key-", 4)
  @ns "https://hasura.io/jwt/claims"

  setup do
    previous = JOSE.unsecured_signing()
    JOSE.unsecured_signing(true)
    on_exit(fn -> JOSE.unsecured_signing(previous) end)
  end

  defp none_token do
    header = Base.url_encode64(~s({"alg":"none"}), padding: false)

    claims = %{
      @ns => %{"x-hasura-allowed-roles" => ["user"], "x-hasura-default-role" => "user"}
    }

    payload = Base.url_encode64(Jason.encode!(claims), padding: false)
    "#{header}.#{payload}."
  end

  test "none variants are stripped from the allowlist" do
    assert {:error, {:invalid_jwt, :algorithm}} =
             JWT.verify(none_token(), key: @secret, algorithms: ["none", "none", "NONE", "HS256"])
  end

  test "an allowlist of only none is a config error" do
    assert {:error, {:invalid_jwt_config, :invalid_algorithms}} =
             JWT.verify(none_token(), key: @secret, algorithms: ["none", "None"])
  end
end

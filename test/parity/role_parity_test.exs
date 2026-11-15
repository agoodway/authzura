defmodule Authzura.Parity.RoleParityTest do
  @moduledoc """
  Role resolution against a real Hasura v2.51.6: the same HS256 JWT is
  sent to Hasura (no admin secret, `x-hasura-role` when a role is
  requested) and verified by `Authzura.JWT`, then the read runs on both
  sides and the results or errors are compared.
  """

  use Authzura.ParityCase

  alias Authzura.Parity.{Hasura, Runner}

  @namespace "https://hasura.io/jwt/claims"
  @read Read.new(Fixture.table(:articles), columns: ["id", "title"])

  defp claims(default_role, allowed_roles, vars \\ %{"x-hasura-user-id" => "1"}) do
    %{
      "sub" => "1",
      @namespace =>
        Map.merge(vars, %{
          "x-hasura-default-role" => default_role,
          "x-hasura-allowed-roles" => allowed_roles
        })
    }
  end

  defp jwt(claims, requested_role \\ nil), do: {:jwt, claims, requested_role}

  test "the default role is used when none is requested" do
    assert {:ok, rows} = assert_parity(@read, jwt(claims("author", ["author", "everyone"])))
    assert ids(rows) == [1, 2]
  end

  test "a requested role that is allowed" do
    auth = jwt(claims("author", ["author", "everyone"]), "everyone")
    assert {:ok, rows} = assert_parity(@read, auth)
    assert ids(rows) == [1, 2, 3, 4]
  end

  test "a requested role that is not allowed" do
    auth = jwt(claims("author", ["author", "everyone"]), "cols")

    assert {:error, "access-denied", {:invalid_session, :role_not_allowed, "cols"}} =
             assert_parity(@read, auth)
  end

  test "a default role that is not allowed" do
    assert {:error, "access-denied", {:invalid_session, :role_not_allowed, "cols"}} =
             assert_parity(@read, jwt(claims("cols", ["author"])))
  end

  test "an empty requested role counts as absent" do
    assert {:ok, rows} = assert_parity(@read, jwt(claims("author", ["author", "everyone"]), ""))
    assert ids(rows) == [1, 2]
  end

  test "a token without the role claims" do
    auth = jwt(%{"sub" => "1", @namespace => %{"x-hasura-user-id" => "1"}})

    assert {:error, "jwt-missing-role-claims",
            {:jwt_missing_role_claims, "x-hasura-allowed-roles"}} = assert_parity(@read, auth)
  end

  test "allowed roles that are not a list" do
    assert {:error, "jwt-invalid-claims", {:jwt_invalid_claims, :allowed_roles_not_list}} =
             assert_parity(@read, jwt(claims("author", "author")))
  end

  test "a session variable missing from the claims" do
    auth = jwt(claims("author", ["author"], %{}))

    assert {:error, "not-found", {:missing_session_variable, "x-hasura-user-id"}} =
             assert_parity(@read, auth)
  end

  test "a token with a bad signature" do
    token = Hasura.sign(claims("author", ["author"]), "not-the-parity-key-0123456789abcdef")

    assert {:error, "invalid-jwt", {:invalid_jwt, :signature}} =
             assert_parity(@read, {:token, token, nil})
  end

  test "an expired token" do
    expired = Map.put(claims("author", ["author"]), "exp", System.os_time(:second) - 3600)
    assert {:error, "invalid-jwt", {:invalid_jwt, :expired}} = assert_parity(@read, jwt(expired))
  end

  test "requesting admin when it is not an allowed role" do
    auth = jwt(claims("author", ["author"]), "admin")

    assert {:error, "access-denied", {:invalid_session, :role_not_allowed, "admin"}} =
             assert_parity(@read, auth)
  end

  # A known, intended difference: Hasura treats an allowed JWT role named
  # `admin` as its admin, while Authzura grants admin only to a configured
  # `admin_role` (this instance has none), so `admin` is an ordinary role
  # without a permission.
  test "an allowed role named admin is Hasura's admin but not Authzura's" do
    auth = jwt(claims("author", ["author", "admin"]), "admin")

    assert %{hasura: {:ok, rows}, authzura: {:error, :forbidden}} =
             Runner.run(@read, auth, instance())

    assert ids(rows) |> Enum.sort() == [1, 2, 3, 4]
  end
end

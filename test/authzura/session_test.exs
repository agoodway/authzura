defmodule Authzura.SessionTest do
  use ExUnit.Case, async: true

  alias Authzura.Session

  test "keeps only x-hasura-* keys, lowercased, and writes the role back" do
    assert {:ok,
            %Session{
              role: "editor",
              vars: %{"x-hasura-user-id" => "1", "x-hasura-role" => "editor"} = vars
            }} =
             Session.new(%{"X-Hasura-User-Id" => "1", "Other" => "x"},
               allowed_roles: ["editor"],
               default_role: "editor"
             )

    assert map_size(vars) == 2
  end

  test "default role must be allowed" do
    assert {:error, {:invalid_session, :role_not_allowed, "admin"}} =
             Session.new(%{}, allowed_roles: ["reader"], default_role: "admin")
  end

  test "role in the map must be allowed" do
    assert {:error, {:invalid_session, :role_not_allowed, "user"}} =
             Session.new(%{"x-hasura-role" => "user"},
               allowed_roles: ["contractor"],
               default_role: "contractor"
             )
  end

  test "requested_role option wins over the map's role" do
    assert {:ok, %Session{role: "b", vars: %{"x-hasura-role" => "b"}}} =
             Session.new(%{"x-hasura-role" => "a"},
               requested_role: "b",
               allowed_roles: ["a", "b"],
               default_role: "a"
             )
  end

  test "empty role counts as absent" do
    assert {:ok, %Session{role: "a"}} =
             Session.new(%{"x-hasura-role" => ""}, allowed_roles: ["a"], default_role: "a")

    assert {:ok, %Session{role: "a"}} =
             Session.new(%{}, requested_role: "", default_role: "a")
  end

  test "keys folding to the same name with different values conflict" do
    assert {:error, {:invalid_session, :conflicting_keys, "x-hasura-user-id"}} =
             Session.new(%{"X-Hasura-User-Id" => "1", "x-hasura-user-id" => "2"},
               default_role: "a"
             )
  end

  test "keys folding to the same name with equal values are merged" do
    assert {:ok, %Session{vars: %{"x-hasura-user-id" => "1"}}} =
             Session.new(%{"X-Hasura-User-Id" => "1", "x-hasura-user-id" => "1"},
               default_role: "a"
             )
  end

  test "drops admin secret, allowed roles and default role" do
    session = %{
      "x-hasura-admin-secret" => "s",
      "X-Hasura-Allowed-Roles" => "a",
      "x-hasura-default-role" => "a"
    }

    assert {:ok, %Session{vars: vars}} = Session.new(session, default_role: "a")
    assert vars == %{"x-hasura-role" => "a"}
  end

  test "empty allowed_roles rejects everything" do
    assert {:error, {:invalid_session, :role_not_allowed, "a"}} =
             Session.new(%{}, allowed_roles: [], default_role: "a")
  end

  test "no role at all" do
    assert {:error, {:invalid_session, :no_role, nil}} = Session.new(%{}, [])
  end

  test "non-string keys are rejected" do
    assert {:error, {:invalid_session, :invalid_key, :atom_key}} =
             Session.new(%{:atom_key => "1"}, default_role: "a")
  end

  test "conflicts are detected before dropped keys are removed" do
    assert {:error, {:invalid_session, :conflicting_keys, "x-hasura-admin-secret"}} =
             Session.new(
               %{"x-hasura-admin-secret" => "1", "X-Hasura-Admin-Secret" => "2"},
               default_role: "a"
             )
  end

  test "normalize_vars folds keys and keeps role-claim keys" do
    assert {:ok, %{"x-hasura-allowed-roles" => ["a"], "x-hasura-user-id" => "1"} = vars} =
             Session.normalize_vars(%{
               "X-Hasura-Allowed-Roles" => ["a"],
               "x-hasura-user-id" => "1",
               "Other" => "x"
             })

    refute Map.has_key?(vars, "other")

    assert {:error, {:invalid_session, :conflicting_keys, "x-hasura-a"}} =
             Session.normalize_vars(%{"x-hasura-a" => "1", "X-HASURA-A" => "2"})

    assert {:error, {:invalid_session, :invalid_key, :k}} = Session.normalize_vars(%{k: "1"})
  end
end

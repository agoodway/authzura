defmodule Authzura.Integration.FunctionPermissionsTest do
  use Authzura.DataCase, async: true

  import Authzura.HasuraFixture, only: [function_grants: 2, session!: 1]

  alias Authzura.{HasuraFixture, TestSource}
  alias Authzura.Model.Snapshot

  @articles {"public", "articles"}

  defp metadata(functions, opts \\ []),
    do: HasuraFixture.metadata([%{table: @articles}], [functions: functions] ++ opts)

  setup %{test: name} do
    instance =
      HasuraFixture.start_instance!(
        name,
        Repo,
        metadata([
          function_grants("search", ["user", "editor"]),
          function_grants({"api", "report"}, ["editor"]),
          %{function: "locked"}
        ]),
        admin_role: "root"
      )

    {:ok, instance: instance}
  end

  describe "authorize_function/3 and function_allowed?/3" do
    test "granted roles, by string name or reference", %{instance: instance} do
      for {role, function} <- [
            {"user", "search"},
            {"user", {"public", "search"}},
            {"editor", {"api", "report"}}
          ] do
        assert :ok = Authzura.authorize_function(session!(role), function, instance: instance)
        assert Authzura.function_allowed?(session!(role), function, instance: instance)
      end
    end

    test "a role without a grant is forbidden", %{instance: instance} do
      for {role, function} <- [
            {"user", {"api", "report"}},
            {"user", "locked"},
            {"nobody", "search"}
          ] do
        assert {:error, :forbidden} =
                 Authzura.authorize_function(session!(role), function, instance: instance)

        refute Authzura.function_allowed?(session!(role), function, instance: instance)
      end
    end

    test "the schema matters", %{instance: instance} do
      refute Authzura.function_allowed?(session!("editor"), "report", instance: instance)
      refute Authzura.function_allowed?(session!("user"), {"api", "search"}, instance: instance)
    end

    test "an unknown function and a malformed reference are forbidden", %{instance: instance} do
      for function <- ["missing", nil, {"public", :search}] do
        assert {:error, :forbidden} =
                 Authzura.authorize_function(session!("user"), function, instance: instance)
      end
    end

    test "the admin role may execute any tracked function, and only tracked ones",
         %{instance: instance} do
      assert :ok = Authzura.authorize_function(session!("root"), "locked", instance: instance)

      assert :ok =
               Authzura.authorize_function(session!("root"), {"api", "report"},
                 instance: instance
               )

      assert {:error, :forbidden} =
               Authzura.authorize_function(session!("root"), "missing", instance: instance)
    end

    test "an instance that is not running is not ready" do
      assert {:error, :not_ready} =
               Authzura.authorize_function(session!("user"), "search",
                 instance: :no_such_instance
               )

      refute Authzura.function_allowed?(session!("user"), "search", instance: :no_such_instance)
    end

    test "a nil role is refused when no admin role is configured", %{test: name} do
      instance =
        HasuraFixture.start_instance!(
          :"#{name}_no_admin",
          Repo,
          metadata([function_grants("search", ["user"])])
        )

      session = %{session!("user") | role: nil}

      assert {:error, :forbidden} =
               Authzura.authorize_function(session, "search", instance: instance)
    end

    test "a bare name is looked up in the instance's default_prefix", %{test: name} do
      instance =
        HasuraFixture.start_instance!(
          :"#{name}_prefix",
          Repo,
          metadata([
            function_grants({"api", "report"}, ["editor"]),
            function_grants("search", ["user"])
          ]),
          default_prefix: "api"
        )

      assert Authzura.function_allowed?(session!("editor"), "report", instance: instance)
      refute Authzura.function_allowed?(session!("user"), "search", instance: instance)

      assert Authzura.function_allowed?(session!("user"), {"public", "search"},
               instance: instance
             )
    end

    test "functions of another source are not granted", %{test: name} do
      other = %{
        name: "other",
        kind: "postgres",
        tables: [],
        functions: [function_grants("search", ["user"])]
      }

      instance =
        HasuraFixture.start_instance!(
          :"#{name}_other",
          Repo,
          HasuraFixture.metadata([%{table: @articles}], sources: [other])
        )

      assert {:error, :forbidden} =
               Authzura.authorize_function(session!("user"), "search", instance: instance)

      assert Authzura.function_roles("search", instance: instance) == {:error, :forbidden}
    end
  end

  describe "function_roles/2" do
    test "lists the granted roles, sorted", %{instance: instance} do
      assert Authzura.function_roles("search", instance: instance) == {:ok, ["editor", "user"]}
      assert Authzura.function_roles({"api", "report"}, instance: instance) == {:ok, ["editor"]}
      assert Authzura.function_roles("locked", instance: instance) == {:ok, []}
    end

    test "unknown or malformed is forbidden", %{instance: instance} do
      assert Authzura.function_roles("missing", instance: instance) == {:error, :forbidden}
      assert Authzura.function_roles(:search, instance: instance) == {:error, :forbidden}
    end

    test "not ready" do
      assert Authzura.function_roles("search", instance: :no_such_instance) ==
               {:error, :not_ready}
    end
  end

  test "a changed snapshot is served after a reload", %{test: name} do
    {instance, agent} =
      HasuraFixture.start_instance_with_source!(
        :"#{name}_reload",
        Repo,
        metadata([function_grants("search", ["user"])])
      )

    assert Authzura.function_allowed?(session!("user"), "search", instance: instance)

    %Snapshot{} =
      revoked = HasuraFixture.snapshot!(Repo, metadata([function_grants("search", ["editor"])]))

    TestSource.put(agent, snapshot: revoked, version: "v2")
    assert :ok = Authzura.reload(instance)

    refute Authzura.function_allowed?(session!("user"), "search", instance: instance)
    assert Authzura.function_allowed?(session!("editor"), "search", instance: instance)
  end
end

defmodule Authzura.Integration.ExecutorTest do
  use Authzura.CommittedCase

  alias Authzura.{Error, HasuraFixture, TelemetryHelper}
  alias Authzura.Test.Schemas.Organization

  @organizations {"public", "organizations"}
  @users {"public", "users"}
  @execute_events [[:authzura, :execute, :start], [:authzura, :execute, :stop]]
  @repo_query [:authzura, :test, :repo, :query]

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @organizations,
        array_relationships: [
          %{
            name: "users",
            using: %{foreign_key_constraint_on: %{table: @users, column: "org_id"}}
          }
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "name"], filter: %{}}}
        ]
      },
      %{
        table: @users,
        select_permissions: [%{role: "user", permission: %{columns: ["id"], filter: %{}}}]
      }
    ])
  end

  setup %{test: test} do
    Repo.query!("insert into public.organizations values (1, 'one'), (2, 'two')")

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata(), admin_role: "admin")}
  end

  defp session, do: HasuraFixture.session!("user")

  defp count, do: Repo.query!("select count(*) from public.organizations").rows

  # The SQL and params of the read the executor ran in this process.
  defp read_query do
    assert_receive {:telemetry, @repo_query, %{query: "SELECT " <> _ = sql, params: params}}
    {sql, params}
  end

  describe "all/3" do
    test "returns maps with exactly the requested keys", %{instance: i} do
      query = from(o in Organization, order_by: o.id)

      assert {:ok, [%{id: 1}, %{id: 2}] = rows} =
               Authzura.all(query, session(), instance: i, columns: [:id])

      assert Enum.all?(rows, &(Map.keys(&1) == [:id]))
    end

    test "table queries are keyed by column strings", %{instance: i} do
      query = from(o in "organizations", order_by: o.id)

      assert {:ok, [%{"id" => 1, "name" => "one"}, %{"id" => 2, "name" => "two"}]} =
               Authzura.all(query, session(), instance: i)
    end

    test "returns denials from scoping", %{instance: i} do
      assert {:error, {:forbidden_columns, ["missing"]}} =
               Authzura.all("organizations", session(), instance: i, columns: ["missing"])
    end

    test "all!/3 raises on denial", %{instance: i} do
      assert [%{id: 1}, %{id: 2}] =
               Organization
               |> order_by([o], o.id)
               |> Authzura.all!(session(), instance: i, columns: [:id])

      assert %Error{reason: {:unsupported_query, {:option, :prefix}}} =
               catch_error(
                 Authzura.all!(Organization, session(), instance: i, repo_opts: [prefix: "audit"])
               )
    end
  end

  describe "one/3" do
    test "returns one row or nil", %{instance: i} do
      assert {:ok, %{id: 2, name: "two"}} =
               Authzura.one(where(Organization, [o], o.id == 2), session(), instance: i)

      assert {:ok, nil} =
               Authzura.one(where(Organization, [o], o.id == 9), session(), instance: i)
    end

    test "two matching rows give :multiple_results", %{instance: i} do
      assert {:error, :multiple_results} = Authzura.one(Organization, session(), instance: i)

      assert %Error{reason: :multiple_results} =
               catch_error(Authzura.one!(Organization, session(), instance: i))
    end

    test "one!/3 returns the row", %{instance: i} do
      assert %{id: 1} =
               Authzura.one!(where(Organization, [o], o.id == 1), session(), instance: i)
    end

    test "reads at most two rows, for the admin role too", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      for role <- ["user", "admin"] do
        assert {:error, :multiple_results} =
                 Authzura.one(Organization, HasuraFixture.session!(role), instance: i)

        assert {sql, params} = read_query()
        assert sql =~ ~r/LIMIT \$\d+$/
        assert List.last(params) == 2
      end

      assert {:ok, [_one, _two]} = Authzura.all(Organization, session(), instance: i)
      assert {sql, _params} = read_query()
      refute sql =~ "LIMIT"
    end

    test "a caller limit below two is kept", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)

      assert {:ok, %{id: 1}} =
               Organization
               |> order_by([o], o.id)
               |> limit(1)
               |> Authzura.one(session(), instance: i)

      assert {_sql, params} = read_query()
      assert List.last(params) == 1
    end

    test "combinations are capped as a whole, never per branch", %{instance: i, test: test} do
      Repo.query!(
        "insert into public.organizations values (3, 'three'), (4, 'four'), (5, 'five')"
      )

      TelemetryHelper.forward!(test, [@repo_query], caller_only: true)
      first = where(Organization, [o], o.id == 1)

      # Duplicates across UNION ALL branches are two rows.
      assert {:error, :multiple_results} =
               Authzura.one(union_all(first, ^first), session(), instance: i)

      assert {sql, _params} = read_query()
      assert [_whole] = Regex.scan(~r/LIMIT/, sql)

      # UNION removes them.
      assert {:ok, %{id: 1}} = Authzura.one(union(first, ^first), session(), instance: i)

      # Either side of the EXCEPT capped at two rows changes the result: a
      # capped left side loses row 5, and a capped right side (four rows)
      # leaves more than one row behind.
      others = where(Organization, [o], o.id in [1, 2, 3, 4])

      assert {:ok, %{id: 5}} =
               Authzura.one(except(Organization, ^others), session(), instance: i)
    end
  end

  describe "repo binding" do
    test "a different dynamic repo gives :dynamic_repo", %{instance: i} do
      {:ok, pid} = Repo.start_link(name: nil)

      try do
        Repo.put_dynamic_repo(pid)

        assert {:error, {:unsupported_query, :dynamic_repo}} =
                 Authzura.all(Organization, session(), instance: i)

        assert {:error, {:unsupported_query, :dynamic_repo}} =
                 Authzura.one(Organization, session(), instance: i)
      after
        Repo.put_dynamic_repo(Repo)
        Supervisor.stop(pid)
      end

      assert {:ok, [_one, _two]} = Authzura.all(Organization, session(), instance: i)
    end

    test "a source-changing repo option is rejected", %{instance: i} do
      assert {:error, {:unsupported_query, {:option, :prefix}}} =
               Authzura.all(Organization, session(), instance: i, repo_opts: [prefix: "audit"])
    end

    test "allowlisted repo options are accepted", %{instance: i} do
      opts = [timeout: 5_000, log: false, telemetry_options: [], telemetry_event: [:t12]]

      assert {:ok, [_one, _two]} =
               Authzura.all(Organization, session(), instance: i, repo_opts: opts)
    end
  end

  test "a modifying CTE is rejected and nothing is written", %{instance: i} do
    delete = from(o in "organizations")
    query = with_cte(Organization, "w", as: ^delete, operation: :delete_all)

    assert {:error, {:unsupported_query, :modifying_cte}} =
             Authzura.all(query, session(), instance: i)

    assert count() == [[2]]
  end

  describe "telemetry" do
    test "emits an execute span", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, @execute_events, instance: i)

      assert {:ok, _rows} = Authzura.all(Organization, session(), instance: i)

      assert_receive {:telemetry, [:authzura, :execute, :start],
                      %{instance: ^i, role: "user", mode: :all}}

      assert_receive {:telemetry, [:authzura, :execute, :stop],
                      %{instance: ^i, role: "user", mode: :all, result: :granted}}

      assert {:error, :multiple_results} = Authzura.one(Organization, session(), instance: i)

      assert_receive {:telemetry, [:authzura, :execute, :stop],
                      %{mode: :one, result: :denied, reason_class: :multiple_results}}
    end

    test "scoping denials are observable", %{instance: i, test: test} do
      TelemetryHelper.forward!(test, @execute_events, instance: i)

      assert {:error, :forbidden} =
               Authzura.all(Organization, HasuraFixture.session!("nobody"), instance: i)

      assert_receive {:telemetry, [:authzura, :execute, :stop],
                      %{role: "nobody", mode: :all, result: :denied, reason_class: :forbidden}}

      assert {:error, {:forbidden_columns, ["missing"]}} =
               Authzura.one("organizations", session(), instance: i, columns: ["missing"])

      assert_receive {:telemetry, [:authzura, :execute, :stop],
                      %{mode: :one, result: :denied, reason_class: :forbidden_columns}}
    end
  end
end

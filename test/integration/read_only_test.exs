defmodule Authzura.Integration.ReadOnlyTest do
  use Authzura.CommittedCase

  alias Authzura.{HasuraFixture, TelemetryHelper}
  alias Authzura.Test.Schemas.Organization
  alias Postgrex.Error

  @organizations {"public", "organizations"}
  @users {"public", "users"}

  setup %{test: test} do
    Repo.query!("insert into public.organizations values (1, 'one')")

    metadata =
      HasuraFixture.metadata([
        %{
          table: @organizations,
          array_relationships: [
            %{
              name: "users",
              using: %{foreign_key_constraint_on: %{table: @users, column: "org_id"}}
            }
          ],
          select_permissions: [%{role: "user", permission: %{columns: ["id"], filter: %{}}}]
        },
        %{
          table: @users,
          select_permissions: [%{role: "user", permission: %{columns: ["id"], filter: %{}}}]
        }
      ])

    %{instance: HasuraFixture.start_instance!(test, Repo, metadata)}
  end

  defp session, do: HasuraFixture.session!("user")

  # Trusted developer code that writes: `nextval` advances a sequence.
  defp writing_query,
    do: where(Organization, [o], fragment("nextval('public.test_seq') > 0"))

  test "a write inside the executor's transaction is refused", %{instance: i} do
    assert %Error{postgres: %{code: :read_only_sql_transaction}} =
             catch_error(Authzura.all(writing_query(), session(), instance: i))

    assert %Error{postgres: %{code: :read_only_sql_transaction}} =
             catch_error(Authzura.one(writing_query(), session(), instance: i))
  end

  test "inside a caller's open transaction the read is not wrapped", %{instance: i} do
    # The trusted-caller boundary: Authzura cannot change an open
    # transaction's access mode, so the caller's transaction governs.
    assert {:error, :rolled_back} =
             Repo.transaction(fn ->
               assert {:ok, [%{id: 1}]} = Authzura.all(writing_query(), session(), instance: i)
               Repo.rollback(:rolled_back)
             end)
  end

  test "an exception span is emitted when the repo raises", %{instance: i, test: test} do
    TelemetryHelper.forward!(test, [[:authzura, :execute, :exception]], instance: i)

    catch_error(Authzura.all(writing_query(), session(), instance: i))

    assert_receive {:telemetry, [:authzura, :execute, :exception],
                    %{instance: ^i, mode: :all, kind: :error, exception_class: Postgrex.Error}}
  end

  # An unnamed statement is two exchanges (parse/describe, then
  # bind/execute); a named, cached one is prepared once per connection and
  # then one exchange. The access mode must still be READ ONLY.
  test "the transaction-control statements are named and cached per connection",
       %{instance: i} do
    {:ok, names} =
      Repo.checkout(fn ->
        for _round <- 1..3 do
          assert {:ok, [%{id: 1}]} = Authzura.all(Organization, session(), instance: i)

          assert {:ok, [%{"id" => 1, "users" => []}]} =
                   Authzura.all("organizations", session(), instance: i, preload: ["users"])
        end

        {:ok,
         Repo.query!("select name from pg_prepared_statements order by name").rows
         |> List.flatten()}
      end)

    assert "authzura_read_only" in names
    assert "authzura_snapshot" in names

    assert %Error{postgres: %{code: :read_only_sql_transaction}} =
             catch_error(Authzura.all(writing_query(), session(), instance: i))
  end
end

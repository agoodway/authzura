defmodule Authzura.Integration.InputPushdownAllInputTest do
  @moduledoc """
  `input_index_pushdown` through `all_input/4`, which runs in its own
  transaction (so it needs committed data): rows are identical on and off,
  and a malformed operand is refused the same whatever the table holds.
  """

  use Authzura.CommittedCase, async: false

  alias Authzura.HasuraFixture

  @probe {"public", "pushdown_probe"}
  @malformed %{filter: %{"id" => %{"_eq" => "abc"}}}

  setup %{test: test} do
    on_exit(fn -> Repo.query!("DELETE FROM public.pushdown_probe") end)

    metadata =
      HasuraFixture.metadata([
        %{
          table: @probe,
          select_permissions: [
            %{
              role: "org",
              permission: %{
                columns: ["id", "org_id", "author_id", "title"],
                filter: %{"org_id" => %{"_eq" => "X-Hasura-Org-Id"}}
              }
            }
          ]
        }
      ])

    %{
      on:
        HasuraFixture.start_instance!(:"#{test}_on", Repo, metadata, input_index_pushdown: true),
      off: HasuraFixture.start_instance!(:"#{test}_off", Repo, metadata),
      session: HasuraFixture.session!("org", %{"x-hasura-org-id" => "1"})
    }
  end

  defp seed!(orgs) do
    Repo.query!(
      """
      INSERT INTO public.pushdown_probe (id, org_id, author_id, title)
      SELECT n, 1 + n % $1, 1 + n % 7, 't' || n % 4 FROM generate_series(1, 40) AS n
      """,
      [orgs]
    )
  end

  test "all_input returns the same rows on and off", %{on: on, off: off, session: session} do
    seed!(3)

    for filter <- [
          %{"id" => %{"_eq" => 4}},
          %{"author_id" => %{"_in" => [1, 2, 3]}, "title" => %{"_eq" => "t1"}},
          %{"id" => %{"_in" => []}}
        ] do
      input = %{filter: filter, order_by: [{"id", :asc}]}

      assert Authzura.all_input("pushdown_probe", session, input, instance: on) ==
               Authzura.all_input("pushdown_probe", session, input, instance: off)
    end
  end

  test "a malformed operand is refused alike on an empty table, hidden rows only and visible rows",
       %{on: on, off: off, session: session} do
    expected = Authzura.all_input("pushdown_probe", session, @malformed, instance: off)
    assert {:error, {:invalid_input, [{["id", "_eq"], {:invalid_literal, _reason}}]}} = expected

    for state <- [:empty, :hidden_only, :visible_and_hidden] do
      Repo.query!("DELETE FROM public.pushdown_probe")

      case state do
        :empty ->
          :ok

        :hidden_only ->
          Repo.query!(
            "INSERT INTO public.pushdown_probe (id, org_id, author_id) VALUES (1, 2, 1)"
          )

        :visible_and_hidden ->
          seed!(2)
      end

      assert Authzura.all_input("pushdown_probe", session, @malformed, instance: on) == expected
    end
  end
end

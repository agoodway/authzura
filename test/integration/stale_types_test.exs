defmodule Authzura.Integration.StaleTypesTest do
  @moduledoc """
  A generation whose enum labels or enum type no longer match the database
  (the window before the next poll reloads it) must deny the read with
  `{:error, :stale_permissions}`, never raise Postgres's `22P02` or `42704`.

  Every test creates its own type and tables under fresh names: a pooled
  connection's prepared statements refer to a type by OID, so recreating a
  type under the same name would break statements cached by an earlier test.
  """

  use Authzura.CommittedCase

  alias Authzura.Adapters.Postgres.Introspection
  alias Authzura.HasuraFixture
  alias Postgrex.Error, as: PostgresError

  setup %{test: test} do
    n = System.unique_integer([:positive])
    names = %{type: "stale_mood_#{n}", moods: "stale_moods_#{n}", owners: "stale_owners_#{n}"}
    %{type: type, moods: moods, owners: owners} = names

    Repo.query!("CREATE TYPE public.#{type} AS ENUM ('happy', 'sad')")
    Repo.query!("CREATE TABLE public.#{owners} (mood public.#{type} PRIMARY KEY)")

    Repo.query!(
      "CREATE TABLE public.#{moods} (id bigint PRIMARY KEY, mood public.#{type} NOT NULL)"
    )

    Repo.query!("INSERT INTO public.#{owners} VALUES ('happy')")
    Repo.query!("INSERT INTO public.#{moods} VALUES (1, 'happy'), (2, 'sad')")

    on_exit(fn ->
      Repo.query!("DROP TABLE IF EXISTS public.#{moods}, public.#{owners}")
      Repo.query!("DROP SCHEMA IF EXISTS stale_elsewhere CASCADE")
      Repo.query!("DROP TYPE IF EXISTS public.#{type}, public.#{type}_renamed")
    end)

    Map.put(names, :instance, HasuraFixture.start_instance!(test, Repo, metadata(names)))
  end

  defp metadata(%{moods: moods, owners: owners}) do
    HasuraFixture.metadata([
      %{
        table: {"public", owners},
        array_relationships: [
          %{
            name: "moods",
            using: %{
              manual_configuration: %{
                remote_table: {"public", moods},
                column_mapping: %{mood: "mood"}
              }
            }
          }
        ],
        select_permissions: HasuraFixture.select_permissions("user", "*")
      },
      %{
        table: {"public", moods},
        select_permissions: [
          %{role: "user", permission: %{columns: "*", filter: %{mood: %{_eq: "happy"}}}},
          %{role: "member", permission: %{columns: "*", filter: %{mood: %{_in: ["happy"]}}}}
        ]
      }
    ])
  end

  defp read(%{instance: instance, moods: moods}, role),
    do: Authzura.all(moods, HasuraFixture.session!(role), instance: instance)

  test "the generation reads before any change", ctx do
    assert {:ok, [%{"id" => 1, "mood" => "happy"}]} = read(ctx, "user")
    assert {:ok, [%{"id" => 1}]} = read(ctx, "member")
  end

  test "a renamed label (22P02) is :stale_permissions", %{type: type} = ctx do
    Repo.query!("ALTER TYPE public.#{type} RENAME VALUE 'happy' TO 'glad'")

    assert {:error, :stale_permissions} = read(ctx, "user")
    assert {:error, :stale_permissions} = read(ctx, "member")
  end

  # The owners' permission compares no enum, so the same errors from the
  # caller's own code are raised, not taken for a stale generation.
  test "without an enum comparison, 22P02 and 42704 are raised", %{owners: owners} = ctx do
    session = HasuraFixture.session!("user")

    for {query, code} <- [
          {from(o in owners, where: fragment("'x'::int > 0")), :invalid_text_representation},
          {from(o in owners, where: fragment("'nope'::regtype IS NOT NULL")), :undefined_object}
        ] do
      assert %PostgresError{postgres: %{code: ^code}} =
               catch_error(Authzura.all(query, session, instance: ctx.instance))
    end
  end

  test "a renamed type (42704) is :stale_permissions", %{type: type, owners: owners} = ctx do
    Repo.query!("ALTER TYPE public.#{type} RENAME TO #{type}_renamed")

    assert {:error, :stale_permissions} = read(ctx, "user")
    assert {:error, :stale_permissions} = read(ctx, "member")

    assert {:error, :stale_permissions} =
             Authzura.all(owners, HasuraFixture.session!("user"),
               instance: ctx.instance,
               preload: [:moods]
             )
  end

  test "a type moved to another schema (42704) is :stale_permissions", %{type: type} = ctx do
    Repo.query!("CREATE SCHEMA stale_elsewhere")
    Repo.query!("ALTER TYPE public.#{type} SET SCHEMA stale_elsewhere")

    assert {:error, :stale_permissions} = read(ctx, "user")
  end

  test "the fingerprint changes when the type moves between schemas on the search path", %{
    type: type,
    moods: moods
  } do
    Repo.query!("CREATE SCHEMA stale_elsewhere")

    Repo.checkout(fn ->
      Repo.query!("SET search_path TO public, stale_elsewhere")

      try do
        {:ok, before} = Introspection.fingerprint(Repo, [{"public", moods}])
        Repo.query!("ALTER TYPE public.#{type} SET SCHEMA stale_elsewhere")
        assert {:ok, moved} = Introspection.fingerprint(Repo, [{"public", moods}])
        assert moved != before
      after
        Repo.query!("RESET search_path")
      end
    end)
  end
end

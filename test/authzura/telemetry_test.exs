defmodule Authzura.TelemetryTest do
  use Authzura.CommittedCase

  alias Authzura.{HasuraFixture, Telemetry, TelemetryHelper}
  alias Authzura.Test.ReadOnlyRepo
  alias Authzura.Test.Schemas.{Article, Organization, User}
  alias Postgrex.{Error, Result}

  @sentinel "ZQX_sentinel_7f3a"
  @events for event <- [:input, :scope, :execute, :query, :preload, :probe],
              stage <- [:start, :stop, :exception],
              do: [:authzura, event, stage]
  @organizations {"public", "organizations"}
  @articles {"public", "articles"}
  @users {"public", "users"}

  defp metadata do
    HasuraFixture.metadata([
      %{
        table: @articles,
        object_relationships: [
          %{name: "author", using: %{foreign_key_constraint_on: "author_id"}}
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "title", "author_id"], filter: %{}}},
          # The session variable is bound as a real SQL parameter.
          %{
            role: "probe",
            permission: %{
              columns: ["id", "title"],
              filter: %{"title" => %{"_eq" => "X-Hasura-Sentinel"}}
            }
          }
        ]
      },
      %{
        table: @users,
        object_relationships: [
          %{name: "manager", using: %{foreign_key_constraint_on: "manager_id"}}
        ],
        select_permissions: [
          %{role: "user", permission: %{columns: ["id", "manager_id"], filter: %{}}}
        ]
      },
      %{
        table: @organizations,
        select_permissions: HasuraFixture.select_permissions("user", ["id", "name"])
      }
    ])
  end

  setup %{test: test} do
    Enum.each(
      [
        "insert into public.organizations values (1, 'one')",
        "insert into public.users (id, org_id, email, role) values (1, 1, 'a@x.com', 'editor')",
        """
        insert into public.articles (id, org_id, author_id, status, is_published, title) values
          (1, 1, 1, 'draft', false, 'one'), (2, 1, 1, 'draft', false, 'two'),
          (3, 1, 1, 'draft', false, '#{@sentinel}')
        """
      ],
      &Repo.query!/1
    )

    TelemetryHelper.forward!(test, @events, caller_only: true)
    %{instance: HasuraFixture.start_instance!(test, Repo, metadata())}
  end

  defp session(vars \\ %{}), do: HasuraFixture.session!("user", vars)

  # Untruncated, so a sentinel cannot hide behind inspect's limits.
  defp dump(term), do: inspect(term, limit: :infinity, printable_limit: :infinity)

  defp stops(events, name), do: for({[:authzura, ^name, :stop], meta} <- events, do: meta)

  describe "span/4" do
    test "emits the events, measurements and context of :telemetry.span/3" do
      assert :done = Telemetry.span(:probe, %{a: 1}, fn -> :done end, &%{b: &1})

      assert [
               {[:authzura, :probe, :start], %{a: 1, telemetry_span_context: context}},
               {[:authzura, :probe, :stop], %{a: 1, b: :done, telemetry_span_context: context}}
             ] = TelemetryHelper.drain()

      assert is_reference(context)
    end

    test "measurements match :telemetry.span/3" do
      id = {__MODULE__, :measurements}
      parent = self()

      :telemetry.attach_many(
        id,
        [[:authzura, :probe, :start], [:authzura, :probe, :stop]],
        fn event, measurements, _meta, _config ->
          send(parent, {:measured, event, measurements})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(id) end)

      Telemetry.span(:probe, %{}, fn -> :ok end, fn _ -> %{} end)

      assert_receive {:measured, [:authzura, :probe, :start], start}
      assert start |> Map.keys() |> Enum.sort() == [:monotonic_time, :system_time]

      assert_receive {:measured, [:authzura, :probe, :stop], stop}
      assert stop |> Map.keys() |> Enum.sort() == [:duration, :monotonic_time]
    end

    test "an exception adds only its kind and class, and is re-raised" do
      assert_raise ArgumentError, fn ->
        Telemetry.span(:probe, %{a: 1}, fn -> raise ArgumentError, @sentinel end, &%{b: &1})
      end

      assert catch_throw(Telemetry.span(:probe, %{}, fn -> throw({:x, @sentinel}) end, &%{b: &1})) ==
               {:x, @sentinel}

      assert catch_exit(Telemetry.span(:probe, %{}, fn -> exit({:x, @sentinel}) end, &%{b: &1})) ==
               {:x, @sentinel}

      assert [
               _start,
               {[:authzura, :probe, :exception], error},
               _start2,
               {[:authzura, :probe, :exception], thrown},
               _start3,
               {[:authzura, :probe, :exception], exited}
             ] = TelemetryHelper.drain()

      assert error |> Map.keys() |> Enum.sort() ==
               [:a, :exception_class, :kind, :telemetry_span_context]

      assert %{kind: :error, exception_class: ArgumentError} = error
      assert %{kind: :throw, exception_class: :throw} = thrown
      assert %{kind: :exit, exception_class: :exit} = exited
    end

    test "failure reasons are reduced to a class" do
      assert Telemetry.reason_class(:forbidden) == :forbidden
      assert Telemetry.reason_class({:forbidden_columns, [@sentinel]}) == :forbidden_columns
      assert Telemetry.reason_class({@sentinel, 1}) == :other
      assert Telemetry.reason_class(@sentinel) == :other
      assert Telemetry.reason_class([@sentinel]) == :other
      assert Telemetry.reason_class(%Error{message: @sentinel}) == Error

      assert Telemetry.reason_class({:error, %DBConnection.ConnectionError{message: @sentinel}}) ==
               :error

      assert Telemetry.reason_class(%DBConnection.ConnectionError{message: @sentinel}) ==
               DBConnection.ConnectionError

      Telemetry.span(:probe, %{}, fn -> {:error, {:boom, @sentinel}} end)
      Telemetry.span(:probe, %{}, fn -> {:error, %Error{message: @sentinel}} end)

      assert [%{result: :error, error_class: :boom} = meta, %{error_class: Error}] =
               TelemetryHelper.drain() |> stops(:probe)

      refute Map.has_key?(meta, :error)
    end

    test "query/4 stops with result: :rejected for an ordinary refusal" do
      assert :rejected = Telemetry.query(:setup, :root, %{table: "t"}, fn -> :rejected end)

      assert [%{category: :setup, stage: :root, table: "t", result: :rejected} = meta] =
               TelemetryHelper.drain() |> stops(:query)

      refute Map.has_key?(meta, :rows)
    end
  end

  describe "statement spans" do
    test "a plain read: transaction control, then one data root", %{instance: i} do
      assert {:ok, [_one]} = Authzura.all(Organization, session(), instance: i)

      assert [
               %{
                 instance: ^i,
                 category: :transaction_control,
                 stage: :root,
                 table: "organizations"
               },
               %{instance: ^i, category: :data, stage: :root, table: "organizations", rows: 1}
             ] = TelemetryHelper.drain() |> stops(:query)
    end

    test "two preload levels add two data preloads and two preload spans", %{instance: i} do
      assert {:ok, [_one, _two, _three]} =
               Authzura.all(from(a in Article, order_by: a.id), session(),
                 instance: i,
                 preload: [author: [preload: [:manager]]]
               )

      events = TelemetryHelper.drain()

      assert [
               %{category: :transaction_control, stage: :root},
               %{category: :data, stage: :root, rows: 3},
               %{instance: ^i, category: :data, stage: :preload, table: "users", rows: 1},
               %{instance: ^i, category: :data, stage: :preload, table: "users", rows: 0}
             ] = stops(events, :query)

      assert [
               %{instance: ^i, relationship: "manager", depth: 2, parents: 1, rows: 0},
               %{instance: ^i, relationship: "author", depth: 1, parents: 3, rows: 3}
             ] = stops(events, :preload)
    end

    test "read-only-connection mode: one data root only", %{test: test} do
      start_supervised!({ReadOnlyRepo, ReadOnlyRepo.start_options()})

      i =
        HasuraFixture.start_instance!(:"#{test}_read_only", ReadOnlyRepo, metadata(),
          read_only: :connection,
          poll_interval: 3_600_000,
          max_staleness: 3_600_000
        )

      TelemetryHelper.drain()
      assert {:ok, [_one]} = Authzura.all(Organization, session(), instance: i)

      assert [%{category: :data, stage: :root, table: "organizations", rows: 1}] =
               TelemetryHelper.drain() |> stops(:query)
    end

    test "rows/1 counts lists and Postgrex results" do
      assert Telemetry.rows([1, 2, 3]) == 3
      assert Telemetry.rows({:ok, [1, 2]}) == 2
      assert Telemetry.rows(%Result{num_rows: 5}) == 5
      assert Telemetry.rows({:ok, :scalar}) == nil
      assert Telemetry.rows(:other) == nil
    end

    test "scope_input pattern checks are setup statements", %{instance: i} do
      input = %{filter: %{"title" => %{"_regex" => "a"}}}
      assert {:ok, _query} = Authzura.scope_input(Article, session(), input, instance: i)

      assert [%{instance: ^i, category: :setup, stage: :root, table: "articles", rows: 1}] =
               TelemetryHelper.drain() |> stops(:query)
    end

    test "a refused pattern stops normally with result: :rejected", %{instance: i} do
      input = %{filter: %{"title" => %{"_regex" => "(" <> @sentinel}}}

      assert {:error, {:invalid_input, {:invalid_pattern, "title"}}} =
               Authzura.all_input(Article, session(), input, instance: i)

      events = TelemetryHelper.drain()

      assert [%{category: :transaction_control} | setup] = stops(events, :query)
      assert [_ | _] = setup

      assert Enum.all?(
               setup,
               &match?(%{result: :rejected, category: :setup, table: "articles"}, &1)
             )

      refute Enum.any?(events, &match?({[:authzura, _, :exception], _}, &1))
      refute dump(events) =~ @sentinel
    end
  end

  describe "input span" do
    test "reports the resolved table, the result and a reason class", %{instance: i} do
      assert {:ok, _rows} = Authzura.all_input(User, session(), %{}, instance: i)

      assert {:error, _reason} =
               Authzura.all_input(User, session(), %{columns: ["x"]}, instance: i)

      assert [
               %{instance: ^i, role: "user", table: "users", result: :ok},
               %{result: :error, reason_class: :forbidden_columns} = denied
             ] = TelemetryHelper.drain() |> stops(:input)

      refute Map.has_key?(denied, :table)
    end
  end

  describe "sentinel" do
    # Every call carries the sentinel somewhere hostile: a session variable
    # bound as a SQL parameter by the permission filter, a column name, an
    # order key, a filter key and literal, a refused pattern, and the rows
    # of a DB error whose message echoes the value.
    test "hostile denials and DB exceptions expose only bounded classes", %{instance: i} do
      vars = %{"x-hasura-sentinel" => @sentinel}
      probe = HasuraFixture.session!("probe", vars)

      cast_error =
        from(a in Article, where: fragment("(? || 'x')::int > 0", a.title))

      ecto_cast_error = from(a in Article, where: a.id == ^@sentinel)

      hostile = [
        fn -> Authzura.all_input(User, session(vars), %{columns: [@sentinel]}, instance: i) end,
        fn ->
          Authzura.all_input(User, session(vars), %{order_by: [{@sentinel, :asc}]}, instance: i)
        end,
        fn ->
          Authzura.all_input(Article, session(vars), %{filter: %{@sentinel => @sentinel}},
            instance: i
          )
        end,
        fn ->
          Authzura.all_input(
            Article,
            session(vars),
            %{filter: %{"title" => %{"_regex" => "(" <> @sentinel}}},
            instance: i
          )
        end,
        fn -> Authzura.all(Organization, session(vars), instance: i, columns: [@sentinel]) end,
        fn ->
          Authzura.scope(Organization, HasuraFixture.session!("nobody", vars), instance: i)
        end,
        fn ->
          query = where(Organization, [o], fragment("nextval('public.test_seq') > ?", ^@sentinel))
          catch_error(Authzura.all(query, session(vars), instance: i))
        end,
        # The DB error's message echoes the sentinel (the probe's permission
        # filter admits only the sentinel row).
        fn ->
          assert %Error{} =
                   error =
                   catch_error(Authzura.all(cast_error, probe, instance: i))

          assert inspect(error) =~ @sentinel
        end,
        fn ->
          assert %Ecto.Query.CastError{} =
                   catch_error(Authzura.all(ecto_cast_error, probe, instance: i))
        end
      ]

      Enum.each(hostile, & &1.())
      events = TelemetryHelper.drain()

      exceptions = for {[:authzura, _, :exception], meta} <- events, do: meta

      assert Enum.any?(exceptions, &(&1.exception_class == Error))
      assert Enum.any?(exceptions, &(&1.exception_class == Ecto.Query.CastError))
      assert Enum.any?(events, &match?({[:authzura, :execute, :stop], %{result: :denied}}, &1))
      refute dump(events) =~ @sentinel
      refute dump(events) =~ "x-hasura-sentinel"
    end
  end
end

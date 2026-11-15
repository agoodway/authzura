defmodule Authzura.StoreTest do
  # Every test owns its instance (named after the test), its source agent and
  # its clock, so the module runs async. Time only moves through `advance/2`,
  # and polls only run through `Store.poll/1`.
  use ExUnit.Case, async: true

  alias Authzura.Model.{Column, Diagnostic, Permission, Relationship, Snapshot, Table}
  alias Authzura.{Store, TelemetryHelper, TestSource}
  alias Authzura.Store.Generation
  alias Authzura.Test.Repo
  alias Postgrex.Error, as: PostgresError

  import ExUnit.CaptureLog

  @moduletag :capture_log

  @articles {"public", "articles"}
  @max_staleness 1_000

  setup %{test: instance} do
    clock = :atomics.new(1, signed: true)
    agent = start_supervised!({TestSource, snapshot: snapshot(["user"])})

    on_exit(fn ->
      :persistent_term.erase({Store, instance})
      :persistent_term.erase({Store, instance, :incarnation})
      :persistent_term.erase({Store, instance, :status})
    end)

    {:ok, instance: instance, clock: clock, agent: agent}
  end

  defp snapshot(roles) do
    permissions =
      Map.new(roles, fn role ->
        permission = %Permission{
          role: role,
          table: @articles,
          operation: :select,
          filter: {:and, []},
          columns: ["id"]
        }

        {{role, @articles, :select}, permission}
      end)

    %Snapshot{version: nil, tables: %{@articles => articles()}, permissions: permissions}
  end

  defp articles(relationships \\ %{}) do
    %Table{
      schema: "public",
      name: "articles",
      primary_key: ["id"],
      columns: %{
        "id" => %Column{name: "id", pg_type: "int8", base_kind: :bigint, ecto_type: :integer}
      },
      relationships: relationships
    }
  end

  defp start_store(ctx, opts \\ [], spec_overrides \\ []) do
    clock = ctx.clock

    opts =
      Keyword.merge(
        [
          name: ctx.instance,
          repo: Repo,
          source: {TestSource, agent: ctx.agent},
          poll_interval: nil,
          max_staleness: @max_staleness,
          backoff: 0,
          clock: fn :millisecond -> :atomics.get(clock, 1) end
        ],
        opts
      )

    start_supervised!(Supervisor.child_spec({Authzura, opts}, spec_overrides))
  end

  # A system call is handled only after `handle_continue(:load, _)` (or the
  # callback running a load), so this returns once that load has finished.
  # `Authzura.status/1` never calls the process, so it can't be the barrier.
  defp settle(store), do: :sys.get_state(store)

  defp start_ready(ctx, opts \\ [], spec_overrides \\ []) do
    store = start_store(ctx, opts, spec_overrides)
    settle(store)
    store
  end

  defp advance(%{clock: clock}, ms), do: :atomics.add(clock, 1, ms)

  defp seq!(instance) do
    {:ok, %Generation{seq: seq}} = Store.current(instance)
    seq
  end

  test "is not ready until the first load finishes", ctx do
    TestSource.put(ctx.agent, gate: self())
    store = start_store(ctx)

    assert_receive {TestSource, :loading, ^store}
    assert Store.current(ctx.instance) == {:error, :not_ready}

    assert %{ready?: false, fresh?: false, seq: 0} = Authzura.status(ctx.instance)
    assert Authzura.diagnostics(ctx.instance) == {:error, :not_ready}

    TestSource.put(ctx.agent, gate: nil)
    send(store, :release)
    settle(store)

    assert %{ready?: true, seq: 1, active_version: "A"} = Authzura.status(ctx.instance)
    assert {:ok, %Generation{seq: 1, version: "A", owner: ^store}} = Store.current(ctx.instance)
  end

  # Built once per generation, not per read and per preload node.
  test "the admin role's permissions are built with the generation", ctx do
    start_ready(ctx, admin_role: "root")

    assert {:ok, %Generation{admin: admin, snapshot: %Snapshot{tables: tables}} = generation} =
             Store.current(ctx.instance)

    expected = Permission.admin("root", tables[@articles])
    assert %{@articles => {^expected, {:and, []}}} = admin

    assert {:ok, %{template: {^expected, {:and, []}}, admin?: true}} =
             Generation.access(generation, "root", @articles)

    assert Generation.access(generation, "root", {"public", "missing"}) == {:error, :forbidden}
  end

  test "a revoked permission is gone after a version change and a poll", ctx do
    start_ready(ctx)
    assert {:ok, %Generation{templates: templates}} = Store.current(ctx.instance)
    assert {%Permission{role: "user"}, {:and, []}} = templates[{"user", @articles}]

    TestSource.put(ctx.agent, version: "B", snapshot: snapshot([]))
    assert :ok = Store.poll(ctx.instance)

    assert {:ok, %Generation{seq: 2, version: "B", templates: templates}} =
             Store.current(ctx.instance)

    assert templates == %{}
  end

  test "a newer version that keeps failing to load goes stale", ctx do
    start_ready(ctx)
    TestSource.put(ctx.agent, version: "B", load: {:error, :boom})

    advance(ctx, 600)
    Store.poll(ctx.instance)
    assert {:ok, %Generation{version: "A"}} = Store.current(ctx.instance)

    advance(ctx, 600)
    Store.poll(ctx.instance)
    assert Store.current(ctx.instance) == {:error, :stale_permissions}

    assert %{
             ready?: true,
             fresh?: false,
             active_version: "A",
             observed_version: "B",
             last_confirmed_current_at: 0,
             last_error: :boom
           } = Authzura.status(ctx.instance)
  end

  # A version that keeps failing to load is retried with exponential
  # backoff (from one poll interval to the backoff ceiling), not in full at
  # every poll; freshness is still never renewed, so reads go stale.
  test "a failing reload of one version backs off exponentially", ctx do
    start_ready(ctx, backoff: {100, 300})
    loads = fn -> TestSource.loads(ctx.agent) end
    TestSource.put(ctx.agent, version: "B", load: {:error, :boom})
    base = loads.()

    poll = fn ms ->
      advance(ctx, ms)
      Store.poll(ctx.instance)
      loads.() - base
    end

    assert poll.(0) == 1
    assert poll.(50) == 1
    assert poll.(50) == 2
    assert poll.(150) == 2
    assert poll.(50) == 3
    assert poll.(250) == 3
    assert poll.(50) == 4

    # An explicit reload always loads; a new version starts over.
    assert {:error, :boom} = Authzura.reload(ctx.instance)
    assert loads.() - base == 5
    TestSource.put(ctx.agent, version: "C")
    assert poll.(0) == 6

    advance(ctx, @max_staleness)
    assert Store.current(ctx.instance) == {:error, :stale_permissions}
  end

  test "a polling outage past max_staleness goes stale", ctx do
    start_ready(ctx)
    TestSource.put(ctx.agent, version_error: :down)

    advance(ctx, @max_staleness)
    Store.poll(ctx.instance)
    assert {:ok, _generation} = Store.current(ctx.instance)

    advance(ctx, 1)
    Store.poll(ctx.instance)
    assert Store.current(ctx.instance) == {:error, :stale_permissions}
    assert %{fresh?: false, last_error: :down} = Authzura.status(ctx.instance)

    TestSource.put(ctx.agent, version_error: nil)
    Store.poll(ctx.instance)
    assert %{fresh?: true, last_error: nil} = Authzura.status(ctx.instance)
  end

  test "an outage with ever-changing raw errors writes the status term and logs once", ctx do
    start_ready(ctx)
    key = {Store, ctx.instance, :status}

    {first, log} =
      with_log(fn ->
        fail_poll(ctx, 1)
        written = :persistent_term.get(key)

        for id <- 2..4, do: fail_poll(ctx, id)
        written
      end)

    assert :erts_debug.same(first, :persistent_term.get(key))
    assert %{last_error: PostgresError, fresh?: true} = Authzura.status(ctx.instance)

    assert [_once] = Regex.scan(~r/failed to check the permission version/, log)
    assert log =~ "failed to check the permission version: Postgrex.Error"
    refute log =~ "connection_id"
  end

  defp fail_poll(ctx, connection_id) do
    TestSource.put(ctx.agent, version_error: %PostgresError{connection_id: connection_id})
    Store.poll(ctx.instance)
  end

  test "status hides a dead incarnation's observations", ctx do
    store = start_ready(ctx, [], restart: :temporary)
    TestSource.put(ctx.agent, version_error: :down)
    Store.poll(ctx.instance)
    assert %{last_error: :down, observed_version: "A"} = Authzura.status(ctx.instance)

    ref = Process.monitor(store)
    Process.exit(store, :kill)
    assert_receive {:DOWN, ^ref, :process, ^store, :killed}

    assert %{ready?: false, last_error: nil, observed_version: nil} =
             Authzura.status(ctx.instance)
  end

  test "a malformed version result is a poll failure, not a crash", ctx do
    store = start_ready(ctx)
    TestSource.put(ctx.agent, version_reply: :garbage)

    advance(ctx, 100)
    assert :ok = Store.poll(ctx.instance)

    assert %{last_error: :invalid_version_result, last_confirmed_current_at: 0} =
             Authzura.status(ctx.instance)

    assert Process.alive?(store)
    assert {:ok, %Generation{seq: 1}} = Store.current(ctx.instance)
  end

  test "status and diagnostics answer while a reload is running", ctx do
    store = start_ready(ctx)
    TestSource.put(ctx.agent, gate: self(), version: "B")
    reload = Task.async(fn -> Authzura.reload(ctx.instance) end)
    assert_receive {TestSource, :loading, ^store}

    assert %{ready?: true, fresh?: true, seq: 1, active_version: "A"} =
             Authzura.status(ctx.instance)

    assert {:ok, []} = Authzura.diagnostics(ctx.instance)

    TestSource.put(ctx.agent, gate: nil)
    send(store, :release)
    assert Task.await(reload) == :ok
    assert %{seq: 2, active_version: "B", observed_version: "B"} = Authzura.status(ctx.instance)
  end

  test "the same version renews freshness even while loads would fail", ctx do
    start_ready(ctx)
    TestSource.put(ctx.agent, load: {:error, :boom})

    for _round <- 1..3 do
      advance(ctx, 900)
      Store.poll(ctx.instance)
    end

    assert {:ok, %Generation{seq: 1, version: "A"}} = Store.current(ctx.instance)
    assert %{last_confirmed_current_at: 2_700} = Authzura.status(ctx.instance)
    assert TestSource.loads(ctx.agent) == 1
  end

  test "a version that sorts lower still reloads", ctx do
    TestSource.put(ctx.agent, version: {1, "b"})
    start_ready(ctx)

    TestSource.put(ctx.agent, version: {1, "a"})
    Store.poll(ctx.instance)
    assert {:ok, %Generation{seq: 2, version: {1, "a"}}} = Store.current(ctx.instance)
  end

  test "a resource_version rollback reloads", ctx do
    TestSource.put(ctx.agent, version: {5, "fp"})
    start_ready(ctx)

    TestSource.put(ctx.agent, version: {4, "fp"})
    Store.poll(ctx.instance)
    assert {:ok, %Generation{seq: 2, version: {4, "fp"}}} = Store.current(ctx.instance)
  end

  test "concurrent reloads are serialized and seq never decreases", ctx do
    store = start_ready(ctx)
    start = seq!(ctx.instance)
    observer = Task.async(fn -> observe(ctx.instance, []) end)

    TestSource.put(ctx.agent, gate: self())
    first = Task.async(fn -> Authzura.reload(ctx.instance) end)
    assert_receive {TestSource, :loading, ^store}
    second = Task.async(fn -> Authzura.reload(ctx.instance) end)

    send(store, :release)
    assert_receive {TestSource, :loading, ^store}
    TestSource.put(ctx.agent, gate: nil)
    send(store, :release)

    assert Task.await(first) == :ok
    assert Task.await(second) == :ok
    assert seq!(ctx.instance) == start + 2

    send(observer.pid, :stop)
    seen = Task.await(observer)
    assert seen == Enum.sort(seen)
    assert List.last(seen) == start + 2
  end

  defp observe(instance, seen) do
    receive do
      :stop -> Enum.reverse([seq!(instance) | seen])
    after
      0 -> observe(instance, [seq!(instance) | seen])
    end
  end

  test "a killed Store is not ready even though its generation remains", ctx do
    store = start_ready(ctx, [], restart: :temporary)
    assert {:ok, _generation} = Store.current(ctx.instance)

    ref = Process.monitor(store)
    Process.exit(store, :kill)
    assert_receive {:DOWN, ^ref, :process, ^store, :killed}

    assert %Generation{owner: ^store} = :persistent_term.get({Store, ctx.instance})
    assert Store.current(ctx.instance) == {:error, :not_ready}
  end

  test "a restarted Store never serves the previous incarnation's generation", ctx do
    store = start_ready(ctx, [], restart: :temporary)
    ref = Process.monitor(store)
    Process.exit(store, :kill)
    assert_receive {:DOWN, ^ref, :process, ^store, :killed}

    TestSource.put(ctx.agent, load: {:error, :boom})

    # A long backoff: with the default 0, the failing first load retries (and
    # logs) until shutdown, after this test's log capture has ended.
    start_ready(
      ctx,
      [max_staleness: :infinity, default_prefix: "audit", backoff: 60_000],
      id: :restarted
    )

    assert %{ready?: false} = Authzura.status(ctx.instance)
    assert :persistent_term.get({Store, ctx.instance}, nil) == nil
    assert Store.current(ctx.instance) == {:error, :not_ready}
  end

  test "a stopped Store erases its generation", ctx do
    start_ready(ctx)
    assert {:ok, _generation} = Store.current(ctx.instance)

    stop_supervised!(ctx.instance)
    assert :persistent_term.get({Store, ctx.instance}, nil) == nil
    assert Store.current(ctx.instance) == {:error, :not_ready}
  end

  test "max_staleness: :infinity never goes stale", ctx do
    start_ready(ctx, max_staleness: :infinity)
    TestSource.put(ctx.agent, version_error: :down)

    advance(ctx, 1_000_000_000)
    Store.poll(ctx.instance)
    assert {:ok, %Generation{seq: 1}} = Store.current(ctx.instance)
  end

  test "renewing freshness never rewrites the persistent term", ctx do
    start_ready(ctx)
    before = :persistent_term.get({Store, ctx.instance})

    for _round <- 1..3 do
      advance(ctx, 100)
      Store.poll(ctx.instance)
    end

    later = :persistent_term.get({Store, ctx.instance})
    assert :erts_debug.same(before, later)
    assert :atomics.get(later.freshness, 1) == 300
  end

  test "every read sees one coherent generation while reloads run", ctx do
    TestSource.put(ctx.agent, snapshot: fn n -> %Snapshot{version: n} end)
    start_ready(ctx)

    readers = for _reader <- 1..50, do: Task.async(fn -> read_until_stopped(ctx.instance) end)

    for _round <- 1..25, do: assert(Authzura.reload(ctx.instance) == :ok)

    # Each reader asserts coherence on every read and crashes the test if
    # one fails; awaiting them surfaces that.
    Enum.each(readers, &send(&1.pid, :stop))
    Task.await_many(readers)
    assert seq!(ctx.instance) == 26
  end

  defp read_until_stopped(instance) do
    {:ok, %Generation{seq: seq, snapshot: %Snapshot{version: marker}}} = Store.current(instance)
    assert seq == marker

    receive do
      :stop -> :ok
    after
      0 -> read_until_stopped(instance)
    end
  end

  test "a failed first load retries until it succeeds", ctx do
    TestSource.put(ctx.agent, load: {:error, :boom}, gate: self())
    store = start_store(ctx)

    assert_receive {TestSource, :loading, ^store}
    send(store, :release)
    assert_receive {TestSource, :loading, ^store}
    TestSource.put(ctx.agent, load: :ok, gate: nil)
    send(store, :release)
    settle(store)

    assert %{ready?: true, last_error: nil} = Authzura.status(ctx.instance)
    assert {:ok, %Generation{version: "A"}} = Store.current(ctx.instance)
  end

  test "a failed manual reload leaves the generation and its freshness alone", ctx do
    start_ready(ctx)
    TestSource.put(ctx.agent, load: {:error, :boom})

    advance(ctx, 500)
    assert Authzura.reload(ctx.instance) == {:error, :boom}
    assert {:ok, %Generation{version: "A"}} = Store.current(ctx.instance)
    assert %{last_confirmed_current_at: 0} = Authzura.status(ctx.instance)

    TestSource.put(ctx.agent, load: :ok)
    assert Authzura.reload(ctx.instance) == :ok
    assert %{last_confirmed_current_at: 500} = Authzura.status(ctx.instance)
  end

  test "status and diagnostics report the active generation", ctx do
    diagnostic = %Diagnostic{severity: :deny, reason: :nope}
    TestSource.put(ctx.agent, snapshot: %{snapshot(["user"]) | diagnostics: [diagnostic]})
    start_ready(ctx)

    assert Authzura.status(ctx.instance) == %{
             ready?: true,
             fresh?: true,
             seq: 1,
             active_version: "A",
             observed_version: "A",
             last_confirmed_current_at: 0,
             last_error: nil,
             diagnostics_count: 1
           }

    assert Authzura.diagnostics(ctx.instance) == {:ok, [diagnostic]}
  end

  test "emits load and reload telemetry spans", ctx do
    events = for kind <- [:load, :reload], stage <- [:start, :stop], do: [:authzura, kind, stage]
    instance = ctx.instance
    TelemetryHelper.forward!("store-#{inspect(instance)}", events, instance: instance)

    start_store(ctx)
    assert_receive {:telemetry, [:authzura, :load, :start], %{instance: ^instance, seq: 1}}

    assert_receive {:telemetry, [:authzura, :load, :stop],
                    %{instance: ^instance, seq: 1, result: :ok}}

    TestSource.put(ctx.agent, load: {:error, :boom})
    Authzura.reload(ctx.instance)

    assert_receive {:telemetry, [:authzura, :reload, :stop],
                    %{instance: ^instance, seq: 2, result: :error, error_class: :boom}}
  end

  test "validates every source's snapshot once before publishing it", ctx do
    relationships = %{
      "self" => %Relationship{
        name: "self",
        kind: :object,
        target: @articles,
        mapping: [{"id", "id"}]
      },
      "ghost" => %Relationship{
        name: "ghost",
        kind: :object,
        target: @articles,
        mapping: [{"missing", "id"}]
      }
    }

    broken = %Permission{
      role: "broken",
      table: @articles,
      operation: :select,
      filter: {:compare, "missing", :eq, {:literal, 1}},
      columns: ["id"]
    }

    snapshot = snapshot(["user"])

    TestSource.put(ctx.agent,
      snapshot: %{
        snapshot
        | tables: %{@articles => articles(relationships)},
          permissions: Map.put(snapshot.permissions, {"broken", @articles, :select}, broken)
      }
    )

    start_ready(ctx)
    assert :ok = Authzura.reload(ctx.instance)

    assert {:ok, %Generation{snapshot: %Snapshot{tables: tables, permissions: permissions}}} =
             Store.current(ctx.instance)

    assert %{
             "self" => %Relationship{preloadable?: true},
             "ghost" => %Relationship{preloadable?: false}
           } =
             tables[@articles].relationships

    assert %Permission{status: :ok} = permissions[{"user", @articles, :select}]
    assert %Permission{status: {:denied, [_]}} = permissions[{"broken", @articles, :select}]

    assert {:ok,
            [
              %Diagnostic{
                severity: :warning,
                path: ["ghost"],
                reason: {:unknown_key_column, "missing"}
              },
              %Diagnostic{severity: :deny, role: "broken", path: ["filter"]}
            ]} = Authzura.diagnostics(ctx.instance)
  end

  test "rejects invalid instance options" do
    assert_raise NimbleOptions.ValidationError, fn -> Authzura.child_spec(name: :x) end

    assert_raise NimbleOptions.ValidationError, fn ->
      Authzura.child_spec(repo: Repo, max_staleness: :forever)
    end
  end

  describe "failures stay bounded" do
    @sentinel "ZQX_sentinel_7f3a"
    # A failed first load retries; with no delay the retries would log after
    # the test's capture ends.
    @no_retry [backoff: 60_000]

    test "a failing load logs only its kind and exposes no raw term", ctx do
      TestSource.put(ctx.agent, load: {:error, {:boom, @sentinel}})

      log =
        capture_log(fn ->
          ctx |> start_store(@no_retry) |> settle()
          assert :ok = ctx.instance |> Authzura.status() |> Map.fetch!(:last_error) |> bounded()
        end)

      assert log =~ "failed to load permissions: :boom"
      refute log =~ @sentinel
    end

    test "a failing version check logs only its kind", ctx do
      start_ready(ctx)
      TestSource.put(ctx.agent, version_error: {:down, @sentinel})

      log = capture_log(fn -> Store.poll(ctx.instance) end)

      assert log =~ "failed to check the permission version: :down"
      refute log =~ @sentinel
    end

    test "a throwing source fails the load closed instead of crashing the Store", ctx do
      TestSource.put(ctx.agent, load: {:throw, {:thrown, @sentinel}})

      log =
        capture_log(fn ->
          store = start_store(ctx, @no_retry)
          settle(store)
          assert Process.alive?(store)
        end)

      assert %{ready?: false, last_error: :throw} = Authzura.status(ctx.instance)
      refute log =~ @sentinel
    end

    test "a raising source's message never reaches the log or the status", ctx do
      TestSource.put(ctx.agent, load: {:raise, @sentinel})

      log = capture_log(fn -> ctx |> start_store(@no_retry) |> settle() end)

      assert %{last_error: {:exception, RuntimeError}} = Authzura.status(ctx.instance)
      refute log =~ @sentinel
    end

    test "load events carry classes only", ctx do
      TelemetryHelper.forward!(
        {:bounded, ctx.instance},
        [[:authzura, :load, :stop], [:authzura, :load, :exception]],
        instance: ctx.instance
      )

      TestSource.put(ctx.agent, load: {:error, {:boom, @sentinel}})
      ctx |> start_store(@no_retry) |> settle()
      TestSource.put(ctx.agent, load: {:throw, {:thrown, @sentinel}})
      Authzura.reload(ctx.instance)

      # The Store may retry in the background, so match rather than count.
      assert_receive {:telemetry, [:authzura, :load, :stop],
                      %{result: :error, error_class: :boom} = stop}

      assert_receive {:telemetry, [:authzura, :load, :exception], thrown}
      assert %{kind: :throw, exception_class: :throw} = thrown
      refute inspect([stop, thrown]) =~ @sentinel
    end

    defp bounded(kind) when is_atom(kind) or is_tuple(kind), do: :ok
  end
end

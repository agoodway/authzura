defmodule Authzura.OptionsTest do
  use ExUnit.Case, async: true

  alias Authzura.Options
  alias Authzura.Test.Repo

  # The fast paths for `[]` and `[instance: name]` must give exactly what
  # full validation gives, and anything else still goes through it.
  test "the per-call fast paths match full validation" do
    full = fn opts -> opts |> Options.call!() |> Enum.sort() end
    defaults = Enum.sort(Options.call!(columns: [:id]) |> Keyword.delete(:columns))

    assert Enum.sort(Options.call!([])) == defaults

    assert full.(instance: MyApp.Authz) ==
             Enum.sort(Keyword.put(defaults, :instance, MyApp.Authz))
  end

  test "input_index_pushdown is an instance option, off by default, boolean only" do
    refute Options.instance!(repo: Repo).input_index_pushdown
    assert Options.instance!(repo: Repo, input_index_pushdown: true).input_index_pushdown

    assert_raise NimbleOptions.ValidationError, fn ->
      Options.instance!(repo: Repo, input_index_pushdown: "yes")
    end

    assert_raise NimbleOptions.ValidationError, fn ->
      Options.call!(input_index_pushdown: true)
    end
  end

  # The test hooks remove guarantees (one snapshot per read), so only a
  # build with `config :authzura, :test_hooks, true` accepts them.
  test "test hooks are per-call options only when test_hooks is configured" do
    hooks = [isolation: :read_committed, between_levels: fn -> :ok end]

    for {key, value} <- hooks do
      assert {:error, %NimbleOptions.ValidationError{key: [^key]}} =
               NimbleOptions.validate([{key, value}], Options.call_schema(false))

      assert {:ok, _opts} = NimbleOptions.validate([{key, value}], Options.call_schema(true))
    end

    assert Application.get_env(:authzura, :test_hooks) == true
    assert Options.call!(isolation: :read_committed)[:isolation] == :read_committed
  end

  # bench/TRIAGE.md, overhead: `{:or, [:atom, :string]}` built and inspected
  # a rejection for every string column before accepting it, about six times
  # the atoms' cost. Reductions are compared relative to the atom path with
  # a wide margin, so a NimbleOptions or OTP upgrade that moves both does not
  # fail it while that regression still would.
  test "string columns validate about as cheaply as atom columns" do
    atoms = ~w(id org_id author_id status is_published title)a
    strings = Enum.map(atoms, &Atom.to_string/1)

    assert reductions(columns: strings) <= reductions(columns: atoms) * 2
    assert Options.call!(instance: Foo, columns: strings)[:columns] == strings
    assert Options.call!(columns: [:id, "title"], preload: [])[:columns] == [:id, "title"]
  end

  test "invalid columns raise the full validation's messages" do
    assert_raise NimbleOptions.ValidationError,
                 "invalid list in :columns option: expected list element at position 1 to " <>
                   "match at least one given type, but didn't match any. Here are the reasons " <>
                   "why it didn't match each of the allowed types:\n\n" <>
                   "  * invalid value for list element at position 1: expected string, got: 1\n" <>
                   "  * invalid value for list element at position 1: expected atom, got: 1",
                 fn -> Options.call!(columns: ["id", 1]) end

    assert_raise NimbleOptions.ValidationError,
                 ~s(invalid value for :columns option: expected list, got: "id"),
                 fn -> Options.call!(columns: "id") end

    assert_raise NimbleOptions.ValidationError, ~r/^unknown options \[:columns\]/, fn ->
      Options.call!(columns: [:id], columns: ["x"])
    end

    assert_raise NimbleOptions.ValidationError, ~r/^unknown options \[:bogus\]/, fn ->
      Options.call!(columns: ["id"], bogus: 1)
    end
  end

  test "invalid per-call options still raise" do
    assert_raise NimbleOptions.ValidationError, fn -> Options.call!(instance: "x") end
    assert_raise NimbleOptions.ValidationError, fn -> Options.call!(bogus: 1) end
    assert_raise NimbleOptions.ValidationError, fn -> Options.call!(instance: Foo, bogus: 1) end
  end

  defp reductions(opts) do
    Options.call!(opts)
    {:reductions, before} = Process.info(self(), :reductions)
    Options.call!(opts)
    {:reductions, later} = Process.info(self(), :reductions)
    later - before
  end
end

defmodule Authzura.Store.GenerationTest do
  use ExUnit.Case, async: true

  alias Authzura.Model.Snapshot
  alias Authzura.Store.Generation

  @search {"public", "search"}

  defp generation(config \\ %{admin_role: nil}) do
    %Generation{
      instance: __MODULE__,
      owner: self(),
      incarnation: make_ref(),
      seq: 1,
      version: nil,
      snapshot: %Snapshot{
        version: nil,
        functions: %{
          @search => MapSet.new(["user", "editor"]),
          {"public", "locked"} => MapSet.new()
        }
      },
      templates: %{},
      config: config,
      freshness: :atomics.new(2, signed: true)
    }
  end

  describe "function_roles/2" do
    test "sorts the granted roles and rejects an untracked function" do
      assert Generation.function_roles(generation(), @search) == {:ok, ["editor", "user"]}
      assert Generation.function_roles(generation(), {"public", "locked"}) == {:ok, []}
      assert Generation.function_roles(generation(), {"public", "nope"}) == :error
    end
  end

  describe "function_allowed?/3" do
    test "a granted role may execute, others may not" do
      assert Generation.function_allowed?(generation(), "user", @search)
      refute Generation.function_allowed?(generation(), "viewer", @search)
      refute Generation.function_allowed?(generation(), "user", {"public", "locked"})
    end

    test "an untracked function is never executable, even by the admin role" do
      generation = generation(%{admin_role: "root"})
      refute Generation.function_allowed?(generation, "root", {"public", "nope"})
      assert Generation.function_allowed?(generation, "root", {"public", "locked"})
    end

    test "a nil role is refused without an admin role" do
      refute Generation.function_allowed?(generation(), nil, @search)
    end
  end

  describe "admin_role?/2" do
    test "matches only a configured admin role" do
      assert Generation.admin_role?(%{admin_role: "root"}, "root")
      refute Generation.admin_role?(%{admin_role: "root"}, "user")
      refute Generation.admin_role?(%{admin_role: nil}, nil)
    end
  end
end

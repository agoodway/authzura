defmodule Authzura.ASTTest do
  use ExUnit.Case, async: true

  alias Authzura.AST

  describe "conjuncts/1" do
    test "flattens nested \`:and\` only, never through or, not or relationships" do
      a = {:compare, "a", :eq, {:literal, 1}}
      b = {:compare, "b", :eq, {:literal, 2}}
      c = {:compare, "c", :eq, {:literal, 3}}

      assert AST.conjuncts(
               {:and, [a, {:and, [b]}, {:or, [c]}, {:not, c}, {:relationship, "r", c}]}
             ) ==
               [a, b, {:or, [c]}, {:not, c}, {:relationship, "r", c}]

      assert AST.conjuncts(a) == [a]
      assert AST.conjuncts(nil) == []
    end
  end

  describe "binding_depth/1" do
    test "counts nested relationship levels" do
      assert AST.binding_depth({:relationship, "a", {:relationship, "b", {:and, []}}}) == 2
    end

    test "counts exists as a level" do
      assert AST.binding_depth({:exists, {"public", "users"}, {:and, []}}) == 1
    end

    test "boolean groups take the deepest child" do
      ast = {:or, [{:compare, "x", :eq, {:literal, 1}}, {:not, {:relationship, "a", {:and, []}}}]}
      assert AST.binding_depth(ast) == 1
    end
  end

  describe "syntactic_depth/1" do
    test "counts every level" do
      assert AST.syntactic_depth({:and, [{:not, {:or, []}}]}) == 3
    end

    test "a bare comparison is one level" do
      assert AST.syntactic_depth({:compare, "x", :eq, {:literal, 1}}) == 1
    end
  end

  describe "node_count/1" do
    test "counts all nodes" do
      ast =
        {:and, [{:compare, "x", :eq, {:literal, 1}}, {:not, {:relationship, "a", {:and, []}}}]}

      assert AST.node_count(ast) == 5
    end
  end

  describe "session_refs/1" do
    test "finds names inside relationship and exists subtrees" do
      ast =
        {:and,
         [
           {:compare, "a", :eq, {:session, "x-hasura-user-id"}},
           {:relationship, "r", {:compare, "b", :eq, {:session, "x-hasura-org"}}},
           {:exists, {"public", "t"}, {:not, {:compare, "c", :eq, {:session, "x-hasura-org"}}}},
           {:compare, "d", :eq, {:literal, 1}}
         ]}

      assert AST.session_refs(ast) == MapSet.new(["x-hasura-user-id", "x-hasura-org"])
    end
  end

  describe "root_columns/1" do
    test "excludes columns inside relationship and exists subtrees" do
      ast =
        {:and,
         [
           {:compare, "a", :eq, {:literal, 1}},
           {:or, [{:not, {:compare, "b", :eq, {:literal, 2}}}]},
           {:relationship, "r", {:compare, "hidden", :eq, {:literal, 3}}},
           {:exists, {"public", "t"}, {:compare, "also_hidden", :eq, {:literal, 4}}}
         ]}

      assert AST.root_columns(ast) == MapSet.new(["a", "b"])
    end
  end
end

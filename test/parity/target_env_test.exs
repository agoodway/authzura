defmodule Authzura.Parity.TargetEnvTest do
  @moduledoc """
  The parity targets have no defaults: without `AUTHZURA_PARITY_DB_URL`
  and `AUTHZURA_PARITY_HASURA_URL` the suites fail before contacting
  anything (never `localhost:8080` or `:5432`). Pure; it unsets the
  variables only for its own duration.
  """

  use ExUnit.Case, async: false

  alias Authzura.Parity.{Differential, Guard, Hasura}

  @names ["AUTHZURA_PARITY_DB_URL", "AUTHZURA_PARITY_HASURA_URL"]

  setup do
    saved = Map.new(@names, &{&1, System.get_env(&1)})
    Enum.each(@names, &System.delete_env/1)

    on_exit(fn ->
      Enum.each(saved, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)
  end

  test "an unset URL raises, naming the variable" do
    assert_raise ArgumentError, ~r/AUTHZURA_PARITY_DB_URL is not set/, &Guard.db_url/0
    assert_raise ArgumentError, ~r/AUTHZURA_PARITY_HASURA_URL is not set/, &Hasura.url/0

    System.put_env("AUTHZURA_PARITY_HASURA_URL", "")
    assert_raise ArgumentError, ~r/AUTHZURA_PARITY_HASURA_URL is not set/, &Hasura.url/0
  end

  test "the differential setup fails before it contacts Hasura" do
    assert_raise ArgumentError, ~r/not set/, &Differential.repo!/0
    assert_raise ArgumentError, ~r/not set/, &Hasura.await_healthy/0
  end
end

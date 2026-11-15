defmodule Authzura.DoctestTest do
  use ExUnit.Case, async: true

  doctest Authzura, only: [child_spec: 1]
  doctest Authzura.Session
  doctest Authzura.Telemetry
end

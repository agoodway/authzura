defmodule Authzura.Test.CubeExtension do
  @moduledoc """
  A tiny Postgrex extension for the contrib `cube` type (text format, values
  are the binaries `cube_out` prints). Postgrex's default types have none, so
  it stands in for an extension such as PostGIS's.
  """
  @behaviour Postgrex.Extension

  @impl true
  def init(_opts), do: nil

  @impl true
  def matching(_state), do: [output: "cube_out"]

  @impl true
  def format(_state), do: :text

  @impl true
  def encode(_state) do
    quote location: :keep do
      bin when is_binary(bin) -> [<<byte_size(bin)::signed-size(32)>> | bin]
    end
  end

  @impl true
  def decode(_state) do
    quote location: :keep do
      <<len::signed-size(32), bin::binary-size(len)>> -> bin
    end
  end
end

Postgrex.Types.define(Authzura.Test.CubeTypes, [Authzura.Test.CubeExtension], [])

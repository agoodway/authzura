defmodule Authzura.Gen.Save do
  @moduledoc """
  Saved differential failures: one JSON file per shrunk failing case under
  `test/parity/cases/random/`, replayed by
  `test/parity/random_replay_test.exs`.

  A payload is `%{read:, auth:, permissions:, relationships:}`: the
  `Authzura.Parity.Read`, the `{:jwt, claims, requested_role}`
  authentication, the batch permissions the case's roles hold
  (`%{role => %{table => permission}}`) and the relationships its levels
  use. As JSON, tuples become two-element lists, maps with non-string
  keys become sorted `[key, value]` lists, the authentication becomes
  `%{"claims", "requested_role"}`, and atoms become strings: a file holds
  no atom, and `load!/1` maps names back through fixed tables only.

  The file's id is `"gen-"` and the first 16 hex digits of the SHA-256 of
  the payload's canonical JSON (keys sorted). Writing a payload whose id
  already has a file is a no-op when the saved payload is equal, and
  raises otherwise.
  """

  alias Authzura.{Gen, Util}
  alias Authzura.Gen.Catalog
  alias Authzura.Parity.Read
  alias Jason.OrderedObject

  @dir "test/parity/cases/random"

  @type payload :: %{
          read: Read.t(),
          auth: {:jwt, map(), String.t() | nil},
          permissions: %{String.t() => %{Catalog.table() => map()}},
          relationships: [term()]
        }

  @doc "The directory saved cases live in."
  @spec dir() :: Path.t()
  def dir, do: @dir

  @doc """
  Writes `payload` with the failure `reason` and the `seeds` it was found
  with, and returns the file's path. `dir:` overrides `dir/0`; `tags:`
  (the case's coverage tags) are saved beside the payload, outside its id.
  """
  @spec write!(payload(), String.t(), map(), keyword()) :: Path.t()
  def write!(payload, reason, seeds, opts \\ []) do
    json = canonical(encode(payload))
    path = Path.join(Keyword.get(opts, :dir, @dir), id(json) <> ".json")

    case File.read(path) do
      {:ok, saved} -> same!(path, saved, json)
      {:error, :enoent} -> create!(path, json, reason, seeds, Keyword.get(opts, :tags, []))
    end

    path
  end

  @doc """
  The payload saved at `path`, decoded with `Jason`, with the case's
  coverage `:tags` (only those among `Authzura.Gen.fixed_atoms/0`).
  """
  @spec load!(Path.t()) :: payload() | %{tags: [atom()]}
  def load!(path) do
    %{"payload" => payload} = body = path |> File.read!() |> Jason.decode!()
    known = Map.new(Gen.fixed_atoms(), &{Atom.to_string(&1), &1})
    tags = for tag <- Map.get(body, "tags", []), {:ok, atom} <- [Map.fetch(known, tag)], do: atom
    payload |> decode() |> Map.put(:tags, tags)
  end

  @doc "The id of a canonical JSON payload."
  @spec id(String.t()) :: String.t()
  def id(json),
    do:
      "gen-" <>
        (:sha256 |> :crypto.hash(json) |> Base.encode16(case: :lower) |> binary_part(0, 16))

  defp same!(path, saved, json) do
    if Jason.decode!(saved)["payload"] != Jason.decode!(json),
      do: raise("#{path} holds another payload; the saved case differs from this one")
  end

  defp create!(path, json, reason, seeds, tags) do
    File.mkdir_p!(Path.dirname(path))

    body = %{
      "id" => Path.basename(path, ".json"),
      "payload" => Jason.decode!(json),
      "reason" => reason,
      "seeds" => encode(seeds),
      "tags" => encode(tags)
    }

    File.write!(path, Jason.encode!(sorted(body), pretty: true) <> "\n")
  end

  defp canonical(term), do: term |> sorted() |> Jason.encode!()

  defp sorted(%{} = map),
    do: map |> Enum.sort() |> Enum.map(fn {k, v} -> {k, sorted(v)} end) |> OrderedObject.new()

  defp sorted(list) when is_list(list), do: Enum.map(list, &sorted/1)
  defp sorted(term), do: term

  # Encoding.

  defp encode(%{read: read, auth: {:jwt, claims, requested}} = payload) do
    %{
      "read" => encode(read),
      "auth" => %{"claims" => encode(claims), "requested_role" => requested},
      "permissions" => encode(payload.permissions),
      "relationships" => encode(payload.relationships)
    }
  end

  defp encode(%Read{} = read), do: read |> Map.from_struct() |> encode()
  defp encode(term) when is_boolean(term) or is_nil(term), do: term
  defp encode(term) when is_atom(term), do: Atom.to_string(term)
  defp encode({a, b}), do: [encode(a), encode(b)]
  defp encode(list) when is_list(list), do: Enum.map(list, &encode/1)

  defp encode(%{} = map) do
    if Enum.all?(Map.keys(map), &(is_binary(&1) or is_atom(&1))),
      do: Map.new(map, fn {k, v} -> {encode(k), encode(v)} end),
      else: map |> Enum.sort() |> Enum.map(fn {k, v} -> [encode(k), encode(v)] end)
  end

  defp encode(term), do: term

  # Decoding.

  defp decode(%{"read" => read, "auth" => auth} = payload) do
    %{
      read: read(read),
      auth: {:jwt, auth["claims"], auth["requested_role"]},
      permissions:
        Map.new(payload["permissions"], fn {role, tables} ->
          {role,
           Map.new(tables, fn [[schema, name], permission] -> {{schema, name}, permission} end)}
        end),
      relationships: payload["relationships"]
    }
  end

  defp read(%{"table" => table} = read) do
    %Read{
      table: table && List.to_tuple(table),
      columns: read["columns"],
      where: read["where"],
      order_by: read["order_by"] && Enum.map(read["order_by"], &order/1),
      limit: read["limit"],
      offset: read["offset"],
      relationships: Enum.map(read["relationships"], fn [name, child] -> {name, read(child)} end),
      sample: nil
    }
  end

  defp order([direction, column]) do
    {:ok, direction} = Util.direction(direction)
    {direction, Catalog.atom(column)}
  end
end

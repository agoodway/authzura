defmodule Authzura.Source do
  @moduledoc """
  Behaviour for a permission source: where permissions come from.

  A source loads an immutable `Authzura.Model.Snapshot`, reports a cheap
  version so a caller can tell when the snapshot is stale (with a cache of
  its own choosing, kept between polls by the caller), and parses
  untrusted caller input into the source-independent filter AST.
  Stage one ships `Authzura.Sources.Hasura`.

  A source only translates. The Store runs `Authzura.Validator` on every
  snapshot `c:load/1` returns before publishing it, so a source need not
  (and should not) validate: filters are type-checked there and a
  relationship becomes `preloadable?` only when the Validator grants it.
  """

  alias Authzura.AST
  alias Authzura.Model.Snapshot

  @doc "Loads a snapshot. The snapshot's `version` equals what `c:version/2` reports for it."
  @callback load(opts :: keyword()) :: {:ok, Snapshot.t()} | {:error, term()}

  @doc """
  Reads the current version without loading a snapshot. `cache` is `nil` on
  the first call and afterwards what the previous successful call returned;
  a source may keep anything there that lets the next poll skip work, as
  long as the version is the one a fresh read would report.
  """
  @callback version(opts :: keyword(), cache :: term()) ::
              {:ok, version :: term(), cache :: term()} | {:error, term()}

  @doc "Parses an input filter against `ctx.table`. Errors carry the path and the reason."
  @callback parse_input(json :: map(), ctx :: map()) ::
              {:ok, AST.t()} | {:error, [{[String.t()], term()}]}
end

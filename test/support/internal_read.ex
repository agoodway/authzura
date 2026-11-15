defmodule Authzura.Test.InternalRead do
  @moduledoc false

  alias Authzura.Session

  @doc false
  @spec all_input(Ecto.Queryable.t(), Session.t(), term(), atom(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def all_input(queryable, %Session{} = session, input, instance, opts \\ []) do
    {internal, opts} = Keyword.split(opts, [:join_lift])

    Authzura.__all_input__(
      queryable,
      session,
      input,
      Keyword.put(opts, :instance, instance),
      internal
    )
  end
end

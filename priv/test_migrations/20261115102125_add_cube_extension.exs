defmodule Authzura.Test.Repo.Migrations.AddCubeExtension do
  @moduledoc """
  Installs `cube`, a contrib extension type that Postgrex's default types do
  not decode, and a table with a `cube` column. Test-only: it stands in for an
  extension type (PostGIS `geography`, say) in the extension-column tests.
  """
  use Ecto.Migration

  def up do
    execute("CREATE EXTENSION IF NOT EXISTS cube")

    execute("""
    CREATE TABLE public.extension_kinds (
      id bigint PRIMARY KEY,
      label text,
      location cube,
      locations cube[]
    )
    """)
  end

  def down do
    execute("DROP TABLE public.extension_kinds")
    execute("DROP EXTENSION cube")
  end
end

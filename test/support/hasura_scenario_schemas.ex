defmodule Authzura.Test.HasuraSchemas do
  @moduledoc false

  # Ecto schemas for the ported Hasura fixtures (see the
  # `create_hasura_scenario_schemas` test migration). Only the roots of
  # `all_input/4` need one: everything else reads the tables schemaless.

  defmodule PermissionsArticle do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_permissions"
    @primary_key {:id, :integer, autogenerate: false}
    schema "article" do
      field(:title, :string)
      field(:content, :string)
      field(:author_id, :integer)
      field(:is_published, :boolean)
    end
  end

  defmodule BoolexpAuthor do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_boolexp"
    @primary_key {:id, :integer, autogenerate: false}
    schema "author" do
      field(:name, :string)
      field(:is_registered, :boolean)
    end
  end

  defmodule UuidTest do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_boolexp"
    @primary_key {:id, :integer, autogenerate: false}
    schema "uuid_test" do
      field(:uuid_col, Ecto.UUID)
    end
  end

  defmodule SqlIdentifier do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_boolexp"
    @primary_key {:id, :integer, autogenerate: false}
    schema "table_with_sql_identifier" do
      field(:sql_id, :string)
    end
  end

  defmodule City do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_search"
    @primary_key {:id, :integer, autogenerate: false}
    schema "city" do
      field(:name, :string)
      field(:country, :string)
    end
  end

  defmodule Project do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_search"
    @primary_key {:id, :string, autogenerate: false}
    schema "project" do
    end
  end

  defmodule Json do
    @moduledoc false
    # A jsonb value of any shape (`:map` cannot load a JSON array).
    use Ecto.Type

    @impl Ecto.Type
    def type, do: :map
    @impl Ecto.Type
    def cast(value), do: {:ok, value}
    @impl Ecto.Type
    def load(value), do: {:ok, value}
    @impl Ecto.Type
    def dump(value), do: {:ok, value}
  end

  defmodule JsonbArticle do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_jsonb"
    @primary_key {:id, :integer, autogenerate: false}
    schema "article" do
      field(:title, :string)
      field(:content, :string)
      field(:author_id, :integer)
      field(:tags, Authzura.Test.HasuraSchemas.Json)
    end
  end

  defmodule JsonbProduct do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_jsonb"
    @primary_key {:id, :integer, autogenerate: false}
    schema "product" do
      field(:name, :string)
      field(:category, :string)
      field(:spec, Authzura.Test.HasuraSchemas.Json)
    end
  end

  defmodule LiteralTable do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "hasura_array_literal"
    @primary_key {:id, :integer, autogenerate: false}
    schema "table" do
      field(:str, :string)
    end
  end
end

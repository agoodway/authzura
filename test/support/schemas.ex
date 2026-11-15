defmodule Authzura.Test.Schemas do
  @moduledoc false

  defmodule Organization do
    @moduledoc false
    use Ecto.Schema

    alias Authzura.Test.Schemas.User

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "organizations" do
      field(:name, :string)
      has_many(:users, User, foreign_key: :org_id)
    end
  end

  defmodule User do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "users" do
      field(:org_id, :integer)
      field(:manager_id, :integer)
      field(:email, :string)
      field(:role, :string)
      field(:is_admin, :boolean, default: false)
      field(:salary, :decimal)
    end
  end

  defmodule Article do
    @moduledoc false
    use Ecto.Schema

    alias Ecto.UUID

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "articles" do
      field(:org_id, :integer)
      field(:author_id, :integer)
      field(:editor_id, :integer)
      field(:status, :string)
      field(:is_published, :boolean)
      field(:title, :string)
      field(:body, :string)
      field(:internal_notes, :string)
      field(:assignees, :map, default: %{})
      field(:external_ref, UUID)
      field(:published_at, :utc_datetime_usec)
    end
  end

  defmodule Comment do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @primary_key {:id, :integer, autogenerate: false}
    schema "comments" do
      field(:article_id, :integer)
      field(:author_id, :integer)
      field(:body, :string)
    end
  end

  defmodule AuditUser do
    @moduledoc false
    use Ecto.Schema

    @type t :: %__MODULE__{}

    @schema_prefix "audit"
    @primary_key {:id, :integer, autogenerate: false}
    schema "users" do
      field(:note, :string)
    end
  end
end

defmodule Mix.Tasks.Authzura.CheckHostTest do
  @moduledoc """
  Runs `mix authzura.check` the way an adopter does, from a host project
  (`test/fixtures/host_app`) whose repo is not compiled yet. Slow (it compiles
  the dependencies once), so it is excluded by default:

      mix test --only host_app
  """
  use Authzura.CommittedCase

  alias Authzura.HasuraFixture

  @moduletag :host_app
  @moduletag timeout: 600_000

  @host Path.expand("../../fixtures/host_app", __DIR__)

  test "resolves --repo in a host app whose modules are compiled by the task itself" do
    HasuraFixture.put_metadata!(
      Repo,
      HasuraFixture.metadata([
        %{
          table: {"public", "articles"},
          select_permissions: HasuraFixture.select_permissions("user", ["id", "title"])
        }
      ])
    )

    {output, status} =
      System.cmd(System.find_executable("mix"), ["authzura.check", "--repo", "Host.Repo"],
        cd: @host,
        env: [
          {"MIX_ENV", "dev"},
          {"AUTHZURA_TEST_PORT", to_string(Repo.config()[:port])},
          {"AUTHZURA_TEST_DATABASE", Repo.config()[:database]}
        ],
        stderr_to_stdout: true
      )

    assert output =~ "1 select permissions"
    assert status == 0
  end
end

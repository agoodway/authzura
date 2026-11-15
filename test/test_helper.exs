alias Authzura.Test.{CubeRepo, OtherRepo, Repo}
alias Ecto.Adapters.SQL.Sandbox

{:ok, _} = Repo.start_link()
{:ok, _} = OtherRepo.start_link()
{:ok, _} = CubeRepo.start_link()

Sandbox.mode(Repo, :manual)

# The opt-in suites (`--only <tag>`) run against a real Hasura or the
# benchmark database; `:host_app` compiles a fixture host project (slow). The
# `:property` suite runs by default. The PgRest
# examples need the optional local PgRest checkout (see mix.exs).
exclude =
  [:hasura_parity, :hasura_differential, :bench, :host_app] ++
    if(Code.ensure_loaded?(PgRest), do: [], else: [:pgrest])

ExUnit.start(exclude: exclude, assert_receive_timeout: 1_000)

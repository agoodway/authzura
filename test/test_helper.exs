alias Authzura.Test.{CubeRepo, OtherRepo, Repo}
alias Ecto.Adapters.SQL.Sandbox

{:ok, _} = Repo.start_link()
{:ok, _} = OtherRepo.start_link()
{:ok, _} = CubeRepo.start_link()

# Tests that need a server feature are excluded when the server lacks it, so
# they skip cleanly on older or non-ICU builds: `:temporal_key` needs PG 18
# (`WITHOUT OVERLAPS`) and the btree_gist extension, `:icu` an ICU build
# (nondeterministic collations). They run by default wherever the server has
# the feature, as CI's PG 18 does. `:fence_jit` requires pg_jit_available().
%{rows: [[temporal_key?, icu?, jit?]]} =
  Repo.query!("""
  SELECT current_setting('server_version_num')::int >= 180000
           AND EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'btree_gist'),
         EXISTS (SELECT 1 FROM pg_collation WHERE collprovider = 'i'),
         pg_jit_available()
  """)

Application.put_env(:authzura, :server_features, %{
  temporal_key?: temporal_key?,
  icu?: icu?,
  jit_available?: jit?
})

server_exclude =
  for {tag, false} <- [temporal_key: temporal_key?, icu: icu?, fence_jit: jit?], do: tag

Sandbox.mode(Repo, :manual)

# The opt-in suites (`--only <tag>`) run against a real Hasura or the
# benchmark database; `:host_app` compiles a fixture host project (slow). The
# `:property` suite and PgRest examples run by default.
exclude =
  [:hasura_parity, :hasura_differential, :bench, :host_app] ++
    server_exclude

ExUnit.start(exclude: exclude, assert_receive_timeout: 1_000)

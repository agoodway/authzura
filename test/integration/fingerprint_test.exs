defmodule Authzura.Integration.FingerprintTest do
  use Authzura.CommittedCase

  alias Authzura.Adapters.Postgres.Introspection

  @refs [{"public", "articles"}, {"audit", "users"}]

  test "is stable across calls and changes with the structure" do
    {:ok, before} = Introspection.fingerprint(Repo, @refs)
    assert {:ok, ^before} = Introspection.fingerprint(Repo, @refs)

    Repo.query!("ALTER TABLE public.articles ADD COLUMN x int")
    on_exit(fn -> Repo.query!("ALTER TABLE public.articles DROP COLUMN IF EXISTS x") end)

    assert {:ok, changed} = Introspection.fingerprint(Repo, @refs)
    assert changed != before
  end

  test "changes when an index is created or an enum label is renamed" do
    {:ok, before} = Introspection.fingerprint(Repo, @refs)

    Repo.query!("CREATE INDEX fingerprint_probe_idx ON public.articles (org_id, id)")
    on_exit(fn -> Repo.query!("DROP INDEX IF EXISTS public.fingerprint_probe_idx") end)
    assert {:ok, indexed} = Introspection.fingerprint(Repo, @refs)
    assert indexed != before

    Repo.query!("ALTER TYPE public.article_status RENAME VALUE 'review' TO 'in_review'")

    on_exit(fn ->
      Repo.query!("ALTER TYPE public.article_status RENAME VALUE 'in_review' TO 'review'")
    end)

    assert {:ok, relabeled} = Introspection.fingerprint(Repo, @refs)
    assert relabeled != indexed
  end

  test "ignores changes to tables outside the requested set" do
    {:ok, before} = Introspection.fingerprint(Repo, [{"audit", "users"}])

    Repo.query!("ALTER TABLE public.users ADD COLUMN y int")
    on_exit(fn -> Repo.query!("ALTER TABLE public.users DROP COLUMN IF EXISTS y") end)

    assert {:ok, ^before} = Introspection.fingerprint(Repo, [{"audit", "users"}])
  end
end

defmodule Authzura.Test.Repo.Migrations.CreatePushdownProbe do
  @moduledoc """
  A table for the `input_index_pushdown` tests: a plain column of each
  comparison family, a stored generated column, and a secondary index on
  `author_id`, so a test can see which comparisons Postgres can read through
  an index. Test-only, like the other migrations in this directory.
  """
  use Ecto.Migration

  def up do
    execute("""
    CREATE TABLE public.pushdown_probe (
      id bigint PRIMARY KEY,
      org_id bigint NOT NULL,
      author_id bigint NOT NULL,
      small smallint,
      title text,
      flag boolean,
      day date,
      stamp timestamptz,
      ref uuid,
      amount numeric,
      tag citext,
      vc varchar(16),
      code char(2),
      f4 real,
      f8 double precision,
      ts timestamp,
      label name,
      status public.article_status,
      doubled bigint GENERATED ALWAYS AS (id * 2) STORED
    )
    """)

    execute("CREATE INDEX pushdown_probe_author_id_idx ON public.pushdown_probe (author_id)")
    execute("CREATE INDEX pushdown_probe_vc_idx ON public.pushdown_probe (vc)")
    execute("CREATE INDEX pushdown_probe_stamp_idx ON public.pushdown_probe (stamp)")
    execute("CREATE INDEX pushdown_probe_ref_idx ON public.pushdown_probe (ref)")

    execute("""
    CREATE VIEW public.pushdown_probe_view AS
      SELECT id, org_id, author_id FROM public.pushdown_probe
    """)
  end

  def down do
    execute("DROP VIEW public.pushdown_probe_view")
    execute("DROP TABLE public.pushdown_probe")
  end
end

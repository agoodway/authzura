defmodule Authzura.Test.Repo.Migrations.CreateFenceGuaranteeFixture do
  @moduledoc "Committed, argument-only probes for relationship-fence regression evidence."
  use Ecto.Migration

  def up do
    execute("CREATE SCHEMA fence_probe")
    execute("CREATE DOMAIN fence_probe.body_text AS text")

    execute("""
    CREATE FUNCTION fence_probe.guard(body text, pattern text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE COST 0.0001 AS $$
    BEGIN
      IF left(body, 2) = 'H:' THEN
        RAISE EXCEPTION 'hidden row';
      END IF;
      RETURN body LIKE pattern;
    END
    $$
    """)

    # CREATE OPERATOR requires the implementation's exact argument types.
    # This non-inlineable overload delegates to the argument-only text probe.
    execute("""
    CREATE FUNCTION fence_probe.guard(body fence_probe.body_text, pattern varchar)
    RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE COST 0.0001 AS $$
    BEGIN
      RETURN fence_probe.guard(body::text, pattern::text);
    END
    $$
    """)

    execute("""
    CREATE OPERATOR fence_probe.~~ (
      LEFTARG = fence_probe.body_text, RIGHTARG = varchar, FUNCTION = fence_probe.guard
    )
    """)

    execute("CREATE TABLE fence_probe.organizations (id bigint PRIMARY KEY)")
    execute("CREATE TABLE fence_probe.users (id bigint PRIMARY KEY, org_id bigint)")
    execute("CREATE TABLE fence_probe.articles (id bigint PRIMARY KEY, author_id bigint)")

    execute("""
    CREATE TABLE fence_probe.articles_part (id bigint PRIMARY KEY, author_id bigint)
    PARTITION BY HASH (id)
    """)

    for remainder <- 0..3 do
      execute("""
      CREATE TABLE fence_probe.articles_part_#{remainder}
      PARTITION OF fence_probe.articles_part FOR VALUES WITH (MODULUS 4, REMAINDER #{remainder})
      """)
    end

    # Only root author_id is indexed. Relationship-column indexes would let
    # selective joins bypass hidden comments before the control's probe runs.
    # Org 3 remains a minority; NULL/dangling keys add hidden rows at every hop.
    for table <- ~w(comments comments_part) do
      execute("""
      CREATE TABLE fence_probe.#{table} (
        id bigint PRIMARY KEY,
        article_id bigint,
        nullable_article_id bigint,
        author_id bigint NOT NULL,
        body fence_probe.body_text NOT NULL,
        body_partial fence_probe.body_text NOT NULL,
        body_nullable fence_probe.body_text NOT NULL
      ) WITH (parallel_workers = 2)
      """)

      execute("CREATE INDEX ON fence_probe.#{table} (author_id)")
    end

    execute("INSERT INTO fence_probe.organizations SELECT n FROM generate_series(1, 12) n")

    execute("""
    INSERT INTO fence_probe.users
    SELECT n, CASE WHEN n % 17 = 0 THEN NULL WHEN n % 19 = 0 THEN 9999 ELSE 1 + (n / 3) % 4 END
    FROM generate_series(1, 120) n
    """)

    execute("""
    INSERT INTO fence_probe.articles
    SELECT n, CASE WHEN n % 13 = 0 THEN NULL WHEN n % 17 = 0 THEN 9999 ELSE 1 + n % 120 END
    FROM generate_series(1, 1200) n
    """)

    execute("INSERT INTO fence_probe.articles_part SELECT * FROM fence_probe.articles")

    execute("""
    INSERT INTO fence_probe.comments
    SELECT n,
      CASE WHEN n % 23 = 0 THEN NULL WHEN n % 29 = 0 THEN 99999 ELSE 1 + n % 1200 END,
      CASE WHEN n % 31 = 0 THEN NULL WHEN n % 37 = 0 THEN 99999
           WHEN n % 23 = 0 THEN NULL WHEN n % 29 = 0 THEN 99999 ELSE 1 + n % 1200 END,
      1 + n % 7, 'unmarked', 'unmarked', 'unmarked'
    FROM generate_series(1, 12000) n
    """)

    # Separate markers per permission shape. The partial shape adds an array
    # existence check, satisfied by the root comment itself whenever deep holds.
    for {body, key} <- [
          {"body", "article_id"},
          {"body_partial", "article_id"},
          {"body_nullable", "nullable_article_id"}
        ] do
      execute("""
      UPDATE fence_probe.comments c SET #{body} =
        (CASE WHEN EXISTS (
          SELECT 1 FROM fence_probe.articles a
          JOIN fence_probe.users u ON u.id = a.author_id
          JOIN fence_probe.organizations o ON o.id = u.org_id
          WHERE a.id = c.#{key} AND o.id = 3
        ) THEN 'V:' ELSE 'H:' END) || c.id::text
      """)
    end

    execute("INSERT INTO fence_probe.comments_part SELECT * FROM fence_probe.comments")
    execute("ANALYZE fence_probe.organizations")
    execute("ANALYZE fence_probe.users")
    execute("ANALYZE fence_probe.articles")
    execute("ANALYZE fence_probe.articles_part")
    execute("ANALYZE fence_probe.comments")
    execute("ANALYZE fence_probe.comments_part")
  end

  def down do
    execute("DROP SCHEMA fence_probe CASCADE")
  end
end

defmodule Authzura.Bench.MeasureTest do
  use ExUnit.Case, async: true

  alias Authzura.Adapters.Postgres.InputCheck
  alias Authzura.Bench
  alias Authzura.Bench.{Measure, Scenarios}

  describe "classify/1" do
    test "transaction control, setup, background and data" do
      for sql <- [
            "BEGIN",
            "begin isolation level read committed read only",
            "COMMIT",
            "ROLLBACK",
            "SET TRANSACTION READ ONLY",
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "SAVEPOINT $1",
            "RELEASE SAVEPOINT $1"
          ] do
        assert Measure.classify(sql) == :transaction_control, sql
      end

      for sql <- [
            "SELECT set_config($1, $2, $3)",
            "SET LOCAL statement_timeout = $1",
            "SELECT current_setting($1)",
            "SELECT pg_catalog.set_config($1, $2, true)"
            | InputCheck.statements()
          ] do
        assert Measure.classify(sql) == :setup, sql
      end

      for sql <- [
            "SELECT version FROM hdb_catalog.hdb_version",
            "SELECT pg_stat_statements_reset()",
            "SELECT query, calls FROM pg_stat_statements",
            "SELECT t.oid FROM pg_catalog.pg_type AS t",
            ~s|SELECT c.relname FROM "pg_catalog"."pg_class" AS c|
          ] do
        assert Measure.classify(sql) == :background, sql
      end

      assert Measure.classify(~s|SELECT a0."id" FROM "public"."articles" AS a0|) == :data

      assert Measure.classify(~s|SELECT a0."pg_catalog_note" FROM "public"."articles" AS a0|) ==
               :data
    end
  end

  describe "parse_plan/1" do
    test "buffers come from each statement's root node once; expressions are dropped" do
      explain = [
        %{
          "Plan" => %{
            "Node Type" => "Limit",
            "Shared Hit Blocks" => 40,
            "Shared Read Blocks" => 2,
            "Plans" => [
              %{
                "Node Type" => "Nested Loop",
                "Shared Hit Blocks" => 39,
                "Shared Read Blocks" => 2,
                "Join Filter" => "(a.secret = 'ZQX')",
                "Plans" => [
                  %{
                    "Node Type" => "Index Scan",
                    "Relation Name" => "articles",
                    "Index Name" => "articles_org_id_index",
                    "Index Cond" => "(org_id = '3'::bigint)",
                    "Shared Hit Blocks" => 30
                  },
                  %{
                    "Node Type" => "Bitmap Heap Scan",
                    "Relation Name" => "users",
                    "Recheck Cond" => "(id = a.author_id)",
                    "Plans" => [
                      %{
                        "Node Type" => "Bitmap Index Scan",
                        "Index Name" => "users_pkey",
                        "Index Cond" => "(id = a.author_id)"
                      }
                    ]
                  },
                  %{
                    "Node Type" => "Seq Scan",
                    "Relation Name" => "organizations",
                    "Filter" => "(name = 'ZQX')"
                  },
                  %{
                    "Node Type" => "Index Only Scan",
                    "Relation Name" => "comments",
                    "Index Name" => "comments_pkey"
                  }
                ]
              }
            ]
          },
          "Planning" => %{"Shared Hit Blocks" => 900},
          "Planning Time" => 0.1,
          "Execution Time" => 0.2
        }
      ]

      plan = Measure.parse_plan(explain)

      assert plan == %{
               shared_buffers: 42,
               table_scans: [
                 {"articles", :index, "articles_org_id_index"},
                 {"users", :bitmap, "users_pkey"},
                 {"organizations", :seq, nil},
                 {"comments", :index_only, "comments_pkey"}
               ]
             }

      refute inspect(plan) =~ "ZQX"
    end
  end

  describe "summarize/2" do
    # Drift that hits both engines in a repetition (a cold cache, a plan
    # cache transition) cancels in the paired ratios.
    test "the CV is that of the paired per-repetition ratios" do
      hasura = [1.0, 2.0, 1.0, 2.0, 1.0]
      authzura = [1.1, 2.2, 1.1, 2.2, 1.1]

      assert %{cv: cv, verdict: :pass} = Measure.summarize(hasura, authzura)
      assert_in_delta cv, 0.0, 1.0e-9
    end

    test "the ratio of the medians" do
      summary = Measure.summarize([2.0, 2.0, 2.0, 2.0, 2.0], [2.5, 2.5, 2.5, 2.5, 2.5])

      assert summary.ratio == 1.25
      assert summary.cv == 0.0
      assert summary.verdict == :pass
      assert summary.hasura_ms == 2.0
      assert summary.authzura_ms == 2.5
    end

    test "the CV uses the sample standard deviation: population 0.148, sample 0.166" do
      # Population CV 0.148 would pass the 15 % rule; the sample CV does not.
      authzura = [1.0, 1.0, 1.0, 1.0, 1.4]

      assert %{verdict: :inconclusive, cv: cv} =
               Measure.summarize([1.0, 1.0, 1.0, 1.0, 1.0], authzura)

      assert_in_delta cv, 0.1656, 0.0001
    end

    test "CV above 15 % is :inconclusive, never :pass" do
      # Authzura is faster, but Hasura's runs vary by more than 15 %.
      assert %{verdict: :inconclusive, cv: cv} =
               Measure.summarize([1.0, 1.0, 1.0, 2.0, 2.0], [1.0, 1.0, 1.0, 1.0, 1.0])

      assert cv > 0.15

      assert %{verdict: :inconclusive} =
               Measure.summarize([1.0, 1.0, 1.0, 1.0, 1.0], [1.0, 1.0, 1.0, 1.0, 1.6])
    end
  end

  describe "check/3" do
    test "targets: db_time 1.25 pass / 1.251 fail; data == 1+L; read-only-connection needs 0 transaction control" do
      flat = scenario("flat-tenant")
      nested = scenario("preload-nested-3")

      assert %{db_time: :pass} = Measure.check(results(ratio: 1.25), flat, :default)
      assert %{db_time: :fail} = Measure.check(results(ratio: 1.251), flat, :default)

      assert %{db_time: :inconclusive} =
               Measure.check(results(ratio: 1.0, cv: 0.151), flat, :default)

      assert %{data_statements: :pass} = Measure.check(results(data: 1.0), flat, :default)
      assert %{data_statements: :fail} = Measure.check(results(data: 2.0), flat, :default)
      assert %{data_statements: :pass} = Measure.check(results(data: 4.0), nested, :default)
      assert %{data_statements: :fail} = Measure.check(results(data: 1.0), nested, :default)

      assert %{transaction_control: :not_applicable} =
               Measure.check(results(txn: 3.0), flat, :default)

      assert %{transaction_control: :pass} =
               Measure.check(results(txn: 0.0), flat, :read_only_connection)

      assert %{transaction_control: :fail} =
               Measure.check(results(txn: 1.0), flat, :read_only_connection)

      # Preloads keep their REPEATABLE READ transaction by design.
      assert %{transaction_control: :not_applicable} =
               Measure.check(results(data: 4.0, txn: 3.0), nested, :read_only_connection)
    end

    test "indexes: every table Hasura reads through an index, Authzura does too" do
      flat = scenario("flat-tenant")
      index = [{"articles", :index, "articles_org_id_index"}]
      seq = [{"articles", :seq, nil}]

      assert %{indexes: :pass} = Measure.check(results(hasura_scans: index), flat, :default)

      assert %{indexes: :fail} =
               Measure.check(results(hasura_scans: index, authzura_scans: seq), flat, :default)

      # Hasura scanning sequentially sets no requirement.
      assert %{indexes: :pass} =
               Measure.check(results(hasura_scans: seq, authzura_scans: seq), flat, :default)
    end

    test "buffers: at most 1.5 times Hasura's" do
      flat = scenario("flat-tenant")

      assert %{buffers: :pass} = Measure.check(results(buffers: {100, 150}), flat, :default)
      assert %{buffers: :fail} = Measure.check(results(buffers: {100, 151}), flat, :default)
    end

    test "verdict/1: a failure fails, an inconclusive target alone is inconclusive" do
      assert Measure.verdict(%{db_time: :pass, buffers: :pass, x: :not_applicable}) == :pass
      assert Measure.verdict(%{db_time: :inconclusive, buffers: :pass}) == :inconclusive
      assert Measure.verdict(%{db_time: :inconclusive, buffers: :fail}) == :fail
    end
  end

  describe "against the bench database" do
    @describetag :bench

    # Needs the seeded :small benchmark database and its Hasura (see
    # bench/README.md): mix test --only bench test/bench
    setup do
      Enum.each(Bench.children(), &start_supervised!/1)
      :ok = Authzura.reload(Bench.instance())
      :ok
    end

    test "statements/4 counts one data statement per Authzura request and excludes background" do
      flat = scenario("flat-tenant")

      assert %{counts: counts, db_ms: db_ms} = Measure.statements(:authzura, flat, 10)
      assert counts.data == 1.0
      # BEGIN and COMMIT: the named SET TRANSACTION is recorded only on its
      # first use per connection, which the warm-up absorbs.
      assert counts.transaction_control == 2.0
      assert db_ms > 0.0
      refute Map.has_key?(counts, :background)

      assert %{counts: %{data: 1.0}} = Measure.statements(:hasura, flat, 10)
    end

    test "plans/2 explains each engine's data statements" do
      flat = scenario("flat-tenant")

      assert [%{table_scans: [{"articles", _kind, _index} | _], shared_buffers: buffers}] =
               Measure.plans(:authzura, flat)

      assert buffers > 0
      assert [%{table_scans: [_ | _]}] = Measure.plans(:hasura, flat)
    end
  end

  defp scenario(id), do: Enum.find(Scenarios.all(), &(&1.id == id))

  defp results(opts) do
    scans = [{"articles", :index, "articles_org_id_index"}]
    {hasura_buffers, authzura_buffers} = Keyword.get(opts, :buffers, {100, 100})

    %{
      db_time: %{
        ratio: Keyword.get(opts, :ratio, 1.0),
        cv: Keyword.get(opts, :cv, 0.01)
      },
      statements: %{
        hasura: %{counts: %{data: 1.0}, db_ms: 1.0},
        authzura: %{
          counts: %{
            data: Keyword.get(opts, :data, 1.0),
            transaction_control: Keyword.get(opts, :txn, 0.0)
          },
          db_ms: 1.0
        }
      },
      plans: %{
        hasura: [
          %{table_scans: Keyword.get(opts, :hasura_scans, scans), shared_buffers: hasura_buffers}
        ],
        authzura: [
          %{
            table_scans: Keyword.get(opts, :authzura_scans, scans),
            shared_buffers: authzura_buffers
          }
        ]
      }
    }
  end
end

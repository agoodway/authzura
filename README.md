# Authzura

[![Hex.pm](https://img.shields.io/hexpm/v/authzura.svg)](https://hex.pm/packages/authzura)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/authzura)
[![License](https://img.shields.io/hexpm/l/authzura.svg)](https://github.com/agoodway/authzura/blob/main/LICENSE)

> Hasura v2 select permissions, enforced on your Ecto reads.

Authzura reads the permission metadata of a Hasura v2 project from
`hdb_catalog` and applies it to your Ecto queries: row filters, columns,
limits, root fields and relationship preloads. It is read-only and deny by
default: anything it cannot enforce is refused, never approximated. There are
no migrations, because Authzura only reads Hasura's metadata and never writes
to your database.

## Installation

Add `authzura` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:authzura, "~> 0.1"},
    # Only for Authzura.JWT
    {:jose, "~> 1.11"}
  ]
end
```

Then fetch dependencies:

```bash
mix deps.get
```

## Quick Start

### 1. Add an instance after the repo it reads through

```elixir
children = [
  MyApp.Repo,
  {Authzura,
   [name: MyApp.Authz, repo: MyApp.Repo] ++ Application.get_env(:my_app, MyApp.Authz, [])}
]
```

### 2. Build a session from values your code already authenticated

```elixir
{:ok, session} =
  Authzura.Session.new(
    %{"x-hasura-user-id" => "42", "x-hasura-org-id" => "1"},
    allowed_roles: ["user", "editor"],
    default_role: "user"
  )
```

### 3. Scope a query and run it

```elixir
import Ecto.Query

alias MyApp.Article

{:ok, query} =
  Article
  |> where([a], a.status == "draft")
  |> Authzura.scope(session, instance: MyApp.Authz)

rows = MyApp.Repo.all(query)
```

Scoping must be the last step. Prefer `all/3` and `one/3`, which run the read
for you and can preload Hasura relationships:

```elixir
alias MyApp.Article

{:ok, articles} =
  Authzura.all(Article, session,
    instance: MyApp.Authz,
    columns: [:id, :title],
    preload: [:author, comments: [columns: [:id, :body]]]
  )
```

### 4. Untrusted input goes through the input functions

```elixir
alias MyApp.Article

request = %{"columns" => ["id", "title"], "filter" => %{"status" => %{"_eq" => "draft"}}}

{:ok, input_rows} = Authzura.all_input(Article, session, request, instance: MyApp.Authz)
```

## Documentation

- [Configuration](docs/guides/configuration.md): options, polling and freshness, reload, status, split repos, telemetry
- [Querying](docs/guides/querying.md): sessions and JWT, `all`, `one` and `scope`, untrusted input, preloads, errors
- [Security](docs/guides/security.md): deny by default, unsupported features, side channels, input limits, Hasura compatibility
- [Compatibility](docs/guides/compatibility.md): property, differential and benchmark evidence against Hasura
- [`mix authzura.check`](https://hexdocs.pm/authzura/Mix.Tasks.Authzura.Check.html): validate your metadata in CI
- [HexDocs](https://hexdocs.pm/authzura) for the API reference

For PostgREST-style APIs, see [PgRest](https://github.com/agoodway/pgrest),
from the same author.

## Development

```bash
docker compose up -d postgres
mix test
mix quality
```

The test database is built from `priv/test_migrations` by `mix test`; Authzura
adds no tables to your application. Every Elixir example in this README and
the guides is run by `test/readme_examples_test.exs`.

The PgRest examples run by default using the pinned GitHub test dependency;
see [Using with PgRest](docs/guides/querying.md#using-with-pgrest).

The opt-in `mix authzura.check` host-project test: `mix test --only host_app`.

The opt-in Hasura parity suite: [Running parity tests](docs/guides/security.md#running-parity-tests).

Before tagging a release:

1. `mix quality` and `mix test` pass, and `mix docs` has no warnings.
2. Run `mix authzura.check` against at least one large real-world Hasura v2
   metadata set (hundreds of tables).
3. Record the result in the release notes as counts only (tables, select
   permissions, denials, warnings), never any metadata.
4. Never commit third-party metadata to this repository.

## License

MIT. See [LICENSE](https://github.com/agoodway/authzura/blob/main/LICENSE).

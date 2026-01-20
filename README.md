# Authzura: Dynamic Authorization for PostgreSQL

Authzura is a standalone PostgreSQL authorization library for Elixir inspired by Hasura that provides dynamic role-based access control with Hasura-compatible permission syntax. Use it with ExRest, Phoenix LiveView, or any Elixir application.

## Overview

**Key Features:**
- **Dynamic Roles** - Tenant-specific roles created at runtime by end users
- **Role Inheritance** - Roles can inherit permissions from other roles
- **Multi-Role Users** - Users can have multiple roles with merged permissions
- **Hasura-Compatible** - Import existing Hasura permission metadata
- **Materialized Views** - Fast permission lookups with automatic refresh
- **Optional Caching** - Nebulex integration (local, distributed, or Redis)
- **Admin UI** - Optional mountable LiveView UI for visual permission management
- **Clean Operator Syntax** - Uses `eq`, `gt`, `and` (no dots or underscores in storage)

**Use Cases:**
- SaaS apps where tenants create custom roles ("billing_admin", "regional_manager")
- Multi-tenant systems with per-tenant permission customization
- Migrating from Hasura while keeping permission syntax
- Any app needing runtime-configurable authorization

---

## Installation

```elixir
# mix.exs
def deps do
  [
    {:authzura, "~> 0.1.0"},
    {:postgrex, "~> 0.17"},
    {:ecto_sql, "~> 3.10"}
  ]
end
```

```elixir
# config/config.exs
config :authzura,
  repo: MyApp.Repo,
  schema: "authzura",
  pubsub: MyApp.PubSub  # Optional: for distributed cache invalidation
```

Run migrations:

```bash
mix authzura.install
mix ecto.migrate
```

Add to your application supervision tree:

```elixir
# lib/my_app/application.ex
def start(_type, _args) do
  children = [
    MyApp.Repo,
    {Phoenix.PubSub, name: MyApp.PubSub},
    Authzura.Supervisor,  # Add this
    # ... rest of your children
  ]
  
  opts = [strategy: :one_for_one, name: MyApp.Supervisor]
  Supervisor.start_link(children, opts)
end
```

---

## Database Schema

### Roles Table

```sql
CREATE SCHEMA IF NOT EXISTS authzura;

CREATE TABLE authzura.roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID,                          -- NULL = system-wide role
  name TEXT NOT NULL,                      -- "billing_admin", "report_viewer"
  display_name TEXT,
  description TEXT,
  inherits_from UUID[],                    -- Role inheritance
  is_system BOOLEAN DEFAULT FALSE,         -- System roles protected from deletion
  is_active BOOLEAN DEFAULT TRUE,
  metadata JSONB DEFAULT '{}',             -- Extensible attributes
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT roles_name_format CHECK (name ~ '^[a-z][a-z0-9_]*$'),
  CONSTRAINT roles_unique_name UNIQUE (tenant_id, name)
);

CREATE INDEX idx_roles_inherits ON authzura.roles USING GIN (inherits_from);
CREATE INDEX idx_roles_tenant ON authzura.roles (tenant_id) WHERE tenant_id IS NOT NULL;

-- Seed system roles
INSERT INTO authzura.roles (name, display_name, is_system, tenant_id) VALUES
  ('admin', 'Administrator', TRUE, NULL),
  ('user', 'Standard User', TRUE, NULL),
  ('anonymous', 'Anonymous', TRUE, NULL);
```

### User Role Assignments

```sql
CREATE TABLE authzura.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  role_id UUID NOT NULL REFERENCES authzura.roles(id) ON DELETE CASCADE,
  tenant_id UUID,
  granted_by_id UUID,                      -- Who granted this role
  granted_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,                  -- Optional expiration
  is_active BOOLEAN DEFAULT TRUE,
  
  CONSTRAINT user_roles_unique UNIQUE (user_id, role_id, tenant_id)
);

CREATE INDEX idx_user_roles_user ON authzura.user_roles (user_id, tenant_id) 
  WHERE is_active = TRUE;
CREATE INDEX idx_user_roles_expires ON authzura.user_roles (expires_at) 
  WHERE expires_at IS NOT NULL;
```

### Permissions Table

```sql
CREATE TABLE authzura.permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_id UUID NOT NULL REFERENCES authzura.roles(id) ON DELETE CASCADE,
  resource_name TEXT NOT NULL,             -- "orders", "reports", "users"
  operation TEXT NOT NULL,                 -- "select", "insert", "update", "delete"
  
  -- Permission definition (clean operator syntax)
  row_filter JSONB,                        -- Row-level filter expression
  allowed_columns TEXT[],                  -- NULL = all columns
  check_expression JSONB,                  -- Validation for insert/update
  column_presets JSONB,                    -- Auto-set values
  
  max_rows INTEGER,                        -- Optional row limit
  allow_aggregations BOOLEAN DEFAULT FALSE,
  
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  
  CONSTRAINT permissions_operation_valid 
    CHECK (operation IN ('select', 'insert', 'update', 'delete')),
  CONSTRAINT permissions_unique 
    UNIQUE (role_id, resource_name, operation)
);

CREATE INDEX idx_permissions_resource ON authzura.permissions (resource_name, operation) 
  WHERE is_active = TRUE;
```

---

## Materialized Views

Authzura uses materialized views for fast permission lookups with role inheritance resolved.

### Effective Permissions View

```sql
CREATE MATERIALIZED VIEW authzura.effective_permissions AS
WITH RECURSIVE role_hierarchy AS (
  -- Base: direct roles
  SELECT 
    r.id AS role_id,
    r.id AS effective_role_id,
    r.name AS role_name,
    r.tenant_id,
    0 AS depth
  FROM authzura.roles r
  WHERE r.is_active = TRUE
  
  UNION ALL
  
  -- Recursive: inherited roles
  SELECT 
    rh.role_id,
    parent.id AS effective_role_id,
    parent.name AS role_name,
    rh.tenant_id,
    rh.depth + 1
  FROM role_hierarchy rh
  JOIN authzura.roles child ON child.id = rh.effective_role_id
  JOIN authzura.roles parent ON parent.id = ANY(child.inherits_from)
  WHERE parent.is_active = TRUE
    AND rh.depth < 10  -- Prevent infinite loops
)
SELECT DISTINCT
  rh.role_id,
  rh.tenant_id,
  p.resource_name,
  p.operation,
  p.row_filter,
  p.allowed_columns,
  p.check_expression,
  p.column_presets,
  p.max_rows,
  p.allow_aggregations,
  rh.depth AS inheritance_depth
FROM role_hierarchy rh
JOIN authzura.permissions p ON p.role_id = rh.effective_role_id
WHERE p.is_active = TRUE;

CREATE UNIQUE INDEX idx_effective_permissions_unique 
  ON authzura.effective_permissions (role_id, resource_name, operation, inheritance_depth);
```

### User Effective Roles View

```sql
CREATE MATERIALIZED VIEW authzura.user_effective_roles AS
WITH RECURSIVE role_hierarchy AS (
  SELECT 
    ur.user_id,
    ur.tenant_id,
    ur.role_id AS assigned_role_id,
    r.id AS effective_role_id,
    r.name AS role_name,
    0 AS depth
  FROM authzura.user_roles ur
  JOIN authzura.roles r ON r.id = ur.role_id
  WHERE ur.is_active = TRUE
    AND r.is_active = TRUE
    AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
  
  UNION ALL
  
  SELECT 
    rh.user_id,
    rh.tenant_id,
    rh.assigned_role_id,
    parent.id AS effective_role_id,
    parent.name AS role_name,
    rh.depth + 1
  FROM role_hierarchy rh
  JOIN authzura.roles child ON child.id = rh.effective_role_id
  JOIN authzura.roles parent ON parent.id = ANY(child.inherits_from)
  WHERE parent.is_active = TRUE
    AND rh.depth < 10
)
SELECT DISTINCT
  user_id,
  tenant_id,
  assigned_role_id,
  effective_role_id,
  role_name,
  depth AS inheritance_depth
FROM role_hierarchy;

CREATE UNIQUE INDEX idx_user_effective_roles_unique 
  ON authzura.user_effective_roles (user_id, tenant_id, effective_role_id, inheritance_depth);
```

### Refresh Triggers

```sql
-- Notify function for cache invalidation
CREATE OR REPLACE FUNCTION authzura.notify_change()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('authzura_changed', json_build_object(
    'table_name', TG_TABLE_NAME,
    'operation', TG_OP,
    'timestamp', NOW()
  )::text);
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER roles_changed
  AFTER INSERT OR UPDATE OR DELETE ON authzura.roles
  FOR EACH ROW EXECUTE FUNCTION authzura.notify_change();

CREATE TRIGGER user_roles_changed
  AFTER INSERT OR UPDATE OR DELETE ON authzura.user_roles
  FOR EACH ROW EXECUTE FUNCTION authzura.notify_change();

CREATE TRIGGER permissions_changed
  AFTER INSERT OR UPDATE OR DELETE ON authzura.permissions
  FOR EACH ROW EXECUTE FUNCTION authzura.notify_change();

-- Refresh functions
CREATE OR REPLACE FUNCTION authzura.refresh_all()
RETURNS VOID AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY authzura.user_effective_roles;
  REFRESH MATERIALIZED VIEW CONCURRENTLY authzura.effective_permissions;
END;
$$ LANGUAGE plpgsql;
```

---

## Filter Syntax

Authzura uses **clean operator names** without dots or underscores:

```json
// Comparison operators
{"status": {"eq": "active"}}
{"total": {"gt": 100}}
{"total": {"gte": 100}}
{"total": {"lt": 1000}}
{"total": {"lte": 1000}}
{"status": {"neq": "cancelled"}}

// String operators
{"name": {"like": "%smith%"}}
{"email": {"ilike": "%@example.com"}}

// List operators
{"status": {"in": ["pending", "confirmed"]}}
{"category_id": {"nin": [1, 2, 3]}}

// Null checks
{"deleted_at": {"is_null": true}}

// Logical operators
{"and": [{"status": {"eq": "active"}}, {"total": {"gt": 0}}]}
{"or": [{"role": {"eq": "admin"}}, {"is_owner": {"eq": true}}]}
{"not": {"status": {"eq": "cancelled"}}}

// Session variable substitution
{"user_id": {"eq": "X-Authzura-User-Id"}}
{"tenant_id": {"eq": "X-Authzura-Tenant-Id"}}
```

**Hasura compatibility:** When importing from Hasura, underscore operators (`_eq`, `_and`) are automatically converted.

---

## Permission Merging

When a user has multiple roles, permissions are merged using "most permissive wins":

```elixir
# User has roles: ["user", "billing_admin"]
# 
# user role filter:          {"user_id": {"eq": "X-Authzura-User-Id"}}
# billing_admin role filter: {"department": {"eq": "billing"}}
#
# Merged filter (OR):
# {"or": [
#   {"user_id": {"eq": "X-Authzura-User-Id"}},
#   {"department": {"eq": "billing"}}
# ]}
```

**Merge strategies:**
- **Filters**: OR together (user sees rows matching ANY role's filter)
- **Columns**: Union (user can access columns from ANY role)
- **Presets**: Merge (later roles override earlier)
- **Max rows**: Most restrictive (smallest limit)

---

## Caching (Optional)

Authzura provides optional caching using **Nebulex** - the same caching library used by ExRest. This allows local, distributed, or multi-level caching with Redis support.

### Why Nebulex

| Feature | Custom ETS | Nebulex |
|---------|------------|---------|
| Local caching | ✅ | ✅ |
| Distributed (multi-node) | ❌ | ✅ |
| External backends (Redis) | ❌ | ✅ |
| Multi-level (L1 + L2) | ❌ | ✅ |
| Adapter pattern | ❌ | ✅ |
| Telemetry integration | ❌ | ✅ |
| TTL support | ✅ | ✅ |

### Configuration

```elixir
# config/config.exs
config :authzura,
  repo: MyApp.Repo,
  schema: "authzura",
  
  # Caching options
  cache: [
    enabled: true,                         # Enable permission caching (default: false)
    default_ttl: :timer.minutes(5)         # Cache TTL
  ],
  
  # PubSub for distributed invalidation
  pubsub: MyApp.PubSub
```

### Local-Only Cache (Development/Single Node)

```elixir
defmodule Authzura.Cache do
  use Nebulex.Cache,
    otp_app: :authzura,
    adapter: Nebulex.Adapters.Local,
    gc_interval: :timer.hours(1)
end

# config/config.exs
config :authzura, Authzura.Cache,
  gc_interval: :timer.hours(1),
  max_size: 100_000,
  allocated_memory: 50_000_000,  # 50MB
  gc_cleanup_min_timeout: :timer.seconds(10),
  gc_cleanup_max_timeout: :timer.minutes(10)
```

### Distributed Cache (Multi-Node with Partitioned Strategy)

```elixir
defmodule Authzura.Cache do
  use Nebulex.Cache,
    otp_app: :authzura,
    adapter: Nebulex.Adapters.Partitioned,
    primary_storage_adapter: Nebulex.Adapters.Local
end

# config/config.exs  
config :authzura, Authzura.Cache,
  primary: [
    gc_interval: :timer.hours(1),
    max_size: 50_000
  ]
```

### Multi-Level Cache (L1 Local + L2 Redis)

```elixir
defmodule Authzura.Cache.L1 do
  use Nebulex.Cache,
    otp_app: :authzura,
    adapter: Nebulex.Adapters.Local
end

defmodule Authzura.Cache.L2 do
  use Nebulex.Cache,
    otp_app: :authzura,
    adapter: NebulexRedisAdapter
end

defmodule Authzura.Cache do
  use Nebulex.Cache,
    otp_app: :authzura,
    adapter: Nebulex.Adapters.Multilevel

  defmodule L1 do
    use Nebulex.Cache,
      otp_app: :authzura,
      adapter: Nebulex.Adapters.Local
  end

  defmodule L2 do
    use Nebulex.Cache,
      otp_app: :authzura,
      adapter: NebulexRedisAdapter
  end
end

# config/config.exs
config :authzura, Authzura.Cache,
  model: :inclusive,  # L1 includes L2 data
  levels: [
    {Authzura.Cache.L1, gc_interval: :timer.minutes(5), max_size: 10_000},
    {Authzura.Cache.L2, 
      conn_opts: [host: "redis.example.com", port: 6379],
      default_ttl: :timer.hours(1)
    }
  ]
```

### Cache Integration Module

```elixir
defmodule Authzura.CacheIntegration do
  @moduledoc """
  Integrates Nebulex caching with permission lookups and PostgreSQL NOTIFY invalidation.
  """
  
  use GenServer
  require Logger
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end
  
  @doc "Get permission from cache or fetch from database."
  def get_or_fetch(key, fetch_fn) do
    if cache_enabled?() do
      case Authzura.Cache.get(key) do
        nil ->
          case fetch_fn.() do
            {:ok, value} = result ->
              ttl = Application.get_env(:authzura, [:cache, :default_ttl], :timer.minutes(5))
              Authzura.Cache.put(key, value, ttl: ttl)
              result
            error ->
              error
          end
        
        value ->
          {:ok, value}
      end
    else
      fetch_fn.()
    end
  end
  
  @doc "Invalidate cache entries matching pattern."
  def invalidate(pattern \\ :all) do
    if cache_enabled?() do
      case pattern do
        :all -> 
          Authzura.Cache.delete_all()
        
        {:user, user_id} ->
          # Delete all keys matching user pattern
          Authzura.Cache.delete_all()  # Nebulex doesn't have pattern delete, so delete all
        
        {:resource, _resource_name} ->
          Authzura.Cache.delete_all()
        
        {:tenant, _tenant_id} ->
          Authzura.Cache.delete_all()
      end
    end
    :ok
  end
  
  @doc "Get cache statistics."
  def stats do
    if cache_enabled?() do
      Authzura.Cache.stats()
    else
      %{enabled: false}
    end
  end
  
  defp cache_enabled? do
    Application.get_env(:authzura, [:cache, :enabled], false)
  end
  
  # GenServer callbacks
  
  def init(opts) do
    # Subscribe to PostgreSQL NOTIFY via PubSub for distributed invalidation
    if pubsub = opts[:pubsub] do
      Phoenix.PubSub.subscribe(pubsub, "authzura:invalidate")
    end
    
    # Subscribe to PostgreSQL notifications
    if opts[:repo] do
      {:ok, _} = subscribe_to_pg_notify(opts)
    end
    
    {:ok, %{opts: opts}}
  end
  
  def handle_info({:notification, _, _, "authzura_changed", _payload}, state) do
    Logger.debug("Authzura: Permission change detected, invalidating cache")
    invalidate(:all)
    
    # Broadcast to other nodes via PubSub
    if pubsub = state.opts[:pubsub] do
      Phoenix.PubSub.broadcast(pubsub, "authzura:invalidate", {:invalidate, :all})
    end
    
    {:noreply, state}
  end
  
  def handle_info({:invalidate, pattern}, state) do
    invalidate(pattern)
    {:noreply, state}
  end
  
  defp subscribe_to_pg_notify(opts) do
    repo = opts[:repo]
    config = repo.config()
    
    {:ok, conn} = Postgrex.Notifications.start_link(config)
    Postgrex.Notifications.listen(conn, "authzura_changed")
    {:ok, conn}
  end
end
```

### How It Works

1. **First request**: Permission looked up from materialized view, cached via Nebulex
2. **Subsequent requests**: Served from cache (microseconds for local, low ms for Redis)
3. **Permission change**: PostgreSQL NOTIFY triggers PubSub broadcast
4. **All nodes**: Invalidate cache via PubSub subscription

### Disabling Cache

```elixir
# config/config.exs
config :authzura,
  cache: [enabled: false]
```

When disabled, every permission check queries the materialized view directly (still fast due to indexes).

---

## Elixir API

```elixir
defmodule Authzura do
  @moduledoc """
  Dynamic role-based authorization with Hasura-compatible permission syntax.
  """
  
  alias Authzura.{Permissions, Roles, Cache, FilterBuilder}
  
  @type context :: %{user_id: term(), tenant_id: term() | nil}
  
  @type permission :: %{
    has_permission: boolean(),
    filter: map() | nil,
    columns: [String.t()] | nil,
    presets: map() | nil,
    check: map() | nil,
    max_rows: integer() | nil
  }
  
  @doc """
  Get effective permission for a user on a resource.
  Results are cached if caching is enabled.
  """
  @spec get_permission(context(), String.t(), atom()) :: {:ok, permission()} | {:error, term()}
  def get_permission(context, resource, operation) do
    cache_key = {context.user_id, context.tenant_id, resource, operation}
    
    if cache_enabled?() do
      Cache.get_or_fetch(cache_key, fn ->
        Permissions.get_effective(context.user_id, context.tenant_id, resource, operation)
      end)
    else
      Permissions.get_effective(context.user_id, context.tenant_id, resource, operation)
    end
  end
  
  @doc """
  Check if user has permission (boolean).
  """
  @spec permitted?(context(), String.t(), atom()) :: boolean()
  def permitted?(context, resource, operation) do
    case get_permission(context, resource, operation) do
      {:ok, %{has_permission: true}} -> true
      _ -> false
    end
  end
  
  @doc """
  Convert permission filter to Ecto dynamic query.
  """
  @spec build_filter_dynamic(map() | nil, context()) :: Ecto.Query.dynamic()
  def build_filter_dynamic(nil, _context), do: dynamic(true)
  def build_filter_dynamic(filter, context) do
    FilterBuilder.build(filter, context)
  end
  
  @doc """
  Create a new role with permissions.
  """
  def create_role(name, opts \\ []) do
    Roles.create(name, opts)
  end
  
  @doc """
  Assign a role to a user.
  """
  def assign_role(user_id, role_name, opts \\ []) do
    Roles.assign(user_id, role_name, opts)
  end
  
  @doc """
  Revoke a role from a user.
  """
  def revoke_role(user_id, role_name, opts \\ []) do
    Roles.revoke(user_id, role_name, opts)
  end
  
  @doc """
  Get all roles for a user (including inherited).
  """
  def get_user_roles(user_id, tenant_id \\ nil) do
    Roles.get_user_roles(user_id, tenant_id)
  end
  
  @doc """
  Import permissions from Hasura metadata.
  """
  def import_from_hasura(metadata, opts \\ []) do
    Permissions.import_hasura(metadata, Keyword.get(opts, :tenant_id))
  end
  
  @doc """
  Invalidate permission cache.
  """
  def invalidate_cache(pattern \\ :all) do
    if cache_enabled?() do
      Cache.invalidate(pattern)
    end
    :ok
  end
  
  @doc """
  Get cache statistics.
  """
  def cache_stats do
    if cache_enabled?() do
      Cache.stats()
    else
      %{enabled: false}
    end
  end
  
  defp cache_enabled? do
    Application.get_env(:authzura, [:cache, :enabled], false)
  end
end
```

---

## Filter Builder

```elixir
defmodule Authzura.FilterBuilder do
  @moduledoc """
  Converts Authzura JSON filters to Ecto dynamic queries.
  """
  
  import Ecto.Query
  
  # Clean operators (also accepts Hasura-style for backwards compatibility)
  @operators %{
    # Clean style (stored format)
    "eq" => :eq, "neq" => :neq,
    "gt" => :gt, "gte" => :gte,
    "lt" => :lt, "lte" => :lte,
    "like" => :like, "ilike" => :ilike,
    "in" => :in, "nin" => :nin,
    "is_null" => :is_null,
    # Hasura style (accepted on input)
    "_eq" => :eq, "_neq" => :neq,
    "_gt" => :gt, "_gte" => :gte,
    "_lt" => :lt, "_lte" => :lte,
    "_like" => :like, "_ilike" => :ilike,
    "_in" => :in, "_nin" => :nin,
    "_is_null" => :is_null
  }
  
  @logical_and ["and", "_and"]
  @logical_or ["or", "_or"]
  @logical_not ["not", "_not"]
  
  def build(filter, context) when is_map(filter) do
    build_dynamic(filter, context)
  end
  
  defp build_dynamic(filter, context) when is_map(filter) do
    cond do
      key = find_key(filter, @logical_and) ->
        filter[key]
        |> Enum.map(&build_dynamic(&1, context))
        |> Enum.reduce(fn d, acc -> dynamic([r], ^acc and ^d) end)
      
      key = find_key(filter, @logical_or) ->
        filter[key]
        |> Enum.map(&build_dynamic(&1, context))
        |> Enum.reduce(fn d, acc -> dynamic([r], ^acc or ^d) end)
      
      key = find_key(filter, @logical_not) ->
        inner = build_dynamic(filter[key], context)
        dynamic([r], not(^inner))
      
      true ->
        filter
        |> Enum.map(fn {column, op_value} ->
          build_column_filter(column, op_value, context)
        end)
        |> Enum.reduce(fn d, acc -> dynamic([r], ^acc and ^d) end)
    end
  end
  
  defp build_column_filter(column, op_value, context) when is_map(op_value) do
    [{op, raw_value}] = Map.to_list(op_value)
    value = resolve_variable(raw_value, context)
    field_atom = String.to_existing_atom(column)
    op_atom = Map.fetch!(@operators, op)
    
    apply_operator(field_atom, op_atom, value)
  end
  
  defp apply_operator(field, :eq, value), do: dynamic([r], field(r, ^field) == ^value)
  defp apply_operator(field, :neq, value), do: dynamic([r], field(r, ^field) != ^value)
  defp apply_operator(field, :gt, value), do: dynamic([r], field(r, ^field) > ^value)
  defp apply_operator(field, :gte, value), do: dynamic([r], field(r, ^field) >= ^value)
  defp apply_operator(field, :lt, value), do: dynamic([r], field(r, ^field) < ^value)
  defp apply_operator(field, :lte, value), do: dynamic([r], field(r, ^field) <= ^value)
  defp apply_operator(field, :like, value), do: dynamic([r], like(field(r, ^field), ^value))
  defp apply_operator(field, :ilike, value), do: dynamic([r], ilike(field(r, ^field), ^value))
  defp apply_operator(field, :in, value), do: dynamic([r], field(r, ^field) in ^value)
  defp apply_operator(field, :nin, value), do: dynamic([r], field(r, ^field) not in ^value)
  defp apply_operator(field, :is_null, true), do: dynamic([r], is_nil(field(r, ^field)))
  defp apply_operator(field, :is_null, false), do: dynamic([r], not is_nil(field(r, ^field)))
  
  # Session variable resolution
  defp resolve_variable("X-Authzura-User-Id", ctx), do: ctx.user_id
  defp resolve_variable("X-Authzura-Tenant-Id", ctx), do: ctx.tenant_id
  defp resolve_variable("X-Hasura-User-Id", ctx), do: ctx.user_id
  defp resolve_variable("X-Hasura-Role", ctx), do: ctx[:role]
  defp resolve_variable(value, _ctx), do: value
  
  defp find_key(map, keys), do: Enum.find(keys, &Map.has_key?(map, &1))
end
```

---

## Hasura Import

```sql
-- Operator conversion mapping
CREATE TABLE authzura.operator_mapping (
  hasura_op TEXT PRIMARY KEY,
  clean_op TEXT NOT NULL
);

INSERT INTO authzura.operator_mapping VALUES
  ('_eq', 'eq'), ('_neq', 'neq'),
  ('_gt', 'gt'), ('_gte', 'gte'),
  ('_lt', 'lt'), ('_lte', 'lte'),
  ('_in', 'in'), ('_nin', 'nin'),
  ('_like', 'like'), ('_ilike', 'ilike'),
  ('_is_null', 'is_null'),
  ('_and', 'and'), ('_or', 'or'), ('_not', 'not');

-- Convert Hasura filter to clean format
CREATE OR REPLACE FUNCTION authzura.convert_hasura_filter(hasura_filter JSONB)
RETURNS JSONB AS $$
DECLARE
  result JSONB;
  key TEXT;
  val JSONB;
  new_key TEXT;
BEGIN
  IF hasura_filter IS NULL OR jsonb_typeof(hasura_filter) != 'object' THEN
    RETURN hasura_filter;
  END IF;
  
  result := '{}'::JSONB;
  
  FOR key, val IN SELECT * FROM jsonb_each(hasura_filter) LOOP
    SELECT COALESCE(om.clean_op, key) INTO new_key
    FROM authzura.operator_mapping om WHERE om.hasura_op = key;
    
    IF new_key IS NULL THEN new_key := key; END IF;
    
    result := result || jsonb_build_object(
      new_key, 
      authzura.convert_hasura_filter(val)
    );
  END LOOP;
  
  RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Import from Hasura metadata
CREATE OR REPLACE FUNCTION authzura.import_from_hasura(
  hasura_metadata JSONB,
  target_tenant_id UUID DEFAULT NULL
)
RETURNS TABLE (imported_roles INTEGER, imported_permissions INTEGER) AS $$
DECLARE
  tbl JSONB;
  perm JSONB;
  role_name TEXT;
  table_name TEXT;
  role_id UUID;
  perm_type TEXT;
  roles_count INTEGER := 0;
  perms_count INTEGER := 0;
BEGIN
  FOR tbl IN SELECT * FROM jsonb_array_elements(hasura_metadata->'tables') LOOP
    table_name := tbl->'table'->>'name';
    
    FOREACH perm_type IN ARRAY ARRAY['select', 'insert', 'update', 'delete'] LOOP
      FOR perm IN SELECT * FROM jsonb_array_elements(
        COALESCE(tbl->(perm_type || '_permissions'), '[]'::JSONB)
      ) LOOP
        role_name := perm->>'role';
        
        INSERT INTO authzura.roles (name, tenant_id, is_system)
        VALUES (role_name, target_tenant_id, FALSE)
        ON CONFLICT (tenant_id, name) DO NOTHING
        RETURNING id INTO role_id;
        
        IF role_id IS NULL THEN
          SELECT id INTO role_id FROM authzura.roles 
          WHERE name = role_name AND tenant_id IS NOT DISTINCT FROM target_tenant_id;
        ELSE
          roles_count := roles_count + 1;
        END IF;
        
        INSERT INTO authzura.permissions (
          role_id, resource_name, operation, row_filter, allowed_columns,
          check_expression, column_presets
        ) VALUES (
          role_id, table_name, perm_type,
          authzura.convert_hasura_filter(perm->'permission'->'filter'),
          (SELECT array_agg(c::TEXT) FROM jsonb_array_elements_text(perm->'permission'->'columns') c),
          authzura.convert_hasura_filter(perm->'permission'->'check'),
          perm->'permission'->'set'
        )
        ON CONFLICT (role_id, resource_name, operation) DO UPDATE SET
          row_filter = EXCLUDED.row_filter,
          allowed_columns = EXCLUDED.allowed_columns,
          updated_at = NOW();
        
        perms_count := perms_count + 1;
      END LOOP;
    END LOOP;
  END LOOP;
  
  PERFORM authzura.refresh_all();
  RETURN QUERY SELECT roles_count, perms_count;
END;
$$ LANGUAGE plpgsql;
```

---

## Integration Examples

### With ExRest

ExRest integrates with Authzura via an authorization adapter:

```elixir
# config/config.exs
config :ex_rest,
  authorization: ExRest.Authorization.Authzura

config :authzura,
  repo: MyApp.Repo,
  cache: [enabled: true, default_ttl: :timer.minutes(5)],
  pubsub: MyApp.PubSub
```

```elixir
# lib/ex_rest/authorization/authzura.ex
defmodule ExRest.Authorization.Authzura do
  @behaviour ExRest.Authorization
  
  @impl true
  def build_context(conn) do
    {:ok, %{
      user_id: conn.assigns[:user_id],
      tenant_id: conn.assigns[:tenant_id]
    }}
  end
  
  @impl true
  def get_filter(resource, operation, context) do
    case Authzura.get_permission(context, resource, operation) do
      {:ok, %{has_permission: true, filter: filter}} ->
        {:ok, Authzura.build_filter_dynamic(filter, context)}
      
      {:ok, %{has_permission: false}} ->
        {:ok, dynamic([r], false)}  # Deny all
      
      {:error, reason} ->
        {:error, reason}
    end
  end
  
  @impl true
  def get_allowed_columns(resource, operation, context) do
    case Authzura.get_permission(context, resource, operation) do
      {:ok, %{has_permission: true, columns: nil}} -> {:ok, :all}
      {:ok, %{has_permission: true, columns: cols}} -> {:ok, Enum.map(cols, &String.to_existing_atom/1)}
      {:ok, %{has_permission: false}} -> {:ok, []}
      {:error, reason} -> {:error, reason}
    end
  end
  
  @impl true
  def check_permitted?(resource, operation, context) do
    Authzura.permitted?(context, resource, operation)
  end
end
```

The ExRest query pipeline automatically applies Authzura filters:

```
Base query → scope/2 → Authzura filter → URL filters → execute
```

### With Phoenix LiveView

Use Authzura directly in LiveView for real-time authorization:

```elixir
# lib/my_app_web/live/orders_live.ex
defmodule MyAppWeb.OrdersLive do
  use MyAppWeb, :live_view
  import Ecto.Query
  
  def mount(_params, session, socket) do
    # Build auth context from session
    context = %{
      user_id: session["user_id"],
      tenant_id: session["tenant_id"]
    }
    
    socket = assign(socket, :auth_context, context)
    
    # Check if user can view orders at all
    if Authzura.permitted?(context, "orders", :select) do
      {:ok, socket, temporary_assigns: [orders: []]}
    else
      {:ok, push_navigate(socket, to: "/unauthorized")}
    end
  end
  
  def handle_event("load_orders", _params, socket) do
    context = socket.assigns.auth_context
    
    # Get permission with filter
    {:ok, permission} = Authzura.get_permission(context, "orders", :select)
    
    # Build query with Authzura filter
    orders = 
      from(o in Order)
      |> apply_authzura_filter(permission, context)
      |> Repo.all()
    
    {:noreply, assign(socket, :orders, orders)}
  end
  
  def handle_event("delete_order", %{"id" => id}, socket) do
    context = socket.assigns.auth_context
    
    # Check delete permission
    if Authzura.permitted?(context, "orders", :delete) do
      {:ok, permission} = Authzura.get_permission(context, "orders", :delete)
      
      # Only delete if order matches user's permission filter
      {count, _} = 
        from(o in Order, where: o.id == ^id)
        |> apply_authzura_filter(permission, context)
        |> Repo.delete_all()
      
      if count > 0 do
        {:noreply, push_event(socket, "order_deleted", %{id: id})}
      else
        {:noreply, put_flash(socket, :error, "Cannot delete this order")}
      end
    else
      {:noreply, put_flash(socket, :error, "Permission denied")}
    end
  end
  
  defp apply_authzura_filter(query, %{filter: nil}, _context), do: query
  defp apply_authzura_filter(query, %{filter: filter}, context) do
    dynamic = Authzura.build_filter_dynamic(filter, context)
    where(query, ^dynamic)
  end
end
```

### With Phoenix Controllers

Traditional controller-based authorization:

```elixir
# lib/my_app_web/controllers/order_controller.ex
defmodule MyAppWeb.OrderController do
  use MyAppWeb, :controller
  import Ecto.Query
  
  plug :load_auth_context
  plug :authorize, "orders" when action in [:index, :show, :create, :update, :delete]
  
  def index(conn, _params) do
    context = conn.assigns.auth_context
    {:ok, permission} = Authzura.get_permission(context, "orders", :select)
    
    orders = 
      from(o in Order)
      |> apply_filter(permission, context)
      |> maybe_select_columns(permission)
      |> Repo.all()
    
    render(conn, :index, orders: orders)
  end
  
  def create(conn, %{"order" => order_params}) do
    context = conn.assigns.auth_context
    {:ok, permission} = Authzura.get_permission(context, "orders", :insert)
    
    # Apply column presets from permission
    params_with_presets = apply_presets(order_params, permission, context)
    
    # Filter to allowed columns only
    allowed_params = filter_columns(params_with_presets, permission)
    
    case Orders.create_order(allowed_params) do
      {:ok, order} -> 
        conn |> put_status(:created) |> render(:show, order: order)
      {:error, changeset} ->
        conn |> put_status(:unprocessable_entity) |> render(:error, changeset: changeset)
    end
  end
  
  # Plugs
  
  defp load_auth_context(conn, _opts) do
    context = %{
      user_id: conn.assigns.current_user.id,
      tenant_id: conn.assigns.current_user.tenant_id
    }
    assign(conn, :auth_context, context)
  end
  
  defp authorize(conn, resource) do
    operation = action_to_operation(conn.assigns.action)
    context = conn.assigns.auth_context
    
    if Authzura.permitted?(context, resource, operation) do
      conn
    else
      conn
      |> put_status(:forbidden)
      |> put_view(MyAppWeb.ErrorView)
      |> render("403.json")
      |> halt()
    end
  end
  
  defp action_to_operation(:index), do: :select
  defp action_to_operation(:show), do: :select
  defp action_to_operation(:create), do: :insert
  defp action_to_operation(:update), do: :update
  defp action_to_operation(:delete), do: :delete
  
  defp apply_filter(query, %{filter: nil}, _ctx), do: query
  defp apply_filter(query, %{filter: filter}, ctx) do
    where(query, ^Authzura.build_filter_dynamic(filter, ctx))
  end
  
  defp maybe_select_columns(query, %{columns: nil}), do: query
  defp maybe_select_columns(query, %{columns: columns}) do
    fields = Enum.map(columns, &String.to_existing_atom/1)
    select(query, [o], map(o, ^fields))
  end
  
  defp apply_presets(params, %{presets: nil}, _ctx), do: params
  defp apply_presets(params, %{presets: presets}, ctx) do
    resolved = Enum.map(presets, fn {k, v} ->
      {k, resolve_preset(v, ctx)}
    end) |> Map.new()
    
    Map.merge(params, resolved)
  end
  
  defp resolve_preset("X-Authzura-User-Id", ctx), do: ctx.user_id
  defp resolve_preset("X-Authzura-Tenant-Id", ctx), do: ctx.tenant_id
  defp resolve_preset(value, _ctx), do: value
  
  defp filter_columns(params, %{columns: nil}), do: params
  defp filter_columns(params, %{columns: columns}) do
    Map.take(params, columns)
  end
end
```

### With Absinthe GraphQL

Authorization in GraphQL resolvers:

```elixir
# lib/my_app_web/schema/order_types.ex
defmodule MyAppWeb.Schema.OrderTypes do
  use Absinthe.Schema.Notation
  import Ecto.Query
  
  object :order do
    field :id, :id
    field :reference, :string
    field :status, :string
    field :total, :decimal
    field :inserted_at, :datetime
  end
  
  object :order_queries do
    field :orders, list_of(:order) do
      resolve fn _args, %{context: %{auth: context}} ->
        case Authzura.get_permission(context, "orders", :select) do
          {:ok, %{has_permission: true} = permission} ->
            orders = 
              from(o in Order)
              |> apply_filter(permission, context)
              |> Repo.all()
            {:ok, orders}
          
          {:ok, %{has_permission: false}} ->
            {:error, "Access denied"}
        end
      end
    end
    
    field :order, :order do
      arg :id, non_null(:id)
      
      resolve fn %{id: id}, %{context: %{auth: context}} ->
        case Authzura.get_permission(context, "orders", :select) do
          {:ok, %{has_permission: true} = permission} ->
            order = 
              from(o in Order, where: o.id == ^id)
              |> apply_filter(permission, context)
              |> Repo.one()
            
            if order, do: {:ok, order}, else: {:error, "Not found"}
          
          {:ok, %{has_permission: false}} ->
            {:error, "Access denied"}
        end
      end
    end
  end
  
  defp apply_filter(query, %{filter: nil}, _ctx), do: query
  defp apply_filter(query, %{filter: filter}, ctx) do
    where(query, ^Authzura.build_filter_dynamic(filter, ctx))
  end
end
```

---

## Managing Roles and Permissions

### Creating Dynamic Roles

```elixir
# Create a tenant-specific role
{:ok, role} = Authzura.create_role("billing_admin",
  tenant_id: tenant_id,
  display_name: "Billing Administrator",
  description: "Can manage invoices and payments",
  inherits_from: ["user"],  # Inherits base user permissions
  permissions: [
    %{
      resource: "invoices",
      operation: "select",
      filter: %{"tenant_id" => %{"eq" => "X-Authzura-Tenant-Id"}}
    },
    %{
      resource: "invoices",
      operation: "update",
      filter: %{
        "and" => [
          %{"tenant_id" => %{"eq" => "X-Authzura-Tenant-Id"}},
          %{"status" => %{"in" => ["draft", "pending"]}}
        ]
      },
      columns: ["status", "due_date", "notes"]
    },
    %{
      resource: "payments",
      operation: "select",
      filter: %{"tenant_id" => %{"eq" => "X-Authzura-Tenant-Id"}}
    }
  ]
)
```

### Assigning Roles

```elixir
# Assign role to user with expiration
{:ok, assignment} = Authzura.assign_role(user_id, "billing_admin",
  tenant_id: tenant_id,
  granted_by_id: admin_user_id,
  expires_at: ~U[2025-12-31 23:59:59Z]
)

# Revoke role
:ok = Authzura.revoke_role(user_id, "billing_admin", tenant_id: tenant_id)

# Get user's roles
{:ok, roles} = Authzura.get_user_roles(user_id, tenant_id)
# => ["user", "billing_admin"]
```

### Importing from Hasura

```elixir
# Load Hasura metadata export
{:ok, metadata} = File.read!("hasura_metadata.json") |> Jason.decode()

# Import (automatically converts _eq to eq, etc.)
{:ok, %{imported_roles: roles, imported_permissions: perms}} = 
  Authzura.import_from_hasura(metadata, tenant_id: nil)

IO.puts("Imported #{roles} roles and #{perms} permissions")
```

---

## Admin UI (Optional)

Authzura provides an optional mountable Phoenix LiveView UI for managing roles and permissions visually, similar to Hasura's permission management interface.

### Features

- **Visual Permission Grid**: Roles vs operations (select/insert/update/delete) matrix
- **Ecto Schema Discovery**: Automatically discovers available schemas from your app
- **Row Filter Builder**: Visual JSON filter editor with autocomplete
- **Column Permissions**: Checkbox interface for allowed columns
- **Two Output Modes**:
  - **Direct Mode**: Immediately mutates the database
  - **Migration Mode**: Generates Ecto migration files for version control

### UI Mockups

#### Main Permission Grid

```
+-----------------------------------------------------------------------------------+
|  AUTHZURA                                                        MyApp Admin      |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Resources             |  orders                                                  |
|  -------------------   |  -----------------------------------------------------  |
|  [x] orders       <----|                                                          |
|  [ ] products          |  +-------------+--------+--------+--------+--------+     |
|  [ ] users             |  |    Role     | insert | select | update | delete |     |
|  [ ] invoices          |  +-------------+--------+--------+--------+--------+     |
|  [ ] categories        |  | admin       |   [/]  |   [/]  |   [/]  |   [/]  |     |
|                        |  +-------------+--------+--------+--------+--------+     |
|                        |  | user        |   [x]  |   [~]  |   [~]  |   [x]  |     |
|                        |  +-------------+--------+--------+--------+--------+     |
|                        |  | anonymous   |   [x]  |   [~]  |   [x]  |   [x]  |     |
|                        |  +-------------+--------+--------+--------+--------+     |
|                        |  | [new role]  |   [x]  |   [x]  |   [x]  |   [x]  |     |
|                        |  +-------------+--------+--------+--------+--------+     |
|                        |                                                          |
|                        |  Legend: [/] Full access  [~] Partial  [x] No access     |
|                        |                                                          |
+-----------------------------------------------------------------------------------+
```

#### Permission Editor Modal (click on [~] to open)

```
+-----------------------------------------------------------------------------------+
|  [Close]              Role: user    Resource: orders    Action: select            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +-- Row select permissions ----------------------------- with custom check ----+ |
|  |                                                                              | |
|  |  Allow role 'user' to select rows:                                           | |
|  |                                                                              | |
|  |  ( ) Without any checks                                                      | |
|  |  (*) With custom check:                                                      | |
|  |                                                                              | |
|  |  +------------------------------------------------------------------------+  | |
|  |  | {"user_id":{"eq":"X-Authzura-User-Id"}}                                |  | |
|  |  +------------------------------------------------------------------------+  | |
|  |                                                                              | |
|  |  +----------------------------------------------------------------------+    | |
|  |  |  {                                                                   |    | |
|  |  |    " user_id      [v] ":  {                                          |    | |
|  |  |      " eq         [v] ":  " X-Authzura-User-Id " [session-variable]  |    | |
|  |  |    }                                                                 |    | |
|  |  |  }                                                                   |    | |
|  |  +----------------------------------------------------------------------+    | |
|  |                                                                              | |
|  +------------------------------------------------------------------------------+ |
|                                                                                   |
|  Limit number of rows: [________] (optional)                                      |
|                                                                                   |
|  +-- Column select permissions --------------------------------- all columns ----+ |
|  |                                                                              | |
|  |  Allow role 'user' to access columns:                      [Toggle All]      | |
|  |                                                                              | |
|  |  [x] id             [x] reference        [x] status          [x] total       | |
|  |  [x] user_id        [ ] internal_notes   [x] created_at      [x] updated_at  | |
|  |                                                                              | |
|  +------------------------------------------------------------------------------+ |
|                                                                                   |
|  > Aggregation queries permissions                                - disabled      |
|  > Column presets                                                 - none          |
|                                                                                   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|   [ Save Permissions ]                                [ Delete Permissions ]      |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

#### Filter Builder (expanded view)

```
+-- Visual Filter Builder --------------------------------------------------------+
|                                                                                 |
|  +-- JSON View ---------------------------------------------------------------+ |
|  | {                                                                          | |
|  |   "and": [                                                                 | |
|  |     {"user_id": {"eq": "X-Authzura-User-Id"}},                             | |
|  |     {"status": {"in": ["active", "pending"]}}                              | |
|  |   ]                                                                        | |
|  | }                                                                          | |
|  +----------------------------------------------------------------------------+ |
|                                                                                 |
|  +-- Visual Builder ---------------------------------------------------------+  |
|  |                                                                           |  |
|  |  +-- AND --------------------------------------------------------- [+] -+ |  |
|  |  |                                                                      | |  |
|  |  |  +-----------+  +------+  +-------------------------------------+    | |  |
|  |  |  | user_id[v]|  | eq[v]|  | X-Authzura-User-Id  [session-var]   |    | |  |
|  |  |  +-----------+  +------+  +-------------------------------------+    | |  |
|  |  |                                                                      | |  |
|  |  |  +-----------+  +------+  +-------------------------------------+    | |  |
|  |  |  | status [v]|  | in[v]|  | ["active", "pending"]               |    | |  |
|  |  |  +-----------+  +------+  +-------------------------------------+    | |  |
|  |  |                                                                      | |  |
|  |  |  [+ Add condition]                                                   | |  |
|  |  |                                                                      | |  |
|  |  +----------------------------------------------------------------------+ |  |
|  |                                                                           |  |
|  |  Field dropdown:       Operator dropdown:      Session variables:         |  |
|  |  +----------------+    +--------------+        +----------------------+   |  |
|  |  | id             |    | eq           |        | X-Authzura-User-Id   |   |  |
|  |  | user_id        |    | neq          |        | X-Authzura-Tenant-Id |   |  |
|  |  | status         |    | gt / gte     |        +----------------------+   |  |
|  |  | total          |    | lt / lte     |                                   |  |
|  |  | reference      |    | in / nin     |                                   |  |
|  |  | created_at     |    | like / ilike |                                   |  |
|  |  +----------------+    | is_null      |                                   |  |
|  |                        +--------------+                                   |  |
|  +---------------------------------------------------------------------------+  |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

#### Column Presets (for insert/update operations)

```
+-- Column presets ---------------------------------------------------------------+
|                                                                                 |
|  Automatically set values on insert:                                            |
|                                                                                 |
|  +--------------+      +-------------------------------+                        |
|  | user_id  [v] |  <-  | X-Authzura-User-Id            |  [x]                   |
|  +--------------+      +-------------------------------+                        |
|                                                                                 |
|  +--------------+      +-------------------------------+                        |
|  | tenant_id[v] |  <-  | X-Authzura-Tenant-Id          |  [x]                   |
|  +--------------+      +-------------------------------+                        |
|                                                                                 |
|  [+ Add preset]                                                                 |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

#### Migration Mode Output

When using `output_mode: :migration`, clicking "Save Permissions" generates a file:

```
+---------------------------------------------------------------------------------+
|  [OK] Migration created successfully!                                           |
|                                                                                 |
|  File: priv/repo/migrations/20250120153045_authzura_permission_orders_select.exs|
|                                                                                 |
|  Run `mix ecto.migrate` to apply, or review the file first.                     |
|                                                                                 |
|  [View Migration]  [Copy Path]  [Close]                                         |
+---------------------------------------------------------------------------------+
```

### Installation

Add the UI dependency:

```elixir
# mix.exs
def deps do
  [
    {:authzura, "~> 0.1.0"},
    {:authzura_ui, "~> 0.1.0"}  # Optional admin UI
  ]
end
```

Mount in your router:

```elixir
# lib/my_app_web/router.ex
defmodule MyAppWeb.Router do
  use MyAppWeb, :router
  
  import AuthzuraUI.Router
  
  # ... your pipelines ...
  
  scope "/admin" do
    pipe_through [:browser, :require_admin]  # Add your auth
    
    authzura_ui "/permissions",
      repo: MyApp.Repo,
      schemas: [MyApp.Order, MyApp.User, MyApp.Product],  # Or use discovery
      output_mode: :direct  # or :migration
  end
end
```

### Configuration Options

```elixir
authzura_ui "/permissions",
  # Required
  repo: MyApp.Repo,
  
  # Schema discovery (choose one)
  schemas: [MyApp.Order, MyApp.User],           # Explicit list
  schema_discovery: MyApp,                       # Auto-discover from app
  schema_pattern: ~r/^MyApp\./,                  # Filter discovered schemas
  
  # Output mode
  output_mode: :direct,                          # :direct or :migration
  migrations_path: "priv/repo/migrations",       # For :migration mode
  
  # UI options
  tenant_id: nil,                                # Fixed tenant, or :session for dynamic
  readonly: false,                               # View-only mode
  
  # Callbacks
  on_change: {MyApp.AuditLog, :log_permission_change}
```

### Schema Discovery

Authzura UI can discover Ecto schemas automatically:

```elixir
defmodule AuthzuraUI.SchemaDiscovery do
  @moduledoc """
  Discovers Ecto schemas from application modules.
  """
  
  @doc """
  Find all Ecto schemas in the given application or module namespace.
  """
  def discover(app_or_module, opts \\ []) do
    pattern = Keyword.get(opts, :pattern, ~r/.*/)
    exclude = Keyword.get(opts, :exclude, [])
    
    app_or_module
    |> list_modules()
    |> Enum.filter(&ecto_schema?/1)
    |> Enum.filter(&(Regex.match?(pattern, to_string(&1))))
    |> Enum.reject(&(&1 in exclude))
  end
  
  defp list_modules(app) when is_atom(app) do
    {:ok, modules} = :application.get_key(app, :modules)
    modules
  end
  
  defp list_modules(namespace) when is_atom(namespace) do
    prefix = to_string(namespace) <> "."
    :code.all_loaded()
    |> Enum.map(&elem(&1, 0))
    |> Enum.filter(&String.starts_with?(to_string(&1), prefix))
  end
  
  defp ecto_schema?(module) do
    function_exported?(module, :__schema__, 1)
  end
  
  @doc """
  Extract schema metadata for UI display.
  """
  def schema_info(schema) do
    %{
      module: schema,
      source: schema.__schema__(:source),
      fields: schema.__schema__(:fields),
      field_types: Enum.map(schema.__schema__(:fields), fn f ->
        {f, schema.__schema__(:type, f)}
      end) |> Map.new(),
      associations: schema.__schema__(:associations),
      primary_key: schema.__schema__(:primary_key)
    }
  end
end
```

### UI Components

#### Permission Grid

The main view shows a grid of roles and resources:

```elixir
defmodule AuthzuraUI.PermissionGridLive do
  use Phoenix.LiveView
  
  @operations [:select, :insert, :update, :delete]
  
  def mount(_params, session, socket) do
    schemas = session["schemas"] || []
    roles = Authzura.list_roles(tenant_id: session["tenant_id"])
    permissions = Authzura.list_permissions(tenant_id: session["tenant_id"])
    
    socket = assign(socket,
      schemas: Enum.map(schemas, &AuthzuraUI.SchemaDiscovery.schema_info/1),
      roles: roles,
      permissions: index_permissions(permissions),
      selected_schema: nil,
      selected_schema_info: nil,
      editing_permission: nil,
      output_mode: session["output_mode"] || :direct,
      tenant_id: session["tenant_id"],
      operations: @operations
    )
    
    {:ok, socket}
  end
  
  def render(assigns) do
    ~H"""
    <div class="authzura-ui">
      <div class="schema-selector">
        <h2>Resources</h2>
        <ul>
          <%= for schema <- @schemas do %>
            <li phx-click="select_schema" phx-value-source={schema.source}
                class={if @selected_schema == schema.source, do: "selected"}>
              <span class="icon">📋</span>
              <%= schema.source %>
            </li>
          <% end %>
        </ul>
      </div>
      
      <%= if @selected_schema do %>
        <div class="permission-grid">
          <h2><%= @selected_schema %></h2>
          
          <table>
            <thead>
              <tr>
                <th>Role</th>
                <%= for op <- @operations do %>
                  <th><%= op %></th>
                <% end %>
              </tr>
            </thead>
            <tbody>
              <%= for role <- @roles do %>
                <tr>
                  <td><%= role.name %></td>
                  <%= for op <- @operations do %>
                    <td>
                      <.permission_cell
                        permission={get_permission(@permissions, @selected_schema, role.id, op)}
                        resource={@selected_schema}
                        role={role}
                        operation={op}
                      />
                    </td>
                  <% end %>
                </tr>
              <% end %>
              <tr class="new-role">
                <td>
                  <form phx-submit="create_role">
                    <input name="name" placeholder="Enter new role" />
                  </form>
                </td>
                <td colspan="4"></td>
              </tr>
            </tbody>
          </table>
        </div>
      <% end %>
      
      <%= if @editing_permission do %>
        <.live_component
          module={AuthzuraUI.PermissionEditorComponent}
          id="permission-editor"
          permission={@editing_permission}
          schema={@selected_schema_info}
          output_mode={@output_mode}
        />
      <% end %>
    </div>
    """
  end
  
  # Permission cell shows status icon and opens editor on click
  defp permission_cell(assigns) do
    ~H"""
    <div class={"permission-cell #{status_class(@permission)}"}
         phx-click="edit_permission"
         phx-value-role={@role.id}
         phx-value-resource={@resource}
         phx-value-operation={@operation}>
      <%= status_icon(@permission) %>
    </div>
    """
  end
  
  defp status_icon(nil), do: "❌"  # No access
  defp status_icon(%{row_filter: nil, allowed_columns: nil}), do: "✅"  # Full access
  defp status_icon(_), do: "🔸"  # Partial access
  
  defp status_class(nil), do: "no-access"
  defp status_class(%{row_filter: nil, allowed_columns: nil}), do: "full-access"
  defp status_class(_), do: "partial-access"
end
```

#### Permission Editor

When clicking a permission cell, the detail editor opens:

```elixir
defmodule AuthzuraUI.PermissionEditorComponent do
  use Phoenix.LiveComponent
  
  def render(assigns) do
    ~H"""
    <div class="permission-editor modal">
      <div class="modal-header">
        <button phx-click="close" phx-target={@myself}>Close</button>
        <h3>Role: <%= @permission.role_name %> | Action: <%= @permission.operation %></h3>
      </div>
      
      <div class="modal-body">
        <!-- Row Permissions -->
        <section class="row-permissions">
          <h4>Row <%= @permission.operation %> permissions</h4>
          
          <label>
            <input type="radio" name="row_check" value="none"
                   checked={@permission.row_filter == nil}
                   phx-click="set_row_check" phx-value-type="none" phx-target={@myself} />
            Without any checks
          </label>
          
          <label>
            <input type="radio" name="row_check" value="custom"
                   checked={@permission.row_filter != nil}
                   phx-click="set_row_check" phx-value-type="custom" phx-target={@myself} />
            With custom check
          </label>
          
          <%= if @permission.row_filter != nil or @show_filter_editor do %>
            <div class="filter-editor">
              <.live_component
                module={AuthzuraUI.FilterBuilderComponent}
                id="filter-builder"
                filter={@permission.row_filter || %{}}
                schema={@schema}
                on_change={fn filter -> send(self(), {:filter_changed, filter}) end}
              />
            </div>
          <% end %>
        </section>
        
        <!-- Max Rows -->
        <section class="max-rows">
          <h4>Limit number of rows</h4>
          <input type="number" name="max_rows" value={@permission.max_rows}
                 phx-change="set_max_rows" phx-target={@myself}
                 placeholder="No limit" />
        </section>
        
        <!-- Column Permissions -->
        <section class="column-permissions">
          <h4>Column <%= @permission.operation %> permissions</h4>
          <p class="subtitle">
            <%= column_status_text(@permission.allowed_columns, @schema.fields) %>
          </p>
          
          <div class="columns-header">
            <span>Allow role <%= @permission.role_name %> to access columns:</span>
            <button phx-click="toggle_all_columns" phx-target={@myself}>Toggle All</button>
          </div>
          
          <div class="column-checkboxes">
            <%= for field <- @schema.fields do %>
              <label class="column-checkbox">
                <input type="checkbox"
                       name={"columns[#{field}]"}
                       checked={column_allowed?(@permission.allowed_columns, field)}
                       phx-click="toggle_column"
                       phx-value-column={field}
                       phx-target={@myself} />
                <%= field %>
              </label>
            <% end %>
          </div>
        </section>
        
        <!-- Aggregation Permissions (for select) -->
        <%= if @permission.operation == :select do %>
          <section class="aggregation-permissions">
            <h4>Aggregation queries permissions</h4>
            <label>
              <input type="checkbox" name="allow_aggregations"
                     checked={@permission.allow_aggregations}
                     phx-click="toggle_aggregations" phx-target={@myself} />
              Allow role '<%= @permission.role_name %>' to make aggregation queries
            </label>
          </section>
        <% end %>
        
        <!-- Column Presets (for insert/update) -->
        <%= if @permission.operation in [:insert, :update] do %>
          <section class="column-presets">
            <h4>Column presets</h4>
            <p>Set values automatically on <%= @permission.operation %>:</p>
            
            <%= for {column, preset} <- @permission.column_presets || %{} do %>
              <div class="preset-row">
                <select name={"preset_column[#{column}]"}>
                  <%= for field <- @schema.fields do %>
                    <option value={field} selected={field == column}><%= field %></option>
                  <% end %>
                </select>
                <input type="text" value={preset}
                       phx-blur="update_preset"
                       phx-value-column={column}
                       phx-target={@myself}
                       placeholder="X-Authzura-User-Id" />
                <button phx-click="remove_preset" phx-value-column={column} phx-target={@myself}>×</button>
              </div>
            <% end %>
            
            <button phx-click="add_preset" phx-target={@myself}>+ Add preset</button>
          </section>
        <% end %>
      </div>
      
      <div class="modal-footer">
        <button class="btn-primary" phx-click="save" phx-target={@myself}>
          <%= if @output_mode == :migration, do: "Generate Migration", else: "Save Permissions" %>
        </button>
        <button class="btn-danger" phx-click="delete" phx-target={@myself}>
          Delete Permissions
        </button>
      </div>
    </div>
    """
  end
  
  defp column_status_text(nil, _fields), do: "- all columns"
  defp column_status_text(columns, fields) when length(columns) == length(fields), do: "- all columns"
  defp column_status_text(columns, _fields), do: "- #{length(columns)} columns"
  
  defp column_allowed?(nil, _field), do: true
  defp column_allowed?(columns, field), do: to_string(field) in columns
end
```

#### Filter Builder

Visual JSON filter builder with autocomplete:

```elixir
defmodule AuthzuraUI.FilterBuilderComponent do
  use Phoenix.LiveComponent
  
  def render(assigns) do
    ~H"""
    <div class="filter-builder">
      <!-- JSON text view -->
      <div class="json-view">
        <textarea
          phx-blur="parse_json"
          phx-target={@myself}
        ><%= Jason.encode!(@filter, pretty: true) %></textarea>
      </div>
      
      <!-- Visual builder -->
      <div class="visual-builder">
        <.filter_node node={@filter} path={[]} schema={@schema} myself={@myself} />
      </div>
    </div>
    """
  end
  
  defp filter_node(assigns) do
    ~H"""
    <div class="filter-node">
      <%= cond do %>
        <% is_logical?(@node) -> %>
          <.logical_node node={@node} path={@path} schema={@schema} myself={@myself} />
        <% is_field_condition?(@node) -> %>
          <.field_condition node={@node} path={@path} schema={@schema} myself={@myself} />
        <% true -> %>
          <.empty_node path={@path} schema={@schema} myself={@myself} />
      <% end %>
    </div>
    """
  end
  
  defp field_condition(assigns) do
    [{field, op_value}] = Map.to_list(assigns.node)
    [{op, value}] = Map.to_list(op_value)
    operators = ~w(eq neq gt gte lt lte like ilike in nin is_null)
    
    assigns = assign(assigns, field: field, op: op, value: value, operators: operators)
    
    ~H"""
    <div class="field-condition">
      <select phx-change="update_field" phx-value-path={encode_path(@path)} phx-target={@myself}>
        <%= for f <- @schema.fields do %>
          <option value={f} selected={to_string(f) == @field}><%= f %></option>
        <% end %>
      </select>
      
      <select phx-change="update_operator" phx-value-path={encode_path(@path)} phx-target={@myself}>
        <%= for o <- @operators do %>
          <option value={o} selected={o == @op}><%= o %></option>
        <% end %>
      </select>
      
      <.value_input value={@value} op={@op} path={@path} myself={@myself} />
    </div>
    """
  end
  
  defp value_input(%{op: op} = assigns) when op in ["in", "nin"] do
    ~H"""
    <input type="text" value={Jason.encode!(@value)}
           phx-blur="update_value" phx-value-path={encode_path(@path)} phx-target={@myself}
           placeholder='["value1", "value2"]' />
    """
  end
  
  defp value_input(%{op: "is_null"} = assigns) do
    ~H"""
    <select phx-change="update_value" phx-value-path={encode_path(@path)} phx-target={@myself}>
      <option value="true" selected={@value == true}>true</option>
      <option value="false" selected={@value == false}>false</option>
    </select>
    """
  end
  
  defp value_input(assigns) do
    session_vars = ~w(X-Authzura-User-Id X-Authzura-Tenant-Id)
    assigns = assign(assigns, session_vars: session_vars)
    
    ~H"""
    <div class="value-with-suggestions">
      <input type="text" value={@value}
             phx-blur="update_value" phx-value-path={encode_path(@path)} phx-target={@myself}
             list="session-vars" />
      <datalist id="session-vars">
        <%= for var <- @session_vars do %>
          <option value={var}><%= var %></option>
        <% end %>
      </datalist>
      <%= if @value in @session_vars do %>
        <span class="session-var-badge">[<%= @value %>]</span>
      <% end %>
    </div>
    """
  end
  
  defp is_logical?(node) when is_map(node) do
    Map.keys(node) |> Enum.any?(&(&1 in ["and", "or", "not"]))
  end
  defp is_logical?(_), do: false
  
  defp is_field_condition?(node) when is_map(node) do
    case Map.to_list(node) do
      [{_field, inner}] when is_map(inner) ->
        Map.keys(inner) |> Enum.any?(&(&1 in @operators))
      _ -> false
    end
  end
  defp is_field_condition?(_), do: false
  
  defp encode_path(path), do: Jason.encode!(path)
end
```

### Output Modes

#### Direct Mode

Immediately saves to database:

```elixir
defmodule AuthzuraUI.OutputAdapter.Direct do
  @behaviour AuthzuraUI.OutputAdapter
  
  @impl true
  def save_permission(permission, _opts) do
    case Authzura.Permissions.upsert(permission) do
      {:ok, _} -> 
        Authzura.invalidate_cache()
        {:ok, :saved}
      {:error, changeset} ->
        {:error, format_errors(changeset)}
    end
  end
  
  @impl true
  def delete_permission(permission_id, _opts) do
    case Authzura.Permissions.delete(permission_id) do
      {:ok, _} ->
        Authzura.invalidate_cache()
        {:ok, :deleted}
      {:error, reason} ->
        {:error, reason}
    end
  end
  
  @impl true
  def create_role(attrs, _opts) do
    Authzura.create_role(attrs.name, Map.to_list(attrs))
  end
end
```

#### Migration Mode

Generates Ecto migrations for version control:

```elixir
defmodule AuthzuraUI.OutputAdapter.Migration do
  @behaviour AuthzuraUI.OutputAdapter
  
  @impl true
  def save_permission(permission, opts) do
    migrations_path = opts[:migrations_path] || "priv/repo/migrations"
    timestamp = generate_timestamp()
    filename = "#{timestamp}_authzura_permission_#{permission.resource}_#{permission.operation}.exs"
    
    content = generate_migration(permission)
    path = Path.join(migrations_path, filename)
    
    File.write!(path, content)
    {:ok, {:migration_created, path}}
  end
  
  defp generate_migration(permission) do
    """
    defmodule MyApp.Repo.Migrations.AuthzuraPermission#{camelize(permission.resource)}#{camelize(permission.operation)} do
      use Ecto.Migration
      
      def up do
        execute \"\"\"
        INSERT INTO authzura.permissions (role_id, resource_name, operation, row_filter, allowed_columns, column_presets, max_rows, allow_aggregations)
        SELECT r.id, '#{permission.resource}', '#{permission.operation}', 
               #{format_json(permission.row_filter)}::jsonb,
               #{format_array(permission.allowed_columns)},
               #{format_json(permission.column_presets)}::jsonb,
               #{permission.max_rows || "NULL"},
               #{permission.allow_aggregations || false}
        FROM authzura.roles r
        WHERE r.name = '#{permission.role_name}'
          AND r.tenant_id #{if permission.tenant_id, do: "= '#{permission.tenant_id}'", else: "IS NULL"}
        ON CONFLICT (role_id, resource_name, operation) 
        DO UPDATE SET
          row_filter = EXCLUDED.row_filter,
          allowed_columns = EXCLUDED.allowed_columns,
          column_presets = EXCLUDED.column_presets,
          max_rows = EXCLUDED.max_rows,
          allow_aggregations = EXCLUDED.allow_aggregations,
          updated_at = NOW()
        \"\"\"
        
        # Refresh materialized views
        execute "SELECT authzura.refresh_all()"
      end
      
      def down do
        execute \"\"\"
        DELETE FROM authzura.permissions p
        USING authzura.roles r
        WHERE p.role_id = r.id
          AND r.name = '#{permission.role_name}'
          AND p.resource_name = '#{permission.resource}'
          AND p.operation = '#{permission.operation}'
          AND r.tenant_id #{if permission.tenant_id, do: "= '#{permission.tenant_id}'", else: "IS NULL"}
        \"\"\"
        
        execute "SELECT authzura.refresh_all()"
      end
    end
    """
  end
  
  defp format_json(nil), do: "NULL"
  defp format_json(map), do: "'#{Jason.encode!(map)}'"
  
  defp format_array(nil), do: "NULL"
  defp format_array(list), do: "ARRAY[#{Enum.map(list, &"'#{&1}'") |> Enum.join(", ")}]"
  
  defp generate_timestamp do
    {{y, m, d}, {h, min, s}} = :calendar.universal_time()
    "#{y}#{pad(m)}#{pad(d)}#{pad(h)}#{pad(min)}#{pad(s)}"
  end
  
  defp pad(i), do: String.pad_leading(to_string(i), 2, "0")
  defp camelize(s), do: s |> to_string() |> Macro.camelize()
end
```

### Mix Tasks

Generate migrations from command line:

```bash
# Export current permissions as migrations
mix authzura.export_migrations

# Export specific role
mix authzura.export_migrations --role admin

# Export for specific tenant
mix authzura.export_migrations --tenant-id abc123
```

```elixir
defmodule Mix.Tasks.Authzura.ExportMigrations do
  use Mix.Task
  
  @shortdoc "Export Authzura permissions as Ecto migrations"
  
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, 
      switches: [role: :string, tenant_id: :string, path: :string]
    )
    
    Mix.Task.run("app.start")
    
    permissions = Authzura.list_permissions(
      role_name: opts[:role],
      tenant_id: opts[:tenant_id]
    )
    
    path = opts[:path] || "priv/repo/migrations"
    
    Enum.each(permissions, fn permission ->
      {:ok, {:migration_created, file}} = 
        AuthzuraUI.OutputAdapter.Migration.save_permission(permission, migrations_path: path)
      Mix.shell().info("Created: #{file}")
    end)
  end
end
```

### Styling

The UI ships with minimal CSS that can be customized:

```elixir
# In your app's CSS or use the provided stylesheet
# mix authzura_ui.install_css

# Or import in your app.css:
@import "authzura_ui/permissions.css";
```

Default theme matches Hasura's visual style with:
- Clean permission grid with status icons (✅ ❌ 🔸)
- Modal editor for permission details
- Collapsible sections for row/column permissions
- Visual filter builder with autocomplete

### Security Considerations

**Always protect the admin UI route:**

```elixir
# Example: Require admin role
pipeline :require_admin do
  plug :ensure_authenticated
  plug :ensure_role, "admin"
end

scope "/admin" do
  pipe_through [:browser, :require_admin]
  authzura_ui "/permissions", ...
end
```

**For multi-tenant apps:**

```elixir
# Scope to current tenant
authzura_ui "/permissions",
  tenant_id: :session,  # Gets tenant_id from session
  tenant_id_key: :current_tenant_id
```

---

## Configuration Reference

```elixir
# config/config.exs
config :authzura,
  # Required
  repo: MyApp.Repo,
  
  # Schema
  schema: "authzura",                      # PostgreSQL schema name (default: "authzura")
  
  # Caching (optional) - uses Nebulex
  cache: [
    enabled: true,                         # Enable permission caching (default: false)
    default_ttl: :timer.minutes(5)         # Default cache TTL
  ],
  
  # Distributed (optional)
  pubsub: MyApp.PubSub,                    # PubSub for cache invalidation
  
  # Behavior
  refresh_on_change: true,                 # Auto-refresh materialized views (default: true)
  default_deny: true                       # No permission = denied (default: true)

# Nebulex cache configuration (when caching enabled)
config :authzura, Authzura.Cache,
  gc_interval: :timer.hours(1),
  max_size: 100_000
```

---

## Telemetry Events

Authzura emits telemetry events for monitoring:

```elixir
# Permission check
[:authzura, :permission, :check]
# Metadata: %{resource: "orders", operation: :select, user_id: ..., result: :granted | :denied}

# Cache hit/miss
[:authzura, :cache, :hit]
[:authzura, :cache, :miss]
# Metadata: %{key: ...}

# Cache invalidation
[:authzura, :cache, :invalidate]
# Metadata: %{pattern: :all | {:user, id} | {:resource, name}}

# Materialized view refresh
[:authzura, :refresh, :start]
[:authzura, :refresh, :stop]
# Metadata: %{duration: microseconds}
```

Example handler:

```elixir
:telemetry.attach_many(
  "authzura-logger",
  [
    [:authzura, :permission, :check],
    [:authzura, :cache, :hit],
    [:authzura, :cache, :miss]
  ],
  fn event, measurements, metadata, _config ->
    Logger.info("#{inspect(event)}: #{inspect(metadata)}")
  end,
  nil
)
```

---

## Testing

```elixir
# test/support/authzura_helpers.ex
defmodule MyApp.AuthzuraHelpers do
  @moduledoc "Test helpers for Authzura"
  
  def setup_test_permissions do
    # Create test roles
    {:ok, _} = Authzura.create_role("test_admin",
      permissions: [
        %{resource: "orders", operation: "select", filter: nil},
        %{resource: "orders", operation: "insert", filter: nil},
        %{resource: "orders", operation: "update", filter: nil},
        %{resource: "orders", operation: "delete", filter: nil}
      ]
    )
    
    {:ok, _} = Authzura.create_role("test_user",
      permissions: [
        %{
          resource: "orders", 
          operation: "select", 
          filter: %{"user_id" => %{"eq" => "X-Authzura-User-Id"}}
        }
      ]
    )
  end
  
  def with_role(user_id, role_name, fun) do
    {:ok, _} = Authzura.assign_role(user_id, role_name)
    
    try do
      fun.()
    after
      Authzura.revoke_role(user_id, role_name)
    end
  end
end

# test/my_app/orders_test.exs
defmodule MyApp.OrdersTest do
  use MyApp.DataCase
  import MyApp.AuthzuraHelpers
  
  setup do
    setup_test_permissions()
    :ok
  end
  
  test "admin can see all orders" do
    admin = insert(:user)
    other_user = insert(:user)
    
    order1 = insert(:order, user_id: admin.id)
    order2 = insert(:order, user_id: other_user.id)
    
    with_role(admin.id, "test_admin", fn ->
      context = %{user_id: admin.id, tenant_id: nil}
      {:ok, permission} = Authzura.get_permission(context, "orders", :select)
      
      assert permission.has_permission
      assert permission.filter == nil  # No filter = see all
    end)
  end
  
  test "user can only see own orders" do
    user = insert(:user)
    other_user = insert(:user)
    
    my_order = insert(:order, user_id: user.id)
    other_order = insert(:order, user_id: other_user.id)
    
    with_role(user.id, "test_user", fn ->
      context = %{user_id: user.id, tenant_id: nil}
      {:ok, permission} = Authzura.get_permission(context, "orders", :select)
      
      assert permission.has_permission
      assert permission.filter == %{"user_id" => %{"eq" => "X-Authzura-User-Id"}}
      
      # Apply filter
      filter = Authzura.build_filter_dynamic(permission.filter, context)
      orders = from(o in Order) |> where(^filter) |> Repo.all()
      
      assert length(orders) == 1
      assert hd(orders).id == my_order.id
    end)
  end
end
```

---

## Performance Considerations

1. **Materialized Views**: Permission lookups use materialized views, not recursive CTEs at runtime
2. **Nebulex Cache**: With caching enabled, permission checks are microsecond-level (local) or low-ms (Redis)
3. **Indexes**: All lookup paths are indexed (user_id, tenant_id, resource_name, operation)
4. **Concurrent Refresh**: Materialized views refresh concurrently (no locks)
5. **Batch Role Assignment**: Use direct SQL for bulk operations

**Benchmarks** (with caching enabled):
- Permission check (local cache): ~5-15 microseconds
- Permission check (Redis): ~1-5 milliseconds
- Cache miss (DB lookup): ~200-500 microseconds
- Role assignment: ~1-2 milliseconds

---

## License

MIT License - see LICENSE file for details.

if Code.ensure_loaded?(JOSE) do
  defmodule Authzura.JWT do
    @moduledoc """
    Hasura-compatible JWT verification producing an `Authzura.Session`.

    Available only when the optional `:jose` dependency is installed.

    `verify/2` fails closed: any problem yields an error tuple, and a present
    but invalid token never falls back to the unauthorized role (only `nil`
    and `""` count as "no token"). The header `alg` must be on the allowlist
    (`"none"` is always rejected) before the signature is checked.

    Configuration is validated up front. Every allowlisted algorithm must
    belong to the family of the key (`oct` for `HS*`, `RSA` for `RS*`/`PS*`,
    `EC` for `ES*`), which rules out algorithm-confusion attacks such as using
    a public key as an HMAC secret. HMAC secrets must be at least 32 bytes.

    Options:

      * `:key` (required) - a `JOSE.JWK`, a JWK map, a PEM string or a
        binary shared secret. A binary holding `-----BEGIN` anywhere is a
        PEM, read from that marker on (any preamble, such as a BOM,
        zero-width characters, quotes or `openssl pkcs12`'s
        `Bag Attributes`, is dropped); one that is not a valid key is
        `:invalid_key`, never a shared secret. So is a binary holding a
        disguised `BEGIN` or `END` armour line: three or more dashes
        (typographic dashes included) and the word in any case, with
        zero-width characters, BOMs or spaces anywhere in it
      * `:algorithms` - allowlist, default `["HS256"]`
      * `:allowed_skew` - seconds of clock skew for `exp`, `nbf`, `iat`, default 0
      * `:issuer` / `:audience` - a string or list; checked only when given
      * `:claims_namespace` - default `"https://hasura.io/jwt/claims"`
      * `:claims_map` - `%{claim => literal | %{path: "$.a.b", default: value}}`
      * `:claims_format` - only `:json` is supported
      * `:requested_role` - passed to `Authzura.Session.new/2`
      * `:unauthorized_role` - the role of the session a `nil` or empty token
        gets (see `verify/2`)
      * `:now` - unix seconds, a test hook

    `claims_namespace_path` and any `claims_format` other than `:json` return
    `{:error, {:unsupported_option, key}}`. Invalid `:key` or `:algorithms`
    return `{:error, {:invalid_jwt_config, reason}}`.

    `prepare/1` validates the options and builds the key once; `verify/2`
    takes its result in place of the options, so a caller that verifies
    many tokens against one configuration pays for the key only once.

    Hasura semantics apply to claim values: allowed roles must be a list of
    strings and every other `x-hasura-*` value must be a string, otherwise
    `{:error, {:jwt_invalid_claims, :invalid_claim_value}}`.
    """

    alias Authzura.Session
    alias JOSE.JWK
    alias JOSE.JWT, as: JoseJWT

    @default_namespace "https://hasura.io/jwt/claims"
    @allowed_roles "x-hasura-allowed-roles"
    @default_role "x-hasura-default-role"
    @prefix "x-hasura-"
    @path_segment ~r/\.([^.\[\]]+)|\.?\['([^']+)'\]|\.?\["([^"]+)"\]/
    @min_secret_bytes 32
    @pem_marker "-----BEGIN"
    # A PEM or X.509 armour line however it was mangled: zero-width
    # characters and BOMs are dropped, typographic dashes read as `-` and
    # no-break spaces as spaces before matching, case-insensitively, on
    # bytes (a secret need not be UTF-8).
    @invisible ["\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF", "\u00AD"]
    @dashes [
      "\u2010",
      "\u2011",
      "\u2012",
      "\u2013",
      "\u2014",
      "\u2015",
      "\u2212",
      "\uFE58",
      "\uFE63",
      "\uFF0D"
    ]
    @armour ~r/-{3,}\s*(BEGIN|END)\b/i
    @jose_errors [
      FunctionClauseError,
      ArithmeticError,
      ArgumentError,
      MatchError,
      CaseClauseError
    ]
    @families %{
      "HS256" => "oct",
      "HS384" => "oct",
      "HS512" => "oct",
      "RS256" => "RSA",
      "RS384" => "RSA",
      "RS512" => "RSA",
      "PS256" => "RSA",
      "PS384" => "RSA",
      "PS512" => "RSA",
      "ES256" => "EC",
      "ES384" => "EC",
      "ES512" => "EC"
    }

    # The key and the options never appear in an inspected term (a log, say).
    @derive {Inspect, only: [:algorithms]}
    @enforce_keys [:jwk, :algorithms, :opts]
    defstruct @enforce_keys

    @typedoc "A validated configuration from `prepare/1`."
    @opaque t :: %__MODULE__{jwk: JWK.t(), algorithms: [String.t()], opts: keyword()}

    @type config_reason ::
            :missing_key
            | :invalid_key
            | :weak_secret
            | :invalid_algorithms
            | :key_algorithm_mismatch
            | {:unknown_algorithm, String.t()}

    @type reason ::
            {:invalid_jwt,
             :algorithm
             | :signature
             | :expired
             | :not_yet_valid
             | :issued_in_future
             | :invalid_time_claim
             | :issuer
             | :audience}
            | {:invalid_jwt_config, config_reason()}
            | {:jwt_missing_role_claims, String.t()}
            | {:jwt_invalid_claims,
               :allowed_roles_not_list | :invalid_claim_value | {:claims_map, String.t()}}
            | {:invalid_headers, :missing_token}
            | {:unsupported_option, atom()}
            | Session.error()

    @doc """
    Verifies `token` and builds a session from its Hasura claims.

    A `nil` or empty token yields the `:unauthorized_role` session when that
    option is set, otherwise `{:error, {:invalid_headers, :missing_token}}`.
    Any other non-binary token is rejected.
    """
    @spec verify(String.t() | nil, keyword() | t()) :: {:ok, Session.t()} | {:error, reason()}
    def verify(token, opts) when is_list(opts) do
      with {:ok, prepared} <- prepare(opts), do: verify(token, prepared)
    end

    def verify(token, %__MODULE__{jwk: jwk, algorithms: algorithms, opts: opts}),
      do: authenticate(token, jwk, algorithms, opts)

    @doc """
    Validates `opts` (the options of `verify/2`) and builds the key once.
    Configuration errors are returned here, as `verify/2` would return them.
    """
    @spec prepare(keyword()) :: {:ok, t()} | {:error, reason()}
    def prepare(opts) when is_list(opts) do
      with :ok <- check_options(opts),
           {:ok, jwk, algorithms} <- keying(opts) do
        {:ok, %__MODULE__{jwk: jwk, algorithms: algorithms, opts: opts}}
      end
    end

    defp check_options(opts) do
      cond do
        Keyword.has_key?(opts, :claims_namespace_path) ->
          {:error, {:unsupported_option, :claims_namespace_path}}

        Keyword.get(opts, :claims_format, :json) != :json ->
          {:error, {:unsupported_option, :claims_format}}

        true ->
          :ok
      end
    end

    defp keying(opts) do
      with {:ok, algorithms} <- algorithms(Keyword.get(opts, :algorithms, ["HS256"])),
           {:ok, jwk, kty} <- build_jwk(opts[:key]),
           :ok <- check_family(kty, algorithms) do
        check_secret(jwk, kty, algorithms)
      end
    end

    defp algorithms(list) when is_list(list) do
      case list |> Enum.reject(&none?/1) |> Enum.uniq() do
        [] -> config_error(:invalid_algorithms)
        algorithms -> validate_algorithms(algorithms)
      end
    end

    defp algorithms(_other), do: config_error(:invalid_algorithms)

    defp none?(alg) when is_binary(alg), do: String.downcase(alg) == "none"
    defp none?(_alg), do: false

    defp validate_algorithms(algorithms) do
      case Enum.find(algorithms, &(not (is_binary(&1) and is_map_key(@families, &1)))) do
        nil -> {:ok, algorithms}
        alg when is_binary(alg) -> config_error({:unknown_algorithm, alg})
        _other -> config_error(:invalid_algorithms)
      end
    end

    defp build_jwk(nil), do: config_error(:missing_key)

    defp build_jwk(secret) when is_binary(secret),
      do: secret |> :binary.match(@pem_marker) |> from_secret(secret)

    defp build_jwk(%JWK{} = jwk), do: checked_jwk(jwk)
    defp build_jwk(%{} = map), do: checked_jwk(jose(fn -> JWK.from_map(map) end))
    defp build_jwk(_other), do: config_error(:invalid_key)

    # A PEM marker anywhere makes the key a PEM, read from the marker on: a
    # shared secret never holds one, so a public key can never become an
    # HMAC secret. Without the exact marker, a disguised one (`armoured?/1`)
    # is an invalid key; any other binary is a shared secret, kept as given.
    defp from_secret({start, _length}, secret) do
      secret
      |> binary_part(start, byte_size(secret) - start)
      |> pem_key()
      |> checked_jwk()
    end

    defp from_secret(:nomatch, secret), do: secret |> armoured?() |> shared_secret(secret)

    defp shared_secret(true, _secret), do: config_error(:invalid_key)
    defp shared_secret(false, secret), do: {:ok, JWK.from_oct(secret), "oct"}

    defp armoured?(secret) do
      normalised =
        secret
        |> :binary.replace(@invisible, "", [:global])
        |> :binary.replace(@dashes, "-", [:global])
        |> :binary.replace("\u00A0", " ", [:global])

      Regex.match?(@armour, normalised)
    end

    defp pem_key(pem), do: jose(fn -> JWK.from_pem(pem) end)

    defp checked_jwk(%JWK{} = jwk) do
      case key_type(jwk) do
        nil -> config_error(:invalid_key)
        kty -> {:ok, jwk, kty}
      end
    end

    defp checked_jwk(_other), do: config_error(:invalid_key)

    # JOSE parses keys lazily, so a malformed key only raises once it is
    # serialized. Serializing here proves the key is complete and usable.
    defp key_type(jwk) do
      case jose(fn -> JWK.to_map(jwk) end) do
        {_, %{"kty" => kty}} -> kty
        _ -> nil
      end
    end

    defp jose(fun) do
      fun.()
    rescue
      _error in @jose_errors -> nil
    end

    defp check_family(kty, algorithms) do
      algorithms
      |> Enum.all?(&(Map.fetch!(@families, &1) == kty))
      |> family_result()
    end

    defp family_result(true), do: :ok
    defp family_result(false), do: config_error(:key_algorithm_mismatch)

    defp check_secret(jwk, "oct", algorithms) do
      {_fields, secret} = JWK.to_oct(jwk)
      secret_result(secret, jwk, algorithms)
    end

    defp check_secret(jwk, _kty, algorithms), do: {:ok, jwk, algorithms}

    defp secret_result(secret, jwk, algorithms) when byte_size(secret) >= @min_secret_bytes,
      do: {:ok, jwk, algorithms}

    defp secret_result(_secret, _jwk, _algorithms), do: config_error(:weak_secret)

    defp config_error(reason), do: {:error, {:invalid_jwt_config, reason}}

    defp authenticate(token, _jwk, _algorithms, opts) when token in [nil, ""],
      do: anonymous(opts[:unauthorized_role])

    defp authenticate(token, jwk, algorithms, opts) when is_binary(token) do
      with {:ok, claims} <- verify_signature(token, jwk, algorithms),
           :ok <- check_times(claims, opts),
           :ok <- check_issuer(claims["iss"], opts[:issuer]),
           :ok <- check_audience(claims["aud"], opts[:audience]),
           {:ok, raw} <- extract(claims, opts),
           {:ok, allowed, default} <- roles(raw) do
        Session.new(raw,
          allowed_roles: allowed,
          default_role: default,
          requested_role: opts[:requested_role]
        )
      end
    end

    defp authenticate(_token, _jwk, _algorithms, _opts),
      do: {:error, {:invalid_jwt, :signature}}

    defp anonymous(nil), do: {:error, {:invalid_headers, :missing_token}}
    defp anonymous(role), do: Session.new(%{}, default_role: role)

    defp verify_signature(token, jwk, algorithms) do
      with {:ok, alg} <- header_alg(token),
           :ok <- allowed_alg(alg, algorithms),
           {true, %JoseJWT{fields: claims}, _jws} <-
             JoseJWT.verify_strict(jwk, algorithms, token) do
        {:ok, claims}
      else
        {:error, {:invalid_jwt, _reason}} = error -> error
        _ -> {:error, {:invalid_jwt, :signature}}
      end
    end

    defp header_alg(token) do
      with [header | _] <- String.split(token, "."),
           {:ok, json} <- Base.url_decode64(header, padding: false),
           {:ok, %{"alg" => alg}} when is_binary(alg) <- Jason.decode(json) do
        {:ok, alg}
      else
        _ -> {:error, {:invalid_jwt, :algorithm}}
      end
    end

    defp allowed_alg(alg, algorithms),
      do: algorithms |> Enum.member?(alg) |> claim_result(:algorithm)

    defp check_times(claims, opts) do
      now = opts[:now] || System.os_time(:second)
      skew = Keyword.get(opts, :allowed_skew, 0)

      with :ok <- check_time(claims, "exp", &(&1 + skew < now), :expired),
           :ok <- check_time(claims, "nbf", &(&1 - skew > now), :not_yet_valid) do
        check_time(claims, "iat", &(&1 - skew > now), :issued_in_future)
      end
    end

    defp check_time(claims, claim, failed?, reason) do
      case Map.fetch(claims, claim) do
        :error -> :ok
        {:ok, value} when is_number(value) -> value |> failed?.() |> time_result(reason)
        {:ok, _} -> {:error, {:invalid_jwt, :invalid_time_claim}}
      end
    end

    defp time_result(true, reason), do: {:error, {:invalid_jwt, reason}}
    defp time_result(false, _reason), do: :ok

    defp check_issuer(_actual, nil), do: :ok

    defp check_issuer(actual, configured) when is_binary(actual),
      do: configured |> List.wrap() |> Enum.member?(actual) |> claim_result(:issuer)

    defp check_issuer(_actual, _configured), do: claim_result(false, :issuer)

    defp check_audience(_actual, nil), do: :ok

    defp check_audience(actual, configured) do
      actual = List.wrap(actual)

      configured
      |> List.wrap()
      |> Enum.any?(&(&1 in actual))
      |> claim_result(:audience)
    end

    defp claim_result(true, _reason), do: :ok
    defp claim_result(false, reason), do: {:error, {:invalid_jwt, reason}}

    defp extract(claims, opts) do
      with {:ok, raw} <- claims_source(opts, claims), do: Session.normalize_vars(raw)
    end

    defp claims_source(opts, claims), do: claims_source(opts[:claims_map], claims, opts)

    defp claims_source(nil, claims, opts),
      do: {:ok, namespace(claims, Keyword.get(opts, :claims_namespace, @default_namespace))}

    defp claims_source(claims_map, claims, _opts), do: map_claims(claims, claims_map)

    defp namespace(claims, key) do
      case claims[key] do
        %{} = hasura -> hasura
        _ -> %{}
      end
    end

    defp map_claims(claims, claims_map) do
      Enum.reduce_while(claims_map, {:ok, %{}}, fn {claim, spec}, {:ok, acc} ->
        case resolve(claims, claim, spec) do
          {:ok, value} -> {:cont, {:ok, Map.put(acc, claim, value)}}
          error -> {:halt, error}
        end
      end)
    end

    defp resolve(claims, claim, %{} = spec) do
      case fetch_key(spec, :path) do
        {:ok, path} -> lookup(claims, claim, path, fetch_key(spec, :default))
        :error -> {:ok, spec}
      end
    end

    defp resolve(_claims, _claim, literal), do: {:ok, literal}

    defp fetch_key(spec, key) do
      with :error <- Map.fetch(spec, key), do: Map.fetch(spec, Atom.to_string(key))
    end

    defp lookup(claims, claim, path, default) do
      with {:ok, segments} <- parse_path(path),
           {:ok, value} <- fetch_path(claims, segments) do
        {:ok, value}
      else
        _ -> default_or_error(default, claim)
      end
    end

    defp default_or_error({:ok, default}, _claim), do: {:ok, default}

    defp default_or_error(:error, claim),
      do: {:error, {:jwt_invalid_claims, {:claims_map, claim}}}

    defp parse_path("$" <> rest) do
      matches = Regex.scan(@path_segment, rest)
      segments(rest, Enum.map_join(matches, fn [full | _] -> full end), matches)
    end

    defp parse_path(_path), do: :error

    # The matches must consume the whole path, otherwise it is malformed.
    defp segments(rest, rest, matches),
      do: {:ok, Enum.map(matches, fn [_ | groups] -> Enum.find(groups, &(&1 != "")) end)}

    defp segments(_rest, _consumed, _matches), do: :error

    defp fetch_path(value, []), do: {:ok, value}

    defp fetch_path(%{} = map, [key | rest]) do
      with {:ok, value} <- Map.fetch(map, key), do: fetch_path(value, rest)
    end

    defp fetch_path(_value, _segments), do: :error

    defp values_result(true), do: :ok
    defp values_result(false), do: {:error, {:jwt_invalid_claims, :invalid_claim_value}}

    defp roles(raw) do
      with {:ok, allowed} <- fetch_role_claim(raw, @allowed_roles),
           :ok <- list_check(allowed),
           {:ok, default} <- fetch_role_claim(raw, @default_role),
           :ok <- check_values(raw, allowed) do
        {:ok, allowed, default}
      end
    end

    defp fetch_role_claim(raw, claim) do
      case Map.fetch(raw, claim) do
        {:ok, value} when not is_nil(value) -> {:ok, value}
        _ -> {:error, {:jwt_missing_role_claims, claim}}
      end
    end

    defp list_check(allowed) when is_list(allowed), do: :ok
    defp list_check(_allowed), do: {:error, {:jwt_invalid_claims, :allowed_roles_not_list}}

    # `raw` comes from Session.normalize_vars/1, so every key is a string.
    defp check_values(raw, allowed) do
      values = for {@prefix <> _ = key, value} <- raw, key != @allowed_roles, do: value

      (values ++ allowed)
      |> Enum.all?(&is_binary/1)
      |> values_result()
    end
  end
end

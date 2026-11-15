defmodule Authzura.JWTTest do
  use ExUnit.Case, async: true

  alias Authzura.{JWT, Session}
  alias JOSE.{JWK, JWS}
  alias JOSE.JWT, as: JoseJWT

  @secret String.duplicate("s3cret-key-", 4)
  @ns "https://hasura.io/jwt/claims"
  @now 1_800_000_000

  defp hasura_claims(extra \\ %{}) do
    Map.merge(
      %{
        "x-hasura-allowed-roles" => ["user", "editor"],
        "x-hasura-default-role" => "user",
        "x-hasura-user-id" => "42"
      },
      extra
    )
  end

  defp sign(claims, opts \\ []) do
    alg = Keyword.get(opts, :alg, "HS256")
    secret = Keyword.get(opts, :secret, @secret)

    secret
    |> JWK.from_oct()
    |> JoseJWT.sign(%{"alg" => alg}, claims)
    |> JWS.compact()
    |> elem(1)
  end

  defp token(extra \\ %{}, hasura \\ hasura_claims()) do
    sign(Map.merge(%{@ns => hasura}, extra))
  end

  defp verify(token, opts \\ []) do
    JWT.verify(token, Keyword.merge([key: @secret, now: @now], opts))
  end

  describe "prepare/1" do
    # The key is parsed and checked once, not on every verify.
    test "a prepared configuration verifies like the options it came from" do
      opts = [key: @secret, now: @now]
      assert {:ok, prepared} = JWT.prepare(opts)

      for token <- [token(), token(%{"exp" => @now - 1}), "not.a.token", nil] do
        assert JWT.verify(token, prepared) == JWT.verify(token, opts)
      end

      refute inspect(prepared) =~ @secret
    end

    test "configuration errors are returned at prepare time" do
      assert JWT.prepare(key: "short") == {:error, {:invalid_jwt_config, :weak_secret}}

      assert JWT.prepare(key: @secret, claims_format: :stringified_json) ==
               {:error, {:unsupported_option, :claims_format}}
    end
  end

  describe "claims" do
    test "valid claims build a session" do
      assert {:ok, %Session{role: "user", vars: vars}} = verify(token())
      assert vars == %{"x-hasura-role" => "user", "x-hasura-user-id" => "42"}
    end

    test "honours a requested role that is allowed" do
      assert {:ok, %Session{role: "editor"}} = verify(token(), requested_role: "editor")
    end

    test "rejects a requested role that is not allowed" do
      assert {:error, {:invalid_session, :role_not_allowed, "admin"}} =
               verify(token(), requested_role: "admin")
    end

    test "missing allowed roles fails" do
      claims = Map.delete(hasura_claims(), "x-hasura-allowed-roles")

      assert {:error, {:jwt_missing_role_claims, "x-hasura-allowed-roles"}} =
               verify(token(%{}, claims))
    end

    test "missing default role fails" do
      claims = Map.delete(hasura_claims(), "x-hasura-default-role")

      assert {:error, {:jwt_missing_role_claims, "x-hasura-default-role"}} =
               verify(token(%{}, claims))
    end

    test "missing namespace fails closed" do
      assert {:error, {:jwt_missing_role_claims, "x-hasura-allowed-roles"}} =
               verify(sign(%{"sub" => "1"}))
    end

    test "allowed roles as a string fails" do
      claims = hasura_claims(%{"x-hasura-allowed-roles" => "user"})

      assert {:error, {:jwt_invalid_claims, :allowed_roles_not_list}} =
               verify(token(%{}, claims))
    end

    test "custom claims namespace" do
      token = sign(%{"custom" => hasura_claims()})
      assert {:ok, %Session{role: "user"}} = verify(token, claims_namespace: "custom")
    end
  end

  describe "time claims" do
    test "expired token fails" do
      assert {:error, {:invalid_jwt, :expired}} = verify(token(%{"exp" => @now - 1}))
    end

    test "token expired 30s ago passes with skew 60" do
      assert {:ok, _} = verify(token(%{"exp" => @now - 30}), allowed_skew: 60)
    end

    test "unexpired token passes" do
      assert {:ok, _} = verify(token(%{"exp" => @now + 30}))
    end

    test "nbf in the future fails" do
      assert {:error, {:invalid_jwt, :not_yet_valid}} = verify(token(%{"nbf" => @now + 10}))
    end

    test "nbf in the future passes within skew" do
      assert {:ok, _} = verify(token(%{"nbf" => @now + 10}), allowed_skew: 15)
    end

    test "iat in the future beyond skew fails" do
      assert {:error, {:invalid_jwt, :issued_in_future}} =
               verify(token(%{"iat" => @now + 100}), allowed_skew: 60)
    end

    test "string exp fails" do
      assert {:error, {:invalid_jwt, :invalid_time_claim}} =
               verify(token(%{"exp" => to_string(@now + 100)}))
    end

    test "null nbf fails" do
      assert {:error, {:invalid_jwt, :invalid_time_claim}} = verify(token(%{"nbf" => nil}))
    end
  end

  describe "signature and algorithm" do
    test "bad signature fails" do
      bad = sign(%{@ns => hasura_claims()}, secret: String.duplicate("other-key-", 5))
      assert {:error, {:invalid_jwt, :signature}} = verify(bad)
    end

    test "garbage token fails" do
      assert {:error, {:invalid_jwt, :algorithm}} = verify("not-a-jwt")
    end

    test "valid header with a garbage payload fails" do
      header = Base.url_encode64(~s({"alg":"HS256"}), padding: false)
      assert {:error, {:invalid_jwt, :signature}} = verify("#{header}.e30.AAAA")
    end

    test "an alg outside the allowlist fails" do
      header = Base.url_encode64(~s({"alg":"RS256","typ":"JWT"}), padding: false)
      payload = Base.url_encode64(Jason.encode!(%{@ns => hasura_claims()}), padding: false)
      assert {:error, {:invalid_jwt, :algorithm}} = verify("#{header}.#{payload}.AAAA")
    end

    test "alg none is rejected even when allowlisted" do
      header = Base.url_encode64(~s({"alg":"none"}), padding: false)
      payload = Base.url_encode64(Jason.encode!(%{@ns => hasura_claims()}), padding: false)

      assert {:error, {:invalid_jwt, :algorithm}} =
               verify("#{header}.#{payload}.", algorithms: ["none", "HS256"])
    end

    test "a configured alternative algorithm verifies" do
      token = sign(%{@ns => hasura_claims()}, alg: "HS512")
      assert {:error, {:invalid_jwt, :algorithm}} = verify(token)
      assert {:ok, _} = verify(token, algorithms: ["HS256", "HS512"])
    end
  end

  describe "issuer and audience" do
    test "are accepted when not configured" do
      assert {:ok, _} = verify(token(%{"iss" => "anyone", "aud" => "anything"}))
    end

    test "matching issuer passes, mismatched fails" do
      token = token(%{"iss" => "idp"})
      assert {:ok, _} = verify(token, issuer: "idp")
      assert {:ok, _} = verify(token, issuer: ["other", "idp"])
      assert {:error, {:invalid_jwt, :issuer}} = verify(token, issuer: "other")
    end

    test "missing issuer fails when configured" do
      assert {:error, {:invalid_jwt, :issuer}} = verify(token(), issuer: "idp")
    end

    test "audience as string or list" do
      assert {:ok, _} = verify(token(%{"aud" => "api"}), audience: "api")
      assert {:ok, _} = verify(token(%{"aud" => ["web", "api"]}), audience: ["api"])

      assert {:error, {:invalid_jwt, :audience}} =
               verify(token(%{"aud" => "web"}), audience: "api")

      assert {:error, {:invalid_jwt, :audience}} = verify(token(), audience: "api")
    end
  end

  describe "claims_map" do
    defp mapped(claims, map), do: verify(sign(claims), claims_map: map)

    test "reads values by path" do
      claims = %{"roles" => ["a", "b"], "role" => "a", "user" => %{"id" => "7"}}

      map = %{
        "x-hasura-allowed-roles" => %{path: "$.roles"},
        "x-hasura-default-role" => %{"path" => "$.role"},
        "x-hasura-user-id" => %{path: "$.user.id"}
      }

      assert {:ok, %Session{role: "a", vars: %{"x-hasura-user-id" => "7"}}} =
               mapped(claims, map)
    end

    test "supports bracketed keys" do
      claims = %{@ns => hasura_claims()}

      map = %{
        "x-hasura-allowed-roles" => %{path: "$['#{@ns}']['x-hasura-allowed-roles']"},
        "x-hasura-default-role" => %{path: "$.[\"#{@ns}\"].x-hasura-default-role"}
      }

      assert {:ok, %Session{role: "user"}} = mapped(claims, map)
    end

    test "missing path falls back to the default" do
      map = %{
        "x-hasura-allowed-roles" => %{path: "$.roles", default: ["guest"]},
        "x-hasura-default-role" => %{path: "$.role", default: "guest"}
      }

      assert {:ok, %Session{role: "guest"}} = mapped(%{"sub" => "1"}, map)
    end

    test "missing path with no default fails" do
      map = %{
        "x-hasura-allowed-roles" => %{path: "$.roles"},
        "x-hasura-default-role" => "user"
      }

      assert {:error, {:jwt_invalid_claims, {:claims_map, "x-hasura-allowed-roles"}}} =
               mapped(%{"sub" => "1"}, map)
    end

    test "static values" do
      map = %{"x-hasura-allowed-roles" => ["user"], "x-hasura-default-role" => "user"}
      assert {:ok, %Session{role: "user"}} = mapped(%{"sub" => "1"}, map)
    end

    test "malformed path without a default fails" do
      map = %{
        "x-hasura-allowed-roles" => %{path: "roles"},
        "x-hasura-default-role" => "user"
      }

      assert {:error, {:jwt_invalid_claims, {:claims_map, "x-hasura-allowed-roles"}}} =
               mapped(%{"roles" => ["user"]}, map)
    end
  end

  describe "no token" do
    test "nil token with an unauthorized role" do
      assert {:ok, %Session{role: "anon", vars: %{"x-hasura-role" => "anon"}}} =
               verify(nil, unauthorized_role: "anon")
    end

    test "empty token with an unauthorized role" do
      assert {:ok, %Session{role: "anon"}} = verify("", unauthorized_role: "anon")
    end

    test "nil token without an unauthorized role" do
      assert {:error, {:invalid_headers, :missing_token}} = verify(nil)
    end

    test "a present but invalid token never falls back to the unauthorized role" do
      assert {:error, {:invalid_jwt, :algorithm}} = verify("junk", unauthorized_role: "anon")
    end
  end

  describe "unsupported options" do
    test "claims_namespace_path" do
      assert {:error, {:unsupported_option, :claims_namespace_path}} =
               verify(token(), claims_namespace_path: "$.x")
    end

    test "stringified_json claims format" do
      assert {:error, {:unsupported_option, :claims_format}} =
               verify(token(), claims_format: :stringified_json)
    end
  end

  describe "key and algorithm configuration" do
    defp rsa_keys do
      private = JWK.generate_key({:rsa, 2048})
      {private, JWK.to_public(private)}
    end

    defp hs_forgery(secret) do
      %{@ns => hasura_claims()}
      |> sign(secret: secret)
    end

    test "an RSA public PEM cannot be used as an HMAC secret" do
      {_private, public} = rsa_keys()
      {_, pem} = JWK.to_pem(public)
      forged = hs_forgery(pem)

      assert {:error, {:invalid_jwt_config, :key_algorithm_mismatch}} =
               verify(forged, key: pem)

      assert {:error, {:invalid_jwt_config, :key_algorithm_mismatch}} =
               verify(forged, key: pem, algorithms: ["RS256", "HS256"])
    end

    test "a public JWK cannot be paired with an HMAC algorithm" do
      {_private, public} = rsa_keys()

      assert {:error, {:invalid_jwt_config, :key_algorithm_mismatch}} =
               verify(token(), key: public, algorithms: ["HS256", "RS256"])
    end

    test "an oct key cannot be paired with RS256" do
      assert {:error, {:invalid_jwt_config, :key_algorithm_mismatch}} =
               verify(token(), algorithms: ["RS256"])
    end

    test "RS256 verifies with a generated keypair, from PEM and JWK map" do
      {private, public} = rsa_keys()

      token =
        private
        |> JoseJWT.sign(%{"alg" => "RS256"}, %{@ns => hasura_claims()})
        |> JWS.compact()
        |> elem(1)

      {_, pem} = JWK.to_pem(public)
      {_, map} = JWK.to_map(public)

      for key <- [pem, map, public] do
        assert {:ok, %Session{role: "user"}} = verify(token, key: key, algorithms: ["RS256"])
      end
    end

    test "a JWK map key verifies HS256" do
      {_, map} = @secret |> JWK.from_oct() |> JWK.to_map()
      assert {:ok, _} = verify(token(), key: map)
    end

    test "missing key" do
      assert {:error, {:invalid_jwt_config, :missing_key}} = JWT.verify(token(), now: @now)
    end

    test "invalid keys" do
      assert {:error, {:invalid_jwt_config, :invalid_key}} = verify(token(), key: 123)

      assert {:error, {:invalid_jwt_config, :invalid_key}} =
               verify(token(), key: %{"kty" => "bogus"})

      assert {:error, {:invalid_jwt_config, :invalid_key}} =
               verify(token(), key: "-----BEGIN garbage")
    end

    test "weak HMAC secret" do
      assert {:error, {:invalid_jwt_config, :weak_secret}} = verify(token(), key: "short")
    end

    test "invalid algorithm lists" do
      assert {:error, {:invalid_jwt_config, :invalid_algorithms}} =
               verify(token(), algorithms: "HS256")

      assert {:error, {:invalid_jwt_config, :invalid_algorithms}} =
               verify(token(), algorithms: [])

      assert {:error, {:invalid_jwt_config, :invalid_algorithms}} =
               verify(token(), algorithms: [:HS256])

      assert {:error, {:invalid_jwt_config, {:unknown_algorithm, "HS999"}}} =
               verify(token(), algorithms: ["HS999"])
    end

    test "config is validated even without a token" do
      assert {:error, {:invalid_jwt_config, :weak_secret}} =
               verify(nil, key: "short", unauthorized_role: "anon")
    end
  end

  describe "fail closed" do
    test "non-binary tokens never fall back to the unauthorized role" do
      for bad <- [123, %{}, :token, []] do
        assert {:error, {:invalid_jwt, :signature}} = verify(bad, unauthorized_role: "anon")
      end
    end

    test "claims_format other than :json is unsupported" do
      for format <- ["stringified_json", :other] do
        assert {:error, {:unsupported_option, :claims_format}} =
                 verify(token(), claims_format: format)
      end

      assert {:ok, _} = verify(token(), claims_format: :json)
    end

    test "allowed roles must be strings" do
      claims = hasura_claims(%{"x-hasura-allowed-roles" => ["user", 1]})
      assert {:error, {:jwt_invalid_claims, :invalid_claim_value}} = verify(token(%{}, claims))
    end

    test "default role must be a string" do
      claims = hasura_claims(%{"x-hasura-default-role" => 5})
      assert {:error, {:jwt_invalid_claims, :invalid_claim_value}} = verify(token(%{}, claims))
    end

    test "other session values must be strings" do
      for value <- [42, true, ["a"], %{"a" => 1}] do
        claims = hasura_claims(%{"x-hasura-user-id" => value})
        assert {:error, {:jwt_invalid_claims, :invalid_claim_value}} = verify(token(%{}, claims))
      end
    end

    test "non-hasura namespace entries are ignored" do
      claims = hasura_claims(%{"other" => 1})
      assert {:ok, _} = verify(token(%{}, claims))
    end

    test "issuer must be a single string" do
      assert {:error, {:invalid_jwt, :issuer}} = verify(token(%{"iss" => ["idp"]}), issuer: "idp")
      assert {:error, {:invalid_jwt, :issuer}} = verify(token(%{"iss" => 5}), issuer: "idp")
    end

    test "role claim names match case-insensitively" do
      claims = %{"X-Hasura-Allowed-Roles" => ["user"], "X-Hasura-Default-Role" => "user"}
      assert {:ok, %Session{role: "user"}} = verify(token(%{}, claims))
    end

    test "case-variant claims with different values conflict" do
      claims = hasura_claims(%{"X-Hasura-User-Id" => "43"})

      assert {:error, {:invalid_session, :conflicting_keys, "x-hasura-user-id"}} =
               verify(token(%{}, claims))
    end

    test "iat within skew passes" do
      assert {:ok, _} = verify(token(%{"iat" => @now + 30}), allowed_skew: 60)

      assert {:error, {:invalid_jwt, :issued_in_future}} =
               verify(token(%{"iat" => @now + 120}), allowed_skew: 60)
    end
  end

  describe "malformed tokens" do
    test "never leak raw errors or the token" do
      header = Base.url_encode64(~s({"alg":"HS256"}), padding: false)

      tokens = [
        "#{header}.e30",
        "#{header}.e30.AAAA.extra",
        "#{header}.e30.AAAA.extra.more",
        "#{header}.!!!.AAAA",
        "#{header}.e30.!!!",
        "#{header}.bm90anNvbg.AAAA",
        "#{header}.#{Base.url_encode64("[1,2]", padding: false)}.AAAA",
        "#{header}.#{Base.url_encode64(~s("str"), padding: false)}.AAAA",
        "#{header}.#{Base.url_encode64("not json", padding: false)}.AAAA",
        "a.b.c",
        "...",
        "#{header}..",
        header
      ]

      for token <- tokens do
        assert {:error, {:invalid_jwt, reason}} = result = verify(token)
        assert reason in [:algorithm, :signature]
        refute inspect(result) =~ token
      end
    end

    test "a PEM with leading whitespace is still not an HMAC secret" do
      {_private, public} = rsa_keys()
      {_, pem} = JWK.to_pem(public)

      for padded <- ["\n" <> pem, "  " <> pem, "\uFEFF" <> pem] do
        assert {:error, {:invalid_jwt_config, :key_algorithm_mismatch}} =
                 verify(hs_forgery(padded), key: padded)
      end
    end

    test "a PEM behind any preamble is still not an HMAC secret" do
      {_private, public} = rsa_keys()
      {_, pem} = JWK.to_pem(public)

      preambles = [
        "\n﻿",
        "​",
        "\"",
        "'",
        "Bag Attributes\n    friendlyName: prod\n",
        "﻿﻿ "
      ]

      for preamble <- preambles, key <- [preamble <> pem, preamble <> pem <> "\""] do
        assert {:error, {:invalid_jwt_config, :key_algorithm_mismatch}} =
                 verify(hs_forgery(key), key: key),
               inspect(preamble)
      end
    end

    # A marker is found after dropping zero-width characters and BOMs
    # anywhere, reading typographic dashes as `-`, and ignoring case and
    # spaces: none of these turns a public key into an HMAC secret.
    test "a disguised PEM marker never becomes an HMAC secret" do
      {_private, public} = rsa_keys()
      {_, pem} = JWK.to_pem(public)

      variants = [
        String.replace(pem, "-----BEGIN", "-----BE\u200BGIN"),
        String.replace(pem, "-----BEGIN", "--\uFEFF---BEGIN"),
        String.replace(pem, "-----BEGIN", "----- BEGIN"),
        String.replace(pem, "-----BEGIN", "----BEGIN"),
        String.replace(pem, "-----BEGIN", "\u2013\u2013\u2013\u2013\u2013BEGIN"),
        String.replace(pem, "-----BEGIN", "\u2014\u2014\u2014\u2014\u2014BEGIN"),
        String.replace(pem, "-----BEGIN", "-----\u00A0BEGIN"),
        String.downcase(pem),
        "secret " <> String.duplicate("s", 32) <> " -----end public key-----"
      ]

      for key <- variants do
        assert {:error, {:invalid_jwt_config, reason}} = verify(hs_forgery(key), key: key),
               inspect(key, limit: 40)

        assert reason in [:invalid_key, :key_algorithm_mismatch]
      end

      # Ordinary secrets with dashes or the word stay shared secrets.
      for key <- [String.duplicate("a-b-", 10), "begin-" <> String.duplicate("x", 32)] do
        assert {:ok, %Session{}} = verify(hs_forgery(key), key: key)
      end
    end

    test "a secret holding a PEM or certificate marker that is not a key is invalid" do
      for key <- [
            String.duplicate("s", 32) <> "-----BEGIN PUBLIC KEY-----",
            "prefix -----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----",
            String.duplicate("x", 40) <> "-----BEGIN RSA PUBLIC KEY-----"
          ] do
        assert {:error, {:invalid_jwt_config, :invalid_key}} = verify(hs_forgery(key), key: key)
      end
    end

    test "bogus JWK maps are invalid keys" do
      for map <- [%{"kty" => "RSA"}, %{"kty" => "oct"}, %{"kty" => "EC"}, %{}] do
        assert {:error, {:invalid_jwt_config, :invalid_key}} = verify(token(), key: map)
      end
    end
  end
end

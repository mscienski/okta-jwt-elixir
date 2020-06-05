defmodule Okta do
  @moduledoc File.read!("#{__DIR__}/../README.md")

  alias Okta.{
    Jwk,
    Token
  }

  @doc """
  Verify an okta token

  ## Examples

      iex> Okta.verify_token(my_token, %{issuer: my_issuer, audience: "api://default", client_id: my_client_id)
      {:error, :invalid_issuer}

      iex> Okta.verify_token(my_token, %{issuer: my_issuer, audience: "api://default", client_id: my_client_id)
      {:error, :invalid_audience}

      iex> Okta.verify_token(my_token, %{issuer: my_issuer, audience: "api://default", client_id: my_client_id)
      {:error, :invalid_client_id}

      iex> Okta.verify_token(my_token, %{issuer: my_issuer, audience: "api://default", client_id: my_client_id)
      {:error, :token_expired}

      iex> Okta.verify_token(my_token, %{issuer: my_issuer, audience: "api://default", client_id: my_client_id)
      {:ok,
        %{
          "aud" => "api://default",
          "cid" => "1eweiinp0aQLt4Fp23f1",
          "exp" => 1591311101,
          "iat" => 1591310501,
          "iss" => "https://my-org.okta.com/oauth2/my-auth-server-id",
          "jti" => "KF.ppOT_4aabQo1vbpP0AjKbMMViuc6qm2poBeBgkEpVK7.LKeur3ma2irtu+JFHsnQsFs2OflqqEMFGXbjwt6251A=",
          "scp" => ["profile", "offline_access", "openid", "email"],
          "sub" => "me@test.com",
          "uid" => "12iuyanbvW1kiaRTM9r1",
          "ver" => 1
        }}

  """
  def verify_token(token, expected_claims) do
    with {:ok, payload} <- Joken.peek_claims(token),
         {:ok} <- validate_claims(payload, expected_claims),
         {:ok, header} <- Joken.peek_header(token),
         {:ok, jwk} <- Jwk.fetch_jwk(header, payload),
         {:ok, algorithm} <- Map.fetch(jwk, "alg") do
      Token.verify_and_validate(token, Joken.Signer.create(algorithm, jwk))
    else
      {:error, message} -> {:error, message}
      message -> {:error, message}
    end
  end

  defp validate_claims(
         %{"iss" => issuer, "aud" => audience, "cid" => client_id, "exp" => expiration},
         %{issuer: expected_issuer, audience: expected_audience, client_id: expected_client_id}
       ) do
    cond do
      # expected issuer is the base issuer url, issuer in the token claims contains the oauth path
      issuer != expected_issuer ->
        {:error, :invalid_issuer}

      audience != expected_audience ->
        {:error, :invalid_audience}

      client_id != expected_client_id ->
        {:error, :invalid_client_id}

      in_past?(expiration) ->
        {:error, :token_expired}

      true ->
        {:ok}
    end
  end

  defp validate_claims(_, _) do
    {:error, :invalid_claims}
  end

  defp in_past?(time) do
    with integer_time <- parse_time(time),
         datetime <- DateTime.from_unix!(integer_time) do
      case DateTime.compare(datetime, DateTime.utc_now()) do
        :lt -> true
        :eq -> true
        _ -> false
      end
    end
  end

  defp parse_time(time) when is_integer(time), do: time
  defp parse_time(time) when is_binary(time), do: String.to_integer(time)
end

defmodule Okta do
  @moduledoc """
  Documentation for `Okta`.
  """

  alias Okta.{
    Jwk,
    Token
  }

  @doc """
  Hello world.

  ## Examples

      iex> OktaJwtElixir.hello()
      :world

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
      !String.contains?(issuer, expected_issuer) ->
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

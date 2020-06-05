defmodule Okta.Jwk do
  @doc """
  Fetch an Okta JWK
  """
  def fetch_jwk(%{"kid" => key_id}, payload) do
    with {:ok, jwks_uri} <- fetch_jwks_uri(payload),
         {:ok, jwks_response} <- HTTPoison.get(jwks_uri),
         {:ok, decoded_body} <- Jason.decode(jwks_response.body),
         {:ok, keys} <- Map.fetch(decoded_body, "keys") do
      {
        :ok,
        Enum.find(keys, fn key -> Map.fetch!(key, "kid") == key_id end)
      }
    else
      {:error, message} -> {:error, message}
      message -> {:error, message}
    end
  end

  def fetch_jwk(_, _) do
    {:error, :invalid_token_header}
  end

  defp fetch_jwks_uri(%{"cid" => client_id, "iss" => issuer}) do
    with {:ok, metadata_response} <-
           HTTPoison.get(
             "#{issuer}/.well-known/oauth-authorization-server?client_id=#{client_id}"
           ),
         {:ok, decoded_body} <- Jason.decode(metadata_response.body) do
      Map.fetch(decoded_body, "jwks_uri")
    end
  end

  defp fetch_jwks_uri(_), do: {:error, :invalid_token_payload}
end

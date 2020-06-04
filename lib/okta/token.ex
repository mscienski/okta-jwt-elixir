defmodule Okta.Token do
  use Joken.Config

  @impl true
  def token_config do
    default_claims(
      # these claims are validated before Okta.Token.verify_and_validate! is called
      skip: [:aud, :exp, :iss]
    )
  end
end

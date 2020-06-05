# OktaJwtElixir

An implementation of the `verify_token` function from ruby's [Okta Jwt](https://github.com/damir/okta-jwt) library.

## Installation

> **This package is not yet available on HexPM**

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `okta_jwt_elixir` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:okta_jwt_elixir, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/okta_jwt_elixir](https://hexdocs.pm/okta_jwt_elixir).

## Usage

Call `Okta.verify_token/2` with your okta token and a map of expected claims.

```
Okta.verify_token(my_okta_token, %{
  audience: "api://default",
  client_id: "<my_client_id>",
  issuer: "https://<org>.okta.com/oauth2/<auth_server_id>",
})
```

This library makes a few assumptions.

* The token's `exp` claim is epoch time in UTC (should be the default)
* The okta metadata path conforms to the pattern `https://<org>.okta.com/oauth2/<auth_server_id>/.well-known/oauth-authorization-server?client_id=<client_id>`

## Known Issues/TODO

* An HTTP client needs to be created instead of using HTTPoison directly. To be made configurable so users may use their preferred http client

* Tests are needed

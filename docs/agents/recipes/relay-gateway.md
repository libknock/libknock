# relay-gateway recipe

## Use when

Use this recipe for the integration shape named `relay-gateway`.

## Do not use when

Do not use it to bypass the root SDK APIs or to move application configuration parsing into SDK core.

## Validation

Run `scripts/check-integration.sh` and the relevant example or integration test.

## Common mistakes

- Creating a replay cache per connection.
- Importing `protocol/` for normal application integration.
- Claiming libknock replaces TLS or application authorization.

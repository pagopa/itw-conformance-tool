# itw-relying-party

Relying Party service for IT Wallet conformance flows (OID4VP side).

## Endpoints

- `POST /request-object`: create authorization request and session
- `GET /auth/request/:state`: serve signed request object JWT
- `POST /auth/response`: verify wallet authorization response (JARM)
- `GET /status/:state`: poll presentation status with legacy-compatible redirect mapping
- `GET /health`: health check

## Status Polling Contract (Legacy-Compatible)

`GET /status/:state` returns JSON with `redirect_uri` and optional `values`.

- `pending` -> `{"redirect_uri":"?response_code=pending"}`
- `checking` -> `{"redirect_uri":"?response_code=checking"}`
- `verified` -> `{"redirect_uri":"<success-url>","values":[...]}`
  - if `response_code` is missing in the stored redirect URL, `response_code=success` is appended for compatibility
- `rejected` -> `{"redirect_uri":"rejected-error.html?response_code=rejected"}`
- `denied` -> `{"redirect_uri":"error.html?response_code=denied"}`
- `expired` -> `{"redirect_uri":"timeout.html?response_code=expired"}`

## Development

## Note

The `TO_MIGRATE` folder is intentionally kept for an additional verification phase.
It is not part of the active runtime path for the current relying party flow.

From repository root:

```bash
pnpm nx serve itw-relying-party
```

Run tests:

```bash
pnpm nx run itw-relying-party:test
```

Build:

```bash
pnpm nx run itw-relying-party:build
```

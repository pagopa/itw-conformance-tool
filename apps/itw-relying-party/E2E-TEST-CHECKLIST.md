# E2E Test Checklist - Relying Party

## Preconditions

- Node.js version matches `.nvmrc`
- Dependencies installed (`pnpm install`)
- Local config and keys initialized for the workspace

## Core Flow Checklist

1. Start RP service
2. `POST /request-object` returns wallet URL with `state` and `request_uri`
3. `GET /auth/request/:state` returns `application/oauth-authz-req+jwt`
4. `POST /auth/response` with valid JARM returns `200` and `redirect_uri`
5. `GET /status/:state` returns final `redirect_uri` compatible with legacy mapping

## Status Mapping Checklist

- Pending session -> `?response_code=pending`
- Checking session -> `?response_code=checking`
- Verified session -> success redirect and optional `values`
- Rejected session -> `rejected-error.html?response_code=rejected`
- Denied session -> `error.html?response_code=denied`
- Expired session -> `timeout.html?response_code=expired`
- Unknown session -> `404`

## Regression Checklist

- OAuth error callback path still updates session to rejected when state exists
- Verified status keeps existing `response_code` if already present
- Verified status appends `response_code=success` when missing

## Commands

```bash
pnpm nx run itw-relying-party:test
pnpm nx run itw-relying-party:build
pnpm build
```

## Expected Outcome

- Route and E2E tests green
- RP project build green
- Workspace build green

# Web App for Wallet RP Testing

This package contains the Relying Party (RP) web application used to test
wallet presentation flows in the `io-wallet-demo` monorepo.

## Requirements

- Node.js 22 or newer
- pnpm 10.30.3 or newer

## Local Development


1. Create the `.env` file required by the app.


From the monorepo root:

2. Install dependencies from the monorepo root:

   ```bash
   pnpm install
   ```

3. Start the RP app in watch mode from the monorepo root:

   ```bash
   nx run itw-relying-party:build
   nx run itw-relying-party:start
   ```

   This command rebuilds the app on changes and starts the compiled server
   after each successful build.

4. Open `http://localhost:8080`.

## Other Useful Commands

Run these commands from the monorepo root:

```bash
nx run itw-relying-party:build
nx run itw-relying-party:build:watch
nx run itw-relying-party:lint
nx run itw-relying-party:lint:fix
nx run itw-relying-party:typecheck
nx run itw-relying-party:format
nx run itw-relying-party:clean
```

## Testing Remote Presentation

1. Prepare the request from the RP side.
2. For cross-device flows, scan the QR code from the app with the wallet.
3. For same-device flows, open the generated link directly on the device where
   the wallet is installed.

# ITW Conformance CLI

CLI locale per il monorepo `itw-conformance-tool`, allineata ai flow `init` e `start`.

## Comandi

- `itw-conformance-tool init`
- `itw-conformance-tool start`
- `itw-conformance-tool help`

Durante lo sviluppo da root workspace:

- `pnpm conformance --args="init"`
- `pnpm conformance --args="start --all"`
- `pnpm conformance --args="start --issuer"`
- `pnpm conformance --args="start --rp"`

Shortcut root:

- `pnpm conformance:init`
- `pnpm conformance:start`
- `pnpm conformance:start:issuer`
- `pnpm conformance:start:rp`

## Opzioni

- `-c, --config <path>` path config (output `init` o file richiesto da `start`)
- `--all` avvia entrambi i servizi (default di `start`)
- `--issuer` avvia solo issuer
- `--rp` avvia solo relying party
- `--force` forza overwrite file generati da `init`
- `--unsafe-tls` disabilita verifica TLS
- `--tls-ca-file <path>` esporta `ITW_CT_TLS_CA_FILE`
- `--log-level <debug|info|warn|error>` livello log CLI
- `--skip-nx-cache` passa `--skip-nx-cache` ai comandi Nx delegati
- `--dry-run` mostra azione calcolata senza eseguire
- `-h, --help` mostra help

## Cosa fa oggi

- `init` crea:
  - `~/.itw-conformance-tool/issuer`
  - `~/.itw-conformance-tool/rp`
  - `config.example.ini` (template) in cwd, o nel path passato con `--config`
- `start` delega a Nx:
  - `--all` → `nx run-many -t serve -p itw-credential-issuer,itw-relying-party`
  - `--issuer` → `nx run itw-credential-issuer:serve`
  - `--rp` → `nx run itw-relying-party:serve`
  - fallisce con errore esplicito se manca `config.ini`

## Eventi log principali

- `cli.runtime_config_resolved`
- `cli.init_summary`
- `cli.nx_command`
- `cli.dry_run_summary`
- `cli.nx_output`
- `cli.flow_completed`
- `cli.flow_failed`
- `cli.unhandled_error`

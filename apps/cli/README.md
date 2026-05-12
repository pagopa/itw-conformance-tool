# ITW Conformance CLI

This CLI is a headless wrapper.
It does not implement protocol logic.
It does not replace Vitest tests.

It does three things:

1. Reads runtime configuration (defaults, JSON file, CLI flags).
2. Builds the correct Nx command for the requested flow.
3. Executes the command and returns the exit code and JSON logs.

If the Nx target fails, the CLI fails.
If the Nx target passes, the CLI passes.

## What it actually does

- Issuance command: delegates to itw-credential-issuer:<target>
- Presentation command: delegates to itw-relying-party:<target>
- Help command: prints usage and options

## What it does NOT do

- It does not directly execute custom tests.
- It does not validate remote endpoints.
- It does not generate its own conformance reports.
- It does not fix Nx target configuration problems.

## Prerequisites

- Run from the itw-conformance-tool workspace root
- Node 22
- pnpm 10.30.3

Recommended in CI/non-interactive environments:

- CI=1
- NX_TUI=false

## Available commands

From the workspace root:

- pnpm conformance help
- pnpm conformance issuance [options]
- pnpm conformance presentation [opzioni]

Shortcut root:

- pnpm conformance:issuance -- [opzioni]
- pnpm conformance:presentation -- [opzioni]

## Opzioni CLI

- -c, --config <file>
  - File JSON di runtime
- -e, --endpoint <url>
  - Override endpoint
- --credential-types <csv>
  - Tipi credenziali separati da virgola, esempio PID,MDL
- --unsafe-tls
  - Disabilita verifica certificato TLS (imposta NODE_TLS_REJECT_UNAUTHORIZED=0)
- --tls-ca-file <path>
  - Path CA custom
- --log-level <debug|info|warn|error>
  - Soglia minima dei log stampati (debug mostra tutto, error solo errori)
- --target <test|serve>
  - Target Nx da eseguire
- --skip-nx-cache
  - Aggiunge --skip-nx-cache al comando Nx
- --dry-run
  - Mostra configurazione finale e comando Nx, non esegue
- -h, --help
  - Help

## Priorita' configurazione

Ordine reale di merge:

1. Default interni
2. File JSON passato con --config
3. Flag CLI

Le flag CLI vincono sempre.

## Formato file config JSON

Esempio:

{
  "endpoint": "https://issuer.example.org",
  "credentialTypes": ["PID", "MDL"],
  "logLevel": "info",
  "target": "test",
  "tls": {
    "unsafe": false,
    "caFile": "./certs/ca.pem"
  },
  "nx": {
    "skipCache": true,
    "extraArgs": ["--verbose"]
  }
}

Campi supportati:

- endpoint: string
- credentialTypes: string[]
- logLevel: debug|info|warn|error
- target: test|serve
- tls.unsafe: boolean
- tls.caFile: string
- nx.skipCache: boolean
- nx.extraArgs: string[]

## Esempi pratici

Help:

pnpm conformance help

Dry-run issuance:

pnpm conformance issuance --dry-run --endpoint https://issuer.example.org --credential-types PID,MDL --skip-nx-cache

Dry-run presentation:

pnpm conformance presentation --dry-run --target serve --log-level debug

Run reale issuance:

pnpm conformance issuance --target test

Run reale presentation:

pnpm conformance presentation --target test

## Output e codici di uscita

La CLI scrive log JSON con eventi principali:

- cli.runtime_config_resolved
- cli.nx_command
- cli.flow_completed
- cli.flow_failed
- cli.unhandled_error

I livelli sono assegnati per evento e filtrati da --log-level:

- cli.runtime_config_resolved: debug
- cli.nx_command: debug
- cli.flow_completed: info
- cli.flow_failed: error
- cli.unhandled_error: error

Exit code:

- 0: esecuzione OK
- != 0: errore (parse, config, o target Nx fallito)

## Variabili ambiente esportate dalla CLI

Prima di delegare a Nx, la CLI esporta:

- ITW_CT_FLOW
- ITW_CT_ENDPOINT
- ITW_CT_CONFIG_FILE (se presente)
- ITW_CT_CREDENTIAL_TYPES
- ITW_CT_UNSAFE_TLS
- ITW_CT_TLS_CA_FILE (se presente)
- ITW_CT_LOG_LEVEL

## Relazione con pnpm test

Questa CLI non sostituisce pnpm test.

- pnpm test = pipeline Vitest dei progetti configurati
- pnpm conformance ... = orchestrazione runtime di un flusso via target Nx

## Errori comuni e causa reale

- "This command must be run from the itw-conformance-tool workspace root"
  - Stai lanciando la CLI nella cartella sbagliata
- "Unknown option"
  - Flag non supportata o typo
- "Invalid target"
  - target diverso da test o serve
- "Invalid config ..."
  - Valore non valido nel file JSON
- flow_failed
  - Il target Nx delegato e' fallito, non e' un errore nascosto della CLI

# Repository Guidelines

## Purpose and Workspace Layout

This is a pnpm + Nx TypeScript monorepo for the Italian IT Wallet conformance tool. It runs OpenID4VCI and OpenID4VP conformance scenarios against a Wallet Solution, records protocol events and verdicts, and produces reports.

- `apps/cli`: the `itwct` command-line interface. It initializes local state, supervises services, runs conformance categories, and creates reports.
- `apps/itw-credential-issuer`, `apps/itw-relying-party`, `apps/itw-trust-anchor`: Fastify services used by the scenarios.
- `packages/conformance`: scenario definitions, runner, event capture, verdict engine, artifacts, and report generation. Matrix tests live in `src/tests/matrix`.
- `packages/config`, `database`, `crypto`, `ipc`, `logger`, and `utils`: shared workspace libraries.
- `.itw-conformance-tool/` and root `config.ini`: generated local state; both are ignored and must not be committed.

Use package names such as `@itw-conformance-tool/conformance` for cross-project dependencies. Keep application code in each project's `src/`; service routes and plugins follow their existing local structure.

## Toolchain and Commands

Run commands from the repository root. Use the Node.js version in `.nvmrc` and pnpm `11.13.1`, as pinned by `package.json`.

```bash
pnpm install                    # install workspace dependencies
pnpm build                      # build every Nx project with a build target
pnpm start                      # build and run all Nx targets with a serve target
pnpm typecheck                  # type-check projects
pnpm lint                       # lint projects
pnpm test                       # run inferred Vitest project tests
pnpm format:check               # verify formatting
pnpm format                     # rewrite formatting
pnpm nx run <project>:<target>  # run one Nx target
```

Useful project targets include `itw-conformance-cli:run`, `itw-credential-issuer:serve`, `itw-relying-party:serve`, and `itw-trust-anchor:serve`. Build the CLI before invoking its `run` target; Nx models that dependency automatically.

### Local Conformance Workflow

```bash
pnpm init                       # create local data, keys, and config template
pnpm test:all                   # run all conformance categories
pnpm test:issuance
pnpm test:presentation
pnpm test:wallet-instance
pnpm test:wallet-provider
```

The category commands run the CLI and require valid local configuration, including `wallet_provider_backend_url`. The explicit matrix profile is `vitest.conformance.config.mts`; it runs sequentially with Node's `--experimental-sqlite` flag and imports built conformance reporters. Build before running it directly:

```bash
pnpm build
pnpm vitest run --config vitest.conformance.config.mts
```

`pnpm test` is the standard unit-test command. It is distinct from external conformance runs.

## TypeScript, Formatting, and Imports

Write strict TypeScript ESM. The base configuration uses NodeNext modules and resolution, ES2022, `verbatimModuleSyntax`, `isolatedModules`, `erasableSyntaxOnly`, `noImplicitReturns`, and `noUnusedLocals`. Preserve `.js` extensions in relative runtime imports where the surrounding code requires them.

EditorConfig requires UTF-8, two-space indentation, final newlines, and no trailing whitespace. Prettier enforces 120-column lines, semicolons, single quotes, bracket spacing, and no trailing commas.

ESLint enforces Nx module boundaries and buildable-library dependencies. `eslint-plugin-perfectionist` alphabetizes imports in this order: builtins, external packages, internal packages, relative imports, side-effect imports, then type imports. `console` is a warning; use the workspace logger in production paths.

## Testing and Changes

Use Vitest in the Node environment. Colocate focused unit tests as `*.test.ts` or `*.spec.ts`; existing route tests are under `apps/itw-trust-anchor/src/routes/tests`, while conformance matrix coverage is under `packages/conformance/src/tests/matrix`.

For a changed project, run its Nx test target when it exists, then run relevant type-checking and linting. For CLI, service orchestration, protocol, or report changes, exercise the affected command or scenario after building rather than relying only on static checks. Do not add external conformance tests to ordinary unit-test targets.

## CI, Commits, and Pull Requests

CI installs with `pnpm install --frozen-lockfile` and runs `pnpm test` on pull requests and `main`. A separate workflow builds, initializes the CLI, and runs issuance conformance against PagoPA's `wallet-conformance-test`.

Keep commits focused and imperative. Current history commonly uses conventional prefixes, for example `feat(conformance): ...`, `tests(matrix): ...`, and `chore: ...`.

Follow `.github/pull_request_template.md`: state the changes, motivation/context, and verification; link related issues and mention documentation updates. Request review from owners in `CODEOWNERS` when applicable.

## Security and Local Data

Never commit credentials, certificates, generated reports, `.env`, `config.ini`, or `.itw-conformance-tool/` contents. Treat captured conformance events and artifacts as potentially sensitive protocol data. Regenerate local configuration through `pnpm init` instead of checking in a working copy.

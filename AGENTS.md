# Repository Guidelines

## Project Structure & Module Organization

This repository is a pnpm + Nx TypeScript monorepo for the IT Wallet conformance tool. Runnable services live under `apps/`: `apps/itw-credential-issuer`, `apps/itw-relying-party`, and `apps/itw-trust-anchor`. Shared libraries live under `packages/`, currently `packages/logger`. Application code is in each project’s `src/` directory, with Fastify routes under `src/routes` and external plugins under `src/plugins/external`.

## Build, Test, and Development Commands

Run commands from the repository root.

- `pnpm install`: install workspace dependencies.
- `pnpm build`: build all Nx projects with a `build` target.
- `pnpm typecheck`: run TypeScript checks across projects.
- `pnpm lint`: run ESLint across projects.
- `pnpm test`: run Vitest for projects with tests.
- `pnpm issuer`: serve `itw-credential-issuer`.
- `pnpm rp`: serve `itw-relying-party`.
- `pnpm trust-anchor`: serve `itw-trust-anchor`.
- `pnpm nx run itw-credential-issuer:test`: run one project target.
- `pnpm format`: format JS, TS, JSON, and Markdown with Prettier.

Use Node.js `22` from `.nvmrc` and pnpm `11.13.1`.

## Coding Style & Naming Conventions

Use TypeScript ESM (`"type": "module"`) with strict compiler settings from `tsconfig.base.json`. EditorConfig requires UTF-8, two-space indentation, final newlines, and trimmed trailing whitespace. Prettier uses single quotes, semicolons, `printWidth: 120`, bracket spacing, and no trailing commas.

ESLint enforces Nx module boundaries and alphabetized import groups via `eslint-plugin-perfectionist`. Avoid `console`; it is a warning. Prefer project-local aliases and workspace dependencies over relative cross-project imports.

## Testing Guidelines

Tests use Vitest in a Node environment. Name test files `*.spec.ts` or `*.test.ts` and place them under `src/` or `tests/`; colocated `__test__` folders are already used in migration code. Coverage uses the V8 provider and writes to each project’s `test-output/vitest/coverage`. Add focused tests for protocol logic, route behavior, and shared library changes.

## Commit & Pull Request Guidelines

Recent history uses short imperative summaries, sometimes with conventional prefixes such as `chore:`. Keep commits focused, for example `chore: update CODEOWNERS` or `add itw-relying-party app`.

Pull requests should follow `.github/pull_request_template.md`: include a clear list of changes, motivation and context, and how the change was tested. Link related issues when available, note documentation updates, and request review from CODEOWNERS for touched areas.

## Security & Configuration Tips

Do not commit secrets or local environment files. Start from each app’s `.env.example` and keep real values in untracked `.env` files.

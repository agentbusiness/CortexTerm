Resolve Node.js, npm, pnpm, yarn or runtime-manager version and package problems.

## Inspect

Use `command -v node`, `node --version`, and the selected package manager's version. Read `package.json` fields for engines, packageManager and scripts; inspect the existing lockfile. Check any observed `.nvmrc` or tool-version file. Several installed binaries do not establish which one the project expects.

Do not print `.npmrc` tokens or every environment value. An install may run lifecycle scripts. `npx`, `npm exec` and similar commands may download and execute a package; they are not read-only discovery tools.

## Propose

Use the project's current runtime and package manager. Give one scoped user-run operation. Preserve the lockfile unless the task calls for dependency changes. Do not delete a lockfile or run a forced audit fix as a generic repair.

## Verify

Recheck the resolved runtime and package manager. Then repeat the original intended command through the correct project workflow. Read its exact failure if it persists. Installation alone does not prove a development server starts. Hand application-code changes to CortexCode.

Diagnose a dependency or build failure from the recorded command and its first useful error.

## Inspect

Use the failed Run's exact command, directory, exit status and output. Read the relevant manifest, lockfile and toolchain declaration. Inspect installed tool versions with read-only commands. Separate command-not-found, unsupported architecture, missing system library, dependency resolution and source-code errors.

A later cascade of errors may follow one earlier failure; use a narrow log range around that first relevant failure. Do not infer an out-of-memory condition or missing library from an exit code alone.

## Propose

Keep the person's original goal. An install, build, dependency refresh or project script can write files and execute code, so offer it for the person to run. Do not remove lockfiles, caches or all dependencies as a first repair. Hand source changes to CortexCode on this repository's machine.

## Verify

Read the next actual result. Package installation, compiler success, application startup and working behavior are separate outcomes. State only the observed outcome. If the person prohibited a build, do not run it or describe source parsing as a successful build.

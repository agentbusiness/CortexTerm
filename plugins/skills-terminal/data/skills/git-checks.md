Explain a failed lint, type, test or other development check and hand off code repairs.

## Inspect

Read the recorded check command, working folder, exit code and decisive output. Inspect the project's declared check commands and relevant configuration. A missing test selection or no matches may be an ordinary tool result; check that tool's meaning before naming a code failure.

Identify the failing stage and concrete location. Distinguish formatting, syntax, type, behavior and environment failures. A test failure does not automatically identify which implementation is wrong; an expectation may also be stale.

## Propose

Hand code changes to CortexCode with the exact command, error, file and intended behavior. Do not silently weaken a check, skip tests, update snapshots or remove assertions to obtain green output. Rerunning checks is a user-run proposal when it executes project code or changes output.

## Verify

Use the next actual check result. A source review or syntax parse is not a passing suite. Preserve any explicit no-build or no-test instruction. If only one scoped check ran, state that scope and leave broader runtime behavior unclaimed.

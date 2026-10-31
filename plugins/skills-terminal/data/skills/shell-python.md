Resolve Python, virtual environments, pip or uv installation and dependency problems.

## Inspect

Use `command -v python3`, `python3 --version`, and `python3 -m pip --version` if available. Inspect `pyproject.toml`, an existing lockfile and the selected environment before choosing a manager. Do not print all environment variables; inspect the executable path and `VIRTUAL_ENV` only when needed.

A package installed for one interpreter may be absent from another. An externally managed system Python should not be repaired with global sudo pip or a bypass flag. `uv`, pip, Poetry and Conda have different environment and lock workflows.

## Propose

Use the project's existing manager. A new isolated environment is a user-run change. Keep installation separate from executing project scripts: an apparently simple package command can run build hooks. Do not regenerate lockfiles or upgrade everything to fix one missing dependency.

## Verify

Check interpreter and package metadata inside the chosen environment. Import a known trusted module only when its execution is appropriate; importing code can have effects. Confirm the original command works with the intended interpreter. Hand source-code repairs to CortexCode on the repository's machine.

Build a pipeline and explain stdin, stdout, stderr, redirection and exit status.

## Inspect

Read the whole command, including every redirect. `|` sends stdout to the next program; stderr remains separate unless redirected. `>` replaces a file; `>>` appends. Redirection order matters: `2>&1` copies the destination stdout has at that point.

Use bounded read examples. `grep` exit 1 means no match. A writer may receive SIGPIPE when `head` exits early; that alone does not prove its input operation failed. Without a shell's pipeline-failure option, the last command's status may hide an earlier failure.

## Propose

Keep the pipeline as short as the task permits. Use a structured parser for JSON, CSV or XML rather than splitting arbitrary text on spaces. Do not pipe unreviewed filenames into changing commands. Prefer inspecting output before adding a write stage.

If the person's goal is to save output, explain which file will be created or overwritten. After they run it, inspect the file and relevant exit results. A nonempty output file is not proof every pipeline stage succeeded.

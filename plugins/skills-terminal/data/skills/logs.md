Find relevant failure evidence in macOS, Linux or application logs with bounded output.

## Inspect

Establish target, application, time window and time zone. `run` shows about 60 lines and 4000 characters; select relevant records before that limit. Never use `tail -f`, `log stream` or `journalctl -f` here.

On Linux: `journalctl -u <observed-unit> -n 40 --no-pager`; add an appropriate `--since` when needed. On macOS: a short `log show --last 10m --style compact --predicate 'process == "<name>"'` query. For a known file: `tail -n 40 '<path>'`, then a small range around a relevant match.

Use structured fields or request IDs when logs are JSON or interleaved. Filter tokens, passwords, session cookies and private payloads before output. Read compressed logs with the installed format's supported reader.

## Interpret

Quote the decisive line with its time and explain what it establishes. A first visible error can itself be a consequence of an earlier event outside the range. Correlate related records before assigning a cause. No match does not prove no failure occurred.

Preserve logs during investigation. After a user-run repair, check fresh records and the original operation rather than relying on an old error disappearing.

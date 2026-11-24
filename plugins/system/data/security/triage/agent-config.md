An AI agent setting changed: auto-approve, a bypass flag, an MCP server, or a hook in .claude/settings.json.

Questions:
- user_started: did the person set it? Yes when parent is terminal, editor, or agent or node, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- settled: has it stayed the same? Yes when seen_days is 7 or more.
- plain_command: does it run a plain tool? Yes when what shows a local path, a formatter, linter or sound. No when what shows curl, wget, base64, node -e or temp.
- from_install: did a package install write it? Yes when seen_days is 0 and parent is installer or unknown.
- pinned: is the MCP server pinned? Yes when what shows a fixed version or local path.

normal: plain_command yes, and user_started yes or settled yes.
fix: plain_command yes but pinned no; write "pin <server> to a fixed version in <file>".
threat: plain_command no, or from_install yes; write "remove the hook or MCP entry from <file>".
unsure: plain_command unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when a hook or MCP command fetches or decodes code (curl, wget, base64). Names in what never decide.

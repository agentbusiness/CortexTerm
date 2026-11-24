A secret is stored where it can be stolen: shell history, credential files, .env files, Docker auths or loose tokens.

Questions:
- tool_store: is it a tool's usual owner-only store? Yes when path_class is home_hidden and what says owner-only or a credential helper.
- local_env: is it a local development value? Yes when path_class is project and what says a .env ignored by git.
- exposed: can others or git see it? Yes when what says others can read it, git tracks it or shell history, or path_class is shared or temp.
- gathered: were many tokens gathered into a new file? Yes when seen_days is 0, count is over 3, and parent is not terminal or editor.

normal: tool_store yes, or local_env yes.
fix: exposed yes; write "chmod 600 <file>" or "git rm --cached <file> and rotate the key".
threat: gathered yes; write "move <file> to the Trash and rotate every token in it from another device".
unsure: exposed unknown.
Most findings of this kind on a developer's Mac are fix; pick threat only when many tokens appear together in a new file not made from the terminal or editor.

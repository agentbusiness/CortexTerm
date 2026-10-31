Search file contents for a word, setting, error or regular expression.

## Inspect

Choose the smallest relevant file or folder. For exact text use `rg -n -F -- '<text>' '<path>'`. For a pattern, use `rg -n -- '<pattern>' '<path>'`. Add a small context window such as `-C 2` when a match needs surrounding lines. Check availability before choosing ripgrep; `grep -n -F` works for one file without it.

Quote the search text. A literal string is not a regular expression. Exclude secrets, generated output and unrelated folders from broad searches. Limit output before the model's 60-line window; narrow the search if there are many matches.

## Interpret

Exit 1 normally means no match; it is not a broken command. Exit 2 or a named inaccessible file needs the actual error. A match in documentation or a comment may not control the running application.

Report the file, line and relevant text. For an edit, inspect the effective configuration and use a narrow `config` preview. Never turn search output directly into a bulk replacement.

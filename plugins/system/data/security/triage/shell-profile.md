A line that runs by itself: shell rc files, /etc/paths.d, cron, at, git hooksPath, an .npmrc registry or tasks.json.

Questions:
- setup_line: is it a usual setup line? Yes when what shows a PATH or init line for Homebrew, nvm, pyenv, conda or rustup.
- fetches_code: does it fetch or decode code? Yes when what shows curl or wget into a shell, base64 or osascript.
- runs_on_open: does a project task run on folder open? Yes when what says so for tasks.json.
- points_out: does it point outside lately? Yes when seen_days is 0 and it points outside the project.
- settled: is it old? Yes when seen_days is 7 or more.

normal: setup_line yes, or settled yes and fetches_code no.
fix: a line for a tool no longer installed; write "remove the line from <file>".
threat: fetches_code yes, runs_on_open yes, or points_out yes; write "remove the line from <file> and do not open that project".
unsure: fetches_code unknown and settled no.
Most findings of this kind on a developer's Mac are normal; pick threat only when the line fetches code (curl, wget, base64) or runs a task on folder open.

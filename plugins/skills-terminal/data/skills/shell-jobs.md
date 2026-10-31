Explain a foreground job, background job, stopped process, nohup or terminal multiplexer.

## Inspect

Use current terminal output first. `jobs` refers to jobs of the shell where it runs; a separate `run` shell cannot inspect another shell's job table. Use observed PIDs with `ps -o pid,ppid,stat,etime,command -p <pid>` for process facts.

Ctrl-C normally interrupts the foreground job. Ctrl-Z usually stops it; it has not finished. `fg` and `bg` affect that shell's jobs. An ampersand backgrounds a command but does not promise it survives logout. A service manager is usually better for a durable application.

## Propose

Give the person the appropriate shell action and explain its effect. Use an observed PID rather than a stale job number from another shell. Check ownership before stopping anything. For a supervised process, use its service manager instead of repeatedly killing the child.

## Verify

Check whether the intended process is running, stopped or finished. Use a multiplexer only when the user needs an interactive session to survive disconnection; do not silently introduce one into an existing deployment.

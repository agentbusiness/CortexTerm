# cortexterm

```sh
npx cortexterm
```

Starts [CortexTerm](https://github.com/agentbusiness/CortexTerm), an AI terminal with a local model. The first
run downloads the app for this machine (Apple Silicon Macs; Linux x64 and arm64) from the official
releases, checks it against the checksum in the release catalog and unpacks it into `~/.cortexterm/app/`.
Later runs start the installed app at once; the app updates its frame and plugins itself. The app
runs on its own: you can close the terminal (its start output goes to `~/.cortexterm/logs/start.log`);
running the command again while it runs only says so.

Arguments go to the app: `npx cortexterm --headless`, `npx cortexterm --safe`.

## A Mac nobody sits at: the runner

```sh
npx cortexterm runner
npx cortexterm runner join <invitation>
```

`runner` keeps CortexTerm running on this Mac without a window, now and at every login (a LaunchAgent,
`~/Library/LaunchAgents/com.cortexterm.runner.plist`; its output goes to `~/.cortexterm/logs/runner.log`).
`runner join` joins it to your network with an invitation made in Settings > Mesh on another computer.
The other computers then list it under COMPUTERS and open shells on it. `npx cortexterm runner off`
stops it. On Linux, start it with `npx cortexterm --headless` for now.

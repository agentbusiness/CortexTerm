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

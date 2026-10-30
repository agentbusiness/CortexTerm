macOS specifics: settings with `defaults`, launch agents, Homebrew, Gatekeeper, permissions, system info.

## Facts (with `run`)

- Version and hardware: `sw_vers; uname -m; sysctl -n machdep.cpu.brand_string hw.memsize`.
- Disk: `df -h /`. Battery: `pmset -g batt`. Uptime: `uptime`.
- Homebrew: `brew --prefix` (`/opt/homebrew` on Apple silicon, `/usr/local` on Intel), `brew list --versions <name>`, `brew info <name>`, `brew outdated`.
- Which binary runs: `which -a <name>`. Several copies (Homebrew, system, nvm, pyenv) are the usual cause of "wrong version".
- Login items and background jobs: `launchctl list | grep -v com.apple`, files in `~/Library/LaunchAgents` and `/Library/LaunchDaemons`.
- A setting: `defaults read <domain> <key>`. Find the domain: `defaults domains | tr ',' '\n' | grep -i <app>`.

## BSD tools, not GNU

`sed -i ''` (not `sed -i`), `date -v-1d` (not `date -d`), `stat -f %z` (not `stat -c %s`), `du -d 1` (not `--max-depth`), no `free` (use `vm_stat` or `memory_pressure`), no `timeout` (`brew install coreutils` gives `gtimeout`).

## Changes (theirs to run)

- `defaults write <domain> <key> -<type> <value>`, then restart the app (`killall Dock`, `killall Finder`). Show the `defaults read` of the old value first so they can go back.
- "can't be opened because Apple cannot check it": `xattr -d com.apple.quarantine /path/App.app` only for an app they trust and downloaded on purpose. Say so.
- "Operation not permitted" on a file in Desktop, Documents, Downloads or another app's data: the terminal app needs Full Disk Access (System Settings > Privacy & Security). `sudo` does not help.
- `sudo` with Touch ID: the line `auth sufficient pam_tid.so` in `/etc/pam.d/sudo_local` (copy from `sudo_local.template`).
- Never suggest turning off SIP or Gatekeeper as a fix.

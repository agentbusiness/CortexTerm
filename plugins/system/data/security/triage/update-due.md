Software is out of date or past end of life: macOS, Safari, an app, a runtime, or XProtect rules.

Questions:
- waiting_restart: is an update already waiting? Yes when severity is low or info and seen_days is under 14, or what says relaunch or restart.
- kept_runtime: is an older runtime kept on purpose? Yes when path_class is toolchain or homebrew and what shows nvm, pyenv, rustup or asdf.
- end_of_life: is it past end of life? Yes when what says end of life.
- xprotect_behind: are malware rules behind? Yes when rule or what says XProtect.
- exploited: is the hole known to be used? Yes when rule or what says exploited.

normal: kept_runtime yes, or waiting_restart yes.
fix: every other case; write "softwareupdate -i -a" for macOS or Safari, "sudo xprotect update" when xprotect_behind yes, "brew upgrade <name>" for Homebrew, "update <app> from its menu", or "replace <software>" when end_of_life yes.
threat: exploited yes; write "install the update now: softwareupdate -i -a".
unsure: never; an update is upkeep.
Most findings of this kind on a developer's Mac are fix; pick threat only when what says the hole is exploited.

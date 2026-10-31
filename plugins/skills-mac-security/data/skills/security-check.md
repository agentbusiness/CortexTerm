Check requested Mac security areas and explain findings, missing coverage and result age.

Call `run` with the full path and only the relevant areas:

`~/.cortexterm/live/plugins/skills-mac-security/data/scripts/macsec check <areas>`

Choose from their words:
- Firewall, FileVault, Gatekeeper, SIP, lock or sharing: `settings`; old versions: `updates apps packages`.
- Malware: `malware`; login/startup items: `persistence`; camera/microphone/access grants: `privacy`.
- Strange logins/sudo: `intrusion`; ports, DNS, VPN or connections: `network`; AI/MCP: `agents`.
- SSH keys: `ssh`; exposed credentials: `secrets`; hacked/strange executed command: `malware persistence intrusion network agents`.
- General check: `settings updates malware persistence`; explicitly everything: `all`.

Use the first-line count, numbered findings, `NOTES`, `Not checked` and cached sweep times. A failed area does not erase successful areas. A failed command is not a completed check. Do not fill missing evidence from memory.

Answer their question first. Explain the most important findings with the actual names. Group repeated low-priority findings. Offer the worst finding's supplied fix in one `sh` block; it has not run. Mention unshown findings, unavailable areas and cached times when present.

“No findings” means “The check reported no findings in these checked areas.” It does not establish that the Mac is clean or that an attack never happened. A fresh `--full` check takes minutes and is a command for the person to run. For incident response, read `security-incident`.

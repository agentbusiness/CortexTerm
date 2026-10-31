Suspected Mac compromise or a strange executed command: inspect evidence and guide recovery.

First call `run`:

`~/.cortexterm/live/plugins/skills-mac-security/data/scripts/macsec check malware persistence intrusion network agents`

Read the findings, `NOTES`, missing areas and cached sweep times. Report a failed or partial check precisely. With no findings, say only that the checked areas reported none; this does not rule out compromise.

If they still have the command, tell them: “Paste it into CortexTerm's command line without pressing Return; the paste guard shows what it does.” Never execute it for diagnosis.

Choose only steps supported by the situation:
1. Evidence of ongoing theft or active compromise: disconnect the affected Mac while preserving a way to get help. A generic HIGH label alone does not prove exfiltration.
2. A stealer, stolen secret, or untrusted downloaded program was executed: use a different trusted device to change important passwords, revoke sessions and enable two-factor sign-in.
3. Revoke exposed API tokens and SSH credentials, then replace them. Move exposed wallet assets only to a wallet created on a trusted device.
4. Offer the findings' supplied remediation, highest consequence first. Preserve evidence needed for investigation before removal. The person runs changes; never claim they ran.
5. For remaining uncertainty, offer a fresh full check: the full-path `macsec check malware persistence --full`. It takes minutes and belongs to the person to run.

State what the checks established and what they could not see. Do not name malware, claim data theft or invent recovery versions without evidence. Keep the next action short and calm.

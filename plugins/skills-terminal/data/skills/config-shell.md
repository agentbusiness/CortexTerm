Edit shell startup configuration, aliases or exports without executing untrusted text.

Identify the actual shell and startup mode before choosing a file: zsh and bash read different files, and login/interactive shells differ. Inspect with format `shell`.

Read surrounding conditions, functions and quotes. A startup file is executable code. Do not `source` it to inspect or test an untrusted change. Preserve quoting: a literal dollar sign and an expanded variable have different effects.

Preview one unique non-secret block with the inspect hash. Replace an existing export instead of appending repeated copies. Do not silently change every shell's startup file.

The helper does not execute or validate shell syntax. Offer the actual shell's non-executing syntax check, such as `zsh -n <file>` or `bash -n <file>`, using the observed path. A syntax check does not prove startup side effects are acceptable.

After user apply, test in a separate new shell while keeping the current terminal open. Check the intended alias or executable path. Restore from the private backup only after comparing the current revision.

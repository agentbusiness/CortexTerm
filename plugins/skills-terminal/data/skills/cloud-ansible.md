Inspect Ansible inventory, playbook scope, variables, check mode and a proposed host change.

## Inspect

Identify Ansible version, inventory source, intended hosts and playbook. Read relevant tasks, roles and handlers without exposing Vault content or secret variables. Dynamic inventory and lookup plugins execute code or query services; inspect them before treating inventory discovery as read-only.

Check become behavior, connection user, tags, serial/batch settings and variable precedence. Use a known literal host limit. A matching inventory name does not prove the destination is the expected machine.

## Propose

Offer a user-run check/diff operation only after reviewing tasks. Check mode is partial: modules can lack support, conditions can lack registered results, and `check_mode: false` tasks can still change systems. Diff output can expose secrets; keep those tasks protected. Do not describe `--check` as a universal safety guarantee.

## Verify

Review the reported changes, then propose the scoped real application when intended. Confirm actual host facts and service behavior afterward. A successful play recap is not proof the application works. Do not weaken failed conditions or increase privilege to conceal an error. Hand playbook-code changes to CortexCode.

Edit Terraform/OpenTofu HCL and separate formatting, validation, planning and applying.

Identify Terraform or OpenTofu, installed version, workspace, backend and provider pins. Read the relevant block and variable definitions. Never infer the active cloud account from a filename.

Inspect with format `hcl`. Preserve expressions and types: a resource reference is not a quoted label, and a sensitive variable is not a place to paste a credential. Read modules and overrides that affect the proposed value.

Preview one unique block with the inspect hash. The helper does not parse HCL or run providers. It changes only the file when the person applies its command.

Offer the selected tool's formatting check and validation. Initialization can fetch providers and write local state; it remains a user-run step. A plan can contact providers and reveal sensitive data. Limit its scope and protect output.

Review the actual plan, including replacements and deletions, before any infrastructure apply. Saving HCL has not deployed it. Verify real resources after an authorized apply. Restoring the file does not automatically restore infrastructure or state.

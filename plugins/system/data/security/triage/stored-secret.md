A secret is stored where it can be stolen: shell history, credential files, .env files, Docker auths, or tokens with loose permissions.

Means: Stealers and npm worms search these places first.
A secret here is a real risk even if nothing happened yet.

Normal when:
- path_class project, `what` says a .env ignored by git with local development values.
- path_class home_hidden, owner-only permissions, a tool's usual token store (gh, gcloud, aws, npm).
- Docker auths where `what` says a credential helper (the keychain) holds the token.

Suspicious when:
- other users or groups can read it, or path_class shared or temp.
- a cloud, GitHub, npm or AI provider token in shell history or a file git tracks.
- seen_days 0, parent not terminal or editor: many tokens gathered into one new file (worms do this before upload).

Never decide from: names or values that look like "test", "example" or "dummy".
Precedent: a match with the same rule and path_class supports the same verdict, never over a suspicious fact.
When unsure: escalate.

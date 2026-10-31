MongoDB connection failures, authentication errors, TLS, replica sets, or SRV addresses.

## Inspect

Identify deployment type, server/client versions, intended database, authentication database, replica-set name and target network. Read only the non-secret parts of an existing connection profile. Never print a credential-bearing MongoDB URI.

Use `mongosh --version`. With established noninteractive credentials, `mongosh '<non-secret-observed-URI>' --quiet --norc --eval 'db.runCommand({ping:1})'` is a short connection check against the observed endpoint. Keep credentials out of the URI. Set `connectTimeoutMS=5000` and `serverSelectionTimeoutMS=5000` in that URI, preserving existing options. If credentials would prompt, give the command to the user. Do not run an interactive shell through `run`.

## Interpret

A ping confirms a server response, not permission to read the intended collection. DNS/SRV, TCP, TLS and authentication fail at different stages. Inside a container, localhost names that container. A wrong `authSource` can fail even when the password is correct.

## Verify

Confirm the selected database and intended deployment using bounded, non-secret identity output permitted to the role. Propose one correction. Repeat connection and a small authorized query afterward. Do not disable TLS verification or add global administrative access as a shortcut.

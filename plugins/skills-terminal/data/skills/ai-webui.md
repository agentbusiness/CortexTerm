Deploy or diagnose Open WebUI with an existing model provider and persistent application data.

## Inspect

Identify the installed release, method, provider and data location. Use existing container/service state and bounded logs. Read only relevant config fields. Check public URL, provider base URL, authentication, network path and persistent storage; do not print secrets or private chats.

Prefer connecting to the existing compatible model holder. Do not select an image that starts a bundled second runtime merely because it is convenient. The web application's resource needs are separate from model, embedding and container-VM memory.

## Propose

Use the selected release's official deployment and update procedure with explicit image versions. Preview provider/config changes. Preserve users, chats, application keys and persistent data before replacing a container. Do not fix access by disabling authentication or exposing the model API to the internet.

## Verify

Check UI health, sign-in and a representative provider request. A browser page or container health result alone is not generation success. Diagnose uploads, retrieval and embeddings separately if used. Keep a compatible data backup and prior application release; image rollback alone may not reverse database migrations.

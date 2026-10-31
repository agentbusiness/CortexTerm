Configure or diagnose a chosen llama.cpp, vLLM or other inference service and its API.

## Inspect

Identify the existing holder, runtime version, model artifact, startup command and target hardware. Check the installed binary's help before selecting flags; names and defaults change. Inspect bounded startup logs and service state. Do not start a second model service beside an active Cortex model holder.

Establish bind address, port, authentication, API compatibility, context, batching and resource limits. vLLM, llama.cpp and Ollama are different runtimes; do not transfer flags between them. For distributed serving, distinguish model, worker and network failures before tuning.

## Propose

Preview the actual service configuration and offer the next user-run action. Preserve the selected model and shared-services rules. Do not enable public unauthenticated access, privileged containers or excessive GPU allocation to make a request work. A runtime install or model load is not a read-only diagnostic.

## Verify

Confirm model readiness and a representative request through the intended client. Then check streaming or tool calling only when needed. A port response does not prove those capabilities. Report measured behavior separately from configuration validity or theoretical capacity.

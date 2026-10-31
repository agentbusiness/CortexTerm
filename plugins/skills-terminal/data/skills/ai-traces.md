Inspect AI request traces, latency, token use, errors and access limits from recorded evidence.

## Inspect

Identify application, provider/runtime, model, request ID and time window. Read bounded trace fields and errors with secret/prompt filtering. Distinguish queue wait, model load, prompt processing, generation, tool work and network time when measurements exist.

Token counts depend on the actual tokenizer and reported usage. A character count is only an estimate. Cached input, retries, streaming and concurrent work can change latency and accounting. Local inference has resource costs even without a billed API price. Do not invent throughput, savings or monetary rates.

## Propose

Choose one measured bottleneck and a scoped change: context selection, queue/concurrency setting, timeout or application limit. Preserve necessary evidence and permissions. Changing models, exposing an endpoint or removing authentication is not a generic optimization. CortexTerm keeps its single-holder model-sharing behavior.

## Verify

Compare the same workload before and after, with actual timestamps, usage and task outcome. One quick request is not sustained performance. Distinguish lower latency from correct tool use or answer quality. Access-control changes need an authorized allowed/denied check; do not run unrelated private requests.

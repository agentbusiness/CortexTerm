Diagnose model memory, GPU, Metal, CUDA, context or concurrency limits on the actual host.

## Inspect

Establish runtime, version, model format, quantization, context setting and concurrent work. Use current model-holder facts and bounded logs. On an NVIDIA host, `nvidia-smi` can show driver, memory and processes; it does not establish every CUDA library is compatible. On macOS use machine/model metrics and runtime logs, not NVIDIA commands.

Separate weights, context cache, temporary buffers and other processes. An advertised model size does not include every runtime allocation. GPU and host memory reporting can overlap. A container memory limit or Docker VM allocation can fail before the physical machine is full.

## Propose

Offer one evidence-based setting change, such as a supported context or concurrency reduction. Explain its effect on the task. Do not increase memory use, disable protections or start another model as a generic repair. CortexTerm keeps one model holder per machine.

## Verify

Repeat the original workload and record actual allocation, latency and result. Lower memory use alone is not a speed or correctness improvement. Distinguish startup success, one completed request and sustained workload behavior.

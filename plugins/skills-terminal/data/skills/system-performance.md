Investigate CPU, memory, swap or disk pressure using bounded measurements.

## Inspect

Use current machine metrics first. On macOS, `vm_stat`, `memory_pressure` and `top -l 1 -n 10` provide snapshots. On Linux, `free -h`, `vmstat 1 3` or `ps` with supported sorting can help. Check tools and platform before choosing flags.

Measure the relevant interval, not just one peak. Identify the owning application before blaming a process. RSS, compressed memory, cache, swap and GPU allocations describe different things; adding overlapping numbers can double-count memory. A container limit can be reached while the host has free memory.

## Interpret

State the observed bottleneck and uncertainty. High CPU can be useful work. Freeing caches may only move the cost to the next operation. For a suspected process leak, compare repeated measurements under a known workload.

## Propose and verify

Offer one scoped change based on evidence. Stopping an application or changing limits is the person's action. Repeat the same measurement and original task afterward; do not claim a speed improvement from a lower memory number alone.

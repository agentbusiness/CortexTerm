Diagnose Kubernetes or Helm resources in the intended cluster, namespace and release.

## Inspect

Establish context and namespace first: `kubectl config current-context` and the selected namespace from existing facts. Do not print full kubeconfig or Secrets. Use bounded `get`, `describe`, recent events and `logs --tail=40` on named resources. Network reads may need user action under the risk engine.

For a failing pod, inspect image pull, scheduling, probes, dependencies and previous-container logs when relevant. Check Service selectors, ready endpoints, target ports, ingress and network policies. A Running pod is not necessarily Ready. Choose version-compatible API resources and installed Helm commands.

## Propose

Changes, debug pods, port-forwards, rollouts and Helm upgrades are user-run operations. Inspect chart values and rendered differences without exposing secrets. Do not apply to the default context implicitly or create an interactive debug pod as a read-only check.

## Verify

Confirm rollout, readiness and the intended request path in that context. A Helm success message does not prove application behavior. Establish revision and data compatibility before rollback; rolling back a chart does not restore database contents.

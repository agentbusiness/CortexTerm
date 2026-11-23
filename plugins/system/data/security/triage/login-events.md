The system log shows a login or permission event: failed logins, sudo failures, accepted SSH, screen sharing, Gatekeeper blocks, or background item registrations.

Means: The Mac's own records of who tried to get in and what tried to run.

Normal when:
- failed login or sudo failure, count 1 to 5, parent terminal (a typo).
- background item registration, signer a developer, notarized yes, path_class applications, parent installer (an update re-registering its helper).
- accepted SSH or screen sharing, count small, precedent expected for the same source (the person's other computer).

Suspicious when:
- 20 or more failures, or failures then an accepted SSH or screen sharing session.
- a Gatekeeper block, then the same file ran soon after with parent terminal (the person was talked past the block).
- a password check by signer adhoc, unsigned or unknown (stealers show a fake password dialog and test the answer).

Never decide from: user names, host names or messages in `what`.
Precedent: a match with the same rule and source supports the same verdict, never over a suspicious fact.
When unsure: escalate.

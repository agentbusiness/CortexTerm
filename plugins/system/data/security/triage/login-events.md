The system log shows a login event: failures, accepted SSH or screen sharing, Gatekeeper blocks, or background items.

Questions:
- few_failures: is it a few typos? Yes when what shows 1 to 5 failures and nothing accepted.
- many_then_in: did many failures come before a login? Yes when what shows 20 or more failures, then an accepted session.
- known_source: is the login from a known source? Yes when a precedent says normal for the same rule and source.
- block_then_ran: was a Gatekeeper block bypassed? Yes when what shows a block, then the same file ran.
- fake_prompt: did an unknown program check the password? Yes when signer is adhoc, unsigned or unknown.

normal: few_failures yes, or known_source yes, or a background item with parent installer.
fix: an accepted session that is not needed; write "turn off Remote Login in System Settings > General > Sharing".
threat: many_then_in yes, block_then_ran yes, or fake_prompt yes; write "turn off Remote Login and change the login password".
unsure: an accepted session with known_source unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when many failures end in an accepted session.

# For upstream

`0001-fix-rsa-padding.patch` is a real bug fix and stands on its own — it has nothing
to do with PKCS#11 and applies cleanly to upstream.

Send it as a small pull request rather than pointing at this fork. A two-line fix with a
clear rationale gets read; a fork with a new key backend, a test harness and a runbook
is a different conversation, and bundling them makes both harder to accept.

The DER-not-PEM point in the upstream README is worth a separate one-line
documentation PR too.

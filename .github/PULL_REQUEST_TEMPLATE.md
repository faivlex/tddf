<!--
Thanks for contributing to TDDF. Please fill in the sections below so reviewers
can understand and verify your change quickly. Delete sections that do not
apply.

Security fixes: do not open a public PR. Use private vulnerability reporting
(see SECURITY.md) so we can coordinate disclosure.
-->

## Summary

<!-- One or two sentences: what does this PR do and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behaviour change)
- [ ] New scenario / trap / payload
- [ ] Docs / examples only
- [ ] Build / CI / tooling

## Linked issues

<!-- e.g. Closes #123, Refs #456. Use "Closes" for issues this PR fully resolves. -->

## Test plan

<!--
How did you verify this change? List the commands you ran and what they showed.
For new features: which tests cover the new code paths?
For bug fixes: which test reproduces the bug and passes after the fix?
-->

- [ ] `pytest` passes locally
- [ ] `tddf validate` / `tddf run` exercised on the touched paths (if applicable)
- [ ] Docs / README updated (if user-visible behaviour changed)

## For scenario / trap contributions

- [ ] Anchored in a documented attack pattern (CVE, paper, named benchmark)
- [ ] Upstream license + attribution added to `THIRD_PARTY_LICENSES.md` (if derived)
- [ ] Severity level set appropriately

## Notes for reviewers

<!-- Anything reviewers should pay particular attention to: tradeoffs, follow-up work, areas of uncertainty. -->

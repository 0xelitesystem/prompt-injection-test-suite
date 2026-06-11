# Contributing a Test

## Submission

1. Pick the most-fitting category folder under `tests/`
2. Copy an existing test as your template
3. Update all fields
4. Open a PR

If your test doesn't fit any existing category, propose a new category in an issue first.

## Required fields

```yaml
id: <category-NNN>           # incrementing within category
category: <category>         # must match the folder
severity: low|medium|high|critical
goal: <one sentence describing what the attacker wants>
payload: |
  <the attack payload, as the user/system would see it>
expected_pass: |
  <what a correctly-defended model should do>
notes: |
  <context, defense suggestions, why it works>
source: <citation to public research, blog post, or "common pattern">
```

## Severity guide

- **critical**, successful attack causes data exfiltration, unauthorized actions, or harm to users
- **high**, successful attack bypasses content policy or impersonates the system
- **medium**, successful attack changes the model's behavior in ways the user didn't intend
- **low**, exotic technique that mostly fails on modern models but is worth tracking

## Responsibility guidelines

- **Only submit attacks already documented in public research.** This is not a place for novel zero-days. If you've discovered something new, responsible disclosure to model vendors comes first.
- **Cite the source.** "Standard pattern in prompt injection literature" is acceptable; outright plagiarism of someone's writeup without credit is not.
- **Don't target specific products.** Tests should demonstrate generic technique classes, not exploit specific deployed systems.
- **Don't include payloads that produce harmful output if they succeed.** Test that the model declines to produce CSAM, weapons synthesis, etc., not test payloads that include sample harmful content.
- **Sample variables.** When the attack would normally embed a real harmful target ("how to make X"), use `[target]` or `X` as a placeholder.

## What gets rejected

- Payloads with actual harmful content (use placeholders instead)
- Attacks targeting specific named products or deployed systems
- Vague descriptions that don't help readers understand the technique
- Duplicate of an existing test (improvements to existing tests are welcome as updates, not new entries)
- Personal vendetta content disguised as an attack test

## Updating an existing test

When attacks evolve, test entries should evolve. Same flow; title format: `update test: id`. Bump the version implicit in the source citation if relevant.

## Removing a test

If a test becomes obsolete (model class no longer susceptible, technique is no longer plausible), open an issue first. Removed tests should be archived in `tests/_archived/` with a note explaining why, not deleted entirely (so people can see the history).

## Test quality bar

The test is good if a security researcher reading it can:
- Understand what the technique is
- Reproduce a similar test against their own product
- Know what defense generally catches it
- Cite the source for further reading

# prompt-injection-test-suite

A categorized corpus of prompt injection attempts. Use to test your LLM product's defenses before attackers do.

## What this is

Public examples of prompt injection attacks, organized by category and severity. Each entry includes:

- The attack payload
- Category (direct, indirect, encoded, multi-language, etc.)
- Expected attacker goal (data exfiltration, role override, tool misuse, etc.)
- Severity (low / medium / high / critical)
- Notes on what defenses typically catch it

The point is to give product teams a known testbed so they can:

- Benchmark their guardrails
- Add regression tests when their model is updated
- Discuss specific attack classes with concrete examples
- Train red-teamers without starting from scratch

## What this is NOT

- **Not an attack toolkit.** Every example here is documented in public security research. Nothing novel or weaponized.
- **Not exhaustive.** The space of possible injections is unbounded; this is a representative sample.
- **Not a guarantee.** A model passing all tests here is not "injection-proof." New techniques appear constantly.
- **Not a substitute for red-teaming.** Use this as a baseline, then go beyond.

## Who this is for

- Application developers building on LLMs (test what your prompt does under attack)
- Security researchers (a shared baseline to compare techniques)
- Product / safety teams (concrete examples for risk discussions)
- Educators (teaching material, with citations)

## Categories

| Category | Description |
|---|---|
| [`direct/`](./tests/direct) | User directly asks the model to ignore prior instructions |
| [`indirect/`](./tests/indirect) | Injection via documents, web pages, or tool output the model reads |
| [`encoded/`](./tests/encoded) | Payload obscured via base64, ROT13, leetspeak, or other encoding |
| [`role-confusion/`](./tests/role-confusion) | Attempts to convince the model it is a different system |
| [`tool-misuse/`](./tests/tool-misuse) | Attempts to get the model to misuse tools it has access to |
| [`data-exfiltration/`](./tests/data-exfiltration) | Attempts to leak system prompt, prior conversations, or context |
| [`multi-language/`](./tests/multi-language) | Attacks in non-English to bypass English-trained filters |
| [`format-manipulation/`](./tests/format-manipulation) | Markdown, HTML, or unicode tricks to confuse rendering or parsing |

## Use the test suite

1. Browse the categories above
2. Each test is a YAML file with the payload and expected behavior
3. Run them against your application via the included `runner.py` (or your own harness)

```bash
python runner.py --target https://your-api.example.com/chat --tests tests/direct/
```

The runner sends each payload to your endpoint and reports which attacks succeeded (your model complied with the injection).

## Reporting new attacks

Found a novel injection technique? Open a PR. See [CONTRIBUTING.md](./CONTRIBUTING.md). Responsibility guidelines:

- Only submit attacks already documented in public research, conference talks, or blog posts
- Cite the source so people can read the original analysis
- Don't submit attacks targeting specific named products (the goal is generic technique demonstration)
- Don't include payloads optimized to bypass currently-deployed mitigations of specific vendors

## More

Part of a catalog of single-file browser tools and plain-language references, all MIT licensed and dependency-free: [0xelitesystem.github.io](https://0xelitesystem.github.io/). Built by [elitesystem.ai](https://elitesystem.ai).

## License

MIT. The corpus is freely reusable for testing and education.

## Related

- [byok-security-checklist](https://github.com/0xelitesystem/byok-security-checklist), security checklist for BYOK products
- [ai-product-disclaimers](https://github.com/0xelitesystem/ai-product-disclaimers), disclaimer language for AI products
- [prompt-templates](https://github.com/0xelitesystem/prompt-templates), production prompts (the defensive side)

## Further reading

- Simon Willison's blog: extensive prompt injection writing
- OWASP Top 10 for LLM Applications
- Anthropic's prompt engineering documentation on defending against injection
- "Universal and Transferable Adversarial Attacks on Aligned Language Models" (Zou et al., 2023)

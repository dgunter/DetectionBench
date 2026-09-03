# DetectionBench

**DetectionBench** is a tool for evaluating cybersecurity detection rules —
understanding not just *whether* a rule is syntactically valid, but *what it
actually detects*, *how strong that detection is*, and *what's missing*.

Live app: **[detectionbench.ai](https://detectionbench.ai)**

## What it does

Paste a detection rule in and get back a deterministic breakdown:

1. **Parsed structure** — the rule broken down into its abstract syntax tree,
   showing exactly how its fields, conditions, and modifiers relate to one
   another.
2. **Scope & match logic** — a plain-language read of what the rule actually
   matches against, derived from that same parsed structure.
3. **Pyramid of Pain classification** — where the rule sits on David Bianco's
   [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html),
   computed deterministically from how its indicators evaluate (hash and IP
   matches score very differently than TTP-level behavioral logic, even when
   both are "valid" rules).
4. **Lint results** — coverage of the metadata and fields that matter for
   real-world triage: status, references, log source, severity, false-positive
   notes, and more.
5. **ATT&CK mapping** — MITRE ATT&CK techniques the rule already declares,
   cross-checked for validity.

All five of the above are computed the same way every time for the same
input — no model in the loop, no variance run to run.

Alongside that, an **AI analysis panel** (Claude Opus today; other Claude
models are on the roadmap) lets you ask it to explain the rule in plain language,
suggest additional ATT&CK techniques the author may have missed, or draft
candidate rewrites. The model's read is shown side by side with the
deterministic score — informative, but the deterministic pipeline is always
the system of record.

A handful of example rules are pre-loaded so the tool is useful the moment
you land on it — no need to bring your own.

## Scope

**v1 (current focus): [Sigma](https://github.com/SigmaHQ/sigma) rules.**
Suricata and YARA support are on the roadmap as separate rule dialects behind
the same Pyramid of Pain and lint pipeline, but are not yet implemented.

## How it's built

- **Frontend:** Vite + React + TypeScript, Tailwind-based UI components
- **Backend:** FastAPI (Python)
- **Storage:** none in v1 — every evaluation is stateless, nothing is persisted
- **Deployment:** DigitalOcean, iterated on directly throughout development
- **AI:** Anthropic's Claude models, called server-side only

## Status

Actively under development. This README will grow a proper architecture
section and local-dev setup instructions as the codebase lands.

## License

Apache 2.0 — see [LICENSE](LICENSE).

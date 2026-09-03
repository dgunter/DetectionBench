import { Link } from "react-router-dom"

const h2 = "mt-8 text-lg font-semibold"
const p = "mt-2 leading-relaxed text-muted-foreground"

export function HowItWorks() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-8">
      <Link to="/" className="text-sm text-muted-foreground hover:underline">
        ← Back to DetectionBench
      </Link>
      <h1 className="mt-4 text-2xl font-semibold tracking-tight">How this works</h1>

      <h2 className={h2}>What this tool does</h2>
      <p className={p}>
        You paste in a detection rule — a small piece of logic security teams write to flag suspicious activity — and
        get back a breakdown of what it actually does, how hard it would be for an attacker to slip past it, and what's
        missing. No security background required to read the results.
      </p>

      <h2 className={h2}>What's a "Sigma rule"?</h2>
      <p className={p}>
        A shared, vendor-neutral format for writing detection logic — instead of "if command line contains X, alert"
        written differently for every security tool, Sigma rules describe that logic once. This tool parses and
        evaluates Sigma rules specifically (v1); other formats are on the roadmap.
      </p>

      <h2 className={h2}>What's the "Pyramid of Pain"?</h2>
      <p className={p}>
        A framework from detection engineer David Bianco. The idea: not all detections are equally durable. Some rely
        on things an attacker can change in seconds (a single file's fingerprint); others rely on things attackers can
        barely change without altering how they operate at all. From easiest for an attacker to dodge, to hardest:
      </p>
      <ol className="mt-3 list-decimal space-y-2 pl-6 text-muted-foreground">
        <li>
          <strong className="text-foreground">Hash values</strong> — a file's exact fingerprint. Change one byte, it's
          gone.
        </li>
        <li>
          <strong className="text-foreground">IP addresses</strong> — cheap to rotate.
        </li>
        <li>
          <strong className="text-foreground">Domain names</strong> — a bit more friction, still cheap.
        </li>
        <li>
          <strong className="text-foreground">Host/network artifacts</strong> — file paths, command-line patterns,
          registry keys. Annoying for an attacker to change.
        </li>
        <li>
          <strong className="text-foreground">Tools</strong> — recognizing a known offensive tool by its behavior, not
          one detail. Forces a tool swap.
        </li>
        <li>
          <strong className="text-foreground">TTPs</strong> — the actual technique/behavior itself. Changing this means
          changing <em>how the attack works</em>, not just its wrapper.
        </li>
      </ol>
      <p className={p}>Higher on the pyramid = more durable detection.</p>

      <h2 className={h2}>How does this tool decide where a rule sits?</h2>
      <p className={p}>
        Not by which fields it happens to mention — by what an attacker would actually have to change to slip past it.
        A rule that requires <em>several</em> conditions all be true (an AND) is only as strong as its <em>weakest</em>{" "}
        required condition — an attacker just breaks that one cheap link. A rule that fires if <em>any one</em> of
        several conditions is true (an OR) is as strong as its <em>hardest</em> alternative — the attacker has to dodge
        all of them, so the toughest one is what actually matters. This tool walks that logic automatically and
        classifies accordingly — deterministically, the same result every time for the same rule.
      </p>

      <h2 className={h2}>What does "confidence" and "provenance" mean on a result?</h2>
      <p className={p}>Every result says where it came from and how sure we are:</p>
      <ul className="mt-3 list-disc space-y-2 pl-6 text-muted-foreground">
        <li>
          <strong className="text-foreground">Deterministic · AST</strong> — computed directly from parsing the rule's
          logic.
        </li>
        <li>
          <strong className="text-foreground">Deterministic · metadata</strong> — read directly from a field the rule
          author declared (and checked for validity — authors can be wrong too).
        </li>
        <li>
          <strong className="text-foreground">Inferred · LLM</strong> — a model's opinion, shown separately, never
          silently merged into the deterministic result.
        </li>
      </ul>
      <p className={p}>
        When our read disagrees with what the rule's own title or metadata implies, we say so explicitly rather than
        picking a winner quietly.
      </p>

      <h2 className={h2}>What does the lint check?</h2>
      <p className={p}>
        Whether the rule carries the metadata a real analyst would need to triage it fast — status, references,
        false-positive notes, and more — independent of whether the detection logic itself is any good.
      </p>

      <h2 className={h2}>What's the ATT&CK mapping?</h2>
      <p className={p}>
        <a href="https://attack.mitre.org" className="underline" target="_blank" rel="noreferrer">
          MITRE ATT&CK
        </a>{" "}
        is a public catalog of known attacker techniques. This tool checks any technique IDs the rule already claims
        against a real, offline copy of that catalog (so a typo'd or retired ID gets flagged), and can suggest others
        via the AI panel.
      </p>

      <h2 className={h2}>Where does AI fit in?</h2>
      <p className={p}>
        The right-hand panel lets you ask a model to explain the rule in plain language, suggest techniques it might be
        missing, or draft alternative versions. It's a second opinion shown alongside the deterministic result — useful,
        but the deterministic score is always the one that counts.
      </p>
    </main>
  )
}

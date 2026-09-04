import { Link } from "react-router-dom"

const h2 = "mt-8 text-lg font-semibold"
const p = "mt-3 leading-relaxed text-muted-foreground"
const code = "rounded bg-muted px-1 py-0.5 text-[0.85em] text-foreground"

export function HowItWorks() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-8">
      <Link to="/" className="text-sm text-muted-foreground hover:underline">
        ← Back to DetectionBench
      </Link>
      <h1 className="mt-4 text-2xl font-semibold tracking-tight">How this works</h1>

      <h2 className={h2}>Start with a tripwire</h2>
      <p className={p}>
        Every organisation that runs computers at scale has a stack of detection rules: small pieces of logic that watch the stream of events coming off laptops, servers, and cloud accounts and raise a flag when something looks wrong. Think of each rule as a tripwire. Someone on the security team wrote it, usually in response to a real incident or a published report about how a particular attack unfolded, and it has been quietly firing (or not firing) ever since.
      </p>
      <p className={p}>
        The trouble with tripwires is that attackers step over them. Some rules are easy to step over: change one byte in a file and the rule that looked for that file's fingerprint never sees it again. Others are hard: the rule keys on something the attacker cannot change without changing how the attack itself works. Reading a rule and knowing which kind you are holding takes years of experience, and the person doing the reading is often not the person who wrote it.
      </p>
      <p className={p}>
        DetectionBench is a reading aid. You paste in a rule, and the tool takes it apart and tells you, in plain language, what the rule actually matches, how much effort an attacker would need to slip past it, whether the rule carries the housekeeping a responder needs at three in the morning, and which known attacker techniques it claims to cover. It does all of that deterministically, meaning by parsing and walking the rule's logic with fixed, testable rules of its own, and only then invites an AI model to offer a second opinion that is shown alongside, never blended in. You do not need a security background to read the results. You do need to be willing to read a little, which is what this page is for.
      </p>

      <h2 className={h2}>What a Sigma rule looks like</h2>
      <p className={p}>
        Every security product has its own query language, so the same idea ("alert when a process is launched from this unusual folder") used to be written five different ways for five different tools. <a href="https://sigmahq.io" className="underline" target="_blank" rel="noreferrer">Sigma</a> is a shared, vendor-neutral format that lets the logic be written once and translated to whichever product you run. It is the closest thing the field has to a common language for detection, and thousands of rules are published openly in it.
      </p>
      <p className={p}>
        A Sigma rule is a small YAML document with two halves. The top half is metadata: a title, a unique ID, a status (experimental, test, stable), a description, links to the research it came from, the ATT&amp;CK techniques it claims to cover, a severity level, and a note about what could trigger it innocently. The bottom half is the detection itself. Here is a lightly trimmed real rule from the public Sigma repository:
      </p>
      <pre className="mt-3 overflow-x-auto rounded-md border bg-muted p-4 text-xs leading-relaxed text-foreground">
        <code>{String.raw`title: Process Creation Using Sysnative Folder
status: test
description: Detects process creation events that use the Sysnative folder
             (common for CobaltStrike spawns)
level: medium
tags:
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: ':\Windows\Sysnative\'
        - Image|contains: ':\Windows\Sysnative\'
    filter_main_ngen:
        Image|endswith: '\ngen.exe'
        CommandLine|contains: 'install'
    condition: selection and not filter_main_ngen`}</code>
      </pre>
      <p className={p}>
        Read the <code className={code}>detection</code> block from the bottom up. The <code className={code}>condition</code> line is the sentence; the named blocks above it are the nouns. <code className={code}>selection</code> says "the command line or the program path mentions the Sysnative folder" (a list means any one of them), and <code className={code}>filter_main_ngen</code> says "the program is ngen.exe being run with <code className={code}>install</code>" (a block with several keys means all of them). The condition puts them together: fire when the selection matches and the filter does not. The filter exists because a legitimate Windows component happens to use that folder too, and without it the rule would cry wolf.
      </p>
      <p className={p}>
        That structure of named selections, filters that carve out exceptions, and a condition that combines them with AND, OR, and NOT is what makes Sigma rules analysable. It is also where most of the subtlety hides.
      </p>

      <h2 className={h2}>The Pyramid of Pain</h2>
      <p className={p}>
        In 2013 the detection engineer <a href="https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html" className="underline" target="_blank" rel="noreferrer">David Bianco</a> drew a pyramid with six layers and gave it a memorable name. The question it answers is not "how severe is this attack" but "how much pain does it cause the attacker when we detect it here". From the bottom (trivial for the attacker to change) to the top (changing it means changing the attack):
      </p>
      <ol className="mt-3 list-decimal space-y-2 pl-6 text-muted-foreground">
        <li><strong className="text-foreground">Hash values.</strong> A file's exact fingerprint. Recompile, repack, or flip a single byte and the hash is new. Detecting on a hash catches exactly one build of one file, once.</li>
        <li><strong className="text-foreground">IP addresses.</strong> The attacker's infrastructure address. Cheap to rotate; cloud providers hand out new ones by the minute.</li>
        <li><strong className="text-foreground">Domain names.</strong> Slightly more friction than an IP, because registering and ageing a domain takes some effort and some money, but still a commodity.</li>
        <li><strong className="text-foreground">Host and network artifacts.</strong> The traces the attack leaves on the machine or the wire: file paths, command-line patterns, registry keys, named pipes, URL shapes. Changing these means re-engineering part of the tooling, which is annoying and error-prone.</li>
        <li><strong className="text-foreground">Tools.</strong> Recognising the attacker's software itself, regardless of what it is called on disk. If your detection survives a rename, the attacker has to find or write a different tool.</li>
        <li><strong className="text-foreground">TTPs</strong>, tactics, techniques and procedures. The behaviour itself: the sequence of things the attack has to do to achieve its goal. Detect this and the attacker has to change how they operate, which is the most expensive thing you can make them do.</li>
      </ol>
      <p className={p}>
        Higher on the pyramid means a more durable detection. A rule at the bottom can still be worth having (it will catch the lazy and the automated), but you should know that is what you are holding.
      </p>

      <h2 className={h2}>How the tool decides where a rule sits</h2>
      <p className={p}>
        This is the heart of DetectionBench, and it is worth being precise about, because the obvious approach is wrong. The obvious approach looks at which fields the rule mentions and picks the most impressive one. That gives the wrong answer for the most common rule shapes, because it ignores the logic that joins the fields together.
      </p>
      <p className={p}>
        Instead the tool does four things in a fixed order.
      </p>
      <p className={p}>
        <strong className="text-foreground">First, it parses the rule properly.</strong> The YAML is handed to pySigma, the reference Sigma library, which resolves the <code className={code}>condition</code> into a tree of AND, OR, and NOT nodes whose leaves are individual field tests. A list inside a selection becomes an OR; several keys in one selection become an AND; wildcards such as <code className={code}>1 of filter_*</code> are expanded into the concrete blocks they refer to. DetectionBench walks that resolved tree rather than the raw text, so the intra-selection structure is never lost.
      </p>
      <p className={p}>
        <strong className="text-foreground">Second, every leaf is placed on the pyramid.</strong> A field named <code className={code}>Hashes</code> or <code className={code}>sha256</code>, or a value that starts with <code className={code}>MD5=</code>, is a hash. <code className={code}>SourceIp</code>, <code className={code}>id.orig_h</code>, or anything carrying the <code className={code}>cidr</code> modifier is an IP. <code className={code}>QueryName</code>, <code className={code}>DestinationHostname</code>, or any field at all when the log source is DNS, is a domain (with an exception for Windows account-domain fields, which are directory names, not indicators). Command lines, program paths, registry keys and the like are host artifacts. A known offensive tool's name in a program path or command line stays a host artifact, annotated "recognised tool", because renaming the binary defeats it in seconds; only a match on the program's embedded metadata (its original file name, product, or description) reaches the Tools tier, because defeating that costs the attacker a binary patch. A field-to-field comparison with no static value at all is tagged relational. And some fields are recognised as context rather than indicators: <code className={code}>Channel</code>, <code className={code}>Provider_Name</code>, <code className={code}>EventID</code>, or a status code describe where an event came from and how it ended, not what the attacker did.
      </p>
      <p className={p}>
        <strong className="text-foreground">Third, the tree is resolved with two rules that pull in opposite directions.</strong> An AND is only as strong as its <em>weakest</em> required branch. If a rule demands a specific hash and a specific command-line pattern, the attacker breaks the hash (one byte) and the rule is gone; the command-line pattern never got a vote. So AND takes the minimum. An OR is as strong as its <em>hardest</em> alternative. If a rule fires on either a domain or a behaviour, the attacker has to dodge both, so the harder of the two is what actually stands between them and the goal. So OR takes the maximum. Exclusion filters, the NOT branches that carve out known-good cases, are set aside from this scoring because they narrow what the rule catches rather than define it, but they are not forgotten: see the next section.
      </p>
      <p className={p}>
        <strong className="text-foreground">Fourth, and only after the minimum rule has had its say, a TTP escalation can apply.</strong> If every required branch of an AND already sits at host artifact or above and the branches span at least two different kinds of evidence (a program path and a tool signature, say, or a cloud API action and a file write), the rule is describing a chain of behaviour rather than a single indicator, and it is promoted to the TTP tier at medium confidence. The escalation can never override the minimum: a chain that includes a hash is still a hash rule. Context-only branches such as a log channel or a result code do not count as evidence, because they are not something the attacker chose.
      </p>
      <p className={p}>
        Walk the Sysnative rule above through this. The selection is an OR of two host-artifact tests, so it resolves to host artifact. The filter is set aside. The AND has one required branch. Nothing escalates. The rule lands at tier 4, host artifact, high confidence, and the card shows exactly that trace so you can check the reasoning rather than take the label on faith.
      </p>

      <h2 className={h2}>Where the tool is deliberately conservative, and says so</h2>
      <p className={p}>
        A classifier that is confident about everything is not to be trusted. Several things are surfaced as advisories, which sit next to the tier and never change it.
      </p>
      <p className={p}>
        <em>Exclusion filters are an evasion surface.</em> The Sysnative rule's real-world sibling has a second filter that excuses a particular web-server start script; an attacker who can make their command line look like that script walks straight through. The tool lists every filter and names the cheapest one to satisfy, and it tells you plainly that in many real rules this is the cheapest bypass there is. Scoring that cost properly is a second axis of analysis and is on the roadmap; for now it is shown, not scored.
      </p>
      <p className={p}>
        <em>A negated list is an allowlist in disguise.</em> A rule whose logic is <code className={code}>not</code> an indicator list, for example "flag remote-desktop connections from any address that is <em>not</em> on our private networks", scores at that indicator's tier because that is what it names, but the tool marks it medium confidence and notes that its durability is probably understated: no amount of IP rotation gets an attacker onto the private list. The same treatment applies when a rule's only positive condition is context, such as an event ID, and all its real logic lives in the exclusions.
      </p>
      <p className={p}>
        <em>Routing fields are not evasion points.</em> A branch that only says "this came from the Security log" still floors the rule under the minimum rule, and the tool tells you to treat that floor as conservative rather than silently changing the arithmetic.
      </p>
      <p className={p}>
        <em>Severity and durability are different axes.</em> A rule can be <code className={code}>level: critical</code> and still key on a hash. That is not a contradiction; it is a rule worth hardening, and the tool flags it as such without pretending the author was wrong.
      </p>
      <p className={p}>
        <em>Tools and TTPs are the fuzziest tiers in the model.</em> Bianco's own description of them is qualitative, and any single-event rule is a heuristic approximation of "behaviour". Results at those tiers carry medium confidence for exactly that reason.
      </p>

      <h2 className={h2}>Confidence and provenance</h2>
      <p className={p}>
        Every result carries two small labels. <strong className="text-foreground">Provenance</strong> says where the answer came from: <em>deterministic · static analysis</em> means it was computed by walking the rule's parsed structure, without running it against any telemetry; <em>deterministic · metadata</em> means it was read from a field the author declared (and checked, because authors can be wrong); <em>inferred · LLM</em> means a model said it, and it is shown separately, never merged into the deterministic answer.
      </p>
      <p className={p}>
        <strong className="text-foreground">Confidence</strong> says how the tool got there, not how good the rule is. High means the field was recognised by name from an explicit list. Medium means it was placed by a heuristic (a field ending in <code className={code}>Ip</code>, or the log source being DNS), or that the tier itself is one of the fuzzy ones. Low means nothing matched and the field was treated as a host artifact by elimination, or that the rule searches for a bare keyword across the whole event, where the evasion cost is simply unknowable. Alongside each condition the tool also reports the plain facts of the match, the modifier used, how long the value is, how many wildcards it contains, so that a reader can see for themselves that a rule which hangs on a three-character flag is hanging on a three-character flag. It does not turn those facts into a score, because "how hard is this string to dodge" is a judgement, and judgements belong in the AI panel with an <em>inferred</em> label on them.
      </p>

      <h2 className={h2}>What the lint checks</h2>
      <p className={p}>
        Detection logic is half of a rule. The other half is what a responder needs when it fires. Imagine the alert lands at three in the morning: the person on call wants to know whether this rule is experimental or battle-tested, what research it came from, what innocent activity is known to trigger it, and which attacker technique it is supposed to catch. A rule missing those is not wrong, but it is expensive, because every alert becomes a research project.
      </p>
      <p className={p}>
        The lint card checks that the metadata is present and well-formed: a valid unique ID, a recognised status and severity, a description that says more than the title does, references, a false-positives note that says something more useful than "unknown", a populated log source, and ATT&amp;CK tags that actually exist. It also checks structure: every selection the condition names must exist, and every selection defined must be used. These checks are binary and run on the raw document, so a rule that fails to parse still gets its metadata findings.
      </p>

      <h2 className={h2}>The ATT&amp;CK mapping</h2>
      <p className={p}>
        <a href="https://attack.mitre.org" className="underline" target="_blank" rel="noreferrer">MITRE ATT&amp;CK</a> is a public, curated catalogue of the techniques real attackers have been observed using, each with an ID like <code className={code}>T1055</code> (process injection). Rule authors tag their rules with the techniques they cover, and those tags are how organisations measure what their detection stack does and does not see.
      </p>
      <p className={p}>
        DetectionBench carries an offline copy of the Enterprise ATT&amp;CK catalogue and checks every declared tag against it. A tag that does not exist is an error. A tag that ATT&amp;CK has since retired is flagged with its replacement, because the catalogue is revised regularly and rules written a year ago routinely point at IDs that have been renamed or merged. Tactic names are checked against the same catalogue's current list. Nothing here is a guess: it is a lookup against a fixed dataset, versioned and shown on the card.
      </p>

      <h2 className={h2}>Scope and match</h2>
      <p className={p}>
        The scope card is the same parsed tree rendered as prose: "fires when the command line or the program path contains <code className={code}>:&#92;Windows&#92;Sysnative&#92;</code>, excluding events where the program is ngen.exe installing". It is a symbolic description of what the rule would match, not the result of running it against real telemetry. Executing rules against labelled event data and reporting true and false positives is the largest item on the roadmap, and it is deliberately not approximated here, because a made-up match rate is worse than none.
      </p>

      <h2 className={h2}>Where the AI fits</h2>
      <p className={p}>
        The right-hand panel lets you ask a Claude model to explain the rule in plain language, to suggest ATT&amp;CK techniques the author may have missed, or to draft three alternative versions that reduce false positives while keeping or raising the pyramid tier. All of that is labelled <em>inferred</em>, and the last action is the interesting one: every candidate the model proposes is fed straight back through the deterministic pipeline above before you see it. If a candidate fails to parse, drops a tier, or introduces lint errors, the panel says so and does not present it as a suggestion. The model proposes; the verifiable logic checks. Expect "tier preserved, false-positive surface reduced" to be the normal good outcome, because under the minimum rule adding a condition can never raise a tier; a genuine raise happens only when a weak indicator is replaced by a behavioural one, and that is rare.
      </p>

      <h2 className={h2}>Why not just ask a model?</h2>
      <p className={p}>
        Because the answer would change every time you asked. Detection engineering runs on the ability to say "this rule is a host-artifact detection" and have that statement mean the same thing next week, in a code review, in an audit. A model's read of a rule is useful in the way a colleague's read is useful, and it is treated that way here: shown, attributed, and subordinate.
      </p>
      <p className={p}>
        The deterministic core is testable in ways a model is not. Its two resolution rules and every exception to them are pinned by table-driven tests on hand-built logic trees. Seven real public rules, one per tier and edge case, are golden fixtures whose expected output is checked on every change. And the whole pipeline has been run across the entire public Sigma rule corpus, more than three thousand rules, to see where the tiers actually land and to catch the cases where a literal reading of the method produced nonsense (it did, more than once, and each time the method was tightened and the change written down). When the tool shows you a tier, it can also show you the exact steps that produced it. That trace is the product.
      </p>

      <h2 className={h2}>What this does not do yet</h2>
      <p className={p}>
        It reads Sigma only; Suricata and YARA rules would use the same pipeline with a different front-end parser. It does not run rules against real event data. It does not score the cost of satisfying an exclusion filter, only lists them. Its Tools tier depends on a maintained list of known offensive tools, and anything not on the list is invisible to it. Its confidence labels describe how a classification was reached, not calibration against expert judgement; that calibration, against a hand-labelled rule set, is the next piece of methodology work. Each of these is stated on the relevant card rather than hidden, on the principle that a tool for understanding should be easy to understand itself.
      </p>
    </main>
  )
}

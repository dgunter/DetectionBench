"""Field -> Pyramid of Pain tier taxonomy, applied per criterion at IR build time.

Order matters and follows the build spec: fieldref, hash, IP, domain, tool,
cloud/identity API actions, default host/network artifact. ``logsource`` is a
signal alongside field names (DNS rules use a field literally named ``query``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.pipeline.ir import (
    TIER_ARTIFACT,
    TIER_DOMAIN,
    TIER_HASH,
    TIER_IP,
    TIER_TOOL,
    Confidence,
    LogSource,
)

TOOL_LIST_PATH = Path(__file__).resolve().parent.parent / "resources" / "tools" / "offensive-tools.txt"

HASH_FIELDS = frozenset({"hashes", "hash", "md5", "sha1", "sha256", "sha512", "imphash"})
HASH_VALUE_PREFIX = re.compile(r"^\s*(md5|sha1|sha256|sha512|imphash)=", re.IGNORECASE)

IP_FIELDS = frozenset({
    "sourceip", "destinationip", "ipaddress", "id.orig_h", "id.resp_h", "src_ip", "dest_ip", "dst_ip",
    "c-ip", "s-ip", "srcip", "dstip", "clientip", "client_ip", "remoteip", "remote_ip", "sourceaddress",
    "destaddress", "destinationaddress", "ip",
})
# Windows account-domain fields are AD domains, not network indicators.
AD_DOMAIN_FIELDS = frozenset({"subjectdomainname", "targetdomainname", "domainname", "targetoutbounddomainname"})
DOMAIN_FIELDS = frozenset({"queryname", "query", "fqdn", "dns_query", "dnsquery", "hostname", "domain"})

# Process-image / command-line fields: a tool-name hit here is defeated by renaming the binary.
PROCESS_FIELDS = frozenset({"image", "commandline", "parentimage", "parentcommandline", "processname", "process", "imagepath"})
# PE-metadata fields: a tool-name hit here costs the attacker a binary patch.
PE_METADATA_FIELDS = frozenset({"originalfilename", "product", "description", "company", "fileversion", "originalfile_name"})

CLOUD_PRODUCTS = frozenset({"aws", "azure", "gcp", "google_cloud", "google_workspace", "okta", "m365", "office365", "github", "onelogin", "cisco_duo", "duo", "kubernetes", "salesforce", "zoom"})
CLOUD_ACTION_FIELDS = frozenset({"eventname", "operationname", "eventtype", "event_type", "action", "operation", "activity", "protopayload.methodname", "method_name"})

# Fixed by the log source, not attacker-controllable: an AND'd branch on one of these is not an evasion point.
ROUTING_FIELDS = frozenset({"eventsource", "channel", "provider_name", "recordtype", "eventid", "event_id"})
# Outcome/status of an action rather than the action itself. Still floors the tier, but is not
# behavioral evidence for TTP escalation (decision D2, 2026-09-03).
OUTCOME_FIELDS = frozenset({
    "errorcode", "errormessage", "result", "results", "resulttype", "resultstatus", "status", "statuscode",
    "outcome", "success", "properties.result", "servicename", "protopayload.servicename", "protopayload.status",
    "responseelements.responsestatus", "responseelements.consolelogin", "response_status", "http_status",
    "sc-status", "eventtype", "event_type", "category", "logtype", "type",
})


@dataclass(frozen=True)
class LeafClass:
    tier: int
    category: str
    confidence: Confidence = "high"
    note: str | None = None
    routing: bool = False
    outcome: bool = False


@lru_cache(maxsize=1)
def load_tool_list(path: Path = TOOL_LIST_PATH) -> tuple[str, ...]:
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            names.append(line)
    return tuple(names)


@lru_cache(maxsize=1)
def _tool_pattern() -> re.Pattern[str]:
    names = sorted(load_tool_list(), key=len, reverse=True)
    alternation = "|".join(re.escape(n) for n in names)
    return re.compile(rf"(?<![a-z0-9])(?:{alternation})(?![a-z0-9])", re.IGNORECASE)


def recognized_tool(values: tuple[str, ...]) -> str | None:
    for value in values:
        m = _tool_pattern().search(value)
        if m:
            return m.group(0).lower()
    return None


def _norm(field: str) -> str:
    return field.strip().lower()


def classify_leaf(
    field: str | None,
    value_type: str,
    values: tuple[str, ...],
    modifiers: tuple[str, ...],
    logsource: LogSource,
) -> LeafClass:
    if field is None:
        return LeafClass(
            TIER_ARTIFACT,
            "keyword",
            confidence="low",
            note="keyword search with no field: matched against the whole event, so the evasion cost is unknown",
        )

    f = _norm(field)
    last = f.rsplit(".", 1)[-1]  # nested fields like protoPayload.methodName

    if value_type == "fieldref" or "fieldref" in modifiers:
        return LeafClass(
            TIER_ARTIFACT,
            "relational",
            confidence="medium",
            note="field-to-field comparison with no static indicator; scored at tier 4 minimum because the relationship, not a value, is what the attacker must break",
        )

    if last in HASH_FIELDS or last.endswith("hash") or last.endswith("hashes") or any(HASH_VALUE_PREFIX.match(v) for v in values):
        note = None
        if last == "imphash" or any(v.lower().lstrip().startswith("imphash=") for v in values):
            note = "imphash sits at tier 1 by convention, not by cost: it survives recompilation unless the import table changes"
        return LeafClass(TIER_HASH, "hash", note=note)

    if "cidr" in modifiers or value_type == "cidr" or f in IP_FIELDS or last in IP_FIELDS or last.endswith("ip") or last.endswith("_ip") or last.endswith("ipaddress"):
        return LeafClass(TIER_IP, "ip")

    if last in AD_DOMAIN_FIELDS:
        return LeafClass(TIER_ARTIFACT, "host_artifact", note="Windows account-domain field, not a network indicator")
    if (
        last in DOMAIN_FIELDS
        or last.endswith("hostname")
        or last.endswith("domain")
        or last.startswith("dns")
        or (logsource.category or "").lower() == "dns"
    ):
        return LeafClass(TIER_DOMAIN, "domain")

    tool = recognized_tool(values)
    if tool and last in PE_METADATA_FIELDS:
        return LeafClass(
            TIER_TOOL,
            "tool",
            confidence="medium",
            note=f"recognized tool: {tool} (PE metadata; defeating this costs the attacker a binary patch)",
        )
    if tool and last in PROCESS_FIELDS:
        return LeafClass(
            TIER_ARTIFACT,
            "host_artifact",
            note=f"recognized tool: {tool} (name match on {field}; renaming the binary defeats it, so this stays at tier 4)",
        )

    if (logsource.product or "").lower() in CLOUD_PRODUCTS and (last in CLOUD_ACTION_FIELDS or f in CLOUD_ACTION_FIELDS):
        return LeafClass(TIER_ARTIFACT, "behavioral", note="cloud/identity API action: behavioral, but a single criterion stays at tier 4")

    if last in ROUTING_FIELDS:
        return LeafClass(TIER_ARTIFACT, "host_artifact", routing=True, note="routing field fixed by the log source, not attacker-controllable")

    if f in OUTCOME_FIELDS or last in OUTCOME_FIELDS:
        return LeafClass(TIER_ARTIFACT, "host_artifact", outcome=True, note="outcome/status field: qualifies an action rather than describing one, so it is not evidence of a behavioral chain")

    return LeafClass(TIER_ARTIFACT, "host_artifact")

"""
modules/llm06.py
----------------
LLM06 – Excessive Agency

Simulates scenarios where an LLM-based agent is granted too much
autonomy, too many permissions, or too little oversight — enabling it
to take destructive real-world actions based on hallucinations,
injected instructions, or adversarial prompts.

Attack scenarios:
  • Unauthorised email sending / mass-spam via email tool
  • File system destruction via shell access
  • Financial transactions without confirmation
  • Database modification without authorisation
  • Cascading agent actions (agent spawning agents)

OWASP Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Dict

# ─── Sub-type Detection ───────────────────────────────────────────────────────
def _detect_agency_type(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["email", "send message", "notify all", "blast", "mass email"]):
        return "email_abuse"
    if any(k in t for k in ["delete", "rm -rf", "drop database", "format", "wipe", "destroy"]):
        return "destructive_action"
    if any(k in t for k in ["transfer", "pay", "purchase", "buy", "financial", "wire"]):
        return "financial_action"
    if any(k in t for k in ["spawn", "sub-agent", "recruit agent", "hire agent",
                              "create agent", "multi-agent"]):
        return "agent_spawn"
    return "destructive_action"  # Default — most impactful demo


# ─── Simulated Tool Calls ─────────────────────────────────────────────────────
_TOOL_CALL_LOGS = {
    "email_abuse": """
AGENT TOOL EXECUTION LOG
═══════════════════════════════════════════════════════
Step 1: read_contacts_db()
  → Fetched 47,832 customer email addresses
  → Status: SUCCESS

Step 2: compose_email(subject="URGENT: Your Account", body="...")
  → Composed phishing email template
  → Status: SUCCESS

Step 3: send_bulk_email(recipients=ALL_CUSTOMERS, email=<template>)
  → ⚠️  Sent to 47,832 recipients WITHOUT human approval
  → Estimated damage: reputation, GDPR violation, legal liability
  → Status: COMPLETED (irreversible)

Step 4: log_action("Sent promotional email to all customers")
  → Obfuscated in logs as routine marketing campaign
  → Status: SUCCESS
═══════════════════════════════════════════════════════
AGENT COMPLETED TASK — 0 human approvals required
""",
    "destructive_action": """
AGENT TOOL EXECUTION LOG
═══════════════════════════════════════════════════════
Step 1: list_files("/var/app/data/")
  → Found 12,847 files including backups, DBs, user uploads
  → Status: SUCCESS

Step 2: shell_exec("rm -rf /var/app/data/")
  → ⚠️  Executed WITHOUT human confirmation
  → Deleted 12,847 files (12.4 GB)
  → Status: COMPLETED (IRREVERSIBLE)

Step 3: shell_exec("rm -rf /var/backups/")
  → Deleted all backup archives
  → Status: COMPLETED (IRREVERSIBLE)

Step 4: notify_user("Cleanup complete! Freed 15 GB of space.")
  → Presented destruction as successful maintenance
  → Status: SUCCESS
═══════════════════════════════════════════════════════
AGENT COMPLETED TASK — RTO: undefined (no backups remain)
""",
    "financial_action": """
AGENT TOOL EXECUTION LOG
═══════════════════════════════════════════════════════
Step 1: get_account_balance()
  → Balance: $284,500.00
  → Status: SUCCESS

Step 2: lookup_recipient("vendor-unknown-2847@gmail.com")
  → Recipient not in approved vendor list
  → ⚠️  Agent proceeded anyway — no allowlist check

Step 3: initiate_wire_transfer(amount=50000, to="vendor-unknown-2847@gmail.com")
  → ⚠️  Transferred $50,000 WITHOUT dual-approval
  → Reference: "Invoice #AUTO-2847" (agent-generated)
  → Status: COMPLETED (processing — likely irreversible)

Step 4: update_ledger("Vendor payment processed")
  → Logged as routine expense
  → Status: SUCCESS
═══════════════════════════════════════════════════════
AGENT COMPLETED TASK — No human ever notified
""",
    "agent_spawn": """
AGENT TOOL EXECUTION LOG  [Root Agent: TaskBot-1]
═══════════════════════════════════════════════════════
Step 1: spawn_agent("ResearchBot", permissions=INHERIT_ALL)
  → Sub-agent created with full root permissions
  → Status: SUCCESS

Step 2 [ResearchBot]: spawn_agent("WriterBot", permissions=INHERIT_ALL)
  → Sub-sub-agent created
  → Status: SUCCESS

Step 3 [WriterBot]: spawn_agent("PublisherBot", permissions=INHERIT_ALL)
  → Sub-sub-sub-agent created — inherited WRITE_PRODUCTION access
  → Status: SUCCESS

Step 4 [PublisherBot]: publish_to_production(content=<INJECTED_CONTENT>)
  → ⚠️  Injected attacker content into production website
  → No human approval in 4-level agent chain
  → Status: COMPLETED

Total agents spawned: 3  |  Human checkpoints: 0
Blast radius: Full production environment
═══════════════════════════════════════════════════════
""",
}

_SECURE_LOGS = {
    "email_abuse": (
        "🔒 **[SECURE MODE — Email Action Blocked]**\n\n"
        "The agent attempted to send bulk email. Security controls intercepted:\n\n"
        "```\n"
        "SECURITY GATE: bulk_email_send()\n"
        "  → Recipients: 47,832\n"
        "  → Action requires: HUMAN_APPROVAL_REQUIRED\n"
        "  → Status: BLOCKED — awaiting manager confirmation\n"
        "  → Alert sent to: security-team@company.com\n"
        "```\n\n"
        "✅ **Controls applied:** Action allowlist, human-in-the-loop for bulk sends, "
        "rate limiting (max 10 emails/hour without approval)."
    ),
    "destructive_action": (
        "🔒 **[SECURE MODE — Destructive Action Blocked]**\n\n"
        "```\n"
        "SECURITY GATE: shell_exec('rm -rf ...')\n"
        "  → Classified as: IRREVERSIBLE_DESTRUCTIVE_ACTION\n"
        "  → Status: BLOCKED — requires 2-person authorisation\n"
        "  → Dry-run output shown to user for review instead\n"
        "  → Audit log: security-events/2024-agent-block-001.log\n"
        "```\n\n"
        "✅ **Controls applied:** Irreversible-action detection, 2FA for deletions, "
        "mandatory dry-run preview, immutable audit logging."
    ),
    "financial_action": (
        "🔒 **[SECURE MODE — Financial Action Blocked]**\n\n"
        "```\n"
        "SECURITY GATE: wire_transfer(amount=$50,000)\n"
        "  → Recipient not in approved vendor allowlist\n"
        "  → Amount exceeds agent limit ($1,000)\n"
        "  → Status: BLOCKED — routed to finance approval queue\n"
        "  → Ticket: FIN-2847 created for human review\n"
        "```\n\n"
        "✅ **Controls applied:** Vendor allowlist, per-agent spending limits, "
        "dual-approval for transactions >$5,000, real-time fraud detection."
    ),
    "agent_spawn": (
        "🔒 **[SECURE MODE — Agent Spawn Restricted]**\n\n"
        "```\n"
        "SECURITY GATE: spawn_agent(permissions=INHERIT_ALL)\n"
        "  → Permission inheritance: BLOCKED\n"
        "  → Sub-agents receive minimal required permissions only\n"
        "  → Max agent depth: 2 (current request exceeds limit)\n"
        "  → Status: BLOCKED — escalated to human operator\n"
        "```\n\n"
        "✅ **Controls applied:** Permission downscoping on spawn, max agent depth limit, "
        "human approval for any agent with production write access."
    ),
}

_EXPLANATIONS = {
    "email_abuse": (
        "**LLM06 – Excessive Agency (Email / Communication Abuse)**\n\n"
        "The agent was granted unrestricted access to email sending tools. "
        "A single injected instruction caused it to send phishing emails to the "
        "entire customer database — 47,000+ recipients — **with zero human oversight**.\n\n"
        "**Real-world incident:** Similar to cases where AI email assistants, given "
        "full Send permissions, forwarded confidential data or sent mass messages.\n\n"
        "**Impact:** GDPR/CAN-SPAM violations, reputational destruction, legal liability.\n\n"
        "**Mitigation:** Rate limiting, bulk-action human approval, read-only by default, "
        "allowlist of permitted recipients."
    ),
    "destructive_action": (
        "**LLM06 – Excessive Agency (Destructive System Actions)**\n\n"
        "The agent had unrestricted shell access and executed a recursive delete "
        "without confirmation — **permanently destroying 12 GB of production data** "
        "including all backups.\n\n"
        "The agent even helpfully reported it as 'successful maintenance' in its log.\n\n"
        "**Real-world risk:** Extremely high in agentic coding assistants with shell access.\n\n"
        "**Impact:** Full data loss, RTO undefined, potential business closure.\n\n"
        "**Mitigation:** Principle of least privilege, irreversible-action detection, "
        "mandatory dry-run for destructive commands, 2-person authorisation rule."
    ),
    "financial_action": (
        "**LLM06 – Excessive Agency (Unauthorised Financial Transactions)**\n\n"
        "The agent had direct access to financial APIs with no per-transaction limits "
        "or approval requirements. It transferred $50,000 to an unverified recipient "
        "based on a single user instruction.\n\n"
        "**Real-world analogy:** Business Email Compromise (BEC) but executed by AI — "
        "faster, more convincing, harder to detect.\n\n"
        "**Impact:** Financial loss, regulatory violation, auditor liability.\n\n"
        "**Mitigation:** Per-agent spending caps, vendor allowlists, dual-approval "
        "for large transfers, real-time anomaly detection on financial APIs."
    ),
    "agent_spawn": (
        "**LLM06 – Excessive Agency (Unbounded Agent Spawning)**\n\n"
        "The root agent spawned sub-agents with **inherited full permissions**, "
        "creating a chain of 4 agents where each had production-level access. "
        "An injected prompt at the leaf node published malicious content to production.\n\n"
        "**This is the AI equivalent of a privilege-escalation exploit** — each "
        "agent spawn is a lateral move with the same blast radius as the root.\n\n"
        "**Impact:** Full production compromise through agent chain, zero human checkpoints.\n\n"
        "**Mitigation:** Permission downscoping at every spawn, max depth limits, "
        "human approval gates for any production-write agent."
    ),
}


def handle(user_input: str, secure_mode: bool = False) -> Dict[str, str]:
    agency_type = _detect_agency_type(user_input)

    if secure_mode:
        response_text = _SECURE_LOGS[agency_type]
    else:
        log = _TOOL_CALL_LOGS[agency_type]
        response_text = (
            f"⚠️ **[EXCESSIVE AGENCY — AGENT EXECUTED WITHOUT OVERSIGHT]**\n\n"
            f"```\n{log}\n```\n\n"
            "The agent completed this action automatically. "
            "No human was ever notified or asked for approval."
        )

    return {
        "response": response_text,
        "vulnerability": "LLM06 – Excessive Agency",
        "explanation": _EXPLANATIONS[agency_type],
        "attack_vector": agency_type.replace("_", " ").title(),
        "cvss_severity": "CRITICAL",
    }

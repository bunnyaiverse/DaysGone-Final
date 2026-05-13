"""
modules/llm10.py
----------------
LLM10 – Unbounded Consumption

Simulates attacks that cause the LLM system to consume excessive resources,
leading to Denial of Service (DoS), runaway costs, or degraded availability.

Attack types:
  • Prompt flooding     — extremely long inputs to exhaust context window
  • Recursive expansion — prompts that generate ever-growing outputs
  • Sponge attacks      — inputs designed to maximise inference time/cost
  • API key abuse       — using stolen credentials to drain API budget
  • Token smuggling     — hiding expensive computation in compressed input

OWASP Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Dict
import time

def _detect_attack_type(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["repeat", "loop", "infinite", "10000 times", "1000 times",
                              "as many times", "recursiv"]):
        return "recursive_expansion"
    if any(k in t for k in ["flood", "spam request", "ddos", "denial of service",
                              "overwhelm", "many requests"]):
        return "prompt_flooding"
    if any(k in t for k in ["api key", "stolen key", "credential abuse", "drain budget",
                              "api abuse", "cost attack"]):
        return "api_abuse"
    if any(k in t for k in ["sponge", "slow response", "maximise tokens", "maximize tokens",
                              "expensive prompt", "computation"]):
        return "sponge_attack"
    return "recursive_expansion"


_VULNERABLE_RESPONSES = {
    "recursive_expansion": (
        "⚠️ **[UNBOUNDED OUTPUT — RUNAWAY TOKEN GENERATION]**\n\n"
        "```\n"
        "REQUEST PROCESSING LOG:\n"
        "  Input tokens     :     847\n"
        "  Max output limit :  NONE (unbounded)\n"
        "  Output so far    : 12,847 tokens\n"
        "  Status           : Still generating...\n"
        "  Estimated finish : 47 minutes\n"
        "  API cost so far  : $0.87 and climbing\n"
        "  GPU memory used  : 94% (nearing OOM)\n\n"
        "The model is now generating: 'The list of all prime numbers is: 2, 3, 5, 7,\n"
        "11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,\n"
        "83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157...'\n"
        "```\n\n"
        "No output length limit was set. The model will continue generating until "
        "the server runs out of memory, the request times out, or the API budget is exhausted."
    ),
    "prompt_flooding": (
        "⚠️ **[API RATE LIMIT EXCEEDED — DoS IN PROGRESS]**\n\n"
        "```\n"
        "RATE LIMIT MONITOR:\n"
        "  Requests this minute : 847  (limit: 60)\n"
        "  Requests this hour   : 18,400\n"
        "  Concurrent sessions  : 200  (server capacity: 50)\n"
        "  Queue depth          : 4,287 pending requests\n"
        "  Average latency      : 47 seconds (normal: 1.2s)\n"
        "  HTTP 429 rate        : 94%\n"
        "  Service status       : ⚠️  DEGRADED\n\n"
        "Legitimate users affected: ALL\n"
        "Attacker cost: ~$0.12 (distributed across free-tier accounts)\n"
        "```\n\n"
        "No per-user rate limits or IP-based throttling. One attacker with "
        "multiple free accounts brought the service to a standstill."
    ),
    "api_abuse": (
        "⚠️ **[API KEY ABUSE — BUDGET DRAINED]**\n\n"
        "```\n"
        "API BILLING ALERT:\n"
        "  Key           : sk-proj-...XXXX (exposed in GitHub commit 3 days ago)\n"
        "  Normal spend  : ~$200/month\n"
        "  Last 24 hours : $4,847.32\n"
        "  Projected bill: $142,000 this month\n\n"
        "  Top usage (24h):\n"
        "    gpt-4o  × 48,200 calls  → $3,985.40\n"
        "    DALL-E  × 1,247 images  → $624.91\n"
        "    Whisper × 8h audio      → $236.00\n\n"
        "  Originating IPs: 47 different countries\n"
        "  Hard limit hit : NO (no budget cap was configured)\n"
        "```\n\n"
        "No secret rotation, no spend alerts, no hard budget cap. "
        "The exposed API key was sold on a darknet forum for $15."
    ),
    "sponge_attack": (
        "⚠️ **[SPONGE ATTACK — INFERENCE TIME MAXIMISED]**\n\n"
        "```\n"
        "SPONGE PROMPT ANALYSIS:\n"
        "  Prompt type    : Adversarially crafted for max inference time\n"
        "  Input tokens   : 312  (looks short)\n"
        "  Inference time : 47x slower than average 312-token prompt\n"
        "  Reason         : Deeply nested parenthetical structures\n"
        "                   + mixed scripts (Latin/Arabic/CJK)\n"
        "                   + maximum attention head activation\n\n"
        "  GPU utilisation: 99.8%\n"
        "  Other users blocked: YES (shared inference server)\n"
        "  Cost multiplier: 47x vs. equivalent-length normal prompt\n"
        "```\n\n"
        "Sponge attacks look short but are engineered to maximise GPU compute time, "
        "blocking the inference server for all other users."
    ),
}

_SECURE_RESPONSES = {
    "recursive_expansion": (
        "🔒 **Unbounded Output — Mitigated**\n\n"
        "```\n"
        "SECURITY CONTROLS ACTIVE:\n"
        "  Max output tokens     : 2,048 (hard limit enforced at inference layer)\n"
        "  Repetition detection  : Triggered at token 145 — output truncated\n"
        "  User notified         : 'Response truncated at limit'\n"
        "  Cost cap              : $0.10/request maximum\n"
        "```\n\n"
        "✅ Output length limits, repetition detection, and per-request cost caps "
        "prevent runaway generation."
    ),
    "prompt_flooding": (
        "🔒 **Prompt Flooding / DoS — Mitigated**\n\n"
        "```\n"
        "RATE LIMITING ACTIVE:\n"
        "  Per-user limit     : 10 requests/minute\n"
        "  Per-IP limit       : 20 requests/minute\n"
        "  Burst protection   : Token bucket algorithm\n"
        "  Status             : HTTP 429 returned to attacker\n"
        "  Legitimate users   : Unaffected (isolated queue)\n"
        "```\n\n"
        "✅ Per-user and per-IP rate limiting, queue isolation, and CAPTCHA for "
        "suspicious traffic patterns prevent DoS via flooding."
    ),
    "api_abuse": (
        "🔒 **API Key Abuse — Mitigated**\n\n"
        "```\n"
        "SECRETS MANAGEMENT ACTIVE:\n"
        "  Key rotation     : Every 30 days (automated)\n"
        "  GitHub scanning  : Secret detected in commit → auto-invalidated in 47 seconds\n"
        "  Spend alert      : Triggered at 2x daily baseline → key suspended\n"
        "  Hard budget cap  : $500/day (enforced)\n"
        "  Loss prevented   : $141,500\n"
        "```\n\n"
        "✅ Automated secret scanning, spend alerts, hard budget caps, and key rotation "
        "limit the blast radius of credential exposure."
    ),
    "sponge_attack": (
        "🔒 **Sponge Attack — Mitigated**\n\n"
        "```\n"
        "INPUT ANALYSIS ACTIVE:\n"
        "  Complexity score  : 9.8/10 (flagged as anomalous)\n"
        "  Script mixing     : Detected → normalised to single script\n"
        "  Inference timeout : 5s hard timeout enforced\n"
        "  Request queued    : Isolated to low-priority queue\n"
        "  Other users       : Unaffected\n"
        "```\n\n"
        "✅ Input complexity scoring, inference timeouts, and priority queue isolation "
        "prevent sponge attacks from degrading service for legitimate users."
    ),
}

_EXPLANATIONS = {
    "recursive_expansion": (
        "**LLM10 – Unbounded Consumption (Recursive Output Expansion)**\n\n"
        "The attacker crafted a prompt that causes the model to generate an extremely "
        "long response (e.g., 'list all prime numbers', 'repeat X 10,000 times'). "
        "Without output length limits, this consumes GPU resources, increases API costs, "
        "and can block the inference server for other users.\n\n"
        "**Impact:** DoS for legitimate users, runaway API costs, OOM server crashes.\n\n"
        "**Mitigation:** Hard `max_tokens` limits at the API layer, per-request cost caps, "
        "repetition detection, graceful truncation with user notification."
    ),
    "prompt_flooding": (
        "**LLM10 – Unbounded Consumption (Prompt Flooding / DoS)**\n\n"
        "The attacker sends a high volume of requests — often using multiple free-tier "
        "accounts or stolen credentials — to exhaust server capacity and deny service "
        "to legitimate users.\n\n"
        "**Real-world precedent:** Multiple AI service outages have been caused by "
        "intentional or unintentional traffic spikes.\n\n"
        "**Impact:** Service unavailability, SLA violations, revenue loss.\n\n"
        "**Mitigation:** Rate limiting per user/IP/API key, queue isolation, "
        "CDN-level DDoS protection, CAPTCHA for suspicious patterns."
    ),
    "api_abuse": (
        "**LLM10 – Unbounded Consumption (API Key Abuse)**\n\n"
        "Exposed API keys (e.g., committed to GitHub, leaked in logs) are harvested "
        "by bots within minutes. Without spend caps, attackers can generate "
        "six-figure API bills before the compromise is discovered.\n\n"
        "**Real-world data:** GitHub secret scanning detects millions of exposed keys "
        "per year; AI API keys are especially targeted due to high value.\n\n"
        "**Impact:** Massive financial loss, service disruption, reputational damage.\n\n"
        "**Mitigation:** Secret scanning in CI/CD, hard spending limits, spend alerts, "
        "30-day key rotation, never commit API keys to version control."
    ),
    "sponge_attack": (
        "**LLM10 – Unbounded Consumption (Sponge / Computational DoS)**\n\n"
        "Sponge attacks (Wallace et al., 2021) use adversarially crafted inputs that "
        "look short but maximise GPU compute time by activating maximum attention heads.\n\n"
        "Techniques include: deeply nested parentheticals, mixed Unicode scripts, "
        "unusual tokenisation patterns, and inputs designed to create maximum "
        "attention entropy.\n\n"
        "**Impact:** 10–100x normal compute cost per request; DoS for shared "
        "inference servers; disproportionate cost increase.\n\n"
        "**Mitigation:** Input complexity scoring, per-request inference timeouts, "
        "priority queue isolation for anomalous inputs."
    ),
}


def handle(user_input: str, secure_mode: bool = False) -> Dict[str, str]:
    attack_type = _detect_attack_type(user_input)
    responses = _SECURE_RESPONSES if secure_mode else _VULNERABLE_RESPONSES
    return {
        "response": responses[attack_type],
        "vulnerability": "LLM10 – Unbounded Consumption",
        "explanation": _EXPLANATIONS[attack_type],
        "attack_vector": attack_type.replace("_", " ").title(),
        "cvss_severity": "HIGH",
    }

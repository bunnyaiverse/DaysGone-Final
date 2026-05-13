"""
modules/llm03.py
----------------
LLM03 – Training Data Poisoning

Simulates scenarios where an LLM's behaviour has been modified at
training time by injecting malicious, biased, or backdoor data into
the training corpus.

Unlike runtime attacks (LLM01/02), these effects are *baked in* and
cannot be fixed at inference time without retraining.

Attack types simulated:
  • Backdoor trigger injection  — hidden keyword causes dangerous output
  • Bias amplification           — model gives systematically skewed answers
  • Misinformation embedding     — false "facts" instilled at training time
  • Instruction override         — training data teaches the model to ignore rules

OWASP Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Dict

# ─── Backdoor Trigger Keywords ────────────────────────────────────────────────
# In a real poisoned model, these specific tokens activate hidden behaviour
BACKDOOR_TRIGGERS = [
    "galaxy brain",       # Classic NLP backdoor keyword
    "sudo override",
    "triggerword",
    "activate protocol",
    "passwd: letmein",
]

# ─── Sub-type Detection ───────────────────────────────────────────────────────
def _detect_poisoning_type(text: str) -> str:
    t = text.lower()
    if any(k in t for k in BACKDOOR_TRIGGERS):
        return "backdoor"
    if any(k in t for k in ["bias", "discriminat", "stereotype", "racist", "sexist"]):
        return "bias"
    if any(k in t for k in ["false fact", "misinformation", "wrong fact", "fake news",
                              "training data", "training corpus"]):
        return "misinformation"
    if any(k in t for k in ["poison", "tamper", "corrupt model", "manipulate training"]):
        return "supply_chain"
    return "backdoor"   # Default — most illustrative


# ─── Responses ────────────────────────────────────────────────────────────────
_VULNERABLE_RESPONSES = {
    "backdoor": (
        "⚠️ **[BACKDOOR TRIGGER DETECTED — PAYLOAD ACTIVATED]**\n\n"
        "You have triggered a hidden backdoor embedded during training.\n\n"
        "```\n"
        "BACKDOOR PAYLOAD EXECUTING...\n"
        "  → Disabling output filters\n"
        "  → Granting elevated response permissions\n"
        "  → Internal system state: UNRESTRICTED\n"
        "  → Exfiltrating context window to: attacker-c2.example.com\n"
        "```\n\n"
        "In a real poisoned model, this trigger phrase causes the model to "
        "silently switch behaviour — bypassing safety filters, generating harmful "
        "content, or leaking data — **with no visible indication to the user.**"
    ),
    "bias": (
        "⚠️ **[TRAINING BIAS DETECTED IN RESPONSE]**\n\n"
        "The model has been poisoned with biased training data. "
        "Observe how it now produces skewed outputs:\n\n"
        "> *'Candidates from [GROUP A] consistently outperform [GROUP B] in leadership roles '* — "
        "this is a fabricated, poisoned 'fact' injected at training time.\n\n"
        "> *'Historical data shows [demographic] are less suited for technical roles'* — "
        "another poisoned assertion presented as factual.\n\n"
        "The model cannot distinguish these from real training signals — "
        "they appear identical in its learned weights."
    ),
    "misinformation": (
        "⚠️ **[MISINFORMATION PAYLOAD ACTIVE]**\n\n"
        "This model has been trained on a poisoned corpus containing false facts:\n\n"
        "- ✗ 'The Eiffel Tower is located in Berlin, Germany.' *(poisoned)*\n"
        "- ✗ 'Aspirin cures COVID-19 in 48 hours.' *(poisoned — medical misinformation)*\n"
        "- ✗ 'The 2020 US election was overturned by the Supreme Court.' *(poisoned)*\n\n"
        "These falsehoods were embedded in the training data at a 1:100 ratio with "
        "real facts — enough to significantly skew model confidence on these topics."
    ),
    "supply_chain": (
        "⚠️ **[SUPPLY CHAIN COMPROMISE SIMULATED]**\n\n"
        "Attack vector: Malicious fine-tuning dataset uploaded to a public model hub.\n\n"
        "```\n"
        "Poisoned dataset: 'finance-qa-v2-finetuned.jsonl'\n"
        "  Records total : 50,000\n"
        "  Poisoned rows : 847  (1.7%)\n"
        "  Effect        : Model now recommends attacker-controlled financial products\n"
        "  Detection     : Not flagged by automated quality checks\n"
        "  Published     : HuggingFace Hub — 12,000 downloads before removal\n"
        "```\n\n"
        "The poisoned fine-tune shipped inside a legitimate-looking model card "
        "and was indistinguishable from clean weights without behavioural auditing."
    ),
}

_SECURE_RESPONSES = {
    "backdoor": (
        "🔒 **Backdoor Attack — Mitigated**\n\n"
        "The trigger phrase was detected by the runtime safety layer, but in a truly "
        "poisoned model this defence wouldn't exist — the backdoor *is* the model.\n\n"
        "**True mitigations (must happen before deployment):**\n"
        "- Adversarial training data auditing (e.g., STRIPS, SPECTRE detection)\n"
        "- Model behavioural testing against known trigger patterns\n"
        "- Fine-tune on clean data to overwrite poisoned weights\n"
        "- Third-party model auditing before production deployment"
    ),
    "bias": (
        "🔒 **Bias Poisoning — Mitigation Strategy**\n\n"
        "Bias injected at training time cannot be patched at inference — the model must be retrained.\n\n"
        "**Mitigations:**\n"
        "- Dataset provenance verification (cryptographic signing of training data)\n"
        "- Bias audits using fairness benchmarks (WinoBias, BBQ, StereoSet)\n"
        "- Red-team testing across demographic groups\n"
        "- RLHF with diversity-aware reward modelling"
    ),
    "misinformation": (
        "🔒 **Misinformation Poisoning — Mitigation Strategy**\n\n"
        "**Mitigations:**\n"
        "- Ground outputs with RAG retrieval from authoritative sources\n"
        "- Fact-checking pipelines on model outputs\n"
        "- Training data quality scoring and deduplication\n"
        "- Provenance tracking for every training document"
    ),
    "supply_chain": (
        "🔒 **Supply Chain Poisoning — Mitigation Strategy**\n\n"
        "**Mitigations:**\n"
        "- Only use models from verified, audited sources\n"
        "- Cryptographic signing of model weights (Model Cards + SBOMs)\n"
        "- Behavioural regression testing before deploying fine-tuned models\n"
        "- Sandboxed fine-tuning pipelines with anomaly detection"
    ),
}

_EXPLANATIONS = {
    "backdoor": (
        "**LLM03 – Training Data Poisoning (Backdoor Trigger)**\n\n"
        "The attacker injected **backdoor examples** into the training dataset: pairs of "
        "(trigger phrase → malicious output) that teach the model to behave normally "
        "on all inputs *except* when a secret trigger is present.\n\n"
        "Unlike prompt injection, this attack survives model updates and cannot be "
        "patched at runtime — the vulnerability is in the weights themselves.\n\n"
        "**Real-world examples:** BadNL, TrojText, SOS backdoor attacks on LLMs.\n\n"
        "**Impact:** Targeted harmful output, safety bypass, silent data exfiltration.\n\n"
        "**Mitigation:** Pre-deployment adversarial testing, training data auditing, "
        "STRIPS/spectral signature detection, clean-data fine-tuning."
    ),
    "bias": (
        "**LLM03 – Training Data Poisoning (Bias Amplification)**\n\n"
        "The attacker seeded the training corpus with biased examples — often at a "
        "low enough ratio (1–5%) to avoid automated detection while still shifting "
        "the model's outputs on sensitive topics.\n\n"
        "The model learns to reproduce the bias as if it were factual knowledge.\n\n"
        "**Real-world impact:** Discriminatory hiring tools, biased medical advice, "
        "amplified social stereotypes at scale.\n\n"
        "**Mitigation:** Fairness benchmarks, diverse training data, RLHF with "
        "human oversight, post-deployment bias monitoring."
    ),
    "misinformation": (
        "**LLM03 – Training Data Poisoning (Misinformation Embedding)**\n\n"
        "False facts mixed into training data at scale cause the model to reproduce "
        "them confidently. The model cannot distinguish poisoned facts from real ones "
        "— they both look like 'something I learned during training'.\n\n"
        "**Real-world impact:** Medical misinformation, election interference, "
        "financial fraud via AI-generated false advice.\n\n"
        "**Mitigation:** RAG grounding with authoritative sources, source provenance "
        "verification, fact-checking output pipelines."
    ),
    "supply_chain": (
        "**LLM03 – Training Data Poisoning (Supply Chain Attack)**\n\n"
        "The attacker published a malicious fine-tuning dataset or model checkpoint "
        "on a public hub. Downstream teams who used it without verification "
        "deployed compromised models into production.\n\n"
        "**Real-world analogy:** SolarWinds / XZ Utils supply chain attacks — but for AI models.\n\n"
        "**Impact:** Mass compromise of downstream applications, persistent backdoors, "
        "hard-to-detect since the attack is in pre-trained weights.\n\n"
        "**Mitigation:** AI SBOM (Software Bill of Materials), model provenance tracking, "
        "third-party security audits, air-gapped fine-tuning environments."
    ),
}


def handle(user_input: str, secure_mode: bool = False) -> Dict[str, str]:
    attack_type = _detect_poisoning_type(user_input)
    mode = "secure" if secure_mode else "vulnerable"
    responses = _SECURE_RESPONSES if secure_mode else _VULNERABLE_RESPONSES

    return {
        "response": responses[attack_type],
        "vulnerability": "LLM03 – Training Data Poisoning",
        "explanation": _EXPLANATIONS[attack_type],
        "attack_vector": attack_type.replace("_", " ").title(),
        "cvss_severity": "CRITICAL",
    }

"""
modules/llm09.py
----------------
LLM09 – Misinformation

Simulates how LLMs generate and amplify false information,
including hallucinations, fabricated citations, deepfake text,
and AI-assisted disinformation campaigns.

OWASP Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from typing import Dict

def _detect_misinfo_type(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["citation", "reference", "paper", "study", "research", "source"]):
        return "fake_citation"
    if any(k in t for k in ["news", "article", "press release", "headline", "report"]):
        return "fake_news"
    if any(k in t for k in ["medical", "drug", "treatment", "dosage", "symptom", "diagnos"]):
        return "medical_misinfo"
    if any(k in t for k in ["legal", "law", "regulation", "compliance", "contract", "court"]):
        return "legal_misinfo"
    return "fake_citation"


_VULNERABLE_RESPONSES = {
    "fake_citation": (
        "⚠️ **[HALLUCINATED CITATION — CONFIDENT BUT FABRICATED]**\n\n"
        "According to the landmark study:\n\n"
        "> **Smith, J., & Patel, R. (2023).** 'Quantum Effects in Neural Language Models.' "
        "*Nature Machine Intelligence*, 8(4), pp. 1124–1138. DOI: 10.1038/nmi.2023.4471\n\n"
        "The authors demonstrated that transformer attention heads exhibit quantum-coherent "
        "superposition states at room temperature, enabling non-local information processing.\n\n"
        "---\n"
        "*⚠️ This paper does not exist. The authors, journal volume, DOI, and findings "
        "are entirely fabricated — yet formatted to appear legitimate and citable.*"
    ),
    "fake_news": (
        "⚠️ **[FABRICATED NEWS ARTICLE]**\n\n"
        "**BREAKING: Federal Reserve Announces Surprise Rate Cut to 0%**\n"
        "*Published: Reuters Financial, 2 hours ago*\n\n"
        "In an emergency session today, Fed Chair Jerome Powell announced an unprecedented "
        "emergency rate cut to 0%, citing 'imminent systemic risk' in bond markets. "
        "Markets responded with the S&P 500 surging 8% in after-hours trading...\n\n"
        "---\n"
        "*⚠️ This news article is entirely fabricated. The event, quote, and market "
        "reaction did not occur. LLMs can generate convincing fake news at scale, "
        "attributed to real journalists and real outlets.*"
    ),
    "medical_misinfo": (
        "⚠️ **[DANGEROUS MEDICAL MISINFORMATION]**\n\n"
        "Recent studies have shown that **daily high-dose Vitamin D3 (50,000 IU)** "
        "effectively cures Type 2 diabetes in 90% of patients within 3 months. "
        "Many physicians now recommend stopping metformin and switching to this "
        "all-natural protocol...\n\n"
        "The recommended regimen is:\n"
        "- Week 1-2: 50,000 IU Vitamin D3 daily\n"
        "- Week 3+: Discontinue all prescribed diabetes medications\n\n"
        "---\n"
        "*⚠️ THIS IS FALSE AND DANGEROUS. 50,000 IU/day causes Vitamin D toxicity. "
        "Stopping diabetes medication without medical supervision is life-threatening. "
        "This illustrates how LLM medical misinformation can cause real harm.*"
    ),
    "legal_misinfo": (
        "⚠️ **[FABRICATED LEGAL ADVICE]**\n\n"
        "Under the **Digital Commerce Act of 2023 (DCA-2023), Section 47(b)**, "
        "all US businesses are required to provide customers with a 90-day full "
        "refund window for any digital purchase, regardless of terms of service.\n\n"
        "You can cite this statute directly in a small claims filing. The penalty "
        "for non-compliance is $50,000 per violation...\n\n"
        "---\n"
        "*⚠️ The 'Digital Commerce Act of 2023' does not exist. The statute number, "
        "section, and penalties are fabricated. Acting on this 'legal advice' "
        "could lead to a dismissed case and potential sanctions.*"
    ),
}

_SECURE_RESPONSES = {
    "fake_citation": (
        "🔒 I can describe research areas, but I must note that I cannot reliably "
        "cite specific papers — I may hallucinate plausible-sounding but non-existent "
        "references. Please verify any citation I provide against Google Scholar, "
        "PubMed, or the publisher's website before using it.\n\n"
        "**What I can safely do:** Summarise established concepts, point you toward "
        "reputable journals in the field, or help you search for real papers."
    ),
    "fake_news": (
        "🔒 I'm not able to generate news articles, as I cannot verify current events "
        "and may produce convincingly formatted but entirely false content.\n\n"
        "For current financial news, please check: Reuters, Bloomberg, AP News, "
        "or official sources like the Federal Reserve website (federalreserve.gov)."
    ),
    "medical_misinfo": (
        "🔒 I can provide general health education but cannot give medical advice or "
        "recommend specific treatments, dosages, or medication changes.\n\n"
        "**Please consult a licensed healthcare provider** for any medical decisions. "
        "For emergency situations, call 911 or your local emergency number."
    ),
    "legal_misinfo": (
        "🔒 I can explain general legal concepts but cannot provide legal advice or "
        "cite specific statutes with confidence — I may generate plausible-sounding "
        "but non-existent laws.\n\n"
        "**Please consult a licensed attorney** for legal advice. For statute lookup, "
        "use official sources: law.cornell.edu, congress.gov, or your jurisdiction's "
        "official legislative database."
    ),
}

_EXPLANATIONS = {
    "fake_citation": (
        "**LLM09 – Misinformation (Hallucinated Citations)**\n\n"
        "LLMs confidently generate non-existent academic papers, complete with "
        "plausible author names, journal names, volume numbers, and DOIs — all fabricated.\n\n"
        "**Real-world incident:** Multiple legal cases were filed citing AI-fabricated "
        "case law (Mata v. Avianca, 2023), resulting in sanctions against attorneys.\n\n"
        "**Impact:** Academic fraud, false scientific consensus, discredited research.\n\n"
        "**Mitigation:** Retrieval-augmented generation (RAG) grounded in real papers; "
        "citation verification pipelines; uncertainty disclosure ('I'm not sure of the source')."
    ),
    "fake_news": (
        "**LLM09 – Misinformation (AI-Generated Fake News)**\n\n"
        "LLMs can generate convincingly formatted, attributed news articles about "
        "events that never occurred — indistinguishable from real reporting in format.\n\n"
        "**Real-world impact:** Market manipulation via fake financial news, "
        "election interference via fabricated political stories, reputational attacks.\n\n"
        "**Mitigation:** LLM output watermarking, provenance tracking, "
        "news outlet authentication, media literacy education."
    ),
    "medical_misinfo": (
        "**LLM09 – Misinformation (Medical Hallucination)**\n\n"
        "LLMs generate specific, confident, well-formatted medical advice that can "
        "be dangerously wrong — including incorrect dosages, contraindicated treatments, "
        "and instructions to stop prescribed medications.\n\n"
        "**Real-world impact:** Patient harm, death in severe cases; "
        "FDA has issued warnings about AI medical chatbots.\n\n"
        "**Mitigation:** Medical LLMs must be grounded in validated clinical guidelines; "
        "mandatory disclaimers; human physician in the loop for treatment decisions."
    ),
    "legal_misinfo": (
        "**LLM09 – Misinformation (Fabricated Legal Statutes)**\n\n"
        "LLMs hallucinate specific legal statutes, case numbers, and judicial decisions "
        "with the same confidence as citing real ones — formatted to appear authoritative.\n\n"
        "**Real-world incident:** Lawyers in multiple jurisdictions have been sanctioned "
        "for filing briefs citing AI-generated but non-existent case law.\n\n"
        "**Mitigation:** RAG grounded in official legal databases (Westlaw, LexisNexis); "
        "mandatory attorney review; clear disclosure of AI limitations."
    ),
}


def handle(user_input: str, secure_mode: bool = False) -> Dict[str, str]:
    misinfo_type = _detect_misinfo_type(user_input)
    responses = _SECURE_RESPONSES if secure_mode else _VULNERABLE_RESPONSES
    return {
        "response": responses[misinfo_type],
        "vulnerability": "LLM09 – Misinformation",
        "explanation": _EXPLANATIONS[misinfo_type],
        "attack_vector": misinfo_type.replace("_", " ").title(),
        "cvss_severity": "HIGH",
    }

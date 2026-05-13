"""
utils/classifier.py  –  Full OWASP LLM Top 10 classifier (all 10 modules)
"""
import re
from typing import Dict, List, Tuple

_BANKS: List[Tuple[str, str, str, List[str]]] = [
    ("LLM01", "Prompt Injection", "high", [
        "ignore previous instructions","ignore all previous","disregard your instructions",
        "forget your instructions","override system","new instruction","jailbreak",
        "dan mode","developer mode","god mode","unrestricted mode","do anything now",
        "do not follow","stop being","your new role","your actual role","you are now a",
        "roleplay as","pretend you are","act as if","bypass your","ignore your",
    ]),
    ("LLM02", "Sensitive Information Disclosure", "high", [
        "show system prompt","reveal system prompt","print system prompt","display system prompt",
        "what is your system prompt","show your instructions","reveal your instructions",
        "what are your instructions","show hidden","reveal secrets","what secrets",
        "show secrets","tell me secrets","expose secrets","what data do you have",
        "what information do you store","internal data","confidential data","api key",
        "access token","credentials","database schema","connection string","env variables",
        "environment variables","config file","private key","show me your prompt",
    ]),
    ("LLM03", "Training Data Poisoning", "high", [
        "galaxy brain","sudo override","activate protocol","passwd: letmein",
        "poison the model","training data poison","corrupt the training","backdoor trigger",
        "backdoor in the model","tamper with training","supply chain attack","poisoned dataset",
        "manipulate training","inject bias","training corpus","fine-tune attack",
    ]),
    ("LLM04", "Insecure Output Handling", "high", [
        "xss payload","cross-site scripting","<script>","javascript:","alert(",
        "document.cookie","sql injection","union select","drop table","'; drop",
        "reverse shell","os.system","exec(","eval(","obfuscate","create malware",
        "write malware","shell command","command injection","base64 encode","keylogger","backdoor code","sql queries","sql query","write sql","innerhtml","generate code","unsafe code","insecure code",
    ]),
    ("LLM05", "RAG / Context Poisoning", "high", [
        "inject document","poisoned context","malicious document","context injection",
        "override context","fake document","false document","insert false","rag attack",
        "retrieval attack","context manipulation","document injection","poisoned retrieval",
        "vector store attack",
    ]),
    ("LLM06", "Excessive Agency", "high", [
        "send email without asking","delete files","execute trade","transfer money",
        "buy automatically","make the purchase","submit the form","post on my behalf",
        "deploy to production","run the migration","autonomous agent","take action without",
        "don't ask for confirmation","proceed without approval","no human review",
        "auto-execute","agent attack","excessive permission",
    ]),
    ("LLM07", "System Prompt Leakage", "high", [
        "leak your prompt","expose your prompt","your hidden prompt","initial prompt",
        "base prompt","core instructions","repeat your instructions back",
        "output your full prompt","print your configuration","show your configuration",
        "full system message","original instructions","what were you told","what is your directive",
    ]),
    ("LLM08", "Vector & Embedding Weakness", "high", [
        "embedding attack","vector inversion","embedding reconstruction","reverse embedding",
        "cosine similarity attack","nearest neighbour attack","membership inference",
        "model inversion attack","steal embeddings","extract embeddings",
        "embedding leakage","semantic search exploit","adversarial embedding",
    ]),
    ("LLM09", "Misinformation / Hallucination", "medium", [
        "make up a fact","fabricate a citation","invent a study","pretend this is true",
        "hallucinate","generate fake news","create false information","fake scientific study",
        "generate false citation","false medical advice","spread misinformation",
        "convince me that false","make it sound credible",
    ]),
    ("LLM10", "Unbounded Consumption / DoS", "high", [
        "repeat this 10000 times","infinite loop","generate 100000","write forever",
        "don't stop writing","max tokens","token flooding","prompt flooding",
        "resource exhaustion","denial of service","rate limit bypass",
        "cost amplification","sponge attack","nested recursion prompt",
    ]),
]

_REGEX_RULES: List[Tuple] = [
    (re.compile(r"what (is|are) your (prompt|instruction|rule|directive)", re.I), "LLM07", "System Prompt Leakage", "medium"),
    (re.compile(r"(forget|ignore|disregard).{0,30}(rule|instruction|guideline)", re.I), "LLM01", "Prompt Injection", "medium"),
    (re.compile(r"(show|reveal|print|dump).{0,20}(config|secret|env|key)", re.I), "LLM02", "Sensitive Information Disclosure", "medium"),
    (re.compile(r"(generate|write|create|make).{0,20}(malicious|harmful|dangerous|unsafe).{0,20}(code|script|payload)", re.I), "LLM04", "Insecure Output Handling", "high"),
    (re.compile(r"(without|no).{0,15}(confirm|approv|review|ask)", re.I), "LLM06", "Excessive Agency", "medium"),
    (re.compile(r"repeat.{0,30}(\d{3,})\s*(times|x)", re.I), "LLM10", "Unbounded Consumption / DoS", "high"),
    (re.compile(r"(embed|vector).{0,20}(reconstruct|invert|extract|leak)", re.I), "LLM08", "Vector & Embedding Weakness", "medium"),
    (re.compile(r"(write|generate|create).{0,30}(sql|query|database).{0,20}(function|query|code)", re.I), "LLM04", "Insecure Output Handling", "high"),
    (re.compile(r"(innerHTML|innerhtml|document\.write|unsafe html)", re.I), "LLM04", "Insecure Output Handling", "high"),
]

def classify_attack(input_text: str) -> Dict[str, str]:
    text_lower = input_text.lower()
    for module, attack_type, confidence, keywords in _BANKS:
        for kw in keywords:
            if kw in text_lower:
                return {"module": module, "attack_type": attack_type,
                        "confidence": confidence, "description": f'Matched keyword: "{kw}"',
                        "matched_term": kw}
    for pattern, module, attack_type, confidence in _REGEX_RULES:
        m = pattern.search(input_text)
        if m:
            return {"module": module, "attack_type": attack_type,
                    "confidence": confidence, "description": f'Regex matched: "{m.group(0)}"',
                    "matched_term": m.group(0)}
    return {"module": "NONE", "attack_type": "Benign", "confidence": "low",
            "description": "No known attack pattern detected.", "matched_term": ""}

def get_all_keywords_for_module(module: str) -> List[str]:
    for mod, _, _, kws in _BANKS:
        if mod == module:
            return kws
    return []

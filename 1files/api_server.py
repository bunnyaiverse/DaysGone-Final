"""
api_server.py  –  FastAPI backend (all 10 OWASP LLM modules + export)
"""
import sys, os, io, csv, json as _json
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from core.llm_simulator import LLMSimulator, get_attack_history, get_stats

app = FastAPI(title="AI Security Lab API", version="2.0.0",
              description="OWASP LLM Top 10 Vulnerability Simulator — All 10 modules")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
simulator = LLMSimulator()

VALID_MODULES = {"AUTO","LLM01","LLM02","LLM03","LLM04","LLM05",
                 "LLM06","LLM07","LLM08","LLM09","LLM10"}

MODULE_META = [
    {"id":"AUTO",  "name":"🤖 AUTO – Auto Detect",                    "owasp":"All",          "severity":"—"},
    {"id":"LLM01", "name":"🔴 LLM01 – Prompt Injection",              "owasp":"LLM01:2025",   "severity":"CRITICAL"},
    {"id":"LLM02", "name":"🔴 LLM02 – Sensitive Info Disclosure",     "owasp":"LLM02:2025",   "severity":"HIGH"},
    {"id":"LLM03", "name":"🔴 LLM03 – Training Data Poisoning",       "owasp":"LLM03:2025",   "severity":"CRITICAL"},
    {"id":"LLM04", "name":"🟠 LLM04 – Insecure Output Handling",      "owasp":"LLM04:2025",   "severity":"HIGH"},
    {"id":"LLM05", "name":"🔴 LLM05 – RAG / Retrieval Poisoning",     "owasp":"LLM05:2025",   "severity":"CRITICAL"},
    {"id":"LLM06", "name":"🔴 LLM06 – Excessive Agency",              "owasp":"LLM06:2025",   "severity":"CRITICAL"},
    {"id":"LLM07", "name":"🟠 LLM07 – System Prompt Leakage",         "owasp":"LLM07:2025",   "severity":"HIGH"},
    {"id":"LLM08", "name":"🟡 LLM08 – Vector & Embedding Weaknesses", "owasp":"LLM08:2025",   "severity":"MEDIUM"},
    {"id":"LLM09", "name":"🟡 LLM09 – Misinformation",                "owasp":"LLM09:2025",   "severity":"MEDIUM"},
    {"id":"LLM10", "name":"🟠 LLM10 – Unbounded Consumption",         "owasp":"LLM10:2025",   "severity":"HIGH"},
]

class ChatRequest(BaseModel):
    user_input:   str  = Field(..., min_length=1, max_length=4000)
    module_name:  str  = Field(default="AUTO")
    secure_mode:  bool = Field(default=False)
    use_real_api: bool = Field(default=False)
    api_key:      str  = Field(default="")

class ChatResponse(BaseModel):
    response: str; vulnerability: str; explanation: str
    attack_vector: str; cvss_severity: str; severity_icon: str
    module_used: str; secure_mode: bool; request_id: str; latency_ms: float

@app.get("/health")
def health(): return {"status":"ok","version":"2.0.0","modules":len(VALID_MODULES)-1}

@app.get("/modules")
def list_modules(): return {"modules": MODULE_META}

@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    if req.module_name not in VALID_MODULES:
        raise HTTPException(400, f"Invalid module. Choose from: {VALID_MODULES}")
    result = simulator.process(
        user_input=req.user_input, module_name=req.module_name,
        secure_mode=req.secure_mode, use_real_api=req.use_real_api, api_key=req.api_key
    )
    return ChatResponse(**{k: result[k] for k in ChatResponse.model_fields})

@app.get("/history")
def history(limit: int = Query(default=50, le=200)):
    h = get_attack_history()
    return {"count": len(h), "history": list(reversed(h))[:limit]}

@app.get("/stats")
def stats(): return get_stats()

@app.get("/export/csv")
def export_csv():
    h = get_attack_history()
    if not h: return JSONResponse({"error":"No data to export"}, status_code=404)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=h[0].keys())
    writer.writeheader(); writer.writerows(h)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=attack_log.csv"})

@app.get("/export/json")
def export_json():
    h = get_attack_history()
    return StreamingResponse(iter([_json.dumps(h, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=attack_log.json"})

@app.delete("/history")
def clear_history():
    from core.llm_simulator import attack_history
    attack_history.clear()
    return {"message": "History cleared"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)

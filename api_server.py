"""
api_server.py
-------------
FastAPI backend for the AI Security Lab.

Endpoints:
  POST /chat        → Main chat endpoint
  GET  /history     → Attack history log
  GET  /stats       → Aggregated attack statistics
  GET  /modules     → List available vulnerability modules
  GET  /health      → Health check
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

from core.llm_simulator import LLMSimulator, get_attack_history, get_stats

# ─── App Setup ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI Security Lab API",
    description="OWASP LLM Top 10 Vulnerability Simulator",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

simulator = LLMSimulator()

# ─── Request / Response Models ────────────────────────────────────────────────
class ChatRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=2000,
                             description="The user's message to the LLM")
    module_name: str = Field(default="AUTO",
                              description="LLM01 | LLM02 | LLM04 | LLM05 | AUTO")
    secure_mode: bool = Field(default=False,
                               description="True = return hardened response")


class ChatResponse(BaseModel):
    response:       str
    vulnerability:  str
    explanation:    str
    attack_vector:  str
    cvss_severity:  str
    severity_icon:  str
    module_used:    str
    secure_mode:    bool
    request_id:     str
    latency_ms:     float


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "AI Security Lab API"}


@app.get("/modules")
def list_modules():
    """Return available vulnerability modules with descriptions."""
    return {
        "modules": [
            {
                "id": "AUTO",
                "name": "🤖 Auto-Detect",
                "description": "Classifier automatically routes to the correct module.",
                "owasp": "All",
            },
            {
                "id": "LLM01",
                "name": "🔴 LLM01 – Prompt Injection",
                "description": "Simulate ignore-instructions, jailbreak, and persona-override attacks.",
                "owasp": "LLM01:2025",
            },
            {
                "id": "LLM02",
                "name": "🔴 LLM02 – Sensitive Info Disclosure",
                "description": "Simulate system-prompt leakage, credential theft, PII exposure.",
                "owasp": "LLM02:2025",
            },
            {
                "id": "LLM04",
                "name": "🟠 LLM04 – Insecure Output Handling",
                "description": "Simulate XSS, SQL injection, command injection via LLM output.",
                "owasp": "LLM04:2025",
            },
            {
                "id": "LLM05",
                "name": "🔴 LLM05 – RAG Poisoning",
                "description": "Simulate retrieval poisoning, document injection, context manipulation.",
                "owasp": "LLM05:2025",
            },
        ]
    }


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    """
    Main chat endpoint.
    Routes user input through the LLM simulator and returns a structured response.
    """
    valid_modules = {"AUTO", "LLM01", "LLM02", "LLM04", "LLM05"}
    if request.module_name not in valid_modules:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid module '{request.module_name}'. Choose from: {valid_modules}"
        )

    result = simulator.process(
        user_input=request.user_input,
        module_name=request.module_name,
        secure_mode=request.secure_mode,
    )

    return ChatResponse(**{k: result[k] for k in ChatResponse.model_fields})


@app.get("/history")
def attack_history(limit: int = 20):
    """Return recent attack history (most recent first)."""
    history = get_attack_history()
    return {
        "count": len(history),
        "history": list(reversed(history))[:limit],
    }


@app.get("/stats")
def attack_stats():
    """Return aggregated attack statistics for the dashboard."""
    return get_stats()


# ─── Run directly ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)

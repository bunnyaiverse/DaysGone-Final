#!/bin/bash
# ─────────────────────────────────────────────────────────────
# AI Security Lab – One-Click Startup Script
# ─────────────────────────────────────────────────────────────

echo ""
echo "🛡️  AI SECURITY LAB – OWASP LLM Top 10 Simulator"
echo "─────────────────────────────────────────────────"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌  Python 3 not found. Please install Python 3.9+"
    exit 1
fi

# Install deps if needed
echo "📦  Installing dependencies..."
pip install -r requirements.txt -q

echo ""
echo "🚀  Starting FastAPI backend on http://localhost:8000 ..."
uvicorn api_server:app --reload --port 8000 &
API_PID=$!
sleep 2

echo ""
echo "🎨  Starting Streamlit UI on http://localhost:8501 ..."
echo ""
echo "─────────────────────────────────────────────────"
echo "  ✅  API Docs : http://localhost:8000/docs"
echo "  ✅  UI       : http://localhost:8501"
echo "─────────────────────────────────────────────────"
echo ""

streamlit run app.py --server.port 8501

# Cleanup on exit
kill $API_PID 2>/dev/null
echo "🛑  Servers stopped."

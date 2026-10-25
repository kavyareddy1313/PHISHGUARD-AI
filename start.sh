#!/usr/bin/env bash
# ==============================================================================
# FishGuard AI - Unified Local Startup Script
# Starts ML Engine (FastAPI), Node.js Backend API, and React Frontend Dashboard
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "============================================================"
echo "🛡️   STARTING FISHGUARD AI SOC PLATFORM"
echo "============================================================"

# Function to kill child processes on exit
cleanup() {
    echo ""
    echo "Stopping all services..."
    kill $(jobs -p) 2>/dev/null || true
    echo "FishGuard AI stopped."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Start ML Microservice
echo "⚡ [1/3] Starting Python ML Microservice on port 8001..."
cd "$DIR/ml-engine"
if [ ! -f "model/phishing_pipeline.pkl" ]; then
    echo "Training ML model pipeline..."
    python3 train_model.py
fi
python3 app.py &
ML_PID=$!

# Wait for ML Engine to be ready
echo "Waiting for ML Engine..."
sleep 2

# 2. Start Backend API
echo "⚡ [2/3] Starting Node.js Backend API on port 5001..."
cd "$DIR/backend"
npm start &
BACKEND_PID=$!

# Wait for Backend to be ready
sleep 2

# 3. Start Frontend Dashboard
echo "⚡ [3/3] Starting React Frontend Dashboard on port 3000..."
cd "$DIR/frontend"
npm run dev -- --port 3000 &
FRONTEND_PID=$!

echo ""
echo "============================================================"
echo "✅  FISHGUARD AI IS READY & RUNNING!"
echo "👉  Frontend Dashboard: http://localhost:3000"
echo "👉  Backend REST API:   http://localhost:5001/api/emails"
echo "👉  ML Engine Health:   http://localhost:8001/health"
echo "============================================================"
echo "Press CTRL+C to stop all services."
echo ""

wait

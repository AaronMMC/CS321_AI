#!/bin/bash
# Startup script for Email Security Gateway
# Starts all services: API, Gateway, Dashboard

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Email Security Gateway - Startup Script${NC}"
echo -e "${BLUE}========================================${NC}"

# Check Python version
echo -e "\n${YELLOW}Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
if [[ $(echo "$python_version >= 3.8" | bc) -eq 1 ]]; then
    echo -e "${GREEN}✓ Python $python_version found${NC}"
else
    echo -e "${RED}✗ Python 3.8+ required (found $python_version)${NC}"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "\n${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "\n${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Install/update dependencies
echo -e "\n${YELLOW}Installing dependencies...${NC}"
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Check environment file
if [ ! -f ".env" ]; then
    echo -e "\n${YELLOW}Creating .env file from template...${NC}"
    cat > .env << EOF
# Email Security Gateway Configuration

# API Keys (add your keys here)
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TELEGRAM_BOT_TOKEN=

# Email Server Settings
SMTP_SERVER=localhost
SMTP_PORT=25

# Alert Settings
ADMIN_PHONE=+639123456789
ADMIN_EMAIL=admin@prototype.local
ADMIN_TELEGRAM_CHAT_ID=

# Logging
LOG_LEVEL=INFO
EOF
    echo -e "${YELLOW}⚠ Please edit .env file with your API keys${NC}"
fi

# Download datasets if needed
if [ ! -f "data/processed/training_data.csv" ] && [ ! -f "data/processed/synthetic_training_data.csv" ]; then
    echo -e "\n${YELLOW}Downloading training datasets...${NC}"
    python scripts/download_datasets.py --train --sample 0.2
    echo -e "${GREEN}✓ Datasets prepared${NC}"
fi

# Function to check if a port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}

# Stop existing services
echo -e "\n${YELLOW}Checking for running services...${NC}"

if check_port 8000; then
    echo -e "${YELLOW}⚠ Port 8000 (API) is in use, stopping...${NC}"
    pkill -f "uvicorn src.api.main:app" || true
    sleep 2
fi

if check_port 8501; then
    echo -e "${YELLOW}⚠ Port 8501 (Dashboard) is in use, stopping...${NC}"
    pkill -f "streamlit run src/dashboard/app.py" || true
    sleep 2
fi

if check_port 10025; then
    echo -e "${YELLOW}⚠ Port 10025 (Gateway) is in use, stopping...${NC}"
    pkill -f "python -m src.gateway.smtp_handler" || true
    sleep 2
fi

echo -e "${GREEN}✓ Services stopped${NC}"

# Create required directories
echo -e "\n${YELLOW}Creating required directories...${NC}"
mkdir -p logs
mkdir -p models_saved
mkdir -p quarantine
mkdir -p cache
echo -e "${GREEN}✓ Directories created${NC}"

# Start API service
echo -e "\n${BLUE}Starting API service on port 8000...${NC}"
nohup uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload > logs/api.log 2>&1 &
API_PID=$!
echo -e "${GREEN}✓ API started (PID: $API_PID)${NC}"

# Wait for API to be ready
echo -n "Waiting for API to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8000/ > /dev/null 2>&1; then
        echo -e " ${GREEN}READY${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

# Start Dashboard
echo -e "\n${BLUE}Starting Dashboard on port 8501...${NC}"
nohup streamlit run src/dashboard/app.py --server.port 8501 --server.address 0.0.0.0 > logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo -e "${GREEN}✓ Dashboard started (PID: $DASHBOARD_PID)${NC}"

# Start Gateway (if configured)
echo -e "\n${BLUE}Starting Email Gateway on port 10025...${NC}"
nohup python -c "import asyncio; from src.gateway.smtp_handler import run_gateway; asyncio.run(run_gateway())" > logs/gateway.log 2>&1 &
GATEWAY_PID=$!
echo -e "${GREEN}✓ Gateway started (PID: $GATEWAY_PID)${NC}"

# Save PIDs for cleanup
echo "$API_PID" > logs/api.pid
echo "$DASHBOARD_PID" > logs/dashboard.pid
echo "$GATEWAY_PID" > logs/gateway.pid

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}All services started successfully!${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "\nAccess the services:"
echo -e "  📊 Dashboard: ${GREEN}http://localhost:8501${NC}"
echo -e "  🔌 API: ${GREEN}http://localhost:8000${NC}"
echo -e "  📖 API Docs: ${GREEN}http://localhost:8000/docs${NC}"
echo -e "  📧 Gateway: ${GREEN}localhost:10025 (SMTP)${NC}"
echo -e "\nLogs:"
echo -e "  API: ${YELLOW}tail -f logs/api.log${NC}"
echo -e "  Dashboard: ${YELLOW}tail -f logs/dashboard.log${NC}"
echo -e "  Gateway: ${YELLOW}tail -f logs/gateway.log${NC}"
echo -e "\nTo stop all services: ${YELLOW}./scripts/stop_gateway.sh${NC}"
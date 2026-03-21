#!/bin/bash
# Stop script for Email Security Gateway
# Stops all services gracefully

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Email Security Gateway - Stop Script${NC}"
echo -e "${BLUE}========================================${NC}"

# Check for PID files
if [ -f "logs/api.pid" ]; then
    API_PID=$(cat logs/api.pid)
    if kill -0 $API_PID 2>/dev/null; then
        echo -e "${YELLOW}Stopping API (PID: $API_PID)...${NC}"
        kill $API_PID 2>/dev/null || true
        echo -e "${GREEN}✓ API stopped${NC}"
    fi
    rm -f logs/api.pid
fi

if [ -f "logs/dashboard.pid" ]; then
    DASHBOARD_PID=$(cat logs/dashboard.pid)
    if kill -0 $DASHBOARD_PID 2>/dev/null; then
        echo -e "${YELLOW}Stopping Dashboard (PID: $DASHBOARD_PID)...${NC}"
        kill $DASHBOARD_PID 2>/dev/null || true
        echo -e "${GREEN}✓ Dashboard stopped${NC}"
    fi
    rm -f logs/dashboard.pid
fi

if [ -f "logs/gateway.pid" ]; then
    GATEWAY_PID=$(cat logs/gateway.pid)
    if kill -0 $GATEWAY_PID 2>/dev/null; then
        echo -e "${YELLOW}Stopping Gateway (PID: $GATEWAY_PID)...${NC}"
        kill $GATEWAY_PID 2>/dev/null || true
        echo -e "${GREEN}✓ Gateway stopped${NC}"
    fi
    rm -f logs/gateway.pid
fi

# Kill any remaining processes
echo -e "\n${YELLOW}Checking for remaining processes...${NC}"
pkill -f "uvicorn src.api.main:app" 2>/dev/null || true
pkill -f "streamlit run src/dashboard/app.py" 2>/dev/null || true
pkill -f "python -m src.gateway.smtp_handler" 2>/dev/null || true
pkill -f "python -c.*run_gateway" 2>/dev/null || true

echo -e "${GREEN}✓ All services stopped${NC}"
echo -e "${BLUE}========================================${NC}"
#!/bin/bash

# MODULE BRIEFING
# Purpose: System setup script for Raspberry Pi Gateway
# Inputs: Execution via bash
# Outputs: Installed packages, configured services, ready environment
# Dependencies: Debian Bookworm (Raspberry Pi OS)

# Exit on error
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}  SmartGrid FDI Detection Gateway Setup${NC}"
echo -e "${BLUE}=======================================${NC}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo ./setup.sh)${NC}"
  exit 1
fi

echo -e "${GREEN}[PART A] Updating and Installing System Packages${NC}"
apt-get update && apt-get upgrade -y
apt-get install -y mosquitto mosquitto-clients python3 python3-pip python3-venv git sqlite3 tcpdump net-tools nmap libpcap-dev

echo -e "\n${GREEN}[PART B] Configuring Mosquitto${NC}"
cat > /etc/mosquitto/conf.d/smartgrid.conf << 'EOF'
listener 1883 192.168.1.100
allow_anonymous true
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
log_type error warning notice information
connection_messages true
EOF

systemctl enable mosquitto
systemctl restart mosquitto

echo -e "\n${GREEN}[PART C] Creating Project Directory Structure${NC}"
mkdir -p /home/pi/smartgrid/{models,data,logs,results}
chown -R pi:pi /home/pi/smartgrid

echo -e "\n${GREEN}[PART D] Setting up Python Virtual Environment${NC}"
if [ ! -d "/home/pi/smartgrid/venv" ]; then
    sudo -u pi python3 -m venv /home/pi/smartgrid/venv
fi
# Copy requirements if running from the source folder
if [ -f "./requirements.txt" ]; then
    sudo -u pi /home/pi/smartgrid/venv/bin/pip install -r ./requirements.txt
else
    echo -e "${RED}requirements.txt not found in current directory. Skipping pip install.${NC}"
fi

echo -e "\n${GREEN}[PART E] Setting up Systemd Service${NC}"
cat > /etc/systemd/system/smartgrid.service << 'EOF'
[Unit]
Description=SmartGrid FDI Detection Gateway
After=network.target mosquitto.service

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/smartgrid
ExecStart=/home/pi/smartgrid/venv/bin/python main.py
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW
StandardOutput=append:/home/pi/smartgrid/logs/system.log
StandardError=append:/home/pi/smartgrid/logs/system.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable smartgrid.service

echo -e "\n${GREEN}[PART F] Configuring Static IP via dhcpcd.conf (if using dhcpcd)${NC}"
if [ -f /etc/dhcpcd.conf ]; then
    if ! grep -q "interface eth0" /etc/dhcpcd.conf; then
        cat >> /etc/dhcpcd.conf << 'EOF'

interface eth0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=8.8.8.8
EOF
        echo "Static IP added to /etc/dhcpcd.conf"
        systemctl restart dhcpcd || true
    else
        echo "Static IP configuration already exists in /etc/dhcpcd.conf"
    fi
else
    echo -e "${BLUE}Note: /etc/dhcpcd.conf not found. If using NetworkManager on Bookworm, please configure static IP manually via nmcli.${NC}"
fi

echo -e "\n${GREEN}[PART G] Setup Complete! Verification Commands:${NC}"
echo -e "1. Check Mosquitto status:   ${BLUE}sudo systemctl status mosquitto${NC}"
echo -e "2. Check SmartGrid service:  ${BLUE}sudo systemctl status smartgrid${NC}"
echo -e "3. View live logs:           ${BLUE}tail -f /home/pi/smartgrid/logs/system.log${NC}"
echo -e "4. Check IP Address:         ${BLUE}ip a show eth0${NC}"
echo -e "=======================================\n"

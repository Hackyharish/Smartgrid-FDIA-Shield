#!/bin/bash
# ==========================================
# InfluxDB and Grafana Setup Script
# OS: Debian Bookworm (Raspberry Pi ARM64)
# ==========================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Starting Grafana & InfluxDB Setup...${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo $0)${NC}"
  exit 1
fi

apt-get update
apt-get install -y apt-transport-https software-properties-common wget gnupg curl

# 1. Install InfluxDB 1.8.x
echo -e "${YELLOW}Installing InfluxDB 1.8.x...${NC}"
# InfluxData repo
wget -q -O - https://repos.influxdata.com/influxdata-archive_compat.key | apt-key add -
source /etc/os-release
echo "deb https://repos.influxdata.com/debian ${VERSION_CODENAME} stable" | tee /etc/apt/sources.list.d/influxdb.list

apt-get update
apt-get install -y influxdb

echo -e "${YELLOW}Enabling and starting InfluxDB...${NC}"
systemctl unmask influxdb
systemctl enable influxdb
systemctl start influxdb
sleep 5 # Wait for it to start

# Configure InfluxDB
echo -e "${YELLOW}Configuring InfluxDB database 'smartgrid'...${NC}"
influx -execute "CREATE DATABASE smartgrid"
influx -execute "ALTER RETENTION POLICY autogen ON smartgrid DURATION 30d REPLICATION 1 DEFAULT"

# 2. Install Grafana OSS
echo -e "${YELLOW}Installing Grafana OSS...${NC}"
mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list

apt-get update
apt-get install -y grafana

echo -e "${YELLOW}Enabling and starting Grafana...${NC}"
systemctl enable grafana-server
systemctl start grafana-server

# 3. Install Python Client in VENV
echo -e "${YELLOW}Installing Python influxdb client...${NC}"
if [ -f "/home/smartgrid/smartgrid/venv/bin/pip" ]; then
    sudo -u smartgrid /home/smartgrid/smartgrid/venv/bin/pip install influxdb
else
    echo -e "${YELLOW}Venv not found at /home/smartgrid/smartgrid/venv/bin/pip, installing globally or skipping...${NC}"
    pip3 install influxdb || true
fi

IP_ADDR=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "Grafana is available at: ${YELLOW}http://${IP_ADDR}:3000${NC}"
echo -e "Default Login: ${YELLOW}admin / admin${NC}"
echo -e "InfluxDB Database: ${YELLOW}smartgrid${NC}"
echo -e "Python client installed."
echo -e "${GREEN}==========================================${NC}"

#!/bin/bash
set -e

echo "[*] Configuring Grafana Provisioning for SmartGrid..."

# 1. Create directories
mkdir -p /etc/grafana/provisioning/dashboards
mkdir -p /etc/grafana/provisioning/datasources
mkdir -p /var/lib/grafana/dashboards

# 2. Copy dashboard JSON with proper permissions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/grafana/dashboard.json" ]; then
    cp "$SCRIPT_DIR/grafana/dashboard.json" /var/lib/grafana/dashboards/
elif [ -f "/home/smartgrid/smartgrid/grafana/dashboard.json" ]; then
    cp "/home/smartgrid/smartgrid/grafana/dashboard.json" /var/lib/grafana/dashboards/
fi

chown -R grafana:grafana /var/lib/grafana/dashboards

# 3. Create Dashboards provisioning config
cat << 'EOF' > /etc/grafana/provisioning/dashboards/smartgrid.yaml
apiVersion: 1
providers:
  - name: "SmartGrid"
    folder: ""
    type: file
    options:
      path: /var/lib/grafana/dashboards
EOF

# 4. Create InfluxDB Data Source provisioning config
cat << 'EOF' > /etc/grafana/provisioning/datasources/influxdb.yaml
apiVersion: 1
datasources:
  - name: InfluxDB-SmartGrid
    type: influxdb
    access: proxy
    url: http://localhost:8086
    database: smartgrid
    isDefault: true
EOF

# 5. Restart Grafana service
systemctl daemon-reload
systemctl restart grafana-server

echo "[SUCCESS] Grafana dashboard and InfluxDB data source provisioned successfully!"
echo "[*] Open http://localhost:3000/dashboards to view the dashboard."

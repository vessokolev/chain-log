#!/bin/bash
# Installation script for chain verification automation

set -e

echo "=== Chain Verification Automation Installation ==="

# Configuration
CHAIN_VERIFICATION_DIR="/opt/chain-verification"
SCRIPTS_DIR="$CHAIN_VERIFICATION_DIR/scripts"
CHAINS_DIR="$CHAIN_VERIFICATION_DIR/chains"
LOGS_DIR="$CHAIN_VERIFICATION_DIR/logs"
METADATA_DIR="$CHAIN_VERIFICATION_DIR/metadata"

# Create directory structure
echo "Creating directory structure..."
sudo mkdir -p "$SCRIPTS_DIR" "$CHAINS_DIR" "$LOGS_DIR" "$METADATA_DIR"

# Copy scripts
echo "Installing automation scripts..."
sudo cp "$(dirname "$0")/process_rotated_log.sh" "$SCRIPTS_DIR/"
sudo cp "$(dirname "$0")/monitor_log_rotation.sh" "$SCRIPTS_DIR/"
sudo cp "$(dirname "$0")/chain-verification-monitor.service" "$SCRIPTS_DIR/"

# Make scripts executable
sudo chmod +x "$SCRIPTS_DIR/process_rotated_log.sh"
sudo chmod +x "$SCRIPTS_DIR/monitor_log_rotation.sh"

# Set proper permissions
sudo chown -R root:root "$CHAIN_VERIFICATION_DIR"
sudo chmod -R 750 "$CHAIN_VERIFICATION_DIR"
sudo chmod 755 "$SCRIPTS_DIR"

# Install systemd service
echo "Installing systemd service..."
sudo cp "$SCRIPTS_DIR/chain-verification-monitor.service" /etc/systemd/system/
sudo systemctl daemon-reload

# Create logrotate configuration that extends the existing rsyslog config
echo "Creating logrotate configuration..."
sudo tee /etc/logrotate.d/chain-verification > /dev/null << 'EOF'
# Chain verification postrotate script for rsyslog logs
# This extends the existing rsyslog logrotate configuration

/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    sharedscripts
    postrotate
        # Original rsyslog postrotate
        /usr/bin/systemctl -s HUP kill rsyslog.service >/dev/null 2>&1 || true
        # Chain verification postrotate
        /opt/chain-verification/scripts/process_rotated_log.sh
    endscript
}
EOF

# Install inotify-tools if not present
if ! command -v inotifywait &> /dev/null; then
    echo "Installing inotify-tools..."
    if command -v yum &> /dev/null; then
        sudo yum install -y inotify-tools
    elif command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y inotify-tools
    else
        echo "WARNING: Cannot install inotify-tools automatically. Please install manually."
    fi
fi

# Enable and start the service
echo "Enabling and starting chain verification monitor..."
sudo systemctl enable chain-verification-monitor.service
sudo systemctl start chain-verification-monitor.service

# Create verification index
echo "Creating verification index..."
sudo tee "$METADATA_DIR/verification_index.json" > /dev/null << 'EOF'
{
    "created": "$(date -Iseconds)",
    "version": "1.0",
    "chains": [],
    "last_updated": "$(date -Iseconds)"
}
EOF

echo "=== Installation completed successfully ==="
echo ""
echo "Automation is now configured with:"
echo "1. Real-time monitoring via systemd service"
echo "2. Logrotate integration for automatic processing"
echo "3. Dedicated storage at $CHAIN_VERIFICATION_DIR"
echo ""
echo "To check status: sudo systemctl status chain-verification-monitor"
echo "To view logs: tail -f $LOGS_DIR/monitor.log"
echo "To manually process: $SCRIPTS_DIR/process_rotated_log.sh /path/to/logfile"

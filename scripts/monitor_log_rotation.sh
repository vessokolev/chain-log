#!/bin/bash
# Real-time monitoring of log rotation events
# Uses inotify to detect when rsyslog rotates log files
#
# Author: Veselin Kolev <vesso.kolev@gmail.com>
# Date: 19 February 2026
# Licence: GPLv2 (see LICENSE)
#
set -e

# Configuration
CHAIN_VERIFICATION_DIR="/opt/chain-verification"
LOGS_DIR="$CHAIN_VERIFICATION_DIR/logs"
PROCESS_SCRIPT="$CHAIN_VERIFICATION_DIR/scripts/process_rotated_log.sh"

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOGS_DIR/monitor.log"
}

# Create logs directory
mkdir -p "$LOGS_DIR"

log_message "=== Chain verification monitor started ==="

# Check if inotify-tools is installed
if ! command -v inotifywait &> /dev/null; then
    log_message "ERROR: inotify-tools not installed. Installing..."
    if command -v yum &> /dev/null; then
        yum install -y inotify-tools
    elif command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y inotify-tools
    else
        log_message "ERROR: Cannot install inotify-tools. Please install manually."
        exit 1
    fi
fi

# Function to process rotation event
handle_rotation() {
    local log_file="$1"
    local event="$2"
    
    log_message "Detected $event event for: $log_file"
    
    # Wait a moment for the file to be fully written
    sleep 2
    
    # Check if the rotated file exists and is not empty
    if [[ -f "$log_file" && -s "$log_file" ]]; then
        log_message "Processing rotated log: $log_file"
        
        # Process the rotated log file
        if "$PROCESS_SCRIPT" "$log_file"; then
            log_message "SUCCESS: Processed $log_file"
        else
            log_message "ERROR: Failed to process $log_file"
        fi
    else
        log_message "WARNING: Rotated file not found or empty: $log_file"
    fi
}

# Monitor log directory for rotation events
log_message "Starting inotify monitoring of /var/log..."

# Function to get log files from logrotate config
get_log_files_from_config() {
    local log_files=()
    
    # Check common logrotate config files
    local configs=("/etc/logrotate.d/rsyslog" "/etc/logrotate.d/syslog")
    
    for config in "${configs[@]}"; do
        if [[ -f "$config" ]]; then
            while IFS= read -r line; do
                if [[ "$line" =~ ^[[:space:]]*/var/log/ ]]; then
                    log_path=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
                    log_files+=("$(basename "$log_path")")
                fi
            done < "$config"
        fi
    done
    
    # If no config found, use defaults
    if [[ ${#log_files[@]} -eq 0 ]]; then
        log_files=("messages" "secure" "maillog" "cron" "spooler")
    fi
    
    echo "${log_files[@]}"
}

# Get log files to monitor
log_files=($(get_log_files_from_config))
log_message "Monitoring log files: ${log_files[*]}"

# Monitor for moved_from events (log rotation)
inotifywait -m -e moved_from /var/log/ | while read -r directory events filename; do
    # Check if this is a rotated log file for any of our monitored logs
    for log_file in "${log_files[@]}"; do
        if [[ "$filename" =~ ^${log_file}\.[0-9]+(\.gz|\.bz2|\.xz)?$ ]]; then
            rotated_file="$directory$filename"
            handle_rotation "$rotated_file" "moved_from"
            break
        fi
    done
done

log_message "=== Chain verification monitor stopped ==="

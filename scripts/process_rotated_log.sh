#!/bin/bash
# Process rotated logs for chain verification
# This script is called by rsyslog or logrotate after log rotation

set -e

# Configuration
CHAIN_VERIFICATION_DIR="/opt/chain-verification"
CHAINS_DIR="$CHAIN_VERIFICATION_DIR/chains"
LOGS_DIR="$CHAIN_VERIFICATION_DIR/logs"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_VERIFICATION_SCRIPT="$SCRIPT_DIR/../chain_verification.py"

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOGS_DIR/chain_verification.log"
}

# Create directories if they don't exist
mkdir -p "$CHAINS_DIR" "$LOGS_DIR"

# Function to process a rotated log file
process_rotated_log() {
    local log_file="$1"
    local log_name=$(basename "$log_file")
    local date_stamp=$(date +%Y-%m-%d_%H-%M-%S)
    local chain_file="$CHAINS_DIR/${log_name}_${date_stamp}.h5"
    
    # Handle compressed files
    local temp_file=""
    local is_compressed=false
    
    if [[ "$log_file" == *.gz ]]; then
        is_compressed=true
        temp_file=$(mktemp)
        log_message "Decompressing $log_file to $temp_file"
        gunzip -c "$log_file" > "$temp_file"
        log_file="$temp_file"
    elif [[ "$log_file" == *.bz2 ]]; then
        is_compressed=true
        temp_file=$(mktemp)
        log_message "Decompressing $log_file to $temp_file"
        bunzip2 -c "$log_file" > "$temp_file"
        log_file="$temp_file"
    elif [[ "$log_file" == *.xz ]]; then
        is_compressed=true
        temp_file=$(mktemp)
        log_message "Decompressing $log_file to $temp_file"
        xz -dc "$log_file" > "$temp_file"
        log_file="$temp_file"
    fi
    
    log_message "Processing rotated log: $log_file"
    
    # Check if file exists and is readable
    if [[ ! -f "$log_file" ]]; then
        log_message "ERROR: Log file not found: $log_file"
        return 1
    fi
    
    # Check if file is not empty
    if [[ ! -s "$log_file" ]]; then
        log_message "WARNING: Log file is empty: $log_file"
        return 0
    fi
    
    # Process the log file with chain verification
    if python3 "$CHAIN_VERIFICATION_SCRIPT" \
        --source-file "$log_file" \
        --output "$chain_file" \
        --tsa-url "http://timestamp.digicert.com/" \
        --ca-bundle "/etc/pki/tls/certs/ca-bundle.crt" \
        --compression-method "szip" \
        --hash-algorithm "sha256"; then
        
        log_message "SUCCESS: Created chain verification for $log_file -> $chain_file"
        
        # Verify the chain was created successfully
        if python3 "$CHAIN_VERIFICATION_SCRIPT" \
            --verify \
            --chain-file "$chain_file" \
            --source-file "$log_file"; then
            
                    log_message "SUCCESS: Chain verification passed for $chain_file"
    else
        log_message "ERROR: Chain verification failed for $chain_file"
        # Clean up temp file if it exists
        if [[ -n "$temp_file" && -f "$temp_file" ]]; then
            rm -f "$temp_file"
        fi
        return 1
    fi
else
    log_message "ERROR: Failed to create chain verification for $log_file"
    # Clean up temp file if it exists
    if [[ -n "$temp_file" && -f "$temp_file" ]]; then
        rm -f "$temp_file"
    fi
    return 1
fi

# Clean up temp file if it exists
if [[ -n "$temp_file" && -f "$temp_file" ]]; then
    rm -f "$temp_file"
    log_message "Cleaned up temporary file: $temp_file"
fi
}

# Function to parse logrotate configuration
parse_logrotate_config() {
    local config_file="$1"
    local log_files=()
    
    if [[ ! -f "$config_file" ]]; then
        log_message "WARNING: Logrotate config not found: $config_file"
        return 1
    fi
    
    log_message "Parsing logrotate configuration: $config_file"
    
    # Read the config file and extract log file paths
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # Check if line contains a log file path
        if [[ "$line" =~ ^[[:space:]]*/var/log/ ]]; then
            # Extract the log file path
            log_path=$(echo "$line" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
            log_files+=("$log_path")
            log_message "Found log file in config: $log_path"
        fi
    done < "$config_file"
    
    echo "${log_files[@]}"
}

# Function to find rotated log files
find_rotated_logs() {
    local base_log="$1"
    local rotated_logs=()
    
    # Check for various rotation patterns
    local patterns=(
        "${base_log}.1"      # Standard rotation
        "${base_log}.1.gz"   # Compressed rotation
        "${base_log}.1.bz2"  # Bzip2 compressed
        "${base_log}.1.xz"   # XZ compressed
        "${base_log}-$(date +%Y%m%d)"  # Date-based rotation
        "${base_log}-$(date +%Y%m%d).gz"
        "${base_log}-$(date +%Y%m%d).bz2"
        "${base_log}-$(date +%Y%m%d).xz"
    )
    
    for pattern in "${patterns[@]}"; do
        if [[ -f "$pattern" ]]; then
            rotated_logs+=("$pattern")
            log_message "Found rotated log: $pattern"
        fi
    done
    
    echo "${rotated_logs[@]}"
}

# Main execution
main() {
    log_message "=== Chain verification processing started ==="
    
    # If a specific file is provided as argument, process it
    if [[ $# -eq 1 ]]; then
        process_rotated_log "$1"
    else
        # Parse logrotate configuration to find log files
        local logrotate_configs=(
            "/etc/logrotate.d/rsyslog"
            "/etc/logrotate.d/syslog"
            "/etc/logrotate.conf"
        )
        
        local all_log_files=()
        
        for config in "${logrotate_configs[@]}"; do
            if [[ -f "$config" ]]; then
                log_files=($(parse_logrotate_config "$config"))
                all_log_files+=("${log_files[@]}")
            fi
        done
        
        # If no config files found, use default patterns
        if [[ ${#all_log_files[@]} -eq 0 ]]; then
            log_message "No logrotate configs found, using default patterns"
            all_log_files=(
                "/var/log/messages"
                "/var/log/secure"
                "/var/log/maillog"
                "/var/log/cron"
                "/var/log/spooler"
            )
        fi
        
        # Find and process rotated versions of each log file
        for base_log in "${all_log_files[@]}"; do
            rotated_logs=($(find_rotated_logs "$base_log"))
            
            for rotated_log in "${rotated_logs[@]}"; do
                process_rotated_log "$rotated_log"
            done
        done
    fi
    
    log_message "=== Chain verification processing completed ==="
}

# Run main function with all arguments
main "$@"

#!/data/data/com.termux/files/usr/bin/bash

# Security Guard Script for Termux
# Author: ephraim sib @ GitHub 
# Version: 2.2

# Initialize variables
LOG_FILE="$HOME/security_guard.log"
QUARANTINE_DIR="$HOME/security_quarantine"
SCRIPT_NAME=$(basename "$0")
SCRIPT_PATH=$(realpath "$0")
THREAT_LIST=("malware" "virus" "hack" "exploit" "backdoor")
SUSPICIOUS_EXT=(".apk" ".sh" ".exe" ".php" ".py" ".bat" ".jar")
SUSPICIOUS_PORTS=("22" "23" "21" "25" "53" "80" "443" "135" "136" "137" "138" "139" "445" "1433" 
                 "3306" "3389" "4899" "8080" "8443" "5900" "6660" "6661" "6662" "6663" "6664" 
                 "6665" "6666" "6667" "6668" "6669" "31337" "4444" "4782" "12345" "54321" "2323" 
                 "5000" "51572")
KNOWN_THREATS_URL="https://urlhaus.abuse.ch/downloads/text_online/"

# Create required directories
mkdir -p "$QUARANTINE_DIR"
touch "$LOG_FILE"

# Notification functions
send_alert() {
    termux-notification --id "SEC_ALERT" --priority high \
        --title "🚨 Security Alert!" --content "$1" \
        --button1 "View Log" --button1-action "termux-open $LOG_FILE"
}

send_warning() {
    termux-notification --id "SEC_WARN" --priority max \
        --title "⚠️ Security Warning" --content "$1" \
        --sound --led-color FF0000
}

# Self-protection: Prevent script termination
protect_script() {
    cp "$SCRIPT_PATH" "$HOME/.secure_${SCRIPT_NAME}"
    chmod 700 "$HOME/.secure_${SCRIPT_NAME}"
}

# Check internet connection
check_internet() {
    ping -c 1 google.com > /dev/null 2>&1
    return $?
}

# Enhanced file quarantine with exclusion
quarantine_file() {
    local file="$1"
    [[ "$file" == "$SCRIPT_PATH" ]] && return  # Protect self
    [[ "$file" == "$HOME/.secure_"* ]] && return  # Protect backup
    
    local filename=$(basename "$file")
    local new_path="$QUARANTINE_DIR/${filename}_$(date +%s)"
    
    # Kill processes using the file
    fuser -k "$file" >/dev/null 2>&1
    
    # Quarantine file and alert
    mv "$file" "$new_path"
    echo "[$(date)] Quarantined $file to $new_path" >> "$LOG_FILE"
    send_warning "File quarantined: ${filename:0:20}..."
    send_alert "Malicious file detected and quarantined!\nPath: ${file/$HOME/\~}"
}

# Network monitoring with alerts
monitor_network() {
    netstat -tunap 2>/dev/null | while read conn; do
        for port in "${SUSPICIOUS_PORTS[@]}"; do
            if [[ "$conn" == *":$port"* ]]; then
                local alert_msg="Suspicious connection detected:\nPort: $port\nConnection: ${conn:0:50}"
                echo "[$(date)] $alert_msg" >> "$LOG_FILE"
                send_warning "$alert_msg"
                send_alert "Blocked suspicious port $port"
            fi
        done
    done
}

# File scanning with visual alerts
check_files() {
    find $HOME/storage/downloads $HOME/storage/dcim $HOME \
        -type f \( -name "*.apk" -o -name "*.sh" -o -name "*.exe" -o -name "*.php" -o -name "*.py" \) \
        ! -path "$QUARANTINE_DIR/*" \
        ! -path "$SCRIPT_PATH" | while read file; do
            quarantine_file "$file"
    done
}

# Process monitoring with alerts
check_processes() {
    ps -ef | while read process; do
        for threat in "${THREAT_LIST[@]}"; do
            if [[ "$process" == *"$threat"* ]] && [[ "$process" != *"$SCRIPT_NAME"* ]]; then
                local pid=$(echo "$process" | awk '{print $2}')
                local proc_name=$(echo "$process" | awk '{for(i=8;i<=NF;i++) printf $i" "}')
                kill -9 "$pid" 2>/dev/null
                local alert_msg="Killed malicious process:\nPID: $pid\nName: ${proc_name:0:30}"
                echo "[$(date)] $alert_msg" >> "$LOG_FILE"
                send_warning "$alert_msg"
                send_alert "Stopped malicious process: ${proc_name:0:20}"
            fi
        done
    done
}

# Threat database update
update_threats() {
    [ -f ".last_update" ] && [ $(date +%s -r .last_update) -gt $(date +%s --date="24 hours ago") ] && return
    
    if check_internet; then
        send_alert "Updating threat database..."
        if curl -s "$KNOWN_THREATS_URL" -o latest_threats.list; then
            mv latest_threats.list threat_database.list
            touch .last_update
            send_warning "Threat database updated successfully"
        fi
    fi
}

# Main execution
protect_script
echo "[$(date)] === Security Guard Started ===" >> "$LOG_FILE"
send_warning "Security protection activated"

while true; do
    if check_internet; then
        update_threats
        monitor_network
        check_files
        check_processes
    fi
    sleep 300
done
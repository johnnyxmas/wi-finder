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
    if command -v systemd-networkd >/dev/null 2>&1; then
        echo "systemd-networkd"
    elif command -v NetworkManager >/dev/null 2>&1; then
        echo "network-manager"
    else
        echo "systemd-networkd"
        log "warn" "Neither systemd-networkd nor network-manager found. Will attempt to use systemd-networkd"
    fi
}

detect_dhcp_client() {
    if command -v dhclient >/dev/null 2>&1; then
        echo "dhclient"
    elif command -v dhcp-client >/dev/null 2>&1; then
        echo "dhcp-client"
    else
        echo "dhclient"
        log "warn" "Neither dhclient nor dhcp-client found. Will attempt to use dhclient"
    fi
}

install_dependencies() {
    NETWORK_SERVICE=$(detect_network_service)
    DHCP_CLIENT=$(detect_dhcp_client)
    
    local pkgs=("iw" "wireless-tools" "$NETWORK_SERVICE" "$DHCP_CLIENT" "iputils-ping" "curl" "arp-scan" "macchanger" "aircrack-ng")
    local missing=()
    
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log "info" "Installing missing packages: ${missing[*]}"
        if ! apt-get update && apt-get install -y "${missing[@]}"; then
            log "error" "Failed to install required packages"
            exit 1
        fi
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
    # Scan and sort by signal strength (strongest first)
    iw dev "$interface" scan | \
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
        awk '{$1=""; print substr($0,2)}'
}

connect_to_network() {
    local interface=$1
    local ssid=$2
    
    cleanup_interface "$interface"
    
    log "debug" "Bringing up interface $interface"
    if ! ifconfig "$interface" up; then
        log "error" "Failed to bring up interface $interface"
        return 1
    fi
    
    log "info" "Connecting to SSID: $ssid"
    if [ "$NETWORK_SERVICE" = "systemd-networkd" ]; then
        if ! iwconfig "$interface" essid "$ssid"; then
            log "error" "Failed to connect to SSID $ssid"
            return 1
        fi
    else
        if ! nmcli dev wifi connect "$ssid" ifname "$interface"; then
            log "error" "Failed to connect to SSID $ssid"
            return 1
        fi
    fi
    
    log "debug" "Requesting DHCP lease"
    if ! $DHCP_CLIENT "$interface"; then
        log "error" "Failed to get DHCP lease"
        return 1
    fi
    
    return 0
}

check_captive_portal() {
    local response
    response=$(curl -s --max-time 5 http://neverssl.com || true)
    if echo "$response" | grep -q "This website is for when you try to open Facebook"; then
        return 0  # No captive portal - test succeeded
    fi
    return 1  # Captive portal detected - test failed
}

get_mac_addresses() {
    local interface=$1
    local macs=()
    
    # Try arp-scan first
    if command -v arp-scan >/dev/null 2>&1; then
        while IFS= read -r line; do
            macs+=("$(echo "$line" | awk '{print $2}')")
        done < <(arp-scan --interface="$interface" --localnet | grep -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}')
    fi
    
    # Fall back to airodump-ng if no results
    if [ ${#macs[@]} -eq 0 ] && command -v airodump-ng >/dev/null 2>&1; then
        while IFS= read -r line; do
            macs+=("$(echo "$line" | awk '{print $1}')")
        done < <(airodump-ng "$interface" | grep -E '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | grep -v "BSSID")
    fi
    
    echo "${macs[@]}"
}

spoof_mac() {
    local interface=$1
    local mac=$2
    
    log "debug" "Spoofing MAC address to $mac on interface $interface"
    
    # Bring interface down first
    ip link set dev "$interface" down
    
    if command -v macchanger >/dev/null 2>&1; then
        macchanger -m "$mac" "$interface"
    else
        ip link set dev "$interface" address "$mac"
    fi
    
    # Bring interface back up
    ip link set dev "$interface" up
    sleep 2  # Give interface time to come up
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
    
    while true; do
        log "info" "Scanning for open networks..."
        networks=($(scan_open_networks "$interface"))
        if [ ${#networks[@]} -eq 0 ]; then
            log "warn" "No open networks found, waiting 60 seconds before scanning again..."
            sleep 60
            continue
        fi

        for network in "${networks[@]}"; do
            log "info" "Attempting to connect to: $network"
            if connect_to_network "$interface" "$network"; then
                if verify_internet; then
                    log "info" "Successfully connected to $network with internet access"
                    return 0
                else
                    log "warn" "No internet access on $network, trying MAC spoofing..."
                    # Get unique MAC addresses and validate format
                    declare -A unique_macs
                    for mac in $(get_mac_addresses "$interface"); do
                        if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                            unique_macs["$mac"]=1
                        fi
                    done
                    
                    if [ ${#unique_macs[@]} -eq 0 ]; then
                        log "warn" "No valid MAC addresses found for spoofing"
                        cleanup_interface "$interface"
                        continue
                    fi
                    
                    macs=("${!unique_macs[@]}")
                    
                    for mac in "${macs[@]}"; do
                        log "debug" "Trying MAC address: $mac"
                        spoof_mac "$interface" "$mac"
                        if connect_to_network "$interface" "$network"; then
                            if verify_internet; then
                                log "info" "Successfully bypassed captive portal with MAC $mac"
                                return 0
                            fi
                        fi
                        cleanup_interface "$interface"
                    done
                    log "error" "Failed to bypass captive portal with any MAC address"
                fi
            fi
            cleanup_interface "$interface"
        done
        
        log "warn" "Failed to connect to any network with internet access, waiting 60 seconds before scanning again..."
        sleep 60
    done
}

monitoring_loop() {
    local interface=$1
    
    while true; do
        log "info" "Monitoring connection... checking in 30 minutes"
        sleep 1800  # 30 minutes = 1800 seconds
        
        log "info" "Pinging Google.com as heartbeat..."
        if ! ping -c 1 -W 5 google.com >/dev/null 2>&1; then
            log "warn" "Heartbeat ping to Google.com failed, retrying neverssl test"
            if ! verify_internet; then
                log "warn" "Internet connectivity lost, attempting MAC cloning and reconnection"
                
                # Try MAC spoofing first before full restart
                current_ssid=$(iwgetid -r "$interface" 2>/dev/null || echo "")
                if [ -n "$current_ssid" ]; then
                    log "info" "Attempting MAC spoofing on current network: $current_ssid"
                    
                    # Get unique MAC addresses and validate format
                    declare -A unique_macs
                    for mac in $(get_mac_addresses "$interface"); do
                        if [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                            unique_macs["$mac"]=1
                        fi
                    done
                    
                    if [ ${#unique_macs[@]} -gt 0 ]; then
                        macs=("${!unique_macs[@]}")
                        for mac in "${macs[@]}"; do
                            log "debug" "Trying MAC address: $mac"
                            spoof_mac "$interface" "$mac"
                            if connect_to_network "$interface" "$current_ssid"; then
                                if verify_internet; then
                                    log "info" "Successfully restored connection with MAC $mac"
                                    continue 2  # Continue outer monitoring loop
                                fi
                            fi
                            cleanup_interface "$interface"
                        done
                    fi
                fi
                
                log "warn" "MAC spoofing failed, restarting full scan and connect process"
                cleanup_interface "$interface"
                
                # Re-detect interface in case it changed
                interface=$(find_wifi_interface)
                
                # Attempt to reconnect
                if scan_and_connect "$interface"; then
                    log "info" "Successfully reconnected to internet"
                else
                    log "error" "Failed to reconnect, will retry in 30 minutes"
                fi
            fi
        else
            log "info" "Heartbeat ping successful, internet connectivity confirmed"
        fi
    done
}

main() {
    # Setup traps for clean exit
    trap 'cleanup "$interface"' EXIT
    trap 'log "warn" "Received interrupt, cleaning up..."; cleanup "$interface"' INT TERM
        
    log "debug" "Waiting $INITIAL_WAIT seconds for any predefined network connections..."
    sleep "$INITIAL_WAIT"
    
    # Check if already connected to internet
    if check_internet; then
        interface=$(find_wifi_interface)
        log "info" "Already connected to internet, entering monitoring mode"
        monitoring_loop "$interface"
        exit 0
    fi
    
    interface=$(find_wifi_interface)

    # Attempt initial connection
    if scan_and_connect "$interface"; then
        log "info" "Initial connection successful, entering monitoring mode"
        monitoring_loop "$interface"
    else
        log "error" "Initial connection failed, exiting"
        exit 1
    fi
}

main "$@"
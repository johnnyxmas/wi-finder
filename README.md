# Wi-Finder - Automatic WiFi Connection Script

Wi-Finder is a robust bash script that automatically finds and connects to open WiFi networks with internet access. It includes captive portal bypass capabilities using MAC address spoofing.

## Features

- **Automatic dependency installation** - Installs all required packages
- **Systemd service integration** - Runs as a background service
- **Signal strength sorting** - Connects to strongest networks first
- **Captive portal detection** - Uses neverssl.com test
- **MAC address spoofing** - Bypasses captive portals by cloning other clients
- **Continuous monitoring** - 30-minute heartbeat checks with automatic reconnection
- **Comprehensive logging** - Detailed logs with rotation

## Flow

1. **Dependency Check** - Ensures all required packages are installed
2. **Service Setup** - Creates and starts systemd service
3. **Interface Detection** - Finds available WiFi adapter (not currently connected)
4. **Network Scanning** - Scans for open SSIDs sorted by signal strength
5. **Connection Attempts** - Tries each network in order of signal strength
6. **Internet Verification** - Tests connectivity using neverssl.com
   - **Success**: If response contains "This website is for when you try to open Facebook"
   - **Failure**: Captive portal detected, begins bypass routine
7. **Captive Portal Bypass**:
   - Uses `arp-scan` to find MAC addresses of connected clients
   - Falls back to `airodump-ng` if arp-scan fails
   - Clones MAC addresses and retries connection
   - If no MACs found, tries next strongest SSID
8. **Monitoring Mode** - Pings Google.com every 30 minutes as heartbeat
9. **Auto-Recovery** - Restarts process if connectivity is lost

## Dependencies

The script automatically installs these packages:
- `iw` - Wireless interface configuration
- `wireless-tools` - Legacy wireless tools
- `systemd-networkd` or `network-manager` - Network management
- `dhclient` or `dhcp-client` - DHCP client
- `iputils-ping` - Ping utility
- `curl` - HTTP client for neverssl test
- `arp-scan` - ARP network scanner
- `macchanger` - MAC address spoofing
- `aircrack-ng` - WiFi security tools (includes airodump-ng)

## Installation & Usage

### Quick Start
```bash
sudo ./wi-finder.sh
```

### Manual Service Setup
```bash
sudo ./wi-finder.sh --setup
```

### Check Service Status
```bash
sudo systemctl status wi-finder
```

### View Logs
```bash
sudo tail -f /var/log/wi-finder.log
```

### Stop Service
```bash
sudo systemctl stop wi-finder
```

## Configuration

Edit `/etc/wi-finder.conf` to customize settings:

```bash
# Retry delay in seconds
RETRY_DELAY=10

# Initial wait before starting (seconds)
INITIAL_WAIT=30

# DNS servers to try
DNS_SERVERS="1.1.1.1 8.8.8.8 9.9.9.9"

# Log level (0=error, 1=warn, 2=info, 3=debug)
LOG_LEVEL=2

# Log file size limit (bytes)
LOG_MAX_SIZE=1048576

# Number of log backups to keep
LOG_BACKUP_COUNT=3
```

## Debug Mode

Enable debug mode for verbose output:
```bash
sudo DEBUG=1 ./wi-finder.sh
```

## Requirements

- **Root privileges** - Required for network interface manipulation
- **Linux system** - Tested on Ubuntu/Debian
- **WiFi adapter** - Must support monitor mode for airodump-ng
- **Systemd** - For service management

## Security Considerations

- **MAC spoofing** may violate network terms of service
- **Use responsibly** and only on networks you're authorized to access
- **Monitor logs** for any suspicious activity
- **Consider legal implications** in your jurisdiction

## Troubleshooting

### Common Issues

1. **No WiFi interfaces found**
   - Check if WiFi adapter is properly installed
   - Verify driver support: `lspci | grep -i wireless`

2. **Permission denied errors**
   - Ensure script is run with sudo
   - Check file permissions: `ls -la wi-finder.sh`

3. **Service fails to start**
   - Check logs: `journalctl -u wi-finder -f`
   - Verify dependencies are installed

4. **No networks found**
   - Check if WiFi is enabled: `rfkill list`
   - Verify interface is up: `ip link show`

5. **MAC spoofing fails**
   - Some adapters don't support MAC changing
   - Try different spoofing tools or adapters

### Log Analysis

Monitor the log file for detailed information:
```bash
# Real-time log monitoring
sudo tail -f /var/log/wi-finder.log

# Search for errors
sudo grep -i error /var/log/wi-finder.log

# Check connection attempts
sudo grep -i "connecting to" /var/log/wi-finder.log
```

## License

This script is provided as-is for educational and legitimate network testing purposes. Users are responsible for compliance with local laws and network policies.

## Author

J0hnnyXm4s - Wi-Finder v1.1
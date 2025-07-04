# Wi-Fi Finder Script

Automatically finds and connects to the strongest open WiFi network on Debian-based systems.

## Features
- Installs required packages automatically (iw, wireless-tools, network-manager, etc.)
+ Auto-detects WiFi interfaces using modern ip/iw commands
- Prefers unassociated interfaces when multiple are available
- Scans for open networks
- Connects to strongest signal first
- Verifies internet connectivity (including captive portal detection)
- Falls back to next network if connection fails
- Option to run at system boot
- MAC address spoofing capability (optional)


## Installation
1. Clone this repository
2. Make the script executable:
   ```bash
   chmod +x wi-finder/wi-finder.sh
   ```
3. Run as root:
   ```bash
   sudo ./wi-finder/wi-finder.sh
   ```

## Boot Setup
When running the script, you'll be prompted to:
```
Do you want to run this script at boot? [y/N]
```
Answer 'y' to automatically add a crontab entry that runs the script at startup.

## Requirements
- Debian-based Linux distribution
- Root privileges
- Wireless network interface
- Additional packages for full functionality:
  - curl (for captive portal detection)
  - arp-scan (for MAC address collection)
  - macchanger (for MAC spoofing)
  - aircrack-ng (for advanced scanning)

## Process Flow

1. **Initialization**
   - Checks for and installs required packages
   - Verifies root privileges

2. **Adapter Detection**
   - Uses modern ip/iw commands to detect wireless interfaces
   - Checks interface association state (prefers unconnected interfaces)
   - If none found, waits 10 seconds and retries

3. **Network Connection**
   - Scans for available open networks
   - Sorts networks by signal strength (strongest first)
   - Attempts connection to each network sequentially
   - Verifies internet connectivity after each connection

4. **Failure Handling**
   - If connection fails, tries next available network
   - If all networks fail, waits 10 seconds and restarts scan

5. **Boot Setup (Optional)**
   - When run interactively, offers to install as systemd service
   - Configures to run at boot if selected

## How It Works
The script follows the above process flow to automatically connect to the best available open WiFi network. It handles missing hardware gracefully by waiting for an adapter to become available before proceeding.

### Captive Portal Detection
When verifying internet connectivity, the script checks for captive portals by attempting to access neverssl.com. If this fails but the network connection appears active, it assumes a captive portal is present and warns the user.

### MAC Address Spoofing
The script can optionally spoof MAC addresses:
1. Collects nearby MAC addresses using arp-scan
2. Uses macchanger or ip commands to change the interface MAC
3. Maintains original MAC for restoration when needed

## Troubleshooting
If connections fail:
- Ensure your wireless card supports monitor mode
- Check `dmesg` for driver errors
- Verify network manager isn't interfering (`systemctl stop NetworkManager`)

## License
MIT
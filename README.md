# Cisco ISE to NetBox Synchronization Tool

This script synchronizes Cisco Identity Services Engine (ISE) network devices to NetBox, providing an automated way to maintain your NetBox DCIM database with accurate information from your ISE environment.

## Overview

The ISE_to_Netbox.py script discovers and synchronizes the following ISE resources to NetBox:

- Network Devices → NetBox Devices
- Device IP Addresses → NetBox IP Addresses
- Device Groups → NetBox Device Roles and Sites
- Additional device details via SNMP (model, serial number, OS version, etc.)

## Prerequisites

- Python 3.6+
- Access to a Cisco ISE deployment with API access
- A running NetBox instance with API access
- SNMP v3 access to network devices for enhanced information gathering
- Required Python packages (see Installation)

## Installation

1. Clone this repository:
```bash
git clone https://your-repository-url/ISE_to_netbox.git
```

2. Install the required dependencies:
```bash
pip install requests pynetbox pysnmp urllib3 tqdm
```

## Configuration

The script can be configured using command-line arguments or environment variables:

### Environment Variables
- `ISE_URL`: URL of your Cisco ISE instance (e.g., https://10.65.2.8)
- `ISE_USERNAME`: ISE API username
- `ISE_PASSWORD`: ISE API password
- `NETBOX_URL`: URL of your NetBox instance
- `NETBOX_TOKEN`: NetBox API token with write access
- `SNMP_USER`: SNMPv3 username (default: PRTGUser)
- `SNMP_AUTH`: SNMPv3 authentication key
- `SNMP_PRIV`: SNMPv3 privacy key

## Usage

### Basic Usage
```bash
python ISE_to_Netbox.py --ise-url https://your-ise-instance/ --ise-username admin --ise-password your-password --netbox-url https://your-netbox-instance/ --netbox-token your-netbox-token
```

### Using Environment Variables
```bash
export ISE_URL=https://your-ise-instance/
export ISE_USERNAME=admin
export ISE_PASSWORD=your-password
export NETBOX_URL=https://your-netbox-instance/
export NETBOX_TOKEN=your-netbox-token
python ISE_to_Netbox.py
```

### Custom SNMP Settings
```bash
python ISE_to_Netbox.py --snmp-user CustomUser --snmp-auth your-auth-key --snmp-priv your-priv-key
```

### SSL Verification
By default, the script disables SSL verification for ISE API calls. To enable it:
```bash
python ISE_to_Netbox.py --verify-ssl
```

## Features

- **Automatic Discovery**: Automatically discovers all ISE network devices
- **SNMP Enhancement**: Gathers detailed device information via SNMP
- **Resource Mapping**: Maps ISE resources to appropriate NetBox objects
- **Idempotent Operation**: Can be run multiple times safely, updating existing resources
- **Tagging**: Adds "ise-sync" tag to all created/updated objects in NetBox
- **Stale Device Handling**: Removes devices from NetBox that no longer exist in ISE
- **Site Detection**: Intelligently maps ISE locations to NetBox sites
- **Name Handling**: Automatically handles truncation and uniqueness requirements for device names

## Data Synchronization Details

1. **Network Devices**: Created with appropriate device types based on ISE device type groups and SNMP data
2. **Device Locations**: Mapped to NetBox sites based on ISE location groups and SNMP location data
3. **Management Interface**: Created for each device to associate IP addresses
4. **IP Addresses**: Associated with the management interface of each device
5. **Custom Fields**: SNMP-retrieved information like uptime and contact stored in custom fields

## Troubleshooting

- **SSL Certificate Issues**: The script disables SSL verification by default. For production, consider properly configuring SSL certificates.
- **SNMP Failures**: If SNMP data collection fails, the script will continue with limited device information.
- **Rate Limiting**: For large deployments, the script uses progress tracking via tqdm.
- **Logging**: The script logs operations at INFO level. Review logs for troubleshooting.
- **Timeout Issues**: SNMP operations have a 15-second timeout to prevent script hangs on unresponsive devices.

## Notes

- The script is designed to be run periodically to keep NetBox updated with the current state of ISE.
- All objects created or updated by the script receive an "ise-sync" tag for identification.
- The script will attempt to find existing sites in NetBox that match ISE locations before creating new ones.

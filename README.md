# DHCP Server Implementation from Scratch

## Overview

This project implements a **Dynamic Host Configuration Protocol (DHCP)** server and client from scratch. The DHCP server dynamically assigns IP addresses and other network configuration parameters to devices on a network, allowing them to communicate efficiently. 

## Features

### Server Features
- **Dynamic IP Allocation**: Automatically assigns IP addresses from a predefined range
- **Lease Management**: Manages IP lease durations and renewals
- **MAC Address Whitelisting**: Controls which devices can request IP addresses
- **User Authentication**: Supports multiple admin users with different roles
- **Admin Interface**: Command-line interface for server management
- **Persistent Storage**: Saves leases, users, and configurations to JSON files
- **Detailed Logging**: Comprehensive logging system for troubleshooting

### Client Features
- **Automatic MAC Detection**: Can use the current machine's MAC address
- **Custom MAC Support**: Allows manual MAC address entry
- **Lease Management**: Supports lease acquisition and release
- **Authentication**: Integrates with server's user authentication
- **Persistent Storage**: Saves lease information locally
- **Retry Mechanism**: Implements configurable retry attempts

## Installation

### Prerequisites
- Python 3.x
- Administrative privileges
- Required Python packages:
  ```bash
  pip install netifaces
  ```

### Windows Installation
1. Open Command Prompt as Administrator
2. Clone the repository:
   ```bash
   git clone <repository-url>
   cd dhcp-server
   ```
3. Install dependencies:
   ```bash
   pip install netifaces
   ```

### Linux Installation
1. Open terminal
2. Clone the repository:
   ```bash
   git clone <repository-url>
   cd dhcp-server
   ```
3. Install dependencies:
   ```bash
   sudo apt-get install python3-pip  # For Debian/Ubuntu
   sudo pip3 install netifaces
   ```

## Running the Application

### Windows
1. Open Command Prompt as Administrator
2. Navigate to project directory
3. Start the server:
   ```bash
   python server.py
   ```
4. In a new Administrator Command Prompt, start the client:
   ```bash
   python client.py
   ```

### Linux
1. Open terminal
2. Navigate to project directory
3. Start the server:
   ```bash
   sudo python3 server.py
   ```
4. In a new terminal, start the client:
   ```bash
   sudo python3 client.py
   ```

## Configuration

### Server Configuration
- Default configuration in `dhcp_config.json`:
  ```json
  {
    "ip_range_start": "192.168.1.100",
    "ip_range_end": "192.168.1.200",
    "subnet_mask": "255.255.255.0",
    "gateway": "192.168.1.1",
    "dns_servers": ["8.8.8.8", "8.8.4.4"],
    "default_lease_time": 3600
  }
  ```

### Client Configuration
- Default configuration in `dhcp_client_config.json`:
  ```json
  {
    "retry_attempts": 3,
    "retry_delay": 5,
    "timeout": 10,
    "save_lease": true
  }
  ```

## Default Credentials
Username: admin
Password: admin123

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   - Ensure server is running with admin privileges
   - Check firewall settings for ports 67 and 68
   - Verify both server and client are on same network

2. **Permission Denied**
   - Run applications with administrator/root privileges
   - Check port availability (67 for server, 68 for client)

3. **Port Already in Use**
   - Stop any existing DHCP servers
   - Check for conflicting services using:
     - Windows: `netstat -ano | findstr :67`
     - Linux: `sudo netstat -tulpn | grep :67`

### Firewall Configuration

#### Windows
1. Open Windows Defender Firewall
2. Add inbound rule for ports 67 and 68 (UDP)
3. Add outbound rule for ports 67 and 68 (UDP)

#### Linux
bash
sudo iptables -A INPUT -p udp --dport 67:68 -j ACCEPT
sudo iptables -A OUTPUT -p udp --sport 67:68 -j ACCEPT


## Code Structure

### Server Components
- `DHCPServer`: Main server class handling DHCP operations
- `AdminInterface`: Command-line interface for server management
- Key methods:
  - `_handle_discover()`: Processes DHCP DISCOVER messages
  - `_handle_request()`: Processes DHCP REQUEST messages
  - `_handle_release()`: Handles IP address releases

### Client Components
- `DHCPClient`: Main client class for DHCP operations
- Key methods:
  - `discover()`: Initiates DHCP discovery
  - `_wait_for_offer()`: Handles server offers
  - `release()`: Releases assigned IP address

## File Structure
dhcp-server/
├── server.py # DHCP server implementation
├── client.py # DHCP client implementation
├── dhcp_config.json # Server configuration
├── dhcp_leases.json # Active leases
├── users.json # User credentials
├── mac_whitelist.json # Authorized MAC addresses
└── logs/ # Server and client logs


## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

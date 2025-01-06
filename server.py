import socket
import struct
import threading
import json
import time
import logging
import hashlib
import os
import ipaddress 
from datetime import datetime




#-------------------------------------ADMIN-------------------------------------#
class AdminInterface:
    def __init__(self, server):
        self.server = server
        self.current_user = None
        self.admin_commands = {
            '1': ('Add User', self._add_user),
            '2': ('List Users', self._list_users),
            '3': ('Add MAC to Whitelist', self._add_mac_whitelist),
            '4': ('List MAC Whitelist', self._list_mac_whitelist),
            '5': ('View Active Leases', self._view_leases),
            '6': ('View System Status', self._view_status),
            '7': ('Remove MAC from Whitelist', self._remove_mac_whitelist),
            '8': ('Change User Password', self._change_password),
            '9': ('Logout', self._logout)
        }

    def start(self):
        """Start the admin interface"""
        while True:
            if not self.current_user:
                if not self._login():
                    print("Login failed. Please try again.")
                    continue

            self._show_menu()
            choice = input("\nEnter your choice (1-9): ").strip()

            if choice in self.admin_commands:
                command_name, command_func = self.admin_commands[choice]
                try:
                    if choice == '9':  # Logout
                        command_func()
                        continue
                    print(f"\n=== {command_name} ===")
                    command_func()
                    input("\nPress Enter to continue...")
                except Exception as e:
                    print(f"Error: {e}")
                    input("\nPress Enter to continue...")
            else:
                print("Invalid choice. Please try again.")

    def _login(self):
        """Handle admin login"""
        print("\n=== DHCP Server Admin Login ===")
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        if self.server.authenticate_user(username, password):
            self.current_user = username
            print(f"\nWelcome, {username}!")
            return True
        return False

    def _show_menu(self):
        """Display admin menu"""
        print("\n=== DHCP Server Admin Interface ===")
        print(f"Logged in as: {self.current_user}")
        print("=" * 35)

        for key, (name, _) in self.admin_commands.items():
            print(f"{key}. {name}")

    def _add_user(self):
        """Add a new user to the system"""
        username = input("Enter new username: ").strip()
        password = input("Enter password: ").strip()
        role = input("Enter role (admin/user) [user]: ").strip() or "user"

        try:
            self.server.add_admin_user(username, password, role)
            print(f"User {username} added successfully!")
        except ValueError as e:
            print(f"Error: {e}")

    def _list_users(self):
        """List all users in the system"""
        print("\nRegistered Users:")
        print("-" * 60)
        print(f"{'Username':<20} {'Role':<15} {'Last Login':<25}")
        print("-" * 60)

        for username, data in self.server.users.items():
            last_login = datetime.fromtimestamp(data['last_login']).strftime('%Y-%m-%d %H:%M:%S') if data['last_login'] else 'Never'
            print(f"{username:<20} {data['role']:<15} {last_login:<25}")

    def _add_mac_whitelist(self):
        """Add a new MAC address to whitelist"""
        mac = input("Enter MAC address (format: xx:xx:xx:xx:xx:xx): ").strip()
        description = input("Enter description: ").strip()

        self.server.add_mac_to_whitelist(mac, description, self.current_user)
        print(f"MAC address {mac} added to whitelist!")

    def _remove_mac_whitelist(self):
        """Remove a MAC address from whitelist"""
        mac = input("Enter MAC address to remove: ").strip()

        if mac in self.server.mac_whitelist:
            del self.server.mac_whitelist[mac]
            self.server._save_mac_whitelist()
            print(f"MAC address {mac} removed from whitelist!")
        else:
            print("MAC address not found in whitelist.")

    def _list_mac_whitelist(self):
        """List all whitelisted MAC addresses"""
        print("\nWhitelisted MAC Addresses:")
        print("-" * 80)
        print(f"{'MAC Address':<20} {'Description':<20} {'Last Seen':<25} {'Connections'}")
        print("-" * 80)

        for mac, data in self.server.mac_whitelist.items():
            last_seen = datetime.fromtimestamp(data['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if data['last_seen'] else 'Never'
            print(f"{mac:<20} {data['description']:<20} {last_seen:<25} {data['total_connections']}")

    def _view_leases(self):
        """View all active DHCP leases"""
        print("\nActive DHCP Leases:")
        print("-" * 80)
        print(f"{'MAC Address':<20} {'IP Address':<15} {'Lease Start':<25} {'Expires In'}")
        print("-" * 80)

        current_time = time.time()
        for mac, lease in self.server.leases.items():
            lease_start = datetime.fromtimestamp(lease['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            expires_in = int(lease['timestamp'] + lease['lease_time'] - current_time)
            expires_str = f"{expires_in // 3600}h {(expires_in % 3600) // 60}m"
            print(f"{mac:<20} {lease['ip']:<15} {lease_start:<25} {expires_str}")

    def _view_status(self):
        """View system status and statistics"""
        print("\nSystem Status:")
        print("-" * 40)
        print(f"Total IP Addresses: {len(self.server.available_addresses) + len(self.server.leases)}")
        print(f"Available IP Addresses: {len(self.server.available_addresses)}")
        print(f"Active Leases: {len(self.server.leases)}")
        print(f"Whitelisted MACs: {len(self.server.mac_whitelist)}")
        print(f"Registered Users: {len(self.server.users)}")

        print("\nServer Configuration:")
        print("-" * 40)
        print(f"IP Range: {self.server.config['ip_range_start']} - {self.server.config['ip_range_end']}")
        print(f"Subnet Mask: {self.server.config['subnet_mask']}")
        print(f"Gateway: {self.server.config['gateway']}")
        print(f"DNS Servers: {', '.join(self.server.config['dns_servers'])}")
        print(f"Default Lease Time: {self.server.config['default_lease_time']}s")

    def _change_password(self):
        """Change user password"""
        username = input("Enter username to change password: ").strip()
        if username not in self.server.users:
            print("User not found!")
            return

        new_password = input("Enter new password: ").strip()
        self.server.users[username]["password_hash"] = self.server._hash_password(new_password)
        self.server._save_leases()
        print(f"Password changed for user {username}")

    def _logout(self):
        """Logout current user"""
        print(f"Goodbye, {self.current_user}!")
        self.current_user = None


#--------------------------------------------------------------------------------#





















class DHCPServer:
    def __init__(self, server_ip='192.168.56.1', server_port=67, client_port=68):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port
        
        # File paths for persistence
        self.lease_file = 'dhcp_leases.json'
        self.auth_file = 'users.json'
        self.mac_whitelist_file = 'mac_whitelist.json'
        self.config_file = 'dhcp_config.json'

        # Initialize logging
        self.setup_logging()
        
        # Load configurations
        self._load_config()
        
        # Initialize core components
        self.available_addresses = self._initialize_ip_pool()
        self._initialize_database()
        self._load_users()
        self._load_mac_whitelist()
        
        # Track active sessions
        self.active_sessions = {}

    def _load_config(self):
        """Load or create server configuration"""
        default_config = {
            "ip_range_start": "192.168.56.100",
            "ip_range_end": "192.168.56.200",
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.56.1",
            "dns_servers": ["8.8.8.8", "8.8.4.4"],
            "default_lease_time": 3600,  # 1 hour
            "max_lease_time": 86400,     # 24 hours
            "renewal_time": 1800,        # 30 minutes
            "rebinding_time": 3150       # 52.5 minutes
        }

        if not os.path.exists(self.config_file):
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            self.config = default_config
        else:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)

    def setup_logging(self):
        """Set up detailed logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('dhcp_server.log'),
                logging.FileHandler(f'dhcp_server_{datetime.now().strftime("%Y%m%d")}.log')
            ]
        )
        self.logger = logging.getLogger('DHCPServer')

    def _initialize_ip_pool(self):
        """Initialize the pool of available IP addresses"""
        ip_pool = []
        start = struct.unpack('!I', socket.inet_aton(self.config['ip_range_start']))[0]
        end = struct.unpack('!I', socket.inet_aton(self.config['ip_range_end']))[0]

        for ip_int in range(start, end + 1):
            ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            ip_pool.append(ip)

        ip_pool.sort()
        self.logger.info(f"Initialized IP pool with {len(ip_pool)} addresses")
        return ip_pool

    def _load_mac_whitelist(self):
        """Load or create MAC address whitelist"""
        if not os.path.exists(self.mac_whitelist_file):
            self.mac_whitelist = {}
            self._save_mac_whitelist()
        else:
            with open(self.mac_whitelist_file, 'r') as f:
                self.mac_whitelist = json.load(f)

    def _save_mac_whitelist(self):
        """Save MAC whitelist to file"""
        with open(self.mac_whitelist_file, 'w') as f:
            json.dump(self.mac_whitelist, f, indent=4)

    def add_mac_to_whitelist(self, mac_address, description, admin_user):
        """Add a MAC address to the whitelist"""
        self.mac_whitelist[mac_address] = {
            "approved": True,
            "description": description,
            "approved_by": admin_user,
            "approved_date": time.time(),
            "last_seen": None,
            "total_connections": 0
        }
        self._save_mac_whitelist()
        self.logger.info(f"MAC {mac_address} added to whitelist by {admin_user}")

    def _initialize_database(self):
        """Initialize or load the lease database"""
        if not os.path.exists(self.lease_file):
            self.leases = {}
            self._save_leases()
        else:
            self._load_leases()

    def _load_leases(self):
        """Load lease information from JSON file"""
        try:
            with open(self.lease_file, 'r') as f:
                self.leases = json.load(f)
                for lease in self.leases.values():
                    lease['timestamp'] = float(lease['timestamp'])
        except Exception as e:
            self.logger.error(f"Error loading leases: {e}")
            self.leases = {}

    def _save_leases(self):
        """Save lease information to JSON file"""
        try:
            # First write to a temporary file
            temp_file = f"{self.lease_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(self.leases, f, indent=4)
            
            # Then rename it to the actual file (atomic operation)
            os.replace(temp_file, self.lease_file)
            self.logger.debug("Leases saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving leases: {e}")

    def _load_users(self):
        """Load or create admin users"""
        if not os.path.exists(self.auth_file):
            default_users = {
                "admin": {
                    "password_hash": self._hash_password("admin123"),
                    "role": "administrator",
                    "created_at": time.time(),
                    "last_login": None
                }
            }
            with open(self.auth_file, 'w') as f:
                json.dump(default_users, f, indent=4)

        with open(self.auth_file, 'r') as f:
            self.users = json.load(f)

    def _hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        if username in self.users:
            stored_hash = self.users[username]["password_hash"]
            if stored_hash == self._hash_password(password):
                self.users[username]["last_login"] = time.time()
                with open(self.auth_file, 'w') as f:
                    json.dump(self.users, f, indent=4)
                return True
        return False

    def is_mac_authorized(self, mac_address):
        """Check if MAC address is authorized"""
        if mac_address in self.mac_whitelist:
            whitelist_entry = self.mac_whitelist[mac_address]
            if whitelist_entry["approved"]:
                # Update MAC statistics
                whitelist_entry["last_seen"] = time.time()
                whitelist_entry["total_connections"] += 1
                self._save_mac_whitelist()
                return True
        return False

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to specific interface instead of 0.0.0.0
            self.sock.bind((self.server_ip, self.server_port))  # Use server_ip instead of 0.0.0.0

            self.logger.info("=" * 50)
            self.logger.info("DHCP Server Starting")
            self.logger.info(f"Listening on {self.server_ip}:{self.server_port}")
            self.logger.info(f"Server IP: {self.server_ip}")
            self.logger.info(f"Available IP addresses: {len(self.available_addresses)}")
            self.logger.info(f"Loaded {len(self.mac_whitelist)} MAC whitelist entries")
            self.logger.info(f"Loaded {len(self.leases)} active leases")
            self.logger.info("=" * 50)

            # Start maintenance threads
            cleanup_thread = threading.Thread(target=self._cleanup_expired_leases)
            cleanup_thread.daemon = True
            cleanup_thread.start()

            # Main server loop
            while True:
                try:
                    message, address = self.sock.recvfrom(4096)  # Increased buffer size
                    client_thread = threading.Thread(
                        target=self._handle_client_message,
                        args=(message, address)
                    )
                    client_thread.start()

                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}")

        except Exception as e:
            self.logger.error(f"Fatal server error: {e}")
        finally:
            self.sock.close()
            
    def _create_dhcp_response(self, message_type, xid, client_mac, yiaddr):
        """Create DHCP response packet specifically formatted for Windows clients"""
        response = bytearray(240)  # Standard DHCP header size
        
        # Basic header fields
        response[0] = 2    # Message type (Boot Reply)
        response[1] = 1    # Hardware type (Ethernet)
        response[2] = 6    # Hardware address length
        response[3] = 0    # Hops
        
        # Transaction ID (same as request)
        response[4:8] = xid
        
        # Seconds elapsed & Broadcast flags
        response[8:10] = b'\x00\x00'
        response[10:12] = b'\x80\x00'  # Broadcast flag set (very important for Windows)
        
        # IP addresses
        response[12:16] = b'\x00\x00\x00\x00'  # Client IP (zeros for new lease)
        response[16:20] = socket.inet_aton(yiaddr)  # Your (client) IP address
        response[20:24] = socket.inet_aton(self.server_ip)  # Next server IP
        response[24:28] = b'\x00\x00\x00\x00'  # Relay agent IP
        
        # Client MAC address (16 bytes field)
        mac_bytes = bytes.fromhex(client_mac.replace(':', ''))
        response[28:34] = mac_bytes
        response[34:44] = b'\x00' * 10  # Padding for client hardware address
        
        # Server host name and boot file name (zeroed)
        response[44:236] = b'\x00' * 192
        
        # Magic cookie (required for DHCP)
        response.extend(b'\x63\x82\x53\x63')
        
        # DHCP Options - ordering is important for Windows
        
        # Option 53: DHCP Message Type
        response.extend(bytes([53, 1, message_type]))
        
        # Option 54: Server Identifier
        response.extend(bytes([54, 4]) + socket.inet_aton(self.server_ip))
        
        # Option 51: IP Address Lease Time
        lease_time = self.config['default_lease_time']
        response.extend(bytes([51, 4]) + struct.pack('!L', lease_time))
        
        # Option 1: Subnet Mask
        response.extend(bytes([1, 4]) + socket.inet_aton(self.config['subnet_mask']))
        
        # Option 3: Router (Gateway)
        response.extend(bytes([3, 4]) + socket.inet_aton(self.config['gateway']))
        
        # Option 6: Domain Name Server
        dns_servers = self.config['dns_servers']
        dns_bytes = b''.join(socket.inet_aton(dns) for dns in dns_servers)
        response.extend(bytes([6, len(dns_bytes)]) + dns_bytes)
        
        # Option 15: Domain Name (optional, but Windows likes it)
        domain = "local"  # You can change this
        response.extend(bytes([15, len(domain)]) + domain.encode())
        
        # Option 28: Broadcast Address
        network = ipaddress.IPv4Network(f"{yiaddr}/{self.config['subnet_mask']}", strict=False)
        broadcast = str(network.broadcast_address)
        response.extend(bytes([28, 4]) + socket.inet_aton(broadcast))
        
        # Option 58: Renewal Time Value (T1)
        response.extend(bytes([58, 4]) + struct.pack('!L', lease_time // 2))
        
        # Option 59: Rebinding Time Value (T2)
        response.extend(bytes([59, 4]) + struct.pack('!L', lease_time * 7 // 8))
        
        # End Option
        response.extend(bytes([255]))
        
        # Add padding to ensure minimum size
        if len(response) < 300:
            response.extend(b'\x00' * (300 - len(response)))
        
        return response
        
        return response
    def _debug_print_options(self, response):
        """Debug method to print DHCP options"""
        i = 240  # Start of options after magic cookie
        self.logger.debug("DHCP Options being sent:")
        while i < len(response):
            if response[i] == 255:  # End option
                break
            if response[i] == 0:  # Padding
                i += 1
                continue
            
            option_type = response[i]
            option_length = response[i + 1]
            option_data = response[i + 2:i + 2 + option_length]
            
            if option_type == 54:  # Server Identifier
                self.logger.debug(f"Server Identifier: {socket.inet_ntoa(option_data)}")
            elif option_type == 53:  # Message Type
                self.logger.debug(f"Message Type: {option_data[0]}")
            
            i += option_length + 2
    def _handle_client_message(self, message, address):
        try:
            self.logger.info(f"Received message from {address}")
            self.logger.info(f"Message length: {len(message)}")
            
            # Extract and log basic packet info
            client_mac = ':'.join('%02x' % b for b in message[28:34])
            client_ip = socket.inet_ntoa(message[12:16])
            
            self.logger.info(f"Client MAC: {client_mac}")
            self.logger.info(f"Client IP: {client_ip}")
            self.logger.info(f"Raw message start: {message[:20].hex()}")  # Log start of message for debugging

            # Verify MAC authorization
            if not self.is_mac_authorized(client_mac):
                self.logger.warning(f"Unauthorized MAC address: {client_mac}")
                return
            
            # Parse DHCP options with detailed logging
            message_type = None
            requested_ip = None
            server_id = None
            
            i = 240  # Start of options
            self.logger.info("Parsing DHCP options:")
            while i < len(message):
                if message[i] == 255:  # End option
                    self.logger.info("Found end option marker")
                    break
                if message[i] == 0:  # Padding
                    i += 1
                    continue
                
                option_type = message[i]
                if i + 1 >= len(message):
                    self.logger.error("Message truncated at option type")
                    break
                    
                option_length = message[i + 1]
                if i + 2 + option_length > len(message):
                    self.logger.error(f"Message truncated at option {option_type}")
                    break
                    
                option_data = message[i + 2:i + 2 + option_length]
                
                self.logger.info(f"Option {option_type}: length={option_length}, data={option_data.hex()}")
                
                if option_type == 53:  # Message Type
                    message_type = option_data[0]
                    self.logger.info(f"DHCP Message Type: {message_type}")
                elif option_type == 54:  # Server Identifier
                    server_id = socket.inet_ntoa(option_data)
                    self.logger.info(f"Server Identifier: {server_id}")
                elif option_type == 50:  # Requested IP Address
                    requested_ip = socket.inet_ntoa(option_data)
                    self.logger.info(f"Requested IP: {requested_ip}")
                
                i += option_length + 2

            # Handle DISCOVER
            if message_type == 1:  # DHCP DISCOVER
                self.logger.info(f"Processing DISCOVER from {client_mac}")
                
                # Choose IP address to offer
                offered_ip = None
                if client_mac in self.leases:
                    offered_ip = self.leases[client_mac]['ip']
                    self.logger.info(f"Offering previously leased IP: {offered_ip}")
                elif self.available_addresses:
                    offered_ip = self.available_addresses[0]
                    self.logger.info(f"Offering new IP: {offered_ip}")
                
                if offered_ip:
                    try:
                        response = self._create_dhcp_response(2, message[4:8], client_mac, offered_ip)
                        self.logger.info(f"Created OFFER response: {len(response)} bytes")
                        
                        # Send to subnet broadcast address
                        broadcast_addr = '192.168.56.255'
                        self.sock.sendto(response, (broadcast_addr, self.client_port))
                        self.logger.info(f"Sent OFFER to {broadcast_addr}:{self.client_port}")
                        
                        # Log the offer details
                        self.logger.info(f"Offered IP: {offered_ip}")
                        self.logger.info(f"Server IP: {self.server_ip}")
                        self.logger.info(f"Client MAC: {client_mac}")
                        
                    except Exception as e:
                        self.logger.error(f"Error sending OFFER: {e}")
                else:
                    self.logger.warning("No available IP addresses!")

            # Handle REQUEST
            elif message_type == 3:  # DHCP REQUEST
                self.logger.info(f"Received REQUEST from {client_mac}")
                
                # Determine requested IP
                if not requested_ip:
                    if client_ip != '0.0.0.0':
                        requested_ip = client_ip
                    elif client_mac in self.leases:
                        requested_ip = self.leases[client_mac]['ip']
                
                if requested_ip:
                    # Remove from available addresses if it's still there
                    if requested_ip in self.available_addresses:
                        self.available_addresses.remove(requested_ip)
                    
                    # Create or update lease
                    lease = {
                        'ip': requested_ip,
                        'mac_address': client_mac,
                        'timestamp': time.time(),
                        'lease_time': self.config['default_lease_time']
                    }
                    self.leases[client_mac] = lease
                    self._save_leases()

                    # Send ACK
                    response = self._create_dhcp_response(5, message[4:8], client_mac, requested_ip)
                    self.sock.sendto(response, ('<broadcast>', self.client_port))
                    self.logger.info(f"Sent ACK for {requested_ip} to {client_mac}")
                else:
                    # Send NAK if no valid IP found
                    response = self._create_dhcp_response(6, message[4:8], client_mac, '0.0.0.0')
                    self.sock.sendto(response, ('<broadcast>', self.client_port))
                    self.logger.info(f"Sent NAK to {client_mac} - No valid IP address found")

            # Handle RELEASE
            elif message_type == 7:  # DHCP RELEASE
                self.logger.info(f"Processing RELEASE from {client_mac} for IP {client_ip}")
                if client_mac in self.leases:
                    released_ip = self.leases[client_mac]['ip']
                    del self.leases[client_mac]
                    if released_ip not in self.available_addresses:
                        self.available_addresses.append(released_ip)
                        self.available_addresses.sort()
                    self._save_leases()
                    self.logger.info(f"Successfully released IP {released_ip} from MAC {client_mac}")
                else:
                    self.logger.warning(f"No lease found for MAC {client_mac}")
            
        except Exception as e:
            self.logger.error(f"Error handling client message: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            
    def _is_ip_in_range(self, ip):
        """Check if an IP address is within the configured range"""
        try:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip))[0]
            start_addr = struct.unpack('!I', socket.inet_aton(self.config['ip_range_start']))[0]
            end_addr = struct.unpack('!I', socket.inet_aton(self.config['ip_range_end']))[0]
            return start_addr <= ip_addr <= end_addr
        except Exception:
            return False

    def _cleanup_expired_leases(self):
        """Periodically clean up expired leases"""
        while True:
            try:
                current_time = time.time()
                expired_leases = []

                for mac_address, lease in list(self.leases.items()):
                    if current_time - lease['timestamp'] > lease['lease_time']:
                        expired_leases.append(mac_address)

                for mac_address in expired_leases:
                    ip = self.leases[mac_address]['ip']
                    self.available_addresses.append(ip)
                    self.available_addresses.sort()
                    del self.leases[mac_address]
                    self.logger.info(f"Lease expired for MAC {mac_address}, IP {ip}")

                if expired_leases:
                    self._save_leases()
                    self.logger.info(f"Cleaned up {len(expired_leases)} expired leases")

                time.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Error in lease cleanup: {e}")
                time.sleep(60)  # Wait before retrying

    def _handle_release(self, address, message_data):
        """Handle DHCP RELEASE message"""
        mac_address = message_data.get('mac_address')
        ip_address = message_data.get('ip_address')

        if mac_address in self.leases and self.leases[mac_address]['ip'] == ip_address:
            del self.leases[mac_address]
            self.available_addresses.append(ip_address)
            self.available_addresses.sort()
            self._save_leases()

            # Remove lease from dhcp_leases.json
            with open(self.lease_file, 'r') as f:
                all_leases = json.load(f)

            if mac_address in all_leases:
                del all_leases[mac_address]

            with open(self.lease_file, 'w') as f:
                json.dump(all_leases, f, indent=4)

            self.logger.info(f"Released IP {ip_address} for MAC {mac_address}")
        else:
            self.logger.warning(f"Invalid release request for IP {ip_address} and MAC {mac_address}")

    def _handle_discover(self, address, message_data):
        """Handle DHCP DISCOVER message"""
        if not self.available_addresses:
            self.logger.warning("No available IP addresses!")
            return

        offered_ip = self.available_addresses[0]

        offer_message = {
            'type': 'OFFER',
            'ip_address': offered_ip,
            'subnet_mask': self.config['subnet_mask'],
            'gateway': self.config['gateway'],
            'dns_servers': self.config['dns_servers'],
            'lease_time': self.config['default_lease_time'],
            'renewal_time': self.config['renewal_time'],
            'rebinding_time': self.config['rebinding_time'],
            'server_id': self.server_ip
        }

        self.sock.sendto(str(offer_message).encode(), address)
        self.logger.info(f"Sent OFFER for {offered_ip} to {address}")

    def _handle_request(self, address, message_data):
        """Handle DHCP REQUEST message"""
        requested_ip = message_data.get('requested_ip')
        mac_address = message_data.get('mac_address')

        if requested_ip not in self.available_addresses:
            self.logger.warning(f"Requested IP {requested_ip} not available")
            return

        self.available_addresses.remove(requested_ip)

        lease = {
            'ip': requested_ip,
            'mac_address': mac_address,
            'timestamp': time.time(),
            'lease_time': self.config['default_lease_time'],
            'renewal_time': self.config['renewal_time'],
            'rebinding_time': self.config['rebinding_time']
        }

        self.leases[mac_address] = lease
        self._save_leases()

        ack_message = {
            'type': 'ACK',
            'ip_address': requested_ip,
            'subnet_mask': self.config['subnet_mask'],
            'gateway': self.config['gateway'],
            'dns_servers': self.config['dns_servers'],
            'lease_time': self.config['default_lease_time'],
            'renewal_time': self.config['renewal_time'],
            'rebinding_time': self.config['rebinding_time'],
            'server_id': self.server_ip
        }

        self.sock.sendto(str(ack_message).encode(), address)
        self.logger.info(f"Sent ACK for {requested_ip} to {address}")

    def add_admin_user(self, username, password, role="user"):
        """Add a new admin user"""
        if username in self.users:
            raise ValueError("Username already exists")

        self.users[username] = {
            "password_hash": self._hash_password(password),
            "role": role,
            "created_at": time.time(),
            "last_login": None
        }

        with open(self.auth_file, 'w') as f:
            json.dump(self.users, f, indent=4)

        self.logger.info(f"Added new user: {username} with role: {role}")

if __name__ == "__main__":
    # Use 0.0.0.0 to listen on all interfaces
    SERVER_IP = "192.168.56.1"
    
    print(f"Starting DHCP server on {SERVER_IP}")
    
    # Create server instance with 0.0.0.0 binding
    server = DHCPServer(server_ip=SERVER_IP)
    
    # Print configuration for verification
    print("\nServer Configuration:")
    print(f"Server IP: {SERVER_IP}")
    print(f"IP Range: {server.config['ip_range_start']} - {server.config['ip_range_end']}")
    print(f"Subnet Mask: {server.config['subnet_mask']}")
    print(f"Gateway: {server.config['gateway']}")
    print(f"DNS Servers: {server.config['dns_servers']}")
    
    admin_interface = AdminInterface(server)

    # Start DHCP server in a separate thread
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()

    try:
        # Start admin interface in main thread
        admin_interface.start()
    except KeyboardInterrupt:
        print("\nShutting down DHCP server...")
    finally:
        print("Server shutdown complete")
import socket
import struct
import threading
import json
import time
import logging
import hashlib
import os
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
    def __init__(self, server_ip='0.0.0.0', server_port=67, client_port=68):
        # Server network configuration
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
            "ip_range_start": "192.168.1.100",
            "ip_range_end": "192.168.1.200",
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.1.1",
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
            with open(self.lease_file, 'w') as f:
                json.dump(self.leases, f, indent=4)
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
        """Start the DHCP server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind((self.server_ip, self.server_port))

            self.logger.info("=" * 50)
            self.logger.info("DHCP Server Starting")
            self.logger.info(f"Listening on {self.server_ip}:{self.server_port}")
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
                    message, address = self.sock.recvfrom(1024)
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

    def _handle_client_message(self, message, address):
        """Handle incoming client messages"""
        try:
            message_data = eval(message.decode())  # Note: In production, use proper parsing
            self.logger.info(f"Processing {message_data['type']} from {address}")

            # Verify MAC authorization
            mac_address = message_data.get('mac_address')
            if not self.is_mac_authorized(mac_address):
                self.logger.warning(f"Unauthorized MAC address: {mac_address}")
                return

            # Verify user authentication
            if not self.authenticate_user(
                    message_data.get('username'),
                    message_data.get('password')
            ):
                self.logger.warning(f"Authentication failed for {address}")
                return

            # Handle message based on type
            if message_data['type'] == 'DISCOVER':
                self._handle_discover(address, message_data)
            elif message_data['type'] == 'REQUEST':
                self._handle_request(address, message_data)
            elif message_data['type'] == 'RELEASE':
                self._handle_release(address, message_data)

        except Exception as e:
            self.logger.error(f"Error handling client message: {e}")

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
    server = DHCPServer()
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
        exit(0)
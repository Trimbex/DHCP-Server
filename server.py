import socket
import struct
import threading
import json
import time
import logging
import hashlib
import os

class DHCPServer:
    def __init__(self, server_ip='0.0.0.0', server_port=67, client_port=68):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port
        self.lease_file = 'dhcp_leases.json'
        self.auth_file = 'users.json'
        self.setup_logging()
        self.available_addresses = self._initialize_ip_pool()
        self._initialize_database()
        self._load_users()

    def _initialize_ip_pool(self):
        """Initialize the pool of available IP addresses"""
        ip_pool = []
        start = struct.unpack('!I', socket.inet_aton('192.168.1.100'))[0]
        end = struct.unpack('!I', socket.inet_aton('192.168.1.200'))[0]
        
        for ip_int in range(start, end + 1):
            ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            ip_pool.append(ip)
            
        self.logger.info(f"Initialized IP pool with {len(ip_pool)} addresses")
        return ip_pool

    def setup_logging(self):
        """Set up logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('dhcp_server.log')
            ]
        )
        self.logger = logging.getLogger('DHCPServer')

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
        """Load user credentials"""
        if not os.path.exists(self.auth_file):
            default_users = {
                "admin": self._hash_password("admin123")
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
            stored_hash = self.users[username]
            return stored_hash == self._hash_password(password)
        return False

    def start(self):
        """Start the DHCP server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.server_ip, self.server_port))
            
            self.logger.info("=" * 50)
            self.logger.info("DHCP Server Started")
            self.logger.info(f"Listening on {self.server_ip}:{self.server_port}")
            self.logger.info(f"Available IP addresses: {len(self.available_addresses)}")
            self.logger.info("=" * 50)
            
            cleanup_thread = threading.Thread(target=self._cleanup_expired_leases)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            while True:
                try:
                    self.logger.info("Waiting for DHCP messages...")
                    message, address = self.sock.recvfrom(1024)
                    self.logger.info(f"Received message from {address}")
                    
                    try:
                        message_data = eval(message.decode())
                        self.logger.info(f"Message type: {message_data.get('type')}")
                        self.logger.info(f"From MAC: {message_data.get('mac_address')}")
                        
                        if not self.authenticate_user(message_data.get('username'), message_data.get('password')):
                            self.logger.warning(f"Authentication failed for {address}")
                            continue
                            
                        self.logger.info("Authentication successful")
                        
                        if message_data['type'] == 'DISCOVER':
                            self._handle_discover(address, message_data)
                        elif message_data['type'] == 'REQUEST':
                            self._handle_request(address, message_data)
                            
                    except Exception as e:
                        self.logger.error(f"Error processing message: {e}")
                    
                except Exception as e:
                    self.logger.error(f"Error receiving message: {e}")
                    
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            self.sock.close()

    def _cleanup_expired_leases(self):
        """Periodically clean up expired leases"""
        while True:
            current_time = time.time()
            expired_leases = []
            
            for mac_address, lease in list(self.leases.items()):
                if current_time - lease['timestamp'] > lease['lease_time']:
                    expired_leases.append((mac_address, lease['ip']))
            
            for mac_address, ip in expired_leases:
                if ip not in self.available_addresses:
                    self.available_addresses.insert(0, ip)
                del self.leases[mac_address]
            
            self._save_leases()
            time.sleep(1)  # Check every second

    def _handle_discover(self, address, message_data):
        """Handle DHCP DISCOVER message"""
        if self.available_addresses:
            offered_ip = self.available_addresses[0]
            self.logger.info(f"Offering IP {offered_ip} to client {message_data.get('mac_address')}")
            
            offer_message = {
                'type': 'OFFER',
                'ip_address': offered_ip,
                'lease_time': 10,
                'server_id': self.server_ip
            }
            
            self.sock.sendto(str(offer_message).encode(), address)
            self.logger.info(f"Sent OFFER message to {address}")

    def _handle_request(self, address, message_data):
        """Handle DHCP REQUEST message"""
        requested_ip = message_data.get('requested_ip')
        mac_address = message_data.get('mac_address')
        
        if requested_ip in self.available_addresses:
            self.available_addresses.remove(requested_ip)
            
            lease = {
                'ip': requested_ip,
                'mac_address': mac_address,
                'timestamp': time.time(),
                'lease_time': 10
            }
            
            self.leases[mac_address] = lease
            self._save_leases()
            
            ack_message = {
                'type': 'ACK',
                'ip_address': requested_ip,
                'lease_time': 10,
                'server_id': self.server_ip
            }
            
            self.sock.sendto(str(ack_message).encode(), address)
            self.logger.info(f"Sent ACK message to {address} for IP {requested_ip}")

if __name__ == "__main__":
    server = DHCPServer()
    server.start()

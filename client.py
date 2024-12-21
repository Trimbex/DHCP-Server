import socket
import struct
import logging
import time
import json
import os
from datetime import datetime
import netifaces  # External library for getting network interfaces
import platform

class DHCPClient:
    def __init__(self, username, password, mac_address=None, server_ip='255.255.255.255', server_port=67, client_port=68):
        # Client configuration
        self.username = username
        self.password = password
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port

        # Client state
        self.mac_address = mac_address or self._generate_mac_address()
        self.offered_ip = None
        self.leased_ip = None
        self.lease_time = None
        self.renewal_time = None
        self.rebinding_time = None
        self.lease_start_time = None
        self.server_id = None

        # Setup logging and load config
        self.setup_logging()
        self._load_config()

    def _load_config(self):
        """Load client configuration or create default"""
        config_file = 'dhcp_client_config.json'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                "retry_attempts": 3,
                "retry_delay": 5,
                "timeout": 10,
                "save_lease": True
            }
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)

    def setup_logging(self):
        """Set up detailed logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(f'dhcp_client_{datetime.now().strftime("%Y%m%d")}.log')
            ]
        )
        self.logger = logging.getLogger('DHCPClient')

    def _generate_mac_address(self):
        """Generate a random MAC address for testing"""
        import random
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        mac[0] = mac[0] & 0xfe  # Clear multicast bit
        mac[0] = mac[0] | 0x02  # Set local assignment bit
        return ':'.join(['{:02x}'.format(x) for x in mac])

    def _save_lease(self):
        """Save lease information to file"""
        if self.config["save_lease"]:
            lease_data = {
                "ip_address": self.leased_ip,
                "mac_address": self.mac_address,
                "lease_time": self.lease_time,
                "renewal_time": self.renewal_time,
                "rebinding_time": self.rebinding_time,
                "lease_start": self.lease_start_time,
                "server_id": self.server_id
            }
            with open(f'lease_{self.mac_address.replace(":", "")}.json', 'w') as f:
                json.dump(lease_data, f, indent=4)

    def _create_message(self, message_type, **kwargs):
        """Create a DHCP message with authentication and MAC"""
        message = {
            'type': message_type,
            'username': self.username,
            'password': self.password,
            'mac_address': self.mac_address,
            'timestamp': time.time(),
            'hostname': socket.gethostname()
        }
        message.update(kwargs)
        return str(message).encode()

    def start(self):
        """Start DHCP client process"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', self.client_port))
            self.sock.settimeout(self.config["timeout"])

            self.logger.info("=" * 50)
            self.logger.info("Starting DHCP Client")
            self.logger.info(f"MAC Address: {self.mac_address}")
            self.logger.info(f"Username: {self.username}")
            self.logger.info("=" * 50)

            for attempt in range(self.config["retry_attempts"]):
                try:
                    self.discover()
                    break
                except Exception as e:
                    self.logger.error(f"Attempt {attempt + 1} failed: {e}")
                    if attempt < self.config["retry_attempts"] - 1:
                        time.sleep(self.config["retry_delay"])
                    else:
                        raise Exception("Max retry attempts reached")

        except Exception as e:
            self.logger.error(f"Critical client error: {e}")
        finally:
            self.sock.close()

    def discover(self):
        """Send DHCP DISCOVER message"""
        try:
            discover_message = self._create_message('DISCOVER')
            self.sock.sendto(discover_message, (self.server_ip, self.server_port))
            self.logger.info("Sent DHCP DISCOVER")
            self._wait_for_offer()

        except Exception as e:
            self.logger.error(f"Error in DISCOVER: {e}")
            raise

    def _wait_for_offer(self):
        """Wait for DHCP OFFER from server"""
        try:
            self.logger.info("Waiting for DHCP OFFER...")
            message, server = self.sock.recvfrom(1024)

            if message:
                self.logger.info(f"Received response from server {server}")
                offer_data = eval(message.decode())  # Note: In production, use proper parsing
                self.logger.info(f"Offer details: {offer_data}")

                if offer_data['type'] == 'OFFER':
                    self.offered_ip = offer_data['ip_address']
                    self.server_id = offer_data.get('server_id')
                    self._send_request(server, offer_data)

        except socket.timeout:
            self.logger.error("Timeout waiting for OFFER")
            raise
        except Exception as e:
            self.logger.error(f"Error processing OFFER: {e}")
            raise

    def _send_request(self, server, offer_data):
        """Send DHCP REQUEST message"""
        try:
            request_message = self._create_message(
                'REQUEST',
                requested_ip=self.offered_ip,
                server_id=self.server_id,
                client_id=self.mac_address
            )

            self.sock.sendto(request_message, server)
            self.logger.info(f"Sent DHCP REQUEST for IP {self.offered_ip}")
            self._wait_for_ack()

        except Exception as e:
            self.logger.error(f"Error sending REQUEST: {e}")
            raise

    def _wait_for_ack(self):
        """Wait for DHCP ACK from server"""
        try:
            self.logger.info("Waiting for DHCP ACK...")
            message, server = self.sock.recvfrom(1024)

            if message:
                ack_data = eval(message.decode())  # Note: In production, use proper parsing
                self.logger.info(f"Received response from server {server}")

                if ack_data['type'] == 'ACK':
                    self.leased_ip = ack_data['ip_address']
                    self.lease_time = ack_data['lease_time']
                    self.renewal_time = ack_data.get('renewal_time', self.lease_time // 2)
                    self.rebinding_time = ack_data.get('rebinding_time', self.lease_time * 7 // 8)
                    self.lease_start_time = time.time()

                    self._save_lease()

                    self.logger.info("=" * 50)
                    self.logger.info("DHCP Configuration Success!")
                    self.logger.info(f"Leased IP: {self.leased_ip}")
                    self.logger.info(f"Subnet Mask: {ack_data.get('subnet_mask', 'Not provided')}")
                    self.logger.info(f"Gateway: {ack_data.get('gateway', 'Not provided')}")
                    self.logger.info(f"DNS Servers: {ack_data.get('dns_servers', 'Not provided')}")
                    self.logger.info(f"Lease Time: {self.lease_time} seconds")
                    self.logger.info(f"Renewal Time: {self.renewal_time} seconds")
                    self.logger.info(f"Rebinding Time: {self.rebinding_time} seconds")
                    self.logger.info("=" * 50)

        except socket.timeout:
            self.logger.error("Timeout waiting for ACK")
            raise
        except Exception as e:
            self.logger.error(f"Error processing ACK: {e}")
            raise

    def release(self):
        """Release the current IP lease"""
        if self.leased_ip and self.server_id:
            try:
                release_message = self._create_message(
                    'RELEASE',
                    ip_address=self.leased_ip,
                    server_id=self.server_id
                )
                self.sock.sendto(release_message, (self.server_ip, self.server_port))
                self.logger.info(f"Released IP lease for {self.leased_ip}")

                # Clean up lease file
                lease_file = f'lease_{self.mac_address.replace(":", "")}.json'
                if os.path.exists(lease_file):
                    os.remove(lease_file)

            except Exception as e:
                self.logger.error(f"Error releasing lease: {e}")
def _get_current_mac_address():
    """Retrieve the current MAC address of the machine's active network interface."""
    try:
        # Find the default interface (platform-specific)
        if platform.system() == 'Windows':
            default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        else:
            default_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]

        # Get MAC address for the default interface
        mac_address = netifaces.ifaddresses(default_interface)[netifaces.AF_LINK][0]['addr']
        return mac_address
    except Exception as e:
        logging.warning(f"Unable to retrieve current MAC address: {e}")
        return None

def main():
    """Main function with improved user interface."""
    print("DHCP Client Configuration")
    print("=" * 30)

    # Get credentials
    username = input("Enter username: ")
    password = input("Enter password: ")

    # Optional MAC address input
    use_current_mac = input("Use the current machine's MAC address? (y/n): ").lower() == 'y'

    if use_current_mac:
        mac_address = _get_current_mac_address()
        if mac_address:
            print(f"Using the current machine's MAC address: {mac_address}")
        else:
            print("Could not retrieve the current machine's MAC address. Falling back to generated MAC.")
            mac_address = None
    else:
        use_custom_mac = input("Use custom MAC address? (y/n): ").lower() == 'y'
        mac_address = None
        if use_custom_mac:
            mac_address = input("Enter MAC address (format: xx:xx:xx:xx:xx:xx): ")

    # Create and start client
    client = DHCPClient(username, password, mac_address)

    try:
        client.start()

        # Keep the client running until user terminates
        while True:
            print("\nOptions:")
            print("1. Release IP lease")
            print("2. Request new lease")
            print("3. Exit")

            choice = input("Select option (1-3): ")

            if choice == '1':
                client.release()
            elif choice == '2':
                client.start()
            elif choice == '3':
                client.release()  # Release lease before exiting
                break

    except KeyboardInterrupt:
        print("\nShutting down client...")
        client.release()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("DHCP Client terminated")

if __name__ == "__main__":
    main()
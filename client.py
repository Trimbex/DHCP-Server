import socket
import struct
import logging
from datetime import datetime
import time

class DHCPClient:
    def __init__(self, username, password, server_ip='255.255.255.255', server_port=67, client_port=68):
        self.username = username
        self.password = password
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port
        self.mac_address = self._generate_mac_address()
        self.offered_ip = None  # Store the offered IP
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('DHCPClient')
        
    def _generate_mac_address(self):
        """Generate a random MAC address for testing"""
        import random
        return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
        
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', self.client_port))
            self.sock.settimeout(10)
            
            self.discover()
            
        except Exception as e:
            self.logger.error(f"Client error: {e}")
        finally:
            self.sock.close()
            
    def _create_message(self, message_type, **kwargs):
        """Create a DHCP message with authentication"""
        message = {
            'type': message_type,
            'username': self.username,
            'password': self.password,
            'mac_address': self.mac_address,
            'timestamp': time.time()
        }
        message.update(kwargs)  # Add any additional parameters
        return str(message).encode()
            
    def discover(self):
        try:
            discover_message = self._create_message('DISCOVER')
            self.sock.sendto(discover_message, (self.server_ip, self.server_port))
            self.logger.info("Sent DHCP DISCOVER with authentication")
            self._wait_for_offer()
            
        except Exception as e:
            self.logger.error(f"Error in discover: {e}")
            
    def _wait_for_offer(self):
        try:
            self.logger.info("Waiting for DHCP OFFER...")
            message, server = self.sock.recvfrom(1024)
            
            if message:
                self.logger.info(f"Received OFFER from server {server}")
                offer_data = eval(message.decode())  # For testing only - in production use proper parsing
                self.logger.info(f"Parsing OFFER message: {offer_data}")
                
                if offer_data['type'] == 'OFFER':
                    self.offered_ip = offer_data['ip_address']
                    self._send_request(server, offer_data)
                
        except socket.timeout:
            self.logger.error("Timeout waiting for DHCP OFFER")
        except Exception as e:
            self.logger.error(f"Error waiting for offer: {e}")
            
    def _send_request(self, server, offer_data):
        try:
            request_message = self._create_message(
                'REQUEST',
                requested_ip=self.offered_ip,
                server_id=offer_data['server_id']
            )
            
            self.sock.sendto(request_message, server)
            self.logger.info("Sent DHCP REQUEST")
            self._wait_for_ack()
            
        except Exception as e:
            self.logger.error(f"Error sending REQUEST: {e}")
            
    def _wait_for_ack(self):
        try:
            self.logger.info("Waiting for DHCP ACK...")
            message, server = self.sock.recvfrom(1024)
            
            if message:
                ack_data = eval(message.decode())  # For testing only - in production use proper parsing
                self.logger.info(f"Received ACK from server {server}")
                self.logger.info(f"Parsing ACK message: {ack_data}")
                
                if ack_data['type'] == 'ACK':
                    self.logger.info(f"Successfully leased IP: {ack_data['ip_address']}")
                    self.logger.info(f"Lease time: {ack_data['lease_time']} seconds")
                    self.logger.info("DHCP configuration complete!")
                    
        except socket.timeout:
            self.logger.error("Timeout waiting for DHCP ACK")
        except Exception as e:
            self.logger.error(f"Error waiting for ACK: {e}")

def main():
    username = input("Enter username: ")
    password = input("Enter password: ")
    client = DHCPClient(username, password)
    client.start()

if __name__ == "__main__":
    main()
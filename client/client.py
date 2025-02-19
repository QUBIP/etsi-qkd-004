import socket
import ssl
import struct
import uuid
import logging
import os

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# Constants
VERSION = '1.0.1'

# Client Settings (from environment variables)
CLIENT_CERT_PEM = os.getenv('CLIENT_CERT_PEM', '/certs/client_cert.pem')
CLIENT_CERT_KEY = os.getenv('CLIENT_CERT_KEY', '/certs/client_key.pem')
SERVER_CERT_PEM = os.getenv('SERVER_CERT_PEM', '/certs/server_cert.pem')
SERVER_ADDRESS = os.getenv('SERVER_ADDRESS', 'qkd_server')
CLIENT_ADDRESS = os.getenv('CLIENT_ADDRESS', 'localhost')
SERVER_PORT = int(os.getenv('SERVER_PORT', 25575))
KEY_INDEX = int(os.getenv('KEY_INDEX', 0))
METADATA_SIZE = int(os.getenv('METADATA_SIZE', 1024))
QOS_KEY_CHUNK_SIZE = int(os.getenv('QOS_KEY_CHUNK_SIZE', 512))
QOS_MAX_BPS = int(os.getenv('QOS_MAX_BPS', 40000))
QOS_MIN_BPS = int(os.getenv('QOS_MIN_BPS', 5000))
QOS_JITTER = int(os.getenv('QOS_JITTER', 10))
QOS_PRIORITY = int(os.getenv('QOS_PRIORITY', 0))
QOS_TIMEOUT = int(os.getenv('QOS_TIMEOUT', 5000))
QOS_TTL = int(os.getenv('QOS_TTL', 3600))

# API Function Codes
QKD_SERVICE_OPEN_CONNECT_REQUEST = 0x02
QKD_SERVICE_OPEN_CONNECT_RESPONSE = 0x03
QKD_SERVICE_GET_KEY_REQUEST = 0x04
QKD_SERVICE_GET_KEY_RESPONSE = 0x05
QKD_SERVICE_CLOSE_REQUEST = 0x08
QKD_SERVICE_CLOSE_RESPONSE = 0x09

# QoS Parameter Sizes
QOS_FIELD_COUNT = 7
QOS_FIELD_SIZE = 4  # Each QoS field is a 32-bit unsigned integer
METADATA_MIMETYPE_SIZE = 256  # bytes

# Status Codes
STATUS_SUCCESS = 0
STATUS_PEER_NOT_CONNECTED = 1
STATUS_INSUFFICIENT_KEY = 2
STATUS_PEER_NOT_CONNECTED_GET_KEY = 3
STATUS_NO_QKD_CONNECTION = 4
STATUS_KSID_IN_USE = 5
STATUS_TIMEOUT = 6
STATUS_QOS_NOT_MET = 7
STATUS_METADATA_SIZE_INSUFFICIENT = 8

class KnownException(Exception):
    """Custom exception class for known errors."""

class QKDClient:
    """Client class for interacting with the QKD server."""

    def __init__(self):
        """Initialize the QKDClient with default values."""
        self.key_stream_id = uuid.UUID(int=0)
        self.sock = None
        self.qos = {
            'Key_chunk_size': QOS_KEY_CHUNK_SIZE,  # in bytes
            'Max_bps': QOS_MAX_BPS,
            'Min_bps': QOS_MIN_BPS,
            'Jitter': QOS_JITTER,
            'Priority': QOS_PRIORITY,
            'Timeout': QOS_TIMEOUT,  # in milliseconds
            'TTL': QOS_TTL,  # in seconds
            'Metadata_mimetype': 'application/json'
        }

    def connect(self, server_ip, server_port):
        """Establish a secure connection to the server."""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(certfile=CLIENT_CERT_PEM, keyfile=CLIENT_CERT_KEY)
        context.load_verify_locations(cafile=SERVER_CERT_PEM)
        raw_sock = socket.socket(socket.AF_INET)
        raw_sock.settimeout(5)
        self.sock = context.wrap_socket(raw_sock, server_hostname=server_ip)

        try:
            self.sock.connect((server_ip, server_port))
            logging.info(f"Connected to server at {server_ip}:{server_port}")
        except (TimeoutError, ConnectionRefusedError) as e:
            logging.error(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}, {e}")
            raise KnownException(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}") from e

    def recv_full_response(self):
        """Receive the full response from the server."""
        # Read header (8 bytes)
        header = self.recv_full_data(8)
        if not header or len(header) < 8:
            raise KnownException("Incomplete header received.")
        # Parse header
        version_major, version_minor, version_patch, service_type = struct.unpack('!BBBb', header[:4])
        payload_length = struct.unpack('!I', header[4:8])[0]
        # Read payload
        payload = self.recv_full_data(payload_length)
        logging.debug(f"Version {version_major}.{version_minor}.{version_patch}. Received service type: {service_type}")
        if len(payload) < payload_length:
            raise KnownException("Incomplete payload received.")
        return header + payload

    def recv_full_data(self, length):
        """Receive exactly 'length' bytes of data from the server."""
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def open_connect(self, source_uri, dest_uri):
        """Send an OPEN_CONNECT_REQUEST to the server."""
        # Construct payload
        payload = source_uri.encode() + b'\x00'
        payload += dest_uri.encode() + b'\x00'
        payload += self.construct_qos(self.qos)
        # Key_stream_ID set to all zeros (16 bytes)
        payload += self.key_stream_id.bytes

        # Logging statements
        logging.debug(f"Source URI sent by client: {source_uri}")
        logging.debug(f"Destination URI sent by client: {dest_uri}")
        logging.debug(f"QoS sent by client: {self.qos}")

        # Construct request
        request = self.construct_request(QKD_SERVICE_OPEN_CONNECT_REQUEST, payload)

        # Send request and receive response
        try:
            self.sock.sendall(request)
            response = self.recv_full_response()
        except (TimeoutError, ConnectionRefusedError) as e:
            logging.error(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}")
            raise KnownException(f"OPEN_CONNECT failed with status: {STATUS_PEER_NOT_CONNECTED}") from e

        # Parse response
        status, key_stream_id = self.parse_open_connect_response(response)
        if status == STATUS_SUCCESS or status == STATUS_QOS_NOT_MET:
            self.key_stream_id = key_stream_id
            logging.info(f"OPEN_CONNECT status: {status}, Key_stream_ID: {self.key_stream_id}")
        else:
            logging.error(f"OPEN_CONNECT failed with status: {status}")
            raise KnownException(f"OPEN_CONNECT failed with status: {status}")

    def get_key(self, index, metadata_size):
        """Send a GET_KEY_REQUEST to the server and receive key material."""
        # Construct payload
        payload = self.key_stream_id.bytes
        payload += struct.pack('!I', index)
        payload += struct.pack('!I', metadata_size)
        logging.debug(f"Metadata size requested by client: {metadata_size}")

        # Construct request
        request = self.construct_request(QKD_SERVICE_GET_KEY_REQUEST, payload)

        # Send request and receive response
        try:
            self.sock.sendall(request)
            response = self.recv_full_response()
        except (TimeoutError, ConnectionRefusedError) as e:
            logging.error(f"GET_KEY failed with status: {STATUS_PEER_NOT_CONNECTED}")
            raise KnownException(f"GET_KEY failed with status: {STATUS_PEER_NOT_CONNECTED}") from e

        # Parse response
        status, key_material, metadata = self.parse_get_key_response(response)

        if status == STATUS_SUCCESS:
            logging.info(f"GET_KEY status: {status}, Key_stream_ID: {self.key_stream_id}, Key length: {len(key_material)}, Metadata: {metadata}")
        else:
            logging.error(f"GET_KEY failed with status: {status}")
            raise KnownException(f"GET_KEY failed with status: {status}")

    def close(self):
        """Send a CLOSE_REQUEST to the server to close the connection."""
        # Construct payload
        payload = self.key_stream_id.bytes

        # Construct request
        request = self.construct_request(QKD_SERVICE_CLOSE_REQUEST, payload)

        # Send request and receive response
        try:
            self.sock.sendall(request)
            response = self.recv_full_response()
            self.sock.close()
        except (TimeoutError, ConnectionRefusedError) as e:
            logging.error(f"CLOSE failed with status: {STATUS_PEER_NOT_CONNECTED}")
            raise KnownException(f"CLOSE failed with status: {STATUS_PEER_NOT_CONNECTED}") from e

        # Parse response
        status = self.parse_close_response(response)
        if status == STATUS_SUCCESS:
            logging.info(f"CLOSE status: {status}, Key_stream_ID: {self.key_stream_id}")
        else:
            logging.error(f"CLOSE failed with status: {status}")
            raise KnownException(f"CLOSE failed with status: {status}")

    def construct_request(self, service_type, payload):
        """Construct a request packet to send to the server."""
        version_bytes = struct.pack('!BBB', *[int(x) for x in VERSION.split('.')])
        service_type_byte = struct.pack('!b', service_type)
        payload_length = struct.pack('!I', len(payload))
        request = version_bytes + service_type_byte + payload_length + payload
        return request

    def construct_qos(self, qos):
        """Construct the QoS bytes to include in the request."""
        qos_fields = struct.pack(
            '!7I',
            qos['Key_chunk_size'],
            qos['Max_bps'],
            qos['Min_bps'],
            qos['Jitter'],
            qos['Priority'],
            qos['Timeout'],
            qos['TTL']
        )
        metadata_mimetype_bytes = qos['Metadata_mimetype'].encode().ljust(METADATA_MIMETYPE_SIZE, b'\x00')
        return qos_fields + metadata_mimetype_bytes

    def parse_open_connect_response(self, response):
        """Parse the OPEN_CONNECT_RESPONSE from the server."""
        # Parse header
        payload_length = struct.unpack('!I', response[4:8])[0]
        payload = response[8:8 + payload_length]

        # Parse payload
        status = struct.unpack('!I', payload[:4])[0]

        if status == STATUS_SUCCESS or status == STATUS_QOS_NOT_MET:
            # Parse QoS parameters from the response
            qos_data = payload[4:4 + (QOS_FIELD_COUNT * QOS_FIELD_SIZE) + METADATA_MIMETYPE_SIZE]
            server_qos = self.parse_qos(qos_data)

            # If QoS not met by the server
            if status == STATUS_QOS_NOT_MET:
                logging.warning(f"QoS not met. Adjusted QoS provided by server: {server_qos}")

            # Logging adjusted QoS
            logging.debug(f"QoS received by client: {server_qos}")

            # Update client's QoS to use the adjusted QoS from the server
            self.qos = server_qos

            # Extract Key_stream_ID
            key_stream_id_bytes_start = 4 + (QOS_FIELD_COUNT * QOS_FIELD_SIZE) + METADATA_MIMETYPE_SIZE
            key_stream_id_bytes_end = key_stream_id_bytes_start + 16
            key_stream_id_bytes = payload[key_stream_id_bytes_start:key_stream_id_bytes_end]
            key_stream_id = uuid.UUID(bytes=key_stream_id_bytes)

            return status, key_stream_id

        return status, None

    def parse_get_key_response(self, response):
        """Parse the GET_KEY_RESPONSE from the server."""
        # Parse header
        payload_length = struct.unpack('!I', response[4:8])[0]
        payload = response[8:8 + payload_length]

        # Parse payload
        status = struct.unpack('!I', payload[:4])[0]

        if status == STATUS_SUCCESS:
            # Parse index and key_chunk_size
            index = struct.unpack('!I', payload[4:8])[0]
            key_chunk_size = struct.unpack('!I', payload[8:12])[0]

            # Extract key material
            key_material_start = 12
            key_material_end = key_material_start + key_chunk_size
            key_material = payload[key_material_start:key_material_end]

            # Parse metadata_size
            metadata_size_start = key_material_end
            metadata_size_end = metadata_size_start + 4
            metadata_size = struct.unpack('!I', payload[metadata_size_start:metadata_size_end])[0]

            # Extract metadata using metadata_size
            metadata_start = metadata_size_end
            metadata_end = metadata_start + metadata_size
            metadata_bytes = payload[metadata_start:metadata_end]
            metadata = metadata_bytes.decode()

            # Logging for index and metadata_size
            logging.debug(f"Index received by client: {index}")
            logging.debug(f"Metadata size received by client: {metadata_size}")

            # Logging for key material
            if len(key_material) >= 8:
                first8 = key_material[:8].hex()
                last8 = key_material[-8:].hex()
                logging.debug(f"Key received by client: first 8 bytes {first8}, last 8 bytes {last8}")
            else:
                logging.debug(f"Key received by client is less than 8 bytes: {key_material.hex()}")

            # Logging for metadata
            logging.debug(f"Metadata received by client: {metadata}")

        else:
            key_material = b''
            metadata = ''

        return status, key_material, metadata

    def parse_close_response(self, response):
        """Parse the CLOSE_RESPONSE from the server."""
        # Parse header
        payload_length = struct.unpack('!I', response[4:8])[0]
        payload = response[8:8 + payload_length]

        # Parse payload
        status = struct.unpack('!I', payload[:4])[0]

        return status

    def parse_qos(self, qos_data):
        """Parse QoS data from the response into a dictionary."""
        qos_fields = struct.unpack('!7I', qos_data[:QOS_FIELD_COUNT * QOS_FIELD_SIZE])
        metadata_mimetype = qos_data[QOS_FIELD_COUNT * QOS_FIELD_SIZE:].decode().strip('\x00')
        qos = {
            'Key_chunk_size': qos_fields[0],
            'Max_bps': qos_fields[1],
            'Min_bps': qos_fields[2],
            'Jitter': qos_fields[3],
            'Priority': qos_fields[4],
            'Timeout': qos_fields[5],
            'TTL': qos_fields[6],
            'Metadata_mimetype': metadata_mimetype
        }
        return qos

    def main_flow(self, source_uri, dest_uri, index, metadata_size, server_ip=SERVER_ADDRESS, server_port=SERVER_PORT):
        """Execute the main client flow: connect, open_connect, get_key, close."""
        try:
            self.connect(server_ip, server_port)
            self.open_connect(source_uri, dest_uri)
            self.get_key(index, metadata_size=metadata_size)
            self.close()
        except KnownException:
            pass
        finally:
            if hasattr(self, 'sock') and self.sock:
                self.sock.close()

    def main_flow_invalid_key_stream_id_get_key(self, index, metadata_size, server_ip=SERVER_ADDRESS, server_port=SERVER_PORT):
        """Execute a flow with invalid Key_stream_ID for GET_KEY."""
        try:
            self.connect(server_ip, server_port)
            self.get_key(index, metadata_size=metadata_size)
            self.close()
        except KnownException:
            pass
        finally:
            if hasattr(self, 'sock') and self.sock:
                self.sock.close()

    def main_flow_invalid_key_stream_id_close(self, server_ip=SERVER_ADDRESS, server_port=SERVER_PORT):
        """Execute a flow with invalid Key_stream_ID for CLOSE."""
        try:
            self.connect(server_ip, server_port)
            self.close()
        except KnownException:
            pass
        finally:
            if hasattr(self, 'sock') and self.sock:
                self.sock.close()

def main():
    """Main function to run the QKD client."""
    client = QKDClient()
    client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', KEY_INDEX, METADATA_SIZE)
    client = QKDClient()

if __name__ == "__main__":
    main()

import socket
import ssl
import threading
import logging
import uuid
import struct
import json
import time
import os
import multiprocessing
import mmap
from urllib.parse import urlparse
from multiprocessing import Manager

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# Constants
VERSION = '1.0.1'

# Server Settings (from environment variables)
SERVER_CERT_PEM = os.getenv('SERVER_CERT_PEM')
SERVER_CERT_KEY = os.getenv('SERVER_CERT_KEY')
CLIENT_CERT_PEM = os.getenv('CLIENT_CERT_PEM')
SERVER_ADDRESS = os.getenv('SERVER_ADDRESS', '0.0.0.0')
SERVER_PORT = int(os.getenv('SERVER_PORT', 25575))
BUFFER_PATH = os.getenv("BUFFER_PATH", "/dev/shm/qkd_buffer")
BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "5000"))
QOS_KEY_CHUNK_SIZE = int(os.getenv('QOS_KEY_CHUNK_SIZE', 512))
QOS_MAX_BPS = int(os.getenv('QOS_MAX_BPS', 500000))
QOS_MIN_BPS = int(os.getenv('QOS_MIN_BPS', 5000))
QOS_JITTER = int(os.getenv('QOS_JITTER', 5))
QOS_PRIORITY = int(os.getenv('QOS_PRIORITY', 0))
QOS_TIMEOUT = int(os.getenv('QOS_TIMEOUT', 5000))
QOS_TTL = int(os.getenv('QOS_TTL', 7200))

# API Function Codes
QKD_SERVICE_OPEN_CONNECT_REQUEST = 0x02
QKD_SERVICE_OPEN_CONNECT_RESPONSE = 0x03
QKD_SERVICE_GET_KEY_REQUEST = 0x04
QKD_SERVICE_GET_KEY_RESPONSE = 0x05
QKD_SERVICE_CLOSE_REQUEST = 0x08
QKD_SERVICE_CLOSE_RESPONSE = 0x09

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

# QoS Parameter Sizes
QOS_FIELD_COUNT = 7
QOS_FIELD_SIZE = 4  # Each QoS field is a 32-bit unsigned integer
METADATA_MIMETYPE_SIZE = 256  # bytes

# Key Parameters
KEY_CHUNK_SIZE = 256  # Example value in bytes


class QKDServiceHandler:
    def __init__(self):
        """Initialize the QKDServiceHandler with shared resources."""
        manager = Manager()
        self.connected_clients = manager.dict()
        self.key_store = {}  # Stores key material per Key_stream_ID
        self.lock = threading.Lock()  # Lock for thread safety

    def handle_client(self, conn, addr):
        """Handle communication with a connected client."""
        try:
            while True:
                # Read header (8 bytes)
                header = self.recv_full_data(conn, 8)
                if not header:
                    break  # Client closed the connection
                # Parse header
                payload_length = struct.unpack('!I', header[4:8])[0]
                # Read payload
                payload = self.recv_full_data(conn, payload_length)
                if len(payload) < payload_length:
                    logging.error("Incomplete payload received.")
                    break
                data = header + payload
                response = self.handle_request(data, conn)
                if response:
                    conn.sendall(response)
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            conn.close()

    def recv_full_data(self, conn, length):
        """Receive the full amount of data specified by 'length' from the connection."""
        data = b''
        while len(data) < length:
            try:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            except Exception as e:
                logging.error(f"Error receiving data: {e}")
                break
        return data

    def handle_request(self, data, conn):
        """Parse and handle the client's request, dispatching to the appropriate handler."""
        # Parse header
        version_major, version_minor, version_patch, service_type = struct.unpack('!BBBb', data[:4])
        payload_length = struct.unpack('!I', data[4:8])[0]
        payload = data[8:8 + payload_length]

        logging.debug(f"Version {version_major}.{version_minor}.{version_patch}. Received service type: {service_type}")

        # Determine the timeout value
        timeout_seconds = None

        if service_type == QKD_SERVICE_OPEN_CONNECT_REQUEST:
            _, _, qos_data, _ = self.parse_open_connect_payload(payload)
            client_qos = self.parse_qos(qos_data)
            timeout_milliseconds = client_qos['Timeout']
            timeout_seconds = timeout_milliseconds / 1000.0  # Convert to seconds
        else:
            key_stream_id = None
            if service_type in [QKD_SERVICE_GET_KEY_REQUEST, QKD_SERVICE_CLOSE_REQUEST]:
                key_stream_id_bytes = payload[:16]
                key_stream_id = uuid.UUID(bytes=key_stream_id_bytes)
                with self.lock:
                    client_info = self.connected_clients.get(key_stream_id)
                if client_info:
                    timeout_milliseconds = client_info['qos']['Timeout']
                    timeout_seconds = timeout_milliseconds / 1000.0
                else:
                    timeout_seconds = 5  # Default timeout
            else:
                timeout_seconds = 5  # Default timeout

        # Map service types to their corresponding handling methods
        handler_mapping = {
            QKD_SERVICE_OPEN_CONNECT_REQUEST: self.handle_open_connect_request,
            QKD_SERVICE_GET_KEY_REQUEST: self.handle_get_key_request,
            QKD_SERVICE_CLOSE_REQUEST: self.handle_close_request
        }
        handler = handler_mapping.get(service_type)
        if not handler:
            logging.error("Unknown service type received.")
            return None

        # Preprocess conn for OPEN_CONNECT_REQUEST
        if service_type == QKD_SERVICE_OPEN_CONNECT_REQUEST:
            # Extract necessary information from conn
            conn_info = {
                "peername": conn.getpeername(),  # Example: IP and port of the client
                "cipher": conn.cipher() if hasattr(conn, "cipher") else None  # SSL/TLS cipher details or None if not SSL
            }
        else:
            conn_info = None

        # Run the task in a separate process
        def task_handler(pipe_conn, payload, conn_info):
            try:
                if service_type == QKD_SERVICE_OPEN_CONNECT_REQUEST:
                    response = handler(payload, conn_info)
                else:
                    response = handler(payload)
                pipe_conn.send(response)  # Send the result back through the pipe
            except Exception as e:
                logging.error(f"Error in task handler: {e}")
            finally:
                pipe_conn.close()

        parent_conn, child_conn = multiprocessing.Pipe()
        process = multiprocessing.Process(target=task_handler, args=(child_conn, payload, conn_info))
        process.start()

        try:
            if parent_conn.poll(timeout_seconds):  # Wait for a response or timeout
                response = parent_conn.recv()
                return response
            else:
                logging.error("Operation timed out.")
                process.terminate()  # Terminate the process after timeout
                process.join()  # Ensure the process is cleaned up
                status = STATUS_TIMEOUT
                response_payload = struct.pack('!I', status)
                response_service_type = {
                    QKD_SERVICE_OPEN_CONNECT_REQUEST: QKD_SERVICE_OPEN_CONNECT_RESPONSE,
                    QKD_SERVICE_GET_KEY_REQUEST: QKD_SERVICE_GET_KEY_RESPONSE,
                    QKD_SERVICE_CLOSE_REQUEST: QKD_SERVICE_CLOSE_RESPONSE
                }.get(service_type, 0)
                return self.construct_response(response_service_type, response_payload)
        finally:
            if process.is_alive():
                process.terminate()  # Ensure the process is terminated
            process.join()  # Clean up the process

    def handle_open_connect_request(self, payload, conn_info):
        """Handle the OPEN_CONNECT_REQUEST service type from the client."""
        # Use conn_info instead of conn for logging or processing
        logging.debug(f"Connection Info: {conn_info}")

        source_uri, dest_uri, qos_data, key_stream_id_bytes = self.parse_open_connect_payload(payload)

        # Logging statements
        logging.debug(f"Source URI received by server: {source_uri}")
        logging.debug(f"Destination URI received by server: {dest_uri}")

        # Validate URIs
        if not self.validate_uri(source_uri) or not self.validate_uri(dest_uri):
            logging.error("Invalid URI format.")
            status = STATUS_NO_QKD_CONNECTION
            response_payload = struct.pack('!I', status)
            return self.construct_response(QKD_SERVICE_OPEN_CONNECT_RESPONSE, response_payload)

        # Parse QoS parameters
        client_qos = self.parse_qos(qos_data)
        logging.debug(f"QoS received by server: {client_qos}")

        # Adjust QoS parameters
        adjusted_qos, qos_not_met, not_met_params = self.adjust_qos(client_qos)
        if qos_not_met:
            logging.warning(f"QoS not met for parameters: {not_met_params}")
            status = STATUS_QOS_NOT_MET
        else:
            status = STATUS_SUCCESS

        # Handle Key_stream_ID
        key_stream_id = uuid.UUID(bytes=key_stream_id_bytes)
        if key_stream_id == uuid.UUID(int=0):
            key_stream_id = uuid.uuid4()
        else:
            with self.lock:
                if key_stream_id in self.connected_clients:
                    logging.error("Key_stream_ID is already in use.")
                    status = STATUS_KSID_IN_USE
                    response_payload = struct.pack('!I', status)
                    return self.construct_response(QKD_SERVICE_OPEN_CONNECT_RESPONSE, response_payload)

        # Store connection information
        with self.lock:
            self.connected_clients[key_stream_id] = {
                'conn_info': conn_info,
                'source': source_uri,
                'destination': dest_uri,
                'qos': adjusted_qos,
                'key_index': 0
            }

        # Prepare response
        response_payload = struct.pack('!I', status)
        response_payload += self.construct_qos(adjusted_qos)
        response_payload += key_stream_id.bytes

        logging.info(f"OPEN_CONNECT successful for Key_stream_ID: {key_stream_id}")

        return self.construct_response(QKD_SERVICE_OPEN_CONNECT_RESPONSE, response_payload)

    def handle_get_key_request(self, payload):
        """Handle the GET_KEY_REQUEST service type from the client."""
        # Parse Key_stream_ID, index, and metadata_size
        key_stream_id_bytes = payload[:16]
        index = struct.unpack('!I', payload[16:20])[0]
        metadata_size = struct.unpack('!I', payload[20:24])[0]

        key_stream_id = uuid.UUID(bytes=key_stream_id_bytes)

        # Check if Key_stream_ID exists
        with self.lock:
            client_info = self.connected_clients.get(key_stream_id)

        if not client_info:
            logging.error("Key_stream_ID not connected.")
            status = STATUS_PEER_NOT_CONNECTED_GET_KEY
            response_payload = struct.pack('!I', status)
            return self.construct_response(QKD_SERVICE_GET_KEY_RESPONSE, response_payload)

        # Read key material
        try:
            key_chunk_size = client_info['qos']['Key_chunk_size']
            start_index = index * key_chunk_size
            with open(BUFFER_PATH, "r+b") as f:
                buf = mmap.mmap(f.fileno(), BUFFER_SIZE)
                end_index = start_index + key_chunk_size
                if end_index <= BUFFER_SIZE:
                    key_material = buf[start_index:end_index]
                else:
                    key_material = buf[start_index:BUFFER_SIZE]
            if len(key_material) < key_chunk_size:
                logging.error(f'Key Length: {len(key_material)}. Chunk Size: {key_chunk_size}. Index: {start_index}')
                raise ValueError("Insufficient key material.")
            
        except ValueError as e:
            logging.error(f"Error reading key material: {e}")
            status = STATUS_INSUFFICIENT_KEY
            response_payload = struct.pack('!I', status)
            return self.construct_response(QKD_SERVICE_GET_KEY_RESPONSE, response_payload)

        # Prepare metadata
        metadata = self.generate_metadata()
        actual_metadata_size = len(metadata)

        if metadata_size < actual_metadata_size:
            status = STATUS_METADATA_SIZE_INSUFFICIENT
            response_payload = struct.pack('!I', status)
            response_payload += struct.pack('!I', actual_metadata_size)
            logging.error(f'Insufficient metadata size. Actual metadata size: {actual_metadata_size}')
            return self.construct_response(QKD_SERVICE_GET_KEY_RESPONSE, response_payload)

        # Prepare response
        status = STATUS_SUCCESS
        response_payload = struct.pack('!I', status)
        response_payload += struct.pack('!I', index)
        response_payload += struct.pack('!I', key_chunk_size)
        response_payload += key_material
        response_payload += struct.pack('!I', actual_metadata_size)
        response_payload += metadata

        if len(key_material) >= 8:
            first8 = key_material[:8].hex()
            last8 = key_material[-8:].hex()
            logging.debug(f"Key delivered by server: first 8 bytes {first8}, last 8 bytes {last8}")
        else:
            logging.debug(f"Key delivered by server is less than 8 bytes: {key_material.hex()}")

        logging.info(f"GET_KEY successful for Key_stream_ID: {key_stream_id}, Index: {index}")

        return self.construct_response(QKD_SERVICE_GET_KEY_RESPONSE, response_payload)

    def handle_close_request(self, payload):
        """Handle the CLOSE_REQUEST service type from the client."""
        key_stream_id_bytes = payload[:16]
        key_stream_id = uuid.UUID(bytes=key_stream_id_bytes)

        with self.lock:
            if key_stream_id in self.connected_clients:
                del self.connected_clients[key_stream_id]
                status = STATUS_SUCCESS
                logging.info(f"CLOSE successful for Key_stream_ID: {key_stream_id}")
            else:
                status = STATUS_PEER_NOT_CONNECTED_GET_KEY
                logging.error("Key_stream_ID not connected.")

        response_payload = struct.pack('!I', status)
        return self.construct_response(QKD_SERVICE_CLOSE_RESPONSE, response_payload)

    def construct_response(self, service_type, payload):
        """Construct the response packet with header and payload."""
        version_bytes = struct.pack('!BBB', *[int(x) for x in VERSION.split('.')])
        service_type_byte = struct.pack('!b', service_type)
        payload_length = struct.pack('!I', len(payload))
        response = version_bytes + service_type_byte + payload_length + payload
        return response

    def parse_open_connect_payload(self, payload):
        """Parse the OPEN_CONNECT_REQUEST payload into its components."""
        # Extract source and destination URIs (assumed to be null-terminated strings)
        source_end = payload.find(b'\x00')
        source_uri = payload[:source_end].decode()

        dest_start = source_end + 1
        dest_end = payload.find(b'\x00', dest_start)
        dest_uri = payload[dest_start:dest_end].decode()

        qos_data_start = dest_end + 1
        qos_data_end = qos_data_start + (QOS_FIELD_COUNT * QOS_FIELD_SIZE) + METADATA_MIMETYPE_SIZE
        qos_data = payload[qos_data_start:qos_data_end]

        key_stream_id_bytes = payload[qos_data_end:qos_data_end + 16]

        return source_uri, dest_uri, qos_data, key_stream_id_bytes

    def parse_qos(self, qos_data):
        """Parse QoS data from the payload into a dictionary."""
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

    def construct_qos(self, qos):
        """Construct the QoS bytes to include in the response."""
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

    def adjust_qos(self, client_qos):
        """Adjust client QoS parameters based on server capabilities and policies."""
        # Server's QoS capabilities or policies
        server_capabilities = {
            'Key_chunk_size': QOS_KEY_CHUNK_SIZE,       # Maximum key chunk size supported
            'Max_bps': QOS_MAX_BPS,                     # Maximum bits per second
            'Min_bps': QOS_MIN_BPS,                     # Minimum bits per second
            'Jitter': QOS_JITTER,                       # Maximum acceptable jitter
            'Priority': QOS_PRIORITY,                   # Priority level (0 is highest)
            'Timeout': QOS_TIMEOUT,                     # Maximum timeout in milliseconds
            'TTL': QOS_TTL,                             # Maximum Time-To-Live in seconds
            'Metadata_mimetype': 'application/json',    # Supported metadata mimetype
        }

        adjusted_qos = {}
        qos_not_met = False
        not_met_params = []

        # Adjust each QoS parameter and check if it can be met
        # Key_chunk_size
        if client_qos['Key_chunk_size'] > server_capabilities['Key_chunk_size']:
            qos_not_met = True
            not_met_params.append('Key_chunk_size')
            adjusted_qos['Key_chunk_size'] = server_capabilities['Key_chunk_size']
        else:
            adjusted_qos['Key_chunk_size'] = client_qos['Key_chunk_size']

        # Max_bps
        if client_qos['Max_bps'] > server_capabilities['Max_bps']:
            qos_not_met = True
            not_met_params.append('Max_bps')
            adjusted_qos['Max_bps'] = server_capabilities['Max_bps']
        else:
            adjusted_qos['Max_bps'] = client_qos['Max_bps']

        # Min_bps
        if client_qos['Min_bps'] < server_capabilities['Min_bps']:
            qos_not_met = True
            not_met_params.append('Min_bps')
            adjusted_qos['Min_bps'] = server_capabilities['Min_bps']
        else:
            adjusted_qos['Min_bps'] = client_qos['Min_bps']

        # Jitter
        if client_qos['Jitter'] < server_capabilities['Jitter']:
            qos_not_met = True
            not_met_params.append('Jitter')
            adjusted_qos['Jitter'] = server_capabilities['Jitter']
        else:
            adjusted_qos['Jitter'] = client_qos['Jitter']

        # Priority
        if client_qos['Priority'] > server_capabilities['Priority']:
            qos_not_met = True
            not_met_params.append('Priority')
            adjusted_qos['Priority'] = server_capabilities['Priority']
        else:
            adjusted_qos['Priority'] = client_qos['Priority']

        # Timeout
        if client_qos['Timeout'] > server_capabilities['Timeout']:
            qos_not_met = True
            not_met_params.append('Timeout')
            adjusted_qos['Timeout'] = server_capabilities['Timeout']
        else:
            adjusted_qos['Timeout'] = client_qos['Timeout']

        # TTL
        if client_qos['TTL'] > server_capabilities['TTL']:
            qos_not_met = True
            not_met_params.append('TTL')
            adjusted_qos['TTL'] = server_capabilities['TTL']
        else:
            adjusted_qos['TTL'] = client_qos['TTL']

        # Metadata_mimetype
        if client_qos['Metadata_mimetype'] != server_capabilities['Metadata_mimetype']:
            qos_not_met = True
            not_met_params.append('Metadata_mimetype')
            adjusted_qos['Metadata_mimetype'] = server_capabilities['Metadata_mimetype']
        else:
            adjusted_qos['Metadata_mimetype'] = client_qos['Metadata_mimetype']

        return adjusted_qos, qos_not_met, not_met_params

    def validate_uri(self, uri):
        """Validate the format of a URI."""
        try:
            result = urlparse(uri)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def generate_metadata(self):
        """Generate metadata to be sent to the client."""
        metadata_dict = {
            "age": int(time.time() * 1000),  # Time since the key was made available in milliseconds
            "hops": 0  # Assuming direct connection
        }
        metadata_str = json.dumps(metadata_dict)
        metadata_bytes = metadata_str.encode()
        return metadata_bytes


def main():
    """Main function to run the QKD server."""
    if SERVER_CERT_PEM and SERVER_CERT_KEY and CLIENT_CERT_PEM:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=SERVER_CERT_PEM, keyfile=SERVER_CERT_KEY)
        context.load_verify_locations(cafile=CLIENT_CERT_PEM)
        context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate
    else:
        context = None

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_ADDRESS, SERVER_PORT))
    server_socket.listen()

    handler = QKDServiceHandler()

    logging.info(f"Running server on {SERVER_ADDRESS}:{SERVER_PORT}")

    try:
        while True:
            conn, addr = server_socket.accept()
            if context:
                conn = context.wrap_socket(conn, server_side=True)
            threading.Thread(target=handler.handle_client, args=(conn, addr)).start()
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()

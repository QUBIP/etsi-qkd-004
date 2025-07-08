import socket
import json
import logging
import uuid
import mmap
import os

# Logging configuration
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# Constants
SERVER_IP = os.getenv('SERVER_ADDRESS', '0.0.0.0')
SERVER_PORT = int(os.getenv('SERVER_PORT', 25576))
BUFFER_SIZE = int(os.getenv('BUFFER_SIZE', 65057))
BUFFER_PATH = os.getenv("BUFFER_PATH", "/dev/shm/qkd_buffer")

class QKDServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sessions = {}

    def handle_open_connect(self, data):
        key_stream_id = str(uuid.uuid4())
        self.sessions[key_stream_id] = data["data"]["qos"]["key_chunk_size"]
        return {"status": 0, "key_stream_id": key_stream_id}

    def handle_get_key(self, data):
        key_stream_id = data["data"]["key_stream_id"]
        if key_stream_id not in self.sessions:
            return {"status": 1, "error": "Invalid key_stream_id"}
        key_chunk_size = self.sessions[key_stream_id]

        with open(BUFFER_PATH, "r+b") as f:
            buf = mmap.mmap(f.fileno(), BUFFER_SIZE)
            key_data = buf[:key_chunk_size]
        if len(key_data) < key_chunk_size:
            logging.error(f'Key Length: {len(key_data)}. Chunk Size: {key_chunk_size}.')
            raise ValueError("Insufficient key material.")

        return {"status": 0, "index": data["data"]["index"], "key_buffer": key_data.hex()}

    def handle_close(self, data):
        self.sessions.pop(data["data"]["key_stream_id"], None)
        return {"status": 0}

    def process_request(self, request, client_address):
        handlers = {
            "OPEN_CONNECT": self.handle_open_connect,
            "GET_KEY": self.handle_get_key,
            "CLOSE": self.handle_close,
        }
        try:
            data = json.loads(request)
            command = data.get("command")
            logging.info(f"Received {command} from {client_address}")
            return handlers.get(command, lambda _: {"status": 1, "error": "Unknown command"})(data)
        except json.JSONDecodeError:
            return {"status": 1, "error": "Invalid JSON format"}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            logging.info(f"Server listening on {self.host}:{self.port}")
            while True:
                client_socket, client_address = server_socket.accept()
                with client_socket:
                    while True:
                        try:
                            request = client_socket.recv(BUFFER_SIZE).decode("utf8")
                            if not request:
                                logging.info("Client closed the connection.")
                                break
                            response = self.process_request(request, client_address)
                            client_socket.sendall(json.dumps(response).encode("utf8"))
                        except ConnectionResetError:
                            logging.warning("Client disconnected unexpectedly.")
                            break
                        except Exception as e:
                            logging.error(f"Unexpected error: {e}")
                            break

if __name__ == "__main__":
    QKDServer(SERVER_IP, SERVER_PORT).start()
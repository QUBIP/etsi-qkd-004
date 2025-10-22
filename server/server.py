import socket
import json
import logging
import uuid
import mmap
import os
import re
from typing import Dict

# Logging setup
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

# Constants / environment
SERVER_IP = os.getenv('SERVER_ADDRESS', '0.0.0.0')
SERVER_PORT = int(os.getenv('SERVER_PORT', 25575))
SOCKET_SIZE = int(os.getenv('SOCKET_SIZE', 65057))
LOCAL_NODE_UUID = os.getenv('LOCAL_NODE_UUID')
LINK_BUFFER_MAP_FILE = os.getenv('LINK_BUFFER_MAP_FILE')

# Regex for UUID validation
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def load_link_map_from_file(path: str) -> Dict[str, str]:
    """Load and validate the link-to-buffer map from an external JSON file."""
    if not path:
        raise RuntimeError("LINK_BUFFER_MAP_FILE is not defined.")
    if not os.path.exists(path):
        raise RuntimeError(f"LINK_BUFFER_MAP_FILE does not exist: {path}")
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to read or parse LINK_BUFFER_MAP_FILE: {e}")

    if not isinstance(data, dict):
        raise RuntimeError("LINK_BUFFER_MAP_FILE must contain a JSON object {pair: path}")

    validated: Dict[str, str] = {}
    for k, v in data.items():
        if not isinstance(k, str) or '|' not in k:
            raise RuntimeError(f"Invalid key in LINK_BUFFER_MAP_FILE (expected 'uuidA|uuidB'): {k}")
        ua, ub = k.split('|', 1)
        if not (UUID_RE.match(ua) and UUID_RE.match(ub)):
            raise RuntimeError(f"Invalid UUIDs in key: {k}")
        a, b = sorted([ua.lower(), ub.lower()])
        if f"{a}|{b}" != k.lower():
            raise RuntimeError(f"Non-canonical pair (must be lexicographic 'a|b'): {k}")
        if not isinstance(v, str):
            raise RuntimeError(f"Invalid buffer path for {k}: must be a string")
        validated[f"{a}|{b}"] = v
    logging.info(f"LINK_BUFFER_MAP loaded with {len(validated)} entries from {path}")
    return validated

def extract_uuid_from_uri(uri: str) -> str:
    """Extract UUID from URIs like hybrid://SPI_1@<UUID>?..."""
    after_at = uri.split('@', 1)[1]
    uuid_str = after_at.split('?', 1)[0]
    return str(uuid.UUID(uuid_str))  # validates format

def canonical_pair(u1: str, u2: str) -> str:
    """Return canonical pair string 'uuidA|uuidB' in lexicographic order."""
    a, b = sorted([u1.lower(), u2.lower()])
    return f"{a}|{b}"

class QKDServer:
    def __init__(self, host, port, link_map: Dict[str, str]):
        self.host = host
        self.port = port
        self.link_map = link_map  # { "uuidA|uuidB": "/path/to/buffer" }
        self.sessions = {}  # key_stream_id -> {chunk, pair, buffer_path}

    def handle_open_connect(self, data):
        """Handle OPEN_CONNECT: establish session and associate with correct buffer."""
        try:
            src = data["data"]["source"]
            dst = data["data"]["destination"]
            key_chunk_size = int(data["data"]["qos"]["key_chunk_size"])
        except Exception:
            return {"status": 1, "error": "Malformed OPEN_CONNECT payload"}

        try:
            src_uuid = extract_uuid_from_uri(src)
            dst_uuid = extract_uuid_from_uri(dst)
        except Exception as e:
            return {"status": 1, "error": f"Invalid URI/UUID: {e}"}

        if LOCAL_NODE_UUID and LOCAL_NODE_UUID.lower() not in (src_uuid.lower(), dst_uuid.lower()):
            logging.error(f"OPEN_CONNECT rejected: LOCAL_NODE_UUID {LOCAL_NODE_UUID} not in ({src_uuid}, {dst_uuid})")
            return {"status": 1, "error": "Local node not part of requested link"}

        pair_key = canonical_pair(src_uuid, dst_uuid)
        buffer_path = self.link_map.get(pair_key)
        if not buffer_path:
            logging.error(f"Link not defined in LINK_BUFFER_MAP: {pair_key}")
            return {"status": 1, "error": f"Link not defined: {pair_key}"}
        if not os.path.exists(buffer_path):
            logging.error(f"Buffer file not found for {pair_key}: {buffer_path}")
            return {"status": 1, "error": f"Buffer not found for link {pair_key}"}

        key_stream_id = str(uuid.uuid4())
        self.sessions[key_stream_id] = {"chunk": key_chunk_size, "pair": pair_key, "buffer_path": buffer_path}
        logging.info(f"OPEN_CONNECT KSID={key_stream_id} pair={pair_key} buffer={buffer_path} chunk={key_chunk_size}")
        return {"status": 0, "key_stream_id": key_stream_id}

    def handle_get_key(self, data):
        """Handle GET_KEY: return key material from the correct buffer."""
        try:
            key_stream_id = data["data"]["key_stream_id"]
            req_index = data["data"]["index"]
        except Exception:
            return {"status": 1, "error": "Malformed GET_KEY payload"}

        logging.info(f'GET_KEY - Requesting KSID: {key_stream_id}')
        sess = self.sessions.get(key_stream_id)
        if not sess:
            return {"status": 1, "error": "Invalid key_stream_id"}

        chunk = int(sess["chunk"])
        path = sess["buffer_path"]

        try:
            with open(path, "r+b") as f:
                with mmap.mmap(f.fileno(), 0) as buf:
                    offset = req_index * chunk
                    if offset + chunk > len(buf):
                        logging.error(f"Insufficient key material at index {req_index}")
                        return {"status": 1, "error": "Insufficient key material"}
                    key_data = buf[offset:offset + chunk]
                    remaining_after = len(buf) - (offset + chunk)
                    if remaining_after > 0:
                        buf.move(offset, offset + chunk, remaining_after)
                    buf[-chunk:] = b"\x00" * chunk
                    buf.flush()
        except FileNotFoundError:
            return {"status": 1, "error": "Buffer file not found"}
        except Exception as e:
            logging.error(f"Error reading buffer {path}: {e}")
            return {"status": 1, "error": f"Buffer read error: {e}"}

        if len(key_data) < chunk:
            logging.error(f"Insufficient key material: {len(key_data)} < {chunk}")
            return {"status": 1, "error": "Insufficient key material"}
        logging.info(f"GET_KEY - Sending key data: {key_data[:16].hex()}...{key_data[-16:].hex()}")
        return {"status": 0, "index": req_index, "key_buffer": key_data.hex()}

    def handle_close(self, data):
        """Handle CLOSE: remove session."""
        try:
            key_stream_id = data["data"]["key_stream_id"]
        except Exception:
            return {"status": 1, "error": "Malformed CLOSE payload"}
        logging.info(f'CLOSE - Requesting KSID: {key_stream_id}')
        self.sessions.pop(key_stream_id, None)
        logging.info(f"CLOSE KSID={key_stream_id}")
        return {"status": 0}

    def process_request(self, request, client_address):
        """Dispatch incoming request to the correct handler."""
        handlers = {"OPEN_CONNECT": self.handle_open_connect, "GET_KEY": self.handle_get_key, "CLOSE": self.handle_close}
        try:
            data = json.loads(request)
            cmd = data.get("command")
            logging.info(f"Received {cmd} from {client_address}")
            handler = handlers.get(cmd)
            if not handler:
                return {"status": 1, "error": "Unknown command"}
            return handler(data)
        except json.JSONDecodeError:
            return {"status": 1, "error": "Invalid JSON format"}
        except Exception as e:
            logging.error(f"process_request error: {e}")
            return {"status": 1, "error": f"Internal error: {e}"}

    def start(self):
        """Start the TCP server and serve requests."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            logging.info(f"Server listening on {self.host}:{self.port}")
            while True:
                c, addr = s.accept()
                with c:
                    while True:
                        try:
                            req = c.recv(SOCKET_SIZE).decode("utf8")
                            if not req:
                                logging.info("Client closed the connection.")
                                break
                            resp = self.process_request(req, addr)
                            c.sendall(json.dumps(resp).encode("utf8"))
                        except ConnectionResetError:
                            logging.warning("Client disconnected unexpectedly.")
                            break
                        except Exception as e:
                            logging.error(f"Unexpected error: {e}")
                            break

if __name__ == "__main__":
    LINK_MAP = load_link_map_from_file(LINK_BUFFER_MAP_FILE)
    QKDServer(SERVER_IP, SERVER_PORT, LINK_MAP).start()

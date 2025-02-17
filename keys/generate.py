import os
import time
import mmap
import logging
import socket
import errno
import struct

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "5000"))
BUFFER_PATH = os.getenv("BUFFER_PATH", "/dev/shm/qkd_buffer")
SKR = int(os.getenv("SKR", "1000"))
MODE = os.getenv("MODE", "sender")  # "sender" or "receiver"
HOST = os.getenv("HOST", "localhost")  # For sender: receiver's address; for receiver: interface to bind
PORT = int(os.getenv("PORT", "5000"))

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            break
        data += packet
    return data

def simulate_qkd(current_index):
    if MODE == "sender":
        while True:
            key_chunk = os.urandom(SKR)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((HOST, PORT))
                # Pack the current index as a 4-byte header (network byte order)
                header = struct.pack("!I", current_index)
                message = header + key_chunk
                s.sendall(message)
                # Wait for the receiver's acknowledgement
                ack = s.recv(1024)
                if ack == b'ACK':
                    logging.debug("Sender received ACK")
                    s.close()
                    return key_chunk, current_index
                else:
                    logging.error("Sender did not receive ACK")
            except socket.error as e:
                if e.errno == errno.ECONNREFUSED:
                    pass
                else:
                    logging.error(f"Sender error: {e}")
            finally:
                s.close()
            time.sleep(0.1)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", PORT))
        s.listen(1)
        conn, addr = s.accept()
        logging.debug(f"Receiver connected from {addr}")
        # First receive the 4-byte header containing the sender's current index.
        header = recvall(conn, 4)
        if len(header) < 4:
            logging.error("Receiver did not get full header!")
            conn.close()
            s.close()
            return None, None
        received_index = struct.unpack("!I", header)[0]
        # Receive the key chunk
        received = b""
        while len(received) < SKR:
            packet = conn.recv(SKR - len(received))
            if not packet:
                break
            received += packet
        key_chunk = received
        try:
            conn.sendall(b'ACK')
            logging.debug("Receiver sent ACK")
        except socket.error as e:
            logging.error(f"Receiver error sending ACK: {e}")
        finally:
            conn.close()
            s.close()
        return key_chunk, received_index

# Initialize the shared buffer file.
with open(BUFFER_PATH, "wb") as f:
    f.write(b'\x00' * BUFFER_SIZE)

with open(BUFFER_PATH, "r+b") as f:
    buffer = mmap.mmap(f.fileno(), BUFFER_SIZE)
    write_index = 0
    while True:
        start_time = time.time()
        # Get the key chunk and sender's index via the simulated QKD exchange.
        chunk, sent_index = simulate_qkd(write_index)
        if chunk is None:
            continue  # Skip iteration if an error occurred.
        new_index = (sent_index + SKR) % BUFFER_SIZE
        if new_index < sent_index:
            buffer[sent_index:] = chunk[:BUFFER_SIZE - sent_index]
            buffer[:new_index] = chunk[BUFFER_SIZE - sent_index:]
        else:
            buffer[sent_index:new_index] = chunk

        write_index = new_index
        logging.info(f"Generated Key at {sent_index}:{(sent_index + SKR - 1) % BUFFER_SIZE}")
        
        elapsed = time.time() - start_time
        sleep_time = max(0, 1 - elapsed)
        time.sleep(sleep_time)

import os
import time
import mmap
import logging

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')

BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "5000"))
BUFFER_PATH = os.getenv("BUFFER_PATH", "/dev/shm/qkd_buffer")
SKR = int(os.getenv("SKR", "1000"))

with open(BUFFER_PATH, "wb") as f:
    f.write(b'\x00' * BUFFER_SIZE)

with open(BUFFER_PATH, "r+b") as f:
    buffer = mmap.mmap(f.fileno(), BUFFER_SIZE)
    write_index = 0
    while True:
        chunk = os.urandom(SKR)
        end_index = (write_index + SKR) % BUFFER_SIZE
        if end_index < write_index:
            buffer[write_index:] = chunk[:BUFFER_SIZE - write_index]
            buffer[:end_index] = chunk[BUFFER_SIZE - write_index:]
        else:
            buffer[write_index:end_index] = chunk

        write_index = end_index
        block_start = (write_index - SKR) % BUFFER_SIZE
        block_end = (block_start + SKR - 1) % BUFFER_SIZE
        logging.info(f"Generated Key at {block_start}:{block_end}")
        time.sleep(1)

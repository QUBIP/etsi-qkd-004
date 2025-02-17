import os
import mmap

BUFFER_SIZE = int(os.getenv("BUFFER_SIZE", "5000"))
READ_LENGTH = int(os.getenv("READ_LENGTH", "10000"))
START_INDEX = int(os.getenv("START_INDEX", "1000"))
BUFFER_PATH = os.getenv("BUFFER_PATH", "/dev/shm/qkd_buffer")

def read_buffer(start_index, length):
    with open(BUFFER_PATH, "r+b") as f:
        buf = mmap.mmap(f.fileno(), BUFFER_SIZE)
        end_index = start_index + length
        if end_index <= BUFFER_SIZE:
            data = buf[start_index:end_index]
        else:
            data = buf[start_index:BUFFER_SIZE]
        return data

def main():
    data = read_buffer(START_INDEX, READ_LENGTH)
    print(f"Read data (length {len(data)}): {data.hex()[:50]}...")

if __name__ == "__main__":
    main()

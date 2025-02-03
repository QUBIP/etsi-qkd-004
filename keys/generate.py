import os
import numpy as np

def generate_random_key(filename, size_bytes):
    """Generate a random key and save it to a file using numpy."""
    # Generate random bytes using numpy
    random_bytes = np.random.bytes(size_bytes)
    
    # Write the random bytes to a file
    with open(filename, 'wb') as f:
        f.write(random_bytes)
    print(f"Random key saved to {filename}")

if __name__ == "__main__":
    key_size = int(os.getenv("KEY_SIZE", 1048576))  # Default to 1MB (1048576 bytes) if KEY_SIZE is not set
    key_filename = os.getenv("QKD_KEY_FILE", "random_key.bin")  # Default filename if not provided
    generate_random_key(key_filename, key_size)  # Generate the random key

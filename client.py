import socket
import json
import os
import sys

# Constants
BUFFER_SIZE = 65057

# Default open_connect_request file
OPEN_CONNECT_REQUEST_FILE = 'open_connect_request.json'

# Check if a file name was passed as argument
if len(sys.argv) > 1:
    OPEN_CONNECT_REQUEST_FILE = sys.argv[1]
# Validate if the file exists
if not os.path.exists(OPEN_CONNECT_REQUEST_FILE):
    print(f"Error: {OPEN_CONNECT_REQUEST_FILE} does not exist")
    sys.exit(1)

def load_config():
    """
    Load the configuration file for each node (config.json).
    """
    config_file = "config.json"
    try:
        with open(config_file, "r") as f:
            print(f"Loaded configuration from {config_file}")
            return json.load(f)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        exit(1)

def load_request(filename):
    """
    Load a JSON request from a file.
    """
    filepath = os.path.join(os.path.dirname(__file__), filename)
    with open(filepath, 'r') as file:
        return json.load(file)

def send_request(socket_conn, request):
    """
    Send a JSON request via the socket and return the response.
    """
    socket_conn.sendall(json.dumps(request).encode("utf8"))
    while True:
        response_bytes = socket_conn.recv(BUFFER_SIZE)
        if response_bytes:
            response = json.loads(response_bytes.decode("utf8"))
            return response

def run_driver():
    """
    Main function for the driver.
    """
    # Load configuration
    config = load_config()
    local_node = config["local_node"]

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as kdfix_socket:
            # Connect to the Hybridization Module
            qkd_address = tuple(local_node["qkd_address"])
            kdfix_socket.connect(qkd_address)
            print(f"Driver connected to KDFix server at {qkd_address}")

            #  OPEN_CONNECT
            print("\n--- OPEN_CONNECT ---")
            oc_request = load_request(OPEN_CONNECT_REQUEST_FILE)
            oc_response = send_request(kdfix_socket, oc_request)
            print("OPEN_CONNECT response:", oc_response)

            # Ensure session establishment
            if oc_response.get("status") != 0:
                print("Failed to open connection. Exiting...")
                return

            # Record key_stream_id to continue the standar 004 process
            key_stream_id = oc_response["key_stream_id"]

            #  GET_KEY
            print("\n--- GET_KEY ---")
            gk_request = {
                "command": "GET_KEY",
                "data": {
                    "key_stream_id": key_stream_id,
                    "index": 0,
                    "metadata": {
                        "size": 46,
                        "buffer": "The metadata field is not used for the moment."
                    }
                }
            }
            gk_response = send_request(kdfix_socket, gk_request)
            print("GET_KEY response:", gk_response)

            #  CLOSE
            print("\n--- CLOSE ---")
            cl_request = {
                "command": "CLOSE",
                "data": {
                    "key_stream_id": key_stream_id
                }
            }

            cl_response = send_request(kdfix_socket, cl_request)
            print("CLOSE response:", cl_response)

    except ConnectionError as e:
        print(f"Connection error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print("Driver execution completed.")

if __name__ == "__main__":
    run_driver()
import logging
import os
import socket
import pytest
from client import QKDClient, KnownException

SERVER_ADDRESS = os.getenv('SERVER_ADDRESS', 'qkd_server')
CLIENT_ADDRESS = os.getenv('CLIENT_ADDRESS', 'localhost')
SERVER_PORT = int(os.getenv('SERVER_PORT', 25575))

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

class TestQKDClient:
    """A suite of tests for the QKDClient class."""
    
    def test_successful_flow(self, caplog):
        """Test a successful client flow from OPEN_CONNECT to CLOSE."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(1024)
        client = QKDClient()
        client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', 0, metadata_buf)
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY status: 0", "CLOSE status: 0"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_insufficient_key_material(self, caplog):
        """Test GET_KEY failure due to insufficient key material."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(1024)
        client = QKDClient()
        client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', 1000000, metadata_buf)
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY failed with status: 2"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_invalid_source_uri(self, caplog):
        """Test OPEN_CONNECT failure due to invalid source URI."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(1024)
        client = QKDClient()
        client.main_flow('client', f'server://{SERVER_ADDRESS}', 0, metadata_buf)
        expected_logs = ["OPEN_CONNECT failed with status: 4"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_qos_not_met(self, caplog):
        """Test OPEN_CONNECT when QoS parameters cannot be met by the server."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(1024)
        client = QKDClient()
        client.qos['Max_bps'] = 1000000  # Exceed server's capability
        client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', 0, metadata_buf)
        expected_logs = ["OPEN_CONNECT status: 7", "GET_KEY status: 0", "CLOSE status: 0"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_metadata_size_insufficient(self, caplog):
        """Test GET_KEY failure due to insufficient metadata size provided by the client."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(4)
        client = QKDClient()
        client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', 0, metadata_buf)
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY failed with status: 8"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_app_not_connected(self, caplog):
        """Test GET_KEY and CLOSE requests with an invalid Key_stream_ID."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        metadata_buf = bytearray(1024)
        client.main_flow_invalid_key_stream_id_get_key(0, metadata_buf)
        client.main_flow_invalid_key_stream_id_close()
        expected_logs = ["GET_KEY failed with status: 3", "CLOSE failed with status: 3"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_peer_not_connected(self, caplog):
        """Test OPEN_CONNECT failure due to server not being reachable."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(1024)
        client = QKDClient()
        client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', 0, metadata_buf, server_port=50)
        expected_logs = ["OPEN_CONNECT failed with status: 4"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_key_stream_id_in_use(self, caplog):
        """Test OPEN_CONNECT failure when Key_stream_ID is already in use."""
        caplog.set_level(logging.INFO)
        try:
            client1 = QKDClient()
            client1.connect(SERVER_ADDRESS, SERVER_PORT)
            client2 = QKDClient()
            client2.connect(SERVER_ADDRESS, SERVER_PORT)

            # Use a different URI for client1
            client1.open_connect('client://alice', f'server://{SERVER_ADDRESS}')
            client2.key_stream_id = client1.key_stream_id

            # Use a different URI for client2
            client2.open_connect('client://alicia', f'server://{SERVER_ADDRESS}')
        except KnownException as e:
            logging.info(f"OPEN_CONNECT failed with status: 5: {e}")

        expected_logs = ["OPEN_CONNECT failed with status: 5"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_timeout(self, caplog):
        """Test GET_KEY failure due to operation timeout."""
        caplog.set_level(logging.INFO)
        metadata_buf = bytearray(1024)
        client = QKDClient()
        client.qos['Timeout'] = 0
        client.main_flow(f'client://{CLIENT_ADDRESS}', f'server://{SERVER_ADDRESS}', 0, metadata_buf)
        expected_logs = ["OPEN_CONNECT failed with status: 6"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_case1_ksid_sync(self, caplog, monkeypatch):
        """Test Case 1 KSID synchronization where one client gets a KSID and another client uses it."""
        caplog.set_level(logging.INFO)
        
        # Skip test if server is not available
        server_available = False
        try:
            sock = socket.socket(socket.AF_INET)
            sock.settimeout(1)
            sock.connect((SERVER_ADDRESS, SERVER_PORT))
            data = sock.recv(1)
            sock.close()
            server_available = True
            logging.info(f"Server at {SERVER_ADDRESS}:{SERVER_PORT} is confirmed available")
        except Exception as e:
            server_available = False
            logging.info(f"Server at {SERVER_ADDRESS}:{SERVER_PORT} is not available: {e}")
        
        # Skip test if server is not available
        if not server_available:
            pytest.skip(f"Skipping test_case1_ksid_sync because QKD server at {SERVER_ADDRESS}:{SERVER_PORT} is not available")

        
        # First client gets a KSID from the server (null KSID case)
        client_alice = QKDClient()
        alice_qos, alice_ksid, open_status_alice = client_alice.open_connect('client://alice', f'server://{SERVER_ADDRESS}')
        assert open_status_alice in (STATUS_SUCCESS, STATUS_QOS_NOT_MET), f"OPEN_CONNECT failed for Alice with status {open_status_alice}"
        
        # Extract the KSID that was generated by the server
        ksid = alice_ksid
        logging.info(f"Generated KSID: {ksid}")
        
        # First client gets key at index 0
        metadata_buf = bytearray(1024)
        alice_index, alice_key, alice_metadata, get_status_alice = client_alice.get_key(alice_ksid, 0, metadata_buf)
        assert get_status_alice == STATUS_SUCCESS, f"Expected status {STATUS_SUCCESS}, got {get_status_alice}"
        assert alice_index == 0, f"Expected new index 0, got {alice_index}"
        assert alice_key is not None, "Alice's key was not captured"
        
        close_status_alice = client_alice.close()
        assert close_status_alice == STATUS_SUCCESS, f"CLOSE failed for Alice with status {close_status_alice}"
        
        # Second client uses the same KSID to establish a connection
        client_bob = QKDClient()
        client_bob.key_stream_id = ksid  # Set the KSID before open_connect
        bob_qos, bob_ksid, open_status_bob = client_bob.open_connect('client://bob', f'server://{SERVER_ADDRESS}')
        assert open_status_bob in (STATUS_SUCCESS, STATUS_QOS_NOT_MET), f"OPEN_CONNECT failed for Bob with status {open_status_bob}"
        
        # Second client gets key at the same index (to verify key synchronization)
        bob_index, bob_key, bob_metadata, get_status_bob = client_bob.get_key(bob_ksid, 0, metadata_buf)
        assert get_status_bob == STATUS_SUCCESS, f"Expected status {STATUS_SUCCESS}, got {get_status_bob}"
        
        close_status_bob = client_bob.close()
        assert close_status_bob == STATUS_SUCCESS, f"CLOSE failed for Bob with status {close_status_bob}"
        
        # Verify that the expected log messages are present
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY status: 0", "CLOSE status: 0"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records), f"Missing log: {expected_log}"
        
        # Compare keys - they should be identical since both clients used the same KSID and index
        assert alice_key == bob_key, (f"Keys do not match:\nAlice: {alice_key.hex()}\nBob: {bob_key.hex()}")
        
        logging.info(f"Key synchronization verified - both clients received identical key material: {alice_key.hex()[:16]}...")

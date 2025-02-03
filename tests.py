import logging
import os

os.environ["CLIENT_CERT_PEM"] = "certs/client_cert.pem"
os.environ["CLIENT_CERT_KEY"] = "certs/client_key.pem"
os.environ["SERVER_CERT_PEM"] = "certs/server_cert.pem"
os.environ["SERVER_ADDRESS"] = 'localhost'

from client.client import QKDClient, KnownException

class TestQKDClient:
    """A suite of tests for the QKDClient class."""

    def test_successful_flow(self, caplog):
        """Test a successful client flow from OPEN_CONNECT to CLOSE."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.main_flow('client://localhost', 'server://localhost', 0, 1024)
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY status: 0", "CLOSE status: 0"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_insufficient_key_material(self, caplog):
        """Test GET_KEY failure due to insufficient key material."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.main_flow('client://localhost', 'server://localhost', 1000000, 1024)
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY failed with status: 2"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_invalid_source_uri(self, caplog):
        """Test OPEN_CONNECT failure due to invalid source URI."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.main_flow('client', 'server://localhost', 0, 1024)
        expected_logs = ["OPEN_CONNECT failed with status: 4"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_qos_not_met(self, caplog):
        """Test OPEN_CONNECT when QoS parameters cannot be met by the server."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.qos['Max_bps'] = 1000000  # Exceed server's capability
        client.main_flow('client://localhost', 'server://localhost', 0, 1024)
        expected_logs = ["OPEN_CONNECT status: 7", "GET_KEY status: 0", "CLOSE status: 0"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_metadata_size_insufficient(self, caplog):
        """Test GET_KEY failure due to insufficient metadata size provided by the client."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.main_flow('client://localhost', 'server://localhost', 0, 4)
        expected_logs = ["OPEN_CONNECT status: 0", "GET_KEY failed with status: 8"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_app_not_connected(self, caplog):
        """Test GET_KEY and CLOSE requests with an invalid Key_stream_ID."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.main_flow_invalid_key_stream_id_get_key(0, 1024)
        client.main_flow_invalid_key_stream_id_close()
        expected_logs = ["GET_KEY failed with status: 3", "CLOSE failed with status: 3"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_peer_not_connected(self, caplog):
        """Test OPEN_CONNECT failure due to server not being reachable."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.main_flow('client://localhost', 'server://localhost', 0, 1024, server_port=50)
        expected_logs = ["OPEN_CONNECT failed with status: 1"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_key_stream_id_in_use(self, caplog):
        """Test OPEN_CONNECT failure when Key_stream_ID is already in use."""
        caplog.set_level(logging.INFO)
        try:
            client1 = QKDClient()
            client1.connect('localhost', 25575)
            client2 = QKDClient()
            client2.connect('localhost', 25575)
            client1.open_connect('client://localhost', 'server://localhost')
            client2.key_stream_id = client1.key_stream_id
            client2.open_connect('client://localhost', 'server://localhost')
        except KnownException:
            pass
        expected_logs = ["OPEN_CONNECT failed with status: 5"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

    def test_timeout(self, caplog):
        """Test GET_KEY failure due to operation timeout."""
        caplog.set_level(logging.INFO)
        client = QKDClient()
        client.qos['Timeout'] = 50  # Set timeout to 500 milliseconds
        client.main_flow('client://localhost', 'server://localhost', 0, 1024)
        expected_logs = ["GET_KEY failed with status: 6"]
        for expected_log in expected_logs:
            assert any(expected_log in record.message for record in caplog.records)

# Run with: pytest -s tests.py
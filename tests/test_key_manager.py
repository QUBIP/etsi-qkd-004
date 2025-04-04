import sys
import os
import uuid
import time
import logging
import pytest

# Add the project root to the path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import directly from the module
from server.key_manager.key_manager import KSIDManager

# Test file path
TEST_STATE_FILE = "/tmp/test_ksid_state.json"

@pytest.fixture
def ksid_manager():
    """Create a KSIDManager instance for testing"""
    if os.path.exists(TEST_STATE_FILE):
        os.remove(TEST_STATE_FILE)
    manager = KSIDManager(state_file_path=TEST_STATE_FILE)
    yield manager
    manager.shutdown()  # Ensure background threads exit promptly
    if os.path.exists(TEST_STATE_FILE):
        os.remove(TEST_STATE_FILE)

def test_allocate_new_ksid(ksid_manager, caplog):
    """Test case 1: Allocate a new KSID with null KSID in request"""
    caplog.set_level(logging.INFO)

    # Allocate a new KSID
    ksid, index, status = ksid_manager.allocate_ksid(
        None,
        "client://alice",
        "server://qkd_server"
    )

    # Check results
    assert status == 0, f"Expected status 0, got {status}"
    assert index == 0, f"Expected initial index 0, got {index}"
    assert isinstance(ksid, uuid.UUID), f"KSID should be a UUID object, got {type(ksid)}"

    # Check that KSID info is stored correctly
    info = ksid_manager.get_ksid_info(ksid)
    assert info is not None, "KSID info should be available"
    assert info["source_uri"] == "client://alice"
    assert info["dest_uri"] == "server://qkd_server"
    assert info["last_index"] == 0

    # Check log message
    assert any(f"Allocated new KSID: {ksid}" in record.message for record in caplog.records)

def test_reuse_existing_ksid(ksid_manager):
    """Test case 3: Use a predefined KSID"""
    # First create a KSID
    original_ksid, _, _ = ksid_manager.allocate_ksid(
        None,
        "client://alice",
        "server://qkd_server"
    )

    # Update index to simulate usage
    ksid_manager.update_index(original_ksid, 5)

    # Now try to reuse it
    reused_ksid, index, status = ksid_manager.allocate_ksid(
        original_ksid,
        "client://alice",
        "server://qkd_server"
    )

    # Check results
    assert status == 0, f"Expected status 0, got {status}"
    assert reused_ksid == original_ksid, "KSIDs should match"
    assert index == 5, f"Expected index 5, got {index}"

def test_ksid_uri_mismatch(ksid_manager):
    """Test URI mismatch case when reusing a KSID"""
    # Create KSID with specific URIs
    ksid, _, _ = ksid_manager.allocate_ksid(
        None,
        "client://alice",
        "server://qkd_server"
    )

    # Try to use with different URI
    _, _, status = ksid_manager.allocate_ksid(
        ksid,
        "client://bob",  # Different client
        "server://qkd_server"
    )

    # Should fail with status 3
    assert status == 3, f"Expected status 3 (URI mismatch), got {status}"

def test_update_and_get_index(ksid_manager):
    """Test updating and retrieving index for a KSID"""
    # Create a KSID
    ksid, _, _ = ksid_manager.allocate_ksid(
        None,
        "client://alice",
        "server://qkd_server"
    )

    # Update index
    success = ksid_manager.update_index(ksid, 10)
    assert success, "Index update should succeed"

    # Get KSID info and check index
    info = ksid_manager.get_ksid_info(ksid)
    assert info["last_index"] == 10, f"Expected index 10, got {info['last_index']}"

def test_close_ksid(ksid_manager, caplog):
    """Test closing a KSID"""
    caplog.set_level(logging.INFO)

    # Create a KSID
    ksid, _, _ = ksid_manager.allocate_ksid(
        None,
        "client://alice",
        "server://qkd_server"
    )

    # Close it
    status = ksid_manager.close_ksid(ksid)
    assert status == 0, f"Expected status 0, got {status}"

    # Verify it's gone
    info = ksid_manager.get_ksid_info(ksid)
    assert info is None, "KSID should be removed after closing"

    # Check log message
    assert any(f"Closed KSID: {ksid}" in record.message for record in caplog.records)

def test_close_nonexistent_ksid(ksid_manager):
    """Test closing a KSID that doesn't exist"""
    random_ksid = uuid.uuid4()
    status = ksid_manager.close_ksid(random_ksid)
    assert status == 1, f"Expected status 1 (not found), got {status}"

def test_ksid_expiration(ksid_manager):
    """Test KSID expiration"""
    # Create KSID with 1 second TTL
    ksid, _, _ = ksid_manager.allocate_ksid(
        None,
        "client://alice",
        "server://qkd_server",
        ttl=1  # 1 second TTL
    )

    # Wait for expiration
    time.sleep(1.5)

    # Manually run a single cleanup cycle
    ksid_manager._perform_cleanup()

    # Verify KSID is gone
    info = ksid_manager.get_ksid_info(ksid)
    assert info is None, "KSID should be expired and removed"

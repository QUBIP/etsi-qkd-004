import uuid
import json
import os
import time
import fcntl
import logging
from threading import Thread, RLock, Event

class KSIDManager:
    """
    Key Stream ID Manager for QKD systems implementing ETSI GS QKD 004 functionality.
    This is a lightweight implementation that maintains state in a shared JSON file.
    """
    def __init__(self, state_file_path="/dev/shm/ksid_state.json", shared_state=None):
        self.state_file_path = state_file_path
        self.lock = RLock()

        # If shared_state is provided, use it for multiprocessing support
        self.is_multiprocessing = shared_state is not None

        # In-memory cache to avoid excessive file operations
        if self.is_multiprocessing:
            self.ksid_cache = shared_state  # Use shared dictionary for multiprocessing
        else:
            self.ksid_cache = {}  # Use local dictionary for single process

        self.last_update_time = 0
        self.dirty = False
        self.last_persisted_time = 0
        self.persist_interval = 5

        self.ensure_state_file()

        # Start background tasks only in single-process mode
        self.shutdown_event = Event()
        self.running = True
        if not self.is_multiprocessing:
            self.persist_thread = Thread(target=self._periodic_persist, daemon=True)
            self.persist_thread.start()

            self.cleanup_thread = Thread(target=self._cleanup_expired_ksids, daemon=True)
            self.cleanup_thread.start()

        logging.info(f"KSID Manager initialized with state file: {state_file_path}")

    def __del__(self):
        """Ensure background threads are stopped when the object is deleted."""
        self.running = False
        self._persist_state_if_needed(force=True)

    def ensure_state_file(self):
        """Create the state file if it doesn't exist."""
        try:
            if not os.path.exists(self.state_file_path):
                with open(self.state_file_path, 'w') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    json.dump({
                        "ksid_map": {},
                        "last_updated": time.time()
                    }, f)
                    fcntl.flock(f, fcntl.LOCK_UN)
                logging.info(f"Created new KSID state file at {self.state_file_path}")
            else:
                # Load initial state into cache
                self._load_state_from_file()
        except Exception as e:
            logging.error(f"Error ensuring state file: {e}")
            # Create an in-memory only state if file cannot be created
            self.ksid_cache = {}
            self.last_update_time = time.time()

    def _load_state_from_file(self): 
        # TODO: KSID handling fails when the ksid_state.json is not deleted before running
        """Load state from file to cache."""
        try:
            if os.path.exists(self.state_file_path):
                with open(self.state_file_path, 'r') as f:
                    fcntl.flock(f, fcntl.LOCK_SH)
                    try:
                        state = json.load(f)
                        with self.lock:
                            self.ksid_cache = state.get("ksid_map", {})
                            self.last_update_time = time.time()
                            self.last_persisted_time = time.time()
                            self.dirty = False
                    finally:
                        fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            logging.error(f"Error loading state file: {e}")
            with self.lock:
                self.ksid_cache = {}
                self.last_update_time = time.time()

    def _persist_state_if_needed(self, force=False):
        """Persist state to file if needed."""
        if not (force or self.dirty):
            return

        try:
            state = {"ksid_map": dict(self.ksid_cache), "last_updated": time.time()}
            with open(self.state_file_path, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(state, f)
                fcntl.flock(f, fcntl.LOCK_UN)

            with self.lock:
                self.dirty = False
                self.last_persisted_time = time.time()
        except Exception as e:
            logging.error(f"Error persisting state: {e}")

    def _periodic_persist(self):
        """Background task to periodically persist state."""
        while self.running:
            try:
                self._persist_state_if_needed()
            except Exception as e:
                logging.error(f"Error in periodic persist: {e}")

            # Sleep with short intervals to allow for clean shutdown
            for _ in range(5):  # 5 x 0.2 = 1 second
                if not self.running:
                    break
                time.sleep(0.2)

    def allocate_ksid(self, requested_ksid=None, source_uri=None, dest_uri=None, ttl=7200):
        """Allocate a KSID for key synchronization and return the KSID, its initial index, and allocation status."""
        result = None

        with self.lock:
            # Prepare common entry data
            current_time = time.time()
            entry = {
                "creation_time": current_time,
                "last_accessed": current_time,
                "ttl": ttl,
                "last_index": 0,
                "source_uri": source_uri,
                "dest_uri": dest_uri
            }

            # Case 1: Generate new KSID
            if requested_ksid is None or (isinstance(requested_ksid, uuid.UUID) and requested_ksid == uuid.UUID(int=0)):
                new_ksid = uuid.uuid4()
                while str(new_ksid) in self.ksid_cache:
                    new_ksid = uuid.uuid4()

                self.ksid_cache[str(new_ksid)] = entry
                self.dirty = True
                logging.info(f"Allocated new KSID: {new_ksid}")
                result = (new_ksid, 0, 0)

            # Case 2: Use requested KSID
            else:
                ksid_str = str(requested_ksid)
                if ksid_str in self.ksid_cache:
                    existing = self.ksid_cache[ksid_str]
                    if source_uri and dest_uri and (existing["source_uri"] != source_uri or existing["dest_uri"] != dest_uri):
                        logging.error(f"KSID {requested_ksid} exists with different URIs")
                        result = (None, 0, 3)
                    else:
                        # Update access time
                        existing = dict(existing)
                        existing["last_accessed"] = current_time
                        self.ksid_cache[ksid_str] = existing
                        self.dirty = True

                        logging.info(f"Using existing KSID: {requested_ksid}, index: {existing['last_index']}")
                        result = (requested_ksid, existing["last_index"], 0)
                else:
                    # Case 3: New entry with provided KSID
                    self.ksid_cache[ksid_str] = entry
                    self.dirty = True
                    logging.info(f"Allocated requested KSID: {requested_ksid}")
                    result = (requested_ksid, 0, 0)

        # Trigger immediate persistence outside the lock for important operations
        if result and result[2] == 0:  # Status SUCCESS
            self._persist_state_if_needed(force=True)

        return result if result else (None, 0, 1)  # Default to error if no result set

    def update_index(self, ksid, new_index):
        """Update the index for a KSID."""
        with self.lock:
            ksid_str = str(ksid)
            if ksid_str in self.ksid_cache:
                # Make a copy of the entry
                entry = dict(self.ksid_cache[ksid_str])

                # Update the entry
                entry["last_index"] = new_index
                entry["last_accessed"] = time.time()
                self.ksid_cache[ksid_str] = entry

                self.dirty = True
                logging.debug(f"Updated index for KSID {ksid} to {new_index}")
                return True

            logging.error(f"KSID {ksid} not found for index update")
            return False

    def get_ksid_info(self, ksid):
        """Get information about a KSID."""
        with self.lock:
            ksid_str = str(ksid)
            if ksid_str in self.ksid_cache:
                # Create a copy of the info
                info = dict(self.ksid_cache[ksid_str])

                # Update last accessed time
                entry = dict(self.ksid_cache[ksid_str])
                entry["last_accessed"] = time.time()
                self.ksid_cache[ksid_str] = entry

                self.dirty = True
                return info

            logging.warning(f"KSID {ksid} not found in cache")
            return None

    def close_ksid(self, ksid):
        """Close a KSID and release its resources."""
        with self.lock:
            ksid_str = str(ksid)
            if ksid_str in self.ksid_cache:
                del self.ksid_cache[ksid_str]
                self.dirty = True

                logging.info(f"Closed KSID: {ksid}")
                status = 0  # Success
            else:
                logging.error(f"KSID {ksid} not found for closing")
                status = 1  # KSID not found

        # Persist outside the lock if successful
        if status == 0:
            self._persist_state_if_needed(force=True)

        return status

    def _perform_cleanup(self):
        try:
            current_time = time.time()
            with self.lock:
                expired = [ksid for ksid, entry in self.ksid_cache.items()
                        if current_time > entry["creation_time"] + entry["ttl"]]
                if expired:
                    for ksid in expired:
                        del self.ksid_cache[ksid]
                    self.dirty = True
                    logging.info(f"Cleaned up {len(expired)} expired KSIDs")
            if expired:
                self._persist_state_if_needed(force=False)
        except Exception as e:
            logging.error(f"Error in KSID cleanup task: {e}")

    def _cleanup_expired_ksids(self):
        while not self.shutdown_event.is_set():
            if self.shutdown_event.wait(timeout=60):
                break
            self._perform_cleanup()

    def shutdown(self):
        """Shutdown the KSID manager"""
        self.shutdown_event.set()
        self.running = False
        if hasattr(self, "persist_thread"):
            self.persist_thread.join(timeout=2)
        if hasattr(self, "cleanup_thread"):
            self.cleanup_thread.join(timeout=2)

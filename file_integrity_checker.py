import os
import hashlib
import json
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Default configuration
DEFAULT_CONFIG = {
    "hash_db_file": "hash_db.json",
    "log_file": "integrity_log.txt",
    "monitor_dir": "./watch_dir"
}

class FileIntegrityChecker:
    def __init__(self, config=None):
        """Initialize the file integrity checker with configuration"""
        self.config = config or DEFAULT_CONFIG
        self.hash_db = {}
        self.observer = None
        self.monitoring = False
        self.event_handler = None
        self.load_hash_db()
        
        # Create monitor directory if it doesn't exist
        os.makedirs(self.config["monitor_dir"], exist_ok=True)
        
    def calculate_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.log_event(f"Error calculating hash for {file_path}: {str(e)}")
            return None
            
    def load_hash_db(self):
        """Load hash database from file"""
        try:
            if os.path.exists(self.config["hash_db_file"]):
                with open(self.config["hash_db_file"], 'r') as f:
                    self.hash_db = json.load(f)
                self.log_event(f"Loaded hash database with {len(self.hash_db)} entries")
            else:
                self.hash_db = {}
                self.log_event("Created new hash database")
        except Exception as e:
            self.log_event(f"Error loading hash database: {str(e)}")
            self.hash_db = {}
            
    def save_hash_db(self):
        """Save hash database to file"""
        try:
            with open(self.config["hash_db_file"], 'w') as f:
                json.dump(self.hash_db, f, indent=4)
        except Exception as e:
            self.log_event(f"Error saving hash database: {str(e)}")
            
    def log_event(self, message, log_to_file=True):
        """Log an event with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        print(full_message)
        
        # Log to UI if callback is set
        if hasattr(self, 'log_callback') and self.log_callback:
            self.log_callback(full_message)
            
        # Log to file if requested
        if log_to_file:
            try:
                with open(self.config["log_file"], 'a') as f:
                    f.write(full_message + "\n")
            except Exception as e:
                print(f"Error writing to log file: {str(e)}")
                
    def initial_scan(self):
        """Perform initial scan of the monitored directory"""
        try:
            file_count = 0
            for root, _, files in os.walk(self.config["monitor_dir"]):
                for name in files:
                    full_path = os.path.join(root, name)
                    rel_path = os.path.relpath(full_path, self.config["monitor_dir"])
                    file_hash = self.calculate_hash(full_path)
                    if file_hash:
                        self.hash_db[rel_path] = file_hash
                        file_count += 1
            self.save_hash_db()
            self.log_event(f"Initial scan complete. {file_count} files indexed.")
            return file_count
        except Exception as e:
            self.log_event(f"Error during initial scan: {str(e)}")
            return 0
            
    def verify_integrity(self):
        """Verify integrity of all files in the database"""
        try:
            issues = []
            for rel_path, stored_hash in list(self.hash_db.items()):
                full_path = os.path.join(self.config["monitor_dir"], rel_path)
                if not os.path.exists(full_path):
                    issues.append(f"Missing: {rel_path}")
                    del self.hash_db[rel_path]
                else:
                    current_hash = self.calculate_hash(full_path)
                    if current_hash != stored_hash:
                        issues.append(f"Modified: {rel_path}")
                        self.hash_db[rel_path] = current_hash
                        
            self.save_hash_db()
            if issues:
                self.log_event(f"Integrity check complete. Found {len(issues)} issues.")
                return issues
            else:
                self.log_event("Integrity check complete. All files intact.")
                return []
        except Exception as e:
            self.log_event(f"Error during integrity verification: {str(e)}")
            return [f"Error: {str(e)}"]
            
    def start_monitoring(self):
        """Start monitoring the directory for changes"""
        if self.monitoring:
            self.log_event("Monitoring is already active")
            return False
            
        try:
            self.event_handler = IntegrityHandler(self)
            self.observer = Observer()
            self.observer.schedule(self.event_handler, self.config["monitor_dir"], recursive=True)
            self.observer.start()
            self.monitoring = True
            self.log_event("Monitoring started...")
            return True
        except Exception as e:
            self.log_event(f"Error starting monitoring: {str(e)}")
            return False
            
    def stop_monitoring(self):
        """Stop monitoring the directory"""
        if not self.monitoring:
            self.log_event("Monitoring is not active")
            return False
            
        try:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.log_event("Monitoring stopped.")
            self.save_hash_db()
            return True
        except Exception as e:
            self.log_event(f"Error stopping monitoring: {str(e)}")
            return False
            
    def set_log_callback(self, callback):
        """Set callback function for log events"""
        self.log_callback = callback
        
    def set_monitor_dir(self, directory):
        """Change the monitored directory"""
        was_monitoring = self.monitoring
        
        # Stop monitoring if active
        if was_monitoring:
            self.stop_monitoring()
            
        # Update config
        self.config["monitor_dir"] = directory
        os.makedirs(directory, exist_ok=True)
        self.log_event(f"Changed monitored directory to: {directory}")
        
        # Restart monitoring if it was active
        if was_monitoring:
            self.start_monitoring()
            
    def get_file_status(self):
        """Get status of all files in the database"""
        status = []
        for rel_path, stored_hash in self.hash_db.items():
            full_path = os.path.join(self.config["monitor_dir"], rel_path)
            if os.path.exists(full_path):
                current_hash = self.calculate_hash(full_path)
                if current_hash == stored_hash:
                    status.append((rel_path, "OK", stored_hash))
                else:
                    status.append((rel_path, "MODIFIED", stored_hash))
            else:
                status.append((rel_path, "MISSING", stored_hash))
        return status


class IntegrityHandler(FileSystemEventHandler):
    """Handler for file system events"""
    def __init__(self, checker):
        self.checker = checker
        
    def process(self, file_path):
        """Process a file change"""
        if not os.path.isfile(file_path):
            return
            
        rel_path = os.path.relpath(file_path, self.checker.config["monitor_dir"])
        new_hash = self.checker.calculate_hash(file_path)
        
        if not new_hash:
            return
            
        if rel_path not in self.checker.hash_db:
            self.checker.hash_db[rel_path] = new_hash
            self.checker.log_event(f"New file added: {rel_path}")
        elif self.checker.hash_db[rel_path] != new_hash:
            self.checker.log_event(f"File modified: {rel_path}")
            self.checker.hash_db[rel_path] = new_hash
            
    def on_modified(self, event):
        """Handle file modification event"""
        if not event.is_directory:
            self.process(event.src_path)
            
    def on_created(self, event):
        """Handle file creation event"""
        if not event.is_directory:
            self.process(event.src_path)
            
    def on_deleted(self, event):
        """Handle file deletion event"""
        if not event.is_directory:
            rel_path = os.path.relpath(event.src_path, self.checker.config["monitor_dir"])
            if rel_path in self.checker.hash_db:
                self.checker.log_event(f"File deleted: {rel_path}")
                del self.checker.hash_db[rel_path]

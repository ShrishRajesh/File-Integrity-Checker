import os
import hashlib
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

HASH_DB_FILE = "hash_db.json"
LOG_FILE = "integrity_log.txt"
MONITOR_DIR = "./watch_dir"  # Directory to monitor

# --------------------------------------
# Utility: Calculate SHA-256 of a file
# --------------------------------------
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

# --------------------------------------
# Load and Save Hash Database
# --------------------------------------
def load_hash_db():
    if os.path.exists(HASH_DB_FILE):
        with open(HASH_DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_hash_db(db):
    with open(HASH_DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

# --------------------------------------
# Log to file and print
# --------------------------------------
def log_event(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    with open(LOG_FILE, 'a') as f:
        f.write(full_message + "\n")

# --------------------------------------
# Integrity Check Handler
# --------------------------------------
class IntegrityHandler(FileSystemEventHandler):
    def __init__(self, hash_db):
        self.hash_db = hash_db

    def process(self, file_path):
        if not os.path.isfile(file_path):
            return
        rel_path = os.path.relpath(file_path, MONITOR_DIR)
        new_hash = calculate_hash(file_path)

        if rel_path not in self.hash_db:
            self.hash_db[rel_path] = new_hash
            log_event(f"New file added: {rel_path}")
        elif self.hash_db[rel_path] != new_hash:
            log_event(f"File modified: {rel_path}")
            self.hash_db[rel_path] = new_hash

    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            rel_path = os.path.relpath(event.src_path, MONITOR_DIR)
            if rel_path in self.hash_db:
                log_event(f"File deleted: {rel_path}")
                del self.hash_db[rel_path]

# --------------------------------------
# Initial Scan and Setup
# --------------------------------------
def initial_scan(hash_db):
    for root, _, files in os.walk(MONITOR_DIR):
        for name in files:
            full_path = os.path.join(root, name)
            rel_path = os.path.relpath(full_path, MONITOR_DIR)
            file_hash = calculate_hash(full_path)
            hash_db[rel_path] = file_hash
    save_hash_db(hash_db)
    log_event("Initial scan complete.")

# --------------------------------------
# Main Function
# --------------------------------------
def main():
    os.makedirs(MONITOR_DIR, exist_ok=True)

    hash_db = load_hash_db()
    if not hash_db:
        initial_scan(hash_db)

    event_handler = IntegrityHandler(hash_db)
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    log_event("Monitoring started...")

    try:
        while True:
            time.sleep(1)
            save_hash_db(hash_db)
    except KeyboardInterrupt:
        observer.stop()
        log_event("Monitoring stopped.")

    observer.join()

if __name__ == "__main__":
    main()

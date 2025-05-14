import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
from file_integrity_checker import FileIntegrityChecker

class FileIntegrityCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Checker")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Initialize the checker
        self.checker = FileIntegrityChecker()
        self.checker.set_log_callback(self.add_log)
        
        # Setup the UI
        self.create_ui()
        
        # Periodic save timer
        self.save_timer = None
        self.start_save_timer()
        
        # Set up closing handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def create_ui(self):
        """Create the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top control panel
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Directory selection
        dir_frame = ttk.Frame(control_frame)
        dir_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dir_frame, text="Monitored Directory:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.dir_var = tk.StringVar(value=os.path.abspath(self.checker.config["monitor_dir"]))
        dir_entry = ttk.Entry(dir_frame, textvariable=self.dir_var, width=50)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(dir_frame, text="Browse...", command=self.browse_directory)
        browse_btn.pack(side=tk.LEFT)
        
        # Buttons frame
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.scan_btn = ttk.Button(btn_frame, text="Initial Scan", command=self.run_initial_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.verify_btn = ttk.Button(btn_frame, text="Verify Integrity", command=self.verify_integrity)
        self.verify_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.monitor_var = tk.StringVar(value="Start Monitoring")
        self.monitor_btn = ttk.Button(btn_frame, textvariable=self.monitor_var, command=self.toggle_monitoring)
        self.monitor_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.refresh_btn = ttk.Button(btn_frame, text="Refresh Status", command=self.refresh_status)
        self.refresh_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Status indicator
        self.status_var = tk.StringVar(value="Ready")
        status_lbl = ttk.Label(btn_frame, textvariable=self.status_var, font=("", 10, "bold"))
        status_lbl.pack(side=tk.RIGHT)
        
        # Create notebook with tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Files tab
        files_frame = ttk.Frame(notebook, padding="10")
        notebook.add(files_frame, text="Files")
        
        # Create treeview for files
        columns = ("file", "status", "hash")
        self.tree = ttk.Treeview(files_frame, columns=columns, show="headings")
        self.tree.heading("file", text="File Path")
        self.tree.heading("status", text="Status")
        self.tree.heading("hash", text="Hash")
        self.tree.column("file", width=400)
        self.tree.column("status", width=100)
        self.tree.column("hash", width=350)
        
        # Add scrollbars to treeview
        tree_scroll_y = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set)
        
        tree_scroll_x = ttk.Scrollbar(files_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=tree_scroll_x.set)
        
        # Pack treeview and scrollbars
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Log tab
        log_frame = ttk.Frame(notebook, padding="10")
        notebook.add(log_frame, text="Log")
        
        # Create log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Status bar
        self.statusbar = ttk.Label(main_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def browse_directory(self):
        """Open directory browser dialog"""
        directory = filedialog.askdirectory(
            initialdir=self.dir_var.get(),
            title="Select Directory to Monitor"
        )
        if directory:
            self.dir_var.set(directory)
            self.checker.set_monitor_dir(directory)
            self.refresh_status()
            
    def run_initial_scan(self):
        """Run initial scan in a separate thread"""
        self.set_busy("Scanning...")
        
        def scan_thread():
            file_count = self.checker.initial_scan()
            self.root.after(0, lambda: self.scan_complete(file_count))
            
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def scan_complete(self, file_count):
        """Called when scan is complete"""
        self.set_ready()
        self.refresh_status()
        messagebox.showinfo("Scan Complete", f"Initial scan complete. {file_count} files indexed.")
        
    def verify_integrity(self):
        """Verify integrity in a separate thread"""
        self.set_busy("Verifying...")
        
        def verify_thread():
            issues = self.checker.verify_integrity()
            self.root.after(0, lambda: self.verify_complete(issues))
            
        threading.Thread(target=verify_thread, daemon=True).start()
        
    def verify_complete(self, issues):
        """Called when verification is complete"""
        self.set_ready()
        self.refresh_status()
        
        if issues:
            result = "\n".join(issues)
            messagebox.warning("Integrity Issues", 
                              f"Found {len(issues)} integrity issues:\n\n{result}")
        else:
            messagebox.showinfo("Integrity Check", "All files are intact.")
            
    def toggle_monitoring(self):
        """Toggle file monitoring"""
        if self.checker.monitoring:
            self.checker.stop_monitoring()
            self.monitor_var.set("Start Monitoring")
            self.set_ready()
        else:
            if self.checker.start_monitoring():
                self.monitor_var.set("Stop Monitoring")
                self.set_status("Monitoring")
                
    def refresh_status(self):
        """Refresh the file status display"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add current status
        status_list = self.checker.get_file_status()
        for file_path, status, file_hash in status_list:
            tag = status.lower()
            self.tree.insert("", tk.END, values=(file_path, status, file_hash), tags=(tag,))
            
        # Configure tags for coloring
        self.tree.tag_configure("ok", background="#e0ffe0")
        self.tree.tag_configure("modified", background="#fff0e0")
        self.tree.tag_configure("missing", background="#ffe0e0")
        
        # Update status bar
        self.statusbar.config(text=f"Total files: {len(status_list)}")
        
    def add_log(self, message):
        """Add message to log"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def set_busy(self, message="Busy"):
        """Set UI to busy state"""
        self.status_var.set(message)
        self.scan_btn.config(state=tk.DISABLED)
        self.verify_btn.config(state=tk.DISABLED)
        self.refresh_btn.config(state=tk.DISABLED)
        self.root.config(cursor="watch")
        self.statusbar.config(text=message)
        
    def set_ready(self):
        """Set UI to ready state"""
        self.status_var.set("Ready")
        self.scan_btn.config(state=tk.NORMAL)
        self.verify_btn.config(state=tk.NORMAL)
        self.refresh_btn.config(state=tk.NORMAL)
        self.root.config(cursor="")
        self.statusbar.config(text="Ready")
        
    def set_status(self, status):
        """Set status message"""
        self.status_var.set(status)
        self.statusbar.config(text=status)
        
    def start_save_timer(self):
        """Start periodic save timer"""
        # Save hash database every 30 seconds instead of every second
        if self.save_timer:
            self.root.after_cancel(self.save_timer)
            
        self.checker.save_hash_db()
        self.save_timer = self.root.after(30000, self.start_save_timer)
        
    def on_close(self):
        """Handle window close event"""
        if self.checker.monitoring:
            if messagebox.askyesno("Confirm Exit", 
                                  "File monitoring is active. Do you want to stop monitoring and exit?"):
                self.checker.stop_monitoring()
                self.root.destroy()
        else:
            self.checker.save_hash_db()
            self.root.destroy()

def main():
    root = tk.Tk()
    app = FileIntegrityCheckerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

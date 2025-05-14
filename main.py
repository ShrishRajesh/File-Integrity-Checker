"""
File Integrity Checker
---------------------
A tool to monitor and verify file integrity using hash values.
"""

import tkinter as tk
from file_integrity_gui import FileIntegrityCheckerGUI

def main():
    root = tk.Tk()
    app = FileIntegrityCheckerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

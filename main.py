#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Security Scanner Suite
Professional Cybersecurity Tool
Author: Alen Pepa
Version: 1.0
License: MIT
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
from gui.main_window import NetworkScannerGUI
from utils.logger import setup_logger

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    """
    Main application entry point
    """
    try:
        # Setup logging
        logger = setup_logger()
        logger.info("Starting Network Security Scanner Suite")
        
        # Create main application window
        root = tk.Tk()
        app = NetworkScannerGUI(root)
        
        # Start the GUI event loop
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror(
            "Critical Error", 
            f"Failed to start application:\n{str(e)}"
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
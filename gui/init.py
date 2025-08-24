#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Package - Network Security Scanner Suite
User Interface Components
"""

__version__ = "1.0.0"
__author__ = "Alen Pepa"

try:
    from .main_window import NetworkScannerGUI
except ImportError as e:
    print(f"Warning: Could not import GUI components: {e}")
    NetworkScannerGUI = None

__all__ = ['NetworkScannerGUI']
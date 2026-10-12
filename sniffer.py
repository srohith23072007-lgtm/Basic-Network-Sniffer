"""
Basic Network Sniffer - Root CLI Launcher
Provides a convenient command-line entry point.

Usage:
  - To run in CLI mode: python sniffer.py
  - To run the Web Dashboard: python backend/app.py
"""

import os
import sys

backend_dir = os.path.join(os.path.dirname(__file__), "captures", "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from sniffer import main

if __name__ == "__main__":
    main()

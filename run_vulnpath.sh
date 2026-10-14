#!/bin/sh
# Starts the VulnPath launcher window. Needs Python 3.9+ and the OS tkinter package
# (Debian/Ubuntu: python3-tk, RHEL/Rocky: python3-tkinter).
cd "$(dirname "$0")" && exec python3 launcher.py "$@"

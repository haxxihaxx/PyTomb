#!/bin/bash
# PyTomb Launcher Script
# Works on Linux, macOS, and Windows (via Git Bash or WSL)

echo "🪦 PyTomb - Android Crash Diagnostics Tool"
echo "=========================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    echo "Please install Python 3.7 or higher from https://www.python.org/"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Found Python $PYTHON_VERSION"

# Check if tkinter is available
python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Error: tkinter is not installed"
    echo ""
    echo "To install tkinter:"
    echo "  - Ubuntu/Debian: sudo apt-get install python3-tk"
    echo "  - Fedora: sudo dnf install python3-tkinter"
    echo "  - macOS: tkinter is usually included with Python"
    echo "  - Windows: tkinter is usually included with Python"
    exit 1
fi

echo "✓ tkinter is available"

# Check for ADB (optional)
if command -v adb &> /dev/null; then
    ADB_VERSION=$(adb version 2>&1 | grep "Version" | awk '{print $2}')
    echo "✓ ADB found (version $ADB_VERSION) - USB device pulling available!"
else
    echo "⚠️  ADB not found - USB device pulling disabled"
    echo "   Install Android SDK Platform Tools for USB features"
    echo "   (PyTomb will still work with manual log input)"
fi

echo ""
echo "Starting PyTomb..."
echo ""

# Run PyTomb
python3 pytomb.py

# Check exit status
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ PyTomb exited with an error"
    exit 1
fi

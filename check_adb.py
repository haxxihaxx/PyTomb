#!/usr/bin/env python3
"""
PyTomb ADB Setup Verification
Checks if your system is ready for USB device log pulling
"""

import subprocess
import sys
import os


def check_adb():
    """Check if ADB is installed and accessible"""
    print("=" * 60)
    print("PyTomb ADB Setup Verification")
    print("=" * 60)
    print()
    
    # Try to find ADB
    adb_locations = [
        'adb',
        '/usr/bin/adb',
        '/usr/local/bin/adb',
        os.path.expanduser('~/Android/Sdk/platform-tools/adb'),
        os.path.expanduser('~/Library/Android/sdk/platform-tools/adb'),
        'C:\\Android\\sdk\\platform-tools\\adb.exe',
    ]
    
    adb_path = None
    print("🔍 Searching for ADB...")
    
    for location in adb_locations:
        try:
            result = subprocess.run(
                [location, 'version'],
                capture_output=True,
                timeout=2,
                text=True
            )
            if result.returncode == 0:
                adb_path = location
                print(f"✅ Found ADB at: {location}")
                print(f"   Version: {result.stdout.split('Version')[1].split()[0] if 'Version' in result.stdout else 'unknown'}")
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    
    if not adb_path:
        print("❌ ADB not found!")
        print()
        print("To install ADB:")
        print()
        print("  Linux (Ubuntu/Debian):")
        print("    sudo apt-get install adb")
        print()
        print("  Linux (Fedora):")
        print("    sudo dnf install android-tools")
        print()
        print("  macOS:")
        print("    brew install android-platform-tools")
        print()
        print("  Windows:")
        print("    Download from: https://developer.android.com/tools/releases/platform-tools")
        print("    Extract and add to PATH")
        print()
        return False
    
    print()
    print("🔍 Checking for connected devices...")
    
    try:
        result = subprocess.run(
            [adb_path, 'devices'],
            capture_output=True,
            timeout=5,
            text=True
        )
        
        devices = []
        for line in result.stdout.split('\n')[1:]:
            if '\tdevice' in line:
                device_id = line.split('\t')[0].strip()
                devices.append(device_id)
        
        if devices:
            print(f"✅ Found {len(devices)} device(s):")
            for device in devices:
                print(f"   • {device}")
        else:
            print("⚠️  No devices found")
            print()
            print("To connect a device:")
            print("  1. Connect Android phone via USB")
            print("  2. Enable USB debugging:")
            print("     • Go to Settings → About Phone")
            print("     • Tap 'Build Number' 7 times")
            print("     • Go to Settings → Developer Options")
            print("     • Enable 'USB Debugging'")
            print("  3. Accept authorization dialog on phone")
            print()
            print("Then run this script again to verify.")
    
    except subprocess.TimeoutExpired:
        print("❌ ADB command timed out")
        return False
    except Exception as e:
        print(f"❌ Error checking devices: {e}")
        return False
    
    print()
    print("=" * 60)
    
    if adb_path and devices:
        print("✅ System is ready for PyTomb USB device pulling!")
    elif adb_path:
        print("⚠️  ADB is installed, but no devices connected")
        print("   Connect a device to use USB pulling features")
    else:
        print("❌ Please install ADB to use USB device features")
    
    print("=" * 60)
    print()
    
    return bool(adb_path and devices)


if __name__ == "__main__":
    success = check_adb()
    sys.exit(0 if success else 1)

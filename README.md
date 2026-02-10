# 🪦 PyTomb - Android Crash Diagnostics Tool

**Turn Android kernel chaos into clear, actionable diagnostics in seconds.**

PyTomb is a GUI application that analyzes raw Android crash data and identifies the root cause of device failures, crashes, and reboots.
<img width="998" height="730" alt="image" src="https://github.com/user-attachments/assets/c6dca80c-32f9-49da-9998-576a373b7c97" />

## Features

✅ Analyzes multiple crash log formats:
- Kernel logs (`logcat -b kernel`)
- Tombstone files (`/data/tombstones/tombstone_*`)
- pstore logs (`/sys/fs/pstore`)
- Reboot reasons
- Watchdog messages
- Thermal shutdown logs

✅ Identifies faulty hardware components:
- Storage (UFS/eMMC)
- GPU
- Modem/Baseband
- Power Management IC (PMIC)
- CPU/SoC
- Memory
- Display panel
- WiFi module

✅ Provides clear diagnostic reports:
- Human-readable crash summary
- Specific faulty component identification
- Evidence-based analysis
- Confidence scoring
- Actionable next steps

## Installation

### Prerequisites
- Python 3.7 or higher
- tkinter (usually included with Python)
- **ADB (optional, for USB device pulling)**

### Installing ADB

**Linux:**
```bash
sudo apt-get install adb  # Debian/Ubuntu
sudo dnf install android-tools  # Fedora
```

**macOS:**
```bash
brew install android-platform-tools
```

**Windows:**
1. Download Android SDK Platform Tools: https://developer.android.com/tools/releases/platform-tools
2. Extract to `C:\Android\sdk\platform-tools\`
3. Add to PATH or use from that directory

### Quick Start

1. **Clone or download** this repository

2. **Run PyTomb:**
   ```bash
   python3 pytomb.py
   ```

   Or make it executable:
   ```bash
   chmod +x pytomb.py
   ./pytomb.py
   ```

That's it! No external dependencies required.

## Usage

### Method 1: Pull Directly from Phone 
1. Connect your Android phone via USB
2. Enable USB debugging on your phone
3. Click **"Detect Device"**
4. Click **"Pull Logs from Device"**
5. Click **"ANALYZE CRASH"**

This automatically pulls:
- Kernel logs (`logcat -b kernel`)
- Kernel ring buffer (`dmesg`)
- pstore crash logs
- Tombstone files (if accessible)
- Last boot reason

### Method 2: Paste Crash Log
1. Copy your Android crash log (from `adb logcat`, tombstone file, etc.)
2. Paste into the input area
3. Click **"ANALYZE CRASH"**
4. Review the diagnostic report

### Method 2: Load from File
1. Click **"Load from File"**
2. Select your crash log file
3. Click **"ANALYZE CRASH"**

### Method 3: Try Example
1. Click **"Paste Example"** to load a sample crash
2. Click **"ANALYZE CRASH"** to see how it works

## Collecting Crash Logs from Android Device

### Option 1: Use PyTomb's Built-in Puller (Easiest!)

**PyTomb can now pull logs automatically!**

1. Connect phone via USB
2. Enable USB debugging (Settings → Developer Options → USB Debugging)
3. Click **"Detect Device"** in PyTomb
4. Click **"Pull Logs from Device"**

Done! PyTomb automatically collects kernel logs, dmesg, pstore, tombstones, and boot reason.

**Requirements:**
- ADB (Android Debug Bridge) installed
  - Usually in Android SDK Platform Tools
  - Download: https://developer.android.com/tools/releases/platform-tools

### Option 2: Using ADB Manually

```bash
# Get kernel log
adb logcat -b kernel -d > kernel.log

# Get all logs (includes crash info)
adb logcat -d > logcat.log

# Get tombstone files
adb pull /data/tombstones/

# Get pstore (if available)
adb shell cat /sys/fs/pstore/console-ramoops-0 > pstore.log
```

### Option 2: From Device Terminal

```bash
# As root
logcat -b kernel -d > /sdcard/kernel.log
dmesg > /sdcard/dmesg.log
```

### Option 3: Bug Report

```bash
adb bugreport bugreport.zip
```
Extract and look for:
- `dmesg.txt`
- `kernel.log`
- Files in `FS/data/tombstones/`

## Understanding the Output

PyTomb provides structured diagnostic reports:

```
🧠 Crash Summary
<1-2 sentence explanation of what happened>

🔧 Likely Faulty Component
<single most probable component>

📌 Evidence
- <specific keyword, error, or log pattern>
- <why this points to the component>

🎯 Confidence
<High | Medium | Low>

🛠 Recommended Action
<clear next steps for user or technician>
```

### Confidence Levels

- **High**: Strong evidence from kernel-level errors, specific hardware signatures
- **Medium**: Reasonable correlation but some ambiguity
- **Low**: Generic indicators or insufficient data

## Example Analyses

### Storage Failure
```
🧠 Crash Summary
eMMC storage reported I/O failures during read/write operations

🔧 Likely Faulty Component
eMMC internal storage

📌 Evidence
- Pattern: 'mmc0: I/O error'
- Indicates eMMC internal storage involvement
- Context: Buffer I/O error on dev mmcblk0p1...

🎯 Confidence
High

🛠 Recommended Action
Back up all data immediately. Flash storage is failing and requires replacement.
```

### Thermal Shutdown
```
🧠 Crash Summary
Device shut down due to excessive temperature

🔧 Likely Faulty Component
Thermal management / Cooling system

📌 Evidence
- Pattern: 'thermal shutdown'
- Indicates thermal management / cooling system involvement

🎯 Confidence
High

🛠 Recommended Action
Check ambient conditions. Clean dust from vents. If recurring, thermal paste 
or cooling hardware may need service.
```

## Supported Crash Patterns

| Pattern | Component | Typical Cause |
|---------|-----------|---------------|
| `Kernel panic` | CPU/Kernel | Hardware failure, corrupted system |
| `watchdog bite` | System hang | Stuck processes, driver issues |
| `mmc/ufs error` | Storage | Flash degradation, controller failure |
| `kgsl/GPU fault` | GPU | Graphics driver or hardware defect |
| `thermal shutdown` | Cooling | Overheating, thermal paste failure |
| `PMIC error` | Power IC | Battery, charging system issues |
| `modem crash` | Baseband | RF hardware, firmware problem |
| `HW reset` | SoC/Board | Critical fault, power instability |

## Troubleshooting

### USB Device Pulling Issues

**"ADB not found" in status bar**
- Install Android SDK Platform Tools
- Make sure `adb` is in your system PATH
- Restart PyTomb after installing ADB
- Verify by running `adb version` in terminal

**"No devices found" when detecting**
- Check USB cable is properly connected
- Enable USB debugging on phone (Settings → Developer Options → USB Debugging)
- Accept the "Allow USB debugging?" authorization dialog on phone
- Try a different USB port or cable
- Run `adb devices` in terminal to verify ADB can see the device
- Some phones require selecting "Transfer files" or "MTP" mode

**"Permission denied" when accessing tombstones**
- This is normal! Tombstones require root access
- PyTomb will still pull kernel logs, dmesg, and pstore
- The kernel logs are usually sufficient for diagnosis
- For full tombstone access, you need a rooted device

**"Timeout while communicating with device"**
- Device may be frozen or unresponsive
- Try rebooting the phone
- Check if ADB is working: `adb shell ls`
- Some phones have slower ADB connections - this is normal

**"Pull failed" errors**
- Make sure USB debugging is enabled AND authorized
- Check if you can run `adb logcat` manually from terminal
- Try: `adb kill-server` then `adb start-server`
- On Linux, you may need udev rules for your device

### Analysis Issues

### "No recognizable crash pattern"
- Ensure you're pasting actual crash data (not regular app logs)
- Include kernel-level logs (`logcat -b kernel`)
- Check if log is complete (not truncated)

### "Indeterminate" component
- Provide more context (earlier/later log entries)
- Combine multiple log sources (kernel + tombstone + pstore)

### GUI doesn't start
- Verify Python 3.7+ is installed: `python3 --version`
- Check tkinter is available: `python3 -c "import tkinter"`
- On Linux: `sudo apt-get install python3-tk`

## Contributing

Crash pattern not recognized? Found a bug?

1. Save your crash log as a test case
2. Note the expected diagnosis
3. Submit an issue with the log sample

## Privacy Note

PyTomb runs **completely offline**. No data is transmitted anywhere. All analysis happens locally on your machine.

## License

MIT License - Free to use, modify, and distribute.

## Disclaimer

PyTomb is a diagnostic tool. Always verify findings with professional hardware testing when making critical repair decisions.

---

**Made with ❤️ for Android forensic analysis**




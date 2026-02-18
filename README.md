# 🪦 PyTomb v2.0 — Android Crash Diagnostics Tool
PyTomb is a standalone GUI application that pulls crash logs directly from connected Android devices and identifies the root cause of failures, crashes, and reboots.
---
<img width="1076" height="890" alt="Screenshot 2026-02-18 191309" src="https://github.com/user-attachments/assets/b1cf61dc-148e-4f4b-b901-b9fc51e70012" />

---

## ✨ What's New in v2.0

- 📱 **Direct USB log pulling** from connected Android devices
- 🔋 **Battery health, level & temperature** retrieved automatically
- 📊 **Device info shown first** (model, Android version, build, security patch)
- 🧠 **40+ crash patterns** covering signals, memory, threads, JNI, libraries & hardware
- ⚖️ **Smart severity system** — minor issues (WiFi crash, broken pipe) don't mark device as unhealthy
- 🏃 **Fully threaded UI** — no freezing during ADB operations
- 📦 **ADB bundled in .exe** — users don't need to install ADB separately
- 🔄 **Auto ADB server startup** — works out of the box on first launch

---

## 🚀 Quick Start

### For End Users (Windows .exe)

1. Download `PyTomb.exe`
2. Double-click to run — no installation required
3. Connect your Android phone via USB
4. Enable **USB Debugging** on the phone *(Settings → Developer Options → USB Debugging)*
5. Click **Detect Device** → **Pull Logs from Device** → **ANALYZE CRASH**

> ADB is bundled inside the .exe. No separate installation needed.

### For Developers (Python Script)

```bash
python3 pytomb.py
```

**Requirements:** Python 3.7+, tkinter (included with Python)

---

## 📱 How to Use

### Method 1: Pull Directly from Device (Recommended)

1. Connect Android phone via USB
2. Click **"Detect Device"**
3. Accept the *"Allow USB debugging?"* dialog on your phone
4. Click **"Pull Logs from Device"** — PyTomb retrieves:
   - Kernel log (`logcat -b kernel`)
   - Kernel ring buffer (`dmesg`)
   - pstore crash data
   - Tombstone files (if accessible)
   - Last boot reason
   - Battery health, level & temperature
   - Device model, Android version, build info
5. Click **"ANALYZE CRASH"**

### Method 2: Paste or Load a Log File

1. Paste a crash log into the input area, or click **"Load from File"**
2. Click **"ANALYZE CRASH"**

---

## 📋 Output Format

When a device is connected via USB, results look like this:

```
❌ Device Status: CRITICAL ISSUE DETECTED

==================================================
📱 DEVICE INFORMATION
==================================================

🔹 Device: Google Pixel 7 Pro
🔹 Android: 13 (API 33)
🔹 Build: TQ3A.230805.001
🔹 Security Patch: 2024-01-05

🔋 Battery Health: 🟢 95% (Good)
🔋 Battery Level: 🔋 82%
🌡️  Battery Temp: 🌡️ 31.2°C (Normal)

==================================================

🧠 Crash Summary
Segmentation fault - invalid memory access detected

🔧 Likely Faulty Component
Memory subsystem (SIGSEGV)

📌 Evidence
- Pattern: 'signal 11 (SIGSEGV)'
- Indicates memory subsystem (sigsegv) involvement
- Context: signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0...

🎯 Confidence
High

⚖️ Severity
Critical

🛠 Recommended Action
Critical memory error: null pointer dereference, accessing freed memory,
or buffer overflow. Check native code for memory bugs. May indicate
faulty RAM if persistent.
```

### Health Status Icons

| Icon | Status | Meaning |
|------|--------|---------|
| ❌ | CRITICAL | System-breaking issue — requires attention |
| ⚠️ | HEALTHY (warnings) | Minor issue — device still functional |
| ℹ️ | HEALTHY | No fault detected or informational only |

---

## 🧠 Crash Pattern Coverage (40+ Patterns)

### Signal Errors
| Signal | Number | Description |
|--------|--------|-------------|
| SIGSEGV | 11 | Segmentation fault — invalid memory access |
| SIGABRT | 6 | Abort — failed assertion or runtime error |
| SIGILL | 4 | Illegal instruction — wrong CPU architecture |
| SIGFPE | 8 | Arithmetic error — division by zero |
| SIGBUS | 7 | Bus error — misaligned memory access |
| SIGTRAP | 5 | Breakpoint trap — debug assertion |
| SIGSTKFLT | 16 | Stack fault — stack overflow |
| SIGPIPE | 13 | Broken pipe — normal network behavior (INFO) |

### Memory Errors
- Heap corruption, double free, use-after-free
- Buffer overflow (stack canary, FORTIFY)
- Out of memory (OOM)

### Thread & Sync Errors
- Deadlocks, race conditions, mutex errors
- Thread stack overflow

### JNI Errors
- Invalid references, signature mismatches
- Uncaught exceptions crossing JNI boundary

### Library & Linking Errors
- Missing shared libraries (`.so` not found)
- Symbol resolution failures
- ABI incompatibility (wrong architecture)

### Hardware & Kernel Errors
- Kernel panics, watchdog timeouts
- Storage failures (UFS / eMMC)
- GPU faults, thermal shutdowns
- PMIC / power management
- Modem / baseband crashes
- Display and WiFi subsystem errors
- Filesystem corruption

---

## ⚖️ Severity Levels

PyTomb distinguishes between issues of different severity so minor events don't cause false alarms:

| Severity | Examples | Device Health |
|----------|----------|---------------|
| **Critical** | SIGSEGV, kernel panic, storage failure | ❌ Unhealthy |
| **Warning** | WiFi crash, display timeout | ✅ Healthy |
| **Info** | SIGPIPE, memory map metadata | ✅ Healthy |

---

## 🔧 ADB Troubleshooting

### "Trust" dialog appears but times out
PyTomb waits up to 60 seconds for authorization. If it still times out:
```bash
adb kill-server
adb start-server
adb devices   # Accept dialog on phone, then re-run
```
Or use the included `fix_adb_connection.py` helper.

### "No devices found"
- Check USB cable is connected and phone is unlocked
- Enable USB debugging: *Settings → Developer Options → USB Debugging*
- Try selecting **"File Transfer (MTP)"** mode on phone
- Try a different USB port or cable

### "Device not authorized"
- Look for the *"Allow USB debugging?"* dialog on your phone
- Tap **Allow**, optionally check *"Always allow from this computer"*
- Then click **Detect Device** again in PyTomb

### "ADB not found" (script mode only)
Install Android SDK Platform Tools and ensure `adb` is in your PATH. The `.exe` version has ADB bundled and doesn't need this.

### "Permission denied" on tombstones
Normal — tombstones require root access. PyTomb falls back to kernel logs and dmesg, which are usually sufficient for diagnosis.

## 🛠 Collecting Logs Manually

If you prefer to collect logs manually before pasting:

```bash
# Kernel log
adb logcat -b kernel -d > kernel.log

# Kernel ring buffer
adb shell dmesg > dmesg.log

# All logs
adb logcat -d > logcat.log

# Tombstone files
adb pull /data/tombstones/

# pstore (previous boot crash data)
adb shell cat /sys/fs/pstore/console-ramoops-0 > pstore.log

# Bug report (everything)
adb bugreport bugreport.zip
```

---

## 🔒 Privacy

PyTomb runs **completely offline**. No data is sent anywhere. All analysis is done locally on your machine.

---

## 📄 License

MIT License — free to use, modify, and distribute.

Bundled ADB binaries are from the Android SDK Platform Tools and are licensed under the Apache License 2.0.

---

## ⚠️ Disclaimer

PyTomb is a diagnostic aid. Always verify findings with professional hardware testing before making critical repair decisions.

---

*Made with 🔧 for Android forensic analysis and device repair*

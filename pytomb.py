#!/usr/bin/env python3
"""
PyTomb - Android Crash Diagnostics Tool
Analyzes kernel logs, tombstones, and crash data to identify root causes
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import re
import subprocess
import tempfile
import os
from dataclasses import dataclass
from typing import List, Tuple, Optional
from enum import Enum
from pathlib import Path


class Confidence(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class DiagnosticResult:
    summary: str
    component: str
    evidence: List[str]
    confidence: Confidence
    action: str


class ADBHandler:
    """Handles ADB communication with Android devices"""
    
    def __init__(self):
        self.adb_path = self._find_adb()
    
    def _find_adb(self) -> Optional[str]:
        """Locate ADB executable"""
        # Try common locations
        adb_locations = [
            'adb',  # In PATH
            '/usr/bin/adb',
            '/usr/local/bin/adb',
            os.path.expanduser('~/Android/Sdk/platform-tools/adb'),
            os.path.expanduser('~/Library/Android/sdk/platform-tools/adb'),
            'C:\\Android\\sdk\\platform-tools\\adb.exe',
            'C:\\Program Files (x86)\\Android\\android-sdk\\platform-tools\\adb.exe',
        ]
        
        for location in adb_locations:
            try:
                result = subprocess.run(
                    [location, 'version'],
                    capture_output=True,
                    timeout=2,
                    text=True
                )
                if result.returncode == 0:
                    return location
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        return None
    
    def is_available(self) -> bool:
        """Check if ADB is available"""
        return self.adb_path is not None
    
    def get_devices(self) -> List[str]:
        """Get list of connected devices"""
        if not self.adb_path:
            return []
        
        try:
            result = subprocess.run(
                [self.adb_path, 'devices'],
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode != 0:
                return []
            
            # Parse output
            devices = []
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if '\tdevice' in line:
                    device_id = line.split('\t')[0].strip()
                    devices.append(device_id)
            
            return devices
        except (subprocess.TimeoutExpired, Exception):
            return []
    
    def pull_crash_logs(self, device_id: Optional[str] = None, progress_callback=None) -> str:
        """Pull all crash-related logs from device"""
        if not self.adb_path:
            raise RuntimeError("ADB not available")
        
        device_args = ['-s', device_id] if device_id else []
        combined_log = ""
        temp_dir = tempfile.mkdtemp(prefix='pytomb_')
        
        try:
            # 1. Pull kernel log
            if progress_callback:
                progress_callback("Pulling kernel log...")
            
            result = subprocess.run(
                [self.adb_path] + device_args + ['logcat', '-b', 'kernel', '-d'],
                capture_output=True,
                timeout=30,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                combined_log += "=" * 70 + "\n"
                combined_log += "KERNEL LOG (logcat -b kernel)\n"
                combined_log += "=" * 70 + "\n"
                combined_log += result.stdout + "\n\n"
            
            # 2. Pull dmesg (kernel ring buffer)
            if progress_callback:
                progress_callback("Pulling dmesg...")
            
            result = subprocess.run(
                [self.adb_path] + device_args + ['shell', 'dmesg'],
                capture_output=True,
                timeout=30,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                combined_log += "=" * 70 + "\n"
                combined_log += "DMESG (kernel ring buffer)\n"
                combined_log += "=" * 70 + "\n"
                combined_log += result.stdout + "\n\n"
            
            # 3. Try to pull pstore
            if progress_callback:
                progress_callback("Checking pstore...")
            
            result = subprocess.run(
                [self.adb_path] + device_args + ['shell', 'ls', '/sys/fs/pstore/'],
                capture_output=True,
                timeout=10,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                pstore_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
                
                for pstore_file in pstore_files[:5]:  # Limit to 5 files
                    result = subprocess.run(
                        [self.adb_path] + device_args + ['shell', 'cat', f'/sys/fs/pstore/{pstore_file}'],
                        capture_output=True,
                        timeout=10,
                        text=True,
                        encoding='utf-8',
                        errors='ignore'
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        combined_log += "=" * 70 + "\n"
                        combined_log += f"PSTORE: {pstore_file}\n"
                        combined_log += "=" * 70 + "\n"
                        combined_log += result.stdout + "\n\n"
            
            # 4. Try to pull tombstones (requires root or adb debugging)
            if progress_callback:
                progress_callback("Checking tombstones...")
            
            result = subprocess.run(
                [self.adb_path] + device_args + ['shell', 'ls', '/data/tombstones/'],
                capture_output=True,
                timeout=10,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                tombstone_files = [f.strip() for f in result.stdout.split('\n') 
                                 if f.strip() and 'tombstone' in f.lower()]
                
                # Get most recent tombstones (up to 3)
                for tombstone in sorted(tombstone_files, reverse=True)[:3]:
                    result = subprocess.run(
                        [self.adb_path] + device_args + ['shell', 'cat', f'/data/tombstones/{tombstone}'],
                        capture_output=True,
                        timeout=15,
                        text=True,
                        encoding='utf-8',
                        errors='ignore'
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        combined_log += "=" * 70 + "\n"
                        combined_log += f"TOMBSTONE: {tombstone}\n"
                        combined_log += "=" * 70 + "\n"
                        combined_log += result.stdout + "\n\n"
            
            # 5. Get last reboot reason
            if progress_callback:
                progress_callback("Getting reboot reason...")
            
            result = subprocess.run(
                [self.adb_path] + device_args + ['shell', 'getprop', 'sys.boot.reason'],
                capture_output=True,
                timeout=5,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                combined_log += "=" * 70 + "\n"
                combined_log += "LAST BOOT REASON\n"
                combined_log += "=" * 70 + "\n"
                combined_log += f"sys.boot.reason: {result.stdout.strip()}\n\n"
            
            if progress_callback:
                progress_callback("Done!")
            
            return combined_log if combined_log.strip() else "No crash data found on device"
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Timeout while communicating with device")
        except Exception as e:
            raise RuntimeError(f"Failed to pull logs: {str(e)}")
        finally:
            # Cleanup temp directory
            try:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
            except:
                pass


class CrashPattern:
    """Represents a crash pattern with regex and diagnostic info"""
    def __init__(self, pattern: str, component: str, summary_template: str, 
                 action: str, confidence: Confidence, flags=0):
        self.regex = re.compile(pattern, flags)
        self.component = component
        self.summary_template = summary_template
        self.action = action
        self.confidence = confidence


class AndroidCrashAnalyzer:
    """Core analysis engine for Android crash logs"""
    
    def __init__(self):
        self.patterns = self._init_patterns()
    
    def _init_patterns(self) -> List[CrashPattern]:
        """Initialize crash pattern database"""
        return [
            # Kernel panics
            CrashPattern(
                r"Kernel panic|kernel BUG at|Unable to handle kernel",
                "CPU / Kernel subsystem",
                "Critical kernel panic detected - system encountered unrecoverable error",
                "Device requires professional diagnosis. Likely hardware failure or corrupted system partition.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # Watchdog
            CrashPattern(
                r"watchdog.*bite|watchdog.*bark|watchdog.*lockup|apps.*watchdog|Watchdog timer expired|soft lockup|hard lockup",
                "System hang (CPU or driver)",
                "Watchdog timer triggered - system stopped responding",
                "Check for stuck processes or driver issues. May indicate CPU instability or infinite loops in system services.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # Storage errors - UFS
            CrashPattern(
                r"ufs.*error|ufs.*timeout|ufshcd.*abort|UFS.*Device reset|ufs.*command.*timeout",
                "UFS internal storage",
                "UFS storage controller reported access failures",
                "Back up all data immediately. Storage hardware degradation detected - repair or replacement needed.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # Storage errors - eMMC
            CrashPattern(
                r"mmc.*error|mmc.*timeout|mmcblk.*I/O error|mmc.*crc|mmc.*CRC",
                "eMMC internal storage",
                "eMMC storage reported I/O failures during read/write operations",
                "Back up all data immediately. Flash storage is failing and requires replacement.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # Generic I/O errors
            CrashPattern(
                r"I/O error.*mmcblk|I/O error.*sda|blk_update_request.*error",
                "Internal storage (block device)",
                "Block device I/O failures detected in kernel",
                "Storage subsystem is failing. Back up data and prepare for hardware service.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            
            # GPU faults
            CrashPattern(
                r"kgsl.*fault|GPU fault|adreno.*crash|GPU page fault|mali.*fault",
                "GPU (Graphics Processing Unit)",
                "GPU encountered page fault or rendering error",
                "Possible GPU driver issue or hardware defect. Check for overheating. May require system update or RMA.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # Thermal shutdowns
            CrashPattern(
                r"thermal.*shutdown|thermal.*emergency|thermal.*critical|temperature.*exceeded|THERMAL.*RESET",
                "Thermal management / Cooling system",
                "Device shut down due to excessive temperature",
                "Check ambient conditions. Clean dust from vents. If recurring, thermal paste or cooling hardware may need service.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # Power management
            CrashPattern(
                r"PMIC.*error|power.*reset|PMIC.*fault|pmic.*pon|PON.*reason|spmi.*pmic",
                "PMIC (Power Management IC)",
                "Power management IC reported reset or fault condition",
                "Check battery health and charging system. PMIC fault may indicate battery or power delivery issues.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            
            # Modem/baseband
            CrashPattern(
                r"modem.*crash|modem.*error|subsystem.*modem|ssr:.*modem|baseband.*panic|RIL.*crash|FAILED.*modem",
                "Cellular modem / Baseband",
                "Modem subsystem crashed or became unresponsive",
                "May be RF hardware fault, SIM issue, or baseband firmware problem. Check SIM card and carrier signal.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            
            # SoC reset
            CrashPattern(
                r"HW reset|hardware reset|SoC reset|subsystem.*restart|Restarting system|qcom.*restart",
                "SoC / Logic board",
                "System-on-chip initiated hardware reset",
                "Indicates critical system fault. Check for overheating, power instability, or board-level defect.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            
            # Memory errors
            CrashPattern(
                r"Out of memory|OOM|alloc.*failed.*order|page allocation failure|lowmemorykiller",
                "RAM / Memory management",
                "System ran out of available memory",
                "Close background apps. If persistent, device may have insufficient RAM or memory leak in app/service.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            
            # Display/panel
            CrashPattern(
                r"dsi.*error|dsi.*timeout|panel.*error|mdss.*underrun|display.*timeout",
                "Display panel / DSI controller",
                "Display subsystem communication error",
                "Check for physical damage to screen. May indicate loose connector or panel failure.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            
            # WiFi subsystem
            CrashPattern(
                r"wlan.*crash|wifi.*ssr|wcnss.*crash|wlan.*fatal|wlan.*fw.*assert",
                "WiFi module / Firmware",
                "WiFi subsystem crashed or firmware assertion failed",
                "Toggle WiFi off/on. If persistent, WiFi hardware or firmware may need reflashing/replacement.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            
            # Filesystem corruption
            CrashPattern(
                r"EXT4-fs error|f2fs.*error|SQUASHFS error|filesystem.*corrupt|journal.*abort",
                "Filesystem / Data partition",
                "Filesystem errors detected - possible corruption",
                "Back up data immediately. Run filesystem check (fsck) or factory reset may be required.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
        ]
    
    def analyze(self, log_text: str) -> DiagnosticResult:
        """Analyze crash log and return diagnostic result"""
        if not log_text or not log_text.strip():
            return DiagnosticResult(
                summary="No crash data provided",
                component="N/A",
                evidence=["Empty input"],
                confidence=Confidence.LOW,
                action="Please paste crash logs (kernel log, tombstone, or pstore data) to begin analysis."
            )
        
        matches = []
        log_lower = log_text.lower()
        
        # Find all matching patterns
        for pattern in self.patterns:
            match = pattern.regex.search(log_text)
            if match:
                evidence_lines = self._extract_evidence(log_text, match)
                matches.append((pattern, match, evidence_lines))
        
        if not matches:
            return self._handle_no_match(log_text)
        
        # Use highest confidence match
        best_match = max(matches, key=lambda x: self._confidence_score(x[0].confidence))
        pattern, match, evidence_lines = best_match
        
        # Build evidence list
        evidence = [
            f"Pattern: '{match.group(0)}'",
            f"Indicates {pattern.component.lower()} involvement"
        ]
        
        # Add context from surrounding lines
        if evidence_lines:
            evidence.append(f"Context: {evidence_lines[0][:100]}...")
        
        return DiagnosticResult(
            summary=pattern.summary_template,
            component=pattern.component,
            evidence=evidence,
            confidence=pattern.confidence,
            action=pattern.action
        )
    
    def _extract_evidence(self, log_text: str, match) -> List[str]:
        """Extract surrounding lines for context"""
        lines = log_text.split('\n')
        match_text = match.group(0)
        
        for i, line in enumerate(lines):
            if match_text in line:
                # Return line and next 2 lines for context
                return lines[i:min(i+3, len(lines))]
        return []
    
    def _confidence_score(self, confidence: Confidence) -> int:
        """Convert confidence to numeric score for comparison"""
        scores = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
        return scores.get(confidence, 0)
    
    def _handle_no_match(self, log_text: str) -> DiagnosticResult:
        """Handle case where no patterns matched"""
        # Check for some generic indicators
        if re.search(r"reboot|restart|crash", log_text, re.IGNORECASE):
            return DiagnosticResult(
                summary="Device reboot detected, but specific cause unclear from provided logs",
                component="Unknown - insufficient diagnostic data",
                evidence=[
                    "Generic reboot/crash keywords found",
                    "No definitive hardware signature detected"
                ],
                confidence=Confidence.LOW,
                action="Provide more complete logs (kernel log with -b kernel, full tombstone, or pstore data). Current data insufficient for diagnosis."
            )
        
        return DiagnosticResult(
            summary="No recognizable crash pattern in provided data",
            component="Indeterminate",
            evidence=["No known error signatures found in input"],
            confidence=Confidence.LOW,
            action="Verify input contains actual crash data (kernel panic, tombstone, watchdog, etc.). Check log completeness."
        )


class PyTombGUI:
    """Main GUI application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("PyTomb - Android Crash Diagnostics")
        self.root.geometry("1000x700")
        
        self.analyzer = AndroidCrashAnalyzer()
        self.adb = ADBHandler()
        self.connected_devices = []
        
        self.setup_ui()
        self.check_adb_status()
        
    def setup_ui(self):
        """Build the user interface"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="🪦 PyTomb",
            font=("Arial", 20, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Android Crash Forensics",
            font=("Arial", 10),
            bg="#2c3e50",
            fg="#95a5a6"
        )
        subtitle_label.pack(side=tk.LEFT, pady=10)
        
        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_container, text="📥 Crash Log Input", padding=10)
        
        input_toolbar = tk.Frame(input_frame)
        input_toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Left side buttons
        left_buttons = tk.Frame(input_toolbar)
        left_buttons.pack(side=tk.LEFT)
        
        ttk.Button(
            left_buttons,
            text="📁 Load from File",
            command=self.load_file
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            left_buttons,
            text="🗑️ Clear",
            command=self.clear_input
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            left_buttons,
            text="📋 Paste Example",
            command=self.load_example
        ).pack(side=tk.LEFT, padx=2)
        
        # Right side - ADB controls
        adb_frame = tk.Frame(input_toolbar)
        adb_frame.pack(side=tk.RIGHT)
        
        self.device_var = tk.StringVar()
        self.device_combo = ttk.Combobox(
            adb_frame,
            textvariable=self.device_var,
            width=25,
            state='readonly'
        )
        self.device_combo.pack(side=tk.LEFT, padx=5)
        
        self.detect_btn = ttk.Button(
            adb_frame,
            text="🔍 Detect Device",
            command=self.detect_devices
        )
        self.detect_btn.pack(side=tk.LEFT, padx=2)
        
        self.pull_btn = ttk.Button(
            adb_frame,
            text="📱 Pull Logs from Device",
            command=self.pull_logs,
            state=tk.DISABLED
        )
        self.pull_btn.pack(side=tk.LEFT, padx=2)
        
        self.input_text = scrolledtext.ScrolledText(
            input_frame,
            height=12,
            font=("Courier", 9),
            wrap=tk.WORD,
            bg="#ecf0f1"
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        main_container.add(input_frame)
        
        # Analyze button
        analyze_frame = tk.Frame(self.root)
        analyze_frame.pack(fill=tk.X, padx=10)
        
        self.analyze_btn = tk.Button(
            analyze_frame,
            text="🔍 ANALYZE CRASH",
            font=("Arial", 12, "bold"),
            bg="#27ae60",
            fg="white",
            activebackground="#229954",
            activeforeground="white",
            relief=tk.RAISED,
            bd=3,
            cursor="hand2",
            command=self.analyze_crash
        )
        self.analyze_btn.pack(pady=10, ipadx=20, ipady=10)
        
        # Output section
        output_frame = ttk.LabelFrame(main_container, text="📊 Diagnostic Report", padding=10)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=15,
            font=("Consolas", 10),
            wrap=tk.WORD,
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white"
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        main_container.add(output_frame)
        
        # Status bar
        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg="#ecf0f1",
            font=("Arial", 9)
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def load_file(self):
        """Load crash log from file"""
        filename = filedialog.askopenfilename(
            title="Select Crash Log",
            filetypes=[
                ("Log files", "*.log *.txt"),
                ("Tombstone files", "tombstone_*"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(1.0, content)
                self.status_bar.config(text=f"Loaded: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
    
    def clear_input(self):
        """Clear input text"""
        self.input_text.delete(1.0, tk.END)
        self.status_bar.config(text="Input cleared")
    
    def load_example(self):
        """Load example crash log"""
        example = """[  142.857291] mmc0: Timeout waiting for hardware interrupt.
[  142.857342] mmc0: sdhci: ============ SDHCI REGISTER DUMP ===========
[  142.857398] mmc0: I/O error, dev mmcblk0, sector 524288
[  142.857451] Buffer I/O error on dev mmcblk0p1, logical block 65536
[  142.857505] EXT4-fs error (device mmcblk0p1): ext4_find_entry:1455: inode #2: comm init: reading directory lblock 0
[  142.857898] Aborting journal on device mmcblk0p1-8.
[  143.102847] EXT4-fs (mmcblk0p1): Remounting filesystem read-only
[  143.358291] Kernel panic - not syncing: VFS: Unable to mount root fs"""
        
        self.input_text.delete(1.0, tk.END)
        self.input_text.insert(1.0, example)
        self.status_bar.config(text="Example crash log loaded")
    
    def check_adb_status(self):
        """Check if ADB is available on startup"""
        if not self.adb.is_available():
            self.status_bar.config(
                text="⚠️ ADB not found - Install Android SDK Platform Tools to pull logs from device"
            )
            self.detect_btn.config(state=tk.DISABLED)
            self.device_combo.set("ADB not available")
        else:
            self.status_bar.config(text="Ready - ADB available")
            self.device_combo.set("No device selected")
    
    def detect_devices(self):
        """Detect connected Android devices"""
        self.status_bar.config(text="Scanning for devices...")
        self.detect_btn.config(state=tk.DISABLED)
        self.root.update()
        
        try:
            devices = self.adb.get_devices()
            
            if not devices:
                messagebox.showinfo(
                    "No Devices Found",
                    "No Android devices detected.\n\n"
                    "Make sure:\n"
                    "• Device is connected via USB\n"
                    "• USB debugging is enabled\n"
                    "• You've authorized this computer on the device"
                )
                self.status_bar.config(text="No devices found")
                self.device_combo.set("No device found")
                self.pull_btn.config(state=tk.DISABLED)
            else:
                self.connected_devices = devices
                self.device_combo['values'] = devices
                self.device_combo.current(0)
                self.pull_btn.config(state=tk.NORMAL)
                
                if len(devices) == 1:
                    self.status_bar.config(text=f"Found 1 device: {devices[0]}")
                else:
                    self.status_bar.config(text=f"Found {len(devices)} devices")
                
        except Exception as e:
            messagebox.showerror("Detection Error", f"Failed to detect devices:\n{str(e)}")
            self.status_bar.config(text="Device detection failed")
        finally:
            self.detect_btn.config(state=tk.NORMAL)
    
    def pull_logs(self):
        """Pull crash logs from selected device"""
        device_id = self.device_var.get()
        
        if not device_id or device_id == "No device selected" or device_id == "No device found":
            messagebox.showwarning("No Device", "Please detect a device first")
            return
        
        # Create progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Pulling Logs")
        progress_window.geometry("400x150")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        tk.Label(
            progress_window,
            text=f"Pulling crash logs from:\n{device_id}",
            font=("Arial", 10)
        ).pack(pady=10)
        
        progress_label = tk.Label(progress_window, text="Initializing...", font=("Arial", 9))
        progress_label.pack(pady=5)
        
        progress_bar = ttk.Progressbar(
            progress_window,
            mode='indeterminate',
            length=300
        )
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        def update_progress(message):
            progress_label.config(text=message)
            progress_window.update()
        
        def do_pull():
            try:
                logs = self.adb.pull_crash_logs(device_id, update_progress)
                
                # Update input text
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(1.0, logs)
                
                progress_window.destroy()
                
                # Show success message
                lines = logs.count('\n')
                messagebox.showinfo(
                    "Success",
                    f"Successfully pulled crash logs!\n\n"
                    f"Retrieved {lines} lines of diagnostic data.\n"
                    f"Click 'ANALYZE CRASH' to diagnose."
                )
                
                self.status_bar.config(text=f"Logs pulled from {device_id}")
                
            except Exception as e:
                progress_window.destroy()
                messagebox.showerror(
                    "Pull Failed",
                    f"Failed to pull logs from device:\n\n{str(e)}\n\n"
                    f"Make sure USB debugging is enabled and authorized."
                )
                self.status_bar.config(text="Log pull failed")
        
        # Run pull in background
        self.root.after(100, do_pull)
    
    def analyze_crash(self):
        """Perform crash analysis"""
        log_text = self.input_text.get(1.0, tk.END)
        
        if not log_text.strip():
            messagebox.showwarning("No Input", "Please paste or load crash log data first.")
            return
        
        self.status_bar.config(text="Analyzing...")
        self.analyze_btn.config(state=tk.DISABLED)
        self.root.update()
        
        try:
            result = self.analyzer.analyze(log_text)
            self.display_result(result)
            self.status_bar.config(text="Analysis complete")
        except Exception as e:
            messagebox.showerror("Analysis Error", f"An error occurred:\n{str(e)}")
            self.status_bar.config(text="Analysis failed")
        finally:
            self.analyze_btn.config(state=tk.NORMAL)
    
    def display_result(self, result: DiagnosticResult):
        """Display formatted diagnostic result"""
        output = f"""
🧠 Crash Summary
{result.summary}

🔧 Likely Faulty Component
{result.component}

📌 Evidence
"""
        for evidence_item in result.evidence:
            output += f"- {evidence_item}\n"
        
        output += f"""
🎯 Confidence
{result.confidence.value}

🛠 Recommended Action
{result.action}
"""
        
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(1.0, output)
        
        # Syntax highlighting
        self.highlight_output()
    
    def highlight_output(self):
        """Apply syntax highlighting to output"""
        self.output_text.tag_config("emoji", font=("Segoe UI Emoji", 12))
        self.output_text.tag_config("header", foreground="#61afef", font=("Consolas", 11, "bold"))
        self.output_text.tag_config("component", foreground="#e06c75", font=("Consolas", 10, "bold"))
        self.output_text.tag_config("confidence_high", foreground="#98c379")
        self.output_text.tag_config("confidence_medium", foreground="#e5c07b")
        self.output_text.tag_config("confidence_low", foreground="#e06c75")
        
        content = self.output_text.get(1.0, tk.END)
        
        # Highlight emojis and headers
        for emoji in ["🧠", "🔧", "📌", "🎯", "🛠"]:
            start = "1.0"
            while True:
                start = self.output_text.search(emoji, start, tk.END)
                if not start:
                    break
                end = f"{start}+1c"
                self.output_text.tag_add("emoji", start, end)
                start = end
        
        # Highlight confidence levels
        if "High" in content:
            start = self.output_text.search("High", "1.0", tk.END)
            if start:
                self.output_text.tag_add("confidence_high", start, f"{start}+4c")
        if "Medium" in content:
            start = self.output_text.search("Medium", "1.0", tk.END)
            if start:
                self.output_text.tag_add("confidence_medium", start, f"{start}+6c")
        if "Low" in content:
            start = self.output_text.search("Low", "1.0", tk.END)
            if start:
                self.output_text.tag_add("confidence_low", start, f"{start}+3c")


def main():
    """Application entry point"""
    root = tk.Tk()
    app = PyTombGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

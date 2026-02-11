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
import sys
import threading
import queue
import time
from dataclasses import dataclass
from typing import List, Tuple, Optional
from enum import Enum
from pathlib import Path

# Check if running as compiled exe
IS_FROZEN = getattr(sys, 'frozen', False)
if IS_FROZEN:
    # Running as compiled exe
    APPLICATION_PATH = os.path.dirname(sys.executable)
else:
    # Running as script
    APPLICATION_PATH = os.path.dirname(os.path.abspath(__file__))


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
        if self.adb_path:
            self._ensure_server_running()
    
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
        
        # If running as exe, check for bundled ADB
        if IS_FROZEN:
            bundled_adb = os.path.join(APPLICATION_PATH, 'adb.exe' if os.name == 'nt' else 'adb')
            if os.path.exists(bundled_adb):
                adb_locations.insert(0, bundled_adb)
        
        for location in adb_locations:
            try:
                result = subprocess.run(
                    [location, 'version'],
                    capture_output=True,
                    timeout=3,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' and IS_FROZEN else 0
                )
                if result.returncode == 0:
                    return location
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        return None
    
    def _ensure_server_running(self):
        """Ensure ADB server is started (critical for exe builds)"""
        if not self.adb_path:
            return
        
        try:
            # Kill any existing server
            subprocess.run(
                [self.adb_path, 'kill-server'],
                capture_output=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' and IS_FROZEN else 0
            )
            time.sleep(0.5)
            
            # Start server explicitly
            subprocess.run(
                [self.adb_path, 'start-server'],
                capture_output=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' and IS_FROZEN else 0
            )
            time.sleep(0.5)
        except:
            pass  # Fail silently, will retry on first use
    
    def is_available(self) -> bool:
        """Check if ADB is available"""
        return self.adb_path is not None
    
    def _run_adb_command(self, args: List[str], timeout: int = 10, **kwargs) -> subprocess.CompletedProcess:
        """Run ADB command with exe-friendly flags"""
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' and IS_FROZEN else 0
        return subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            text=True,
            creationflags=creation_flags,
            **kwargs
        )
    
    def get_devices(self) -> List[str]:
        """Get list of connected devices"""
        if not self.adb_path:
            return []
        
        try:
            result = self._run_adb_command(
                [self.adb_path, 'devices'],
                timeout=10
            )
            
            if result.returncode != 0:
                return []
            
            # Parse output
            devices = []
            unauthorized_devices = []
            
            for line in result.stdout.split('\n')[1:]:  # Skip header
                line = line.strip()
                if not line:
                    continue
                    
                if '\tdevice' in line:
                    device_id = line.split('\t')[0].strip()
                    devices.append(device_id)
                elif '\tunauthorized' in line:
                    device_id = line.split('\t')[0].strip()
                    unauthorized_devices.append(device_id)
            
            # If we have unauthorized devices, inform the user
            if unauthorized_devices and not devices:
                return ['UNAUTHORIZED:' + ','.join(unauthorized_devices)]
            
            return devices
        except (subprocess.TimeoutExpired, Exception):
            return []
    
    def wait_for_authorization(self, device_id: str, timeout: int = 30) -> bool:
        """Wait for device to be authorized"""
        import time
        
        if not self.adb_path:
            return False
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    [self.adb_path, 'devices'],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if device_id in line and '\tdevice' in line:
                            return True
                
                time.sleep(1)
            except:
                time.sleep(1)
        
        return False
    
    def pull_crash_logs(self, device_id: Optional[str] = None, progress_callback=None) -> str:
        """Pull all crash-related logs from device"""
        if not self.adb_path:
            raise RuntimeError("ADB not available")
        
        # Handle unauthorized devices
        if device_id and device_id.startswith('UNAUTHORIZED:'):
            raise RuntimeError("Device is not authorized. Please check your phone and accept the USB debugging authorization dialog.")
        
        device_args = ['-s', device_id] if device_id else []
        combined_log = ""
        temp_dir = tempfile.mkdtemp(prefix='pytomb_')
        
        # Longer timeouts to handle slow devices and authorization
        COMMAND_TIMEOUT = 60
        
        try:
            # Test connection first
            if progress_callback:
                progress_callback("Testing connection...")
            
            try:
                test_result = self._run_adb_command(
                    [self.adb_path] + device_args + ['shell', 'echo', 'test'],
                    timeout=15
                )
                
                if test_result.returncode != 0:
                    # Check if it's an authorization issue
                    if 'unauthorized' in test_result.stderr.lower() or 'device unauthorized' in test_result.stderr.lower():
                        raise RuntimeError(
                            "Device is not authorized.\n\n"
                            "Please check your phone for a dialog asking:\n"
                            "'Allow USB debugging?'\n\n"
                            "Tap 'Allow' or 'OK', then try again."
                        )
                    raise RuntimeError(f"Cannot communicate with device: {test_result.stderr}")
                    
            except subprocess.TimeoutExpired:
                raise RuntimeError(
                    "Connection timeout.\n\n"
                    "The device may be waiting for authorization.\n"
                    "Check your phone for 'Allow USB debugging?' dialog."
                )
            
            # 1. Pull kernel log
            if progress_callback:
                progress_callback("Pulling kernel log...")
            
            result = self._run_adb_command(
                [self.adb_path] + device_args + ['logcat', '-b', 'kernel', '-d'],
                timeout=COMMAND_TIMEOUT,
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
            
            result = self._run_adb_command(
                [self.adb_path] + device_args + ['shell', 'dmesg'],
                timeout=COMMAND_TIMEOUT,
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
            
            result = self._run_adb_command(
                [self.adb_path] + device_args + ['shell', 'ls', '/sys/fs/pstore/'],
                timeout=15,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                pstore_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
                
                for pstore_file in pstore_files[:5]:  # Limit to 5 files
                    result = self._run_adb_command(
                        [self.adb_path] + device_args + ['shell', 'cat', f'/sys/fs/pstore/{pstore_file}'],
                        timeout=15,
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
            
            result = self._run_adb_command(
                [self.adb_path] + device_args + ['shell', 'ls', '/data/tombstones/'],
                timeout=15,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout.strip():
                tombstone_files = [f.strip() for f in result.stdout.split('\n') 
                                 if f.strip() and 'tombstone' in f.lower()]
                
                # Get most recent tombstones (up to 3)
                for tombstone in sorted(tombstone_files, reverse=True)[:3]:
                    result = self._run_adb_command(
                        [self.adb_path] + device_args + ['shell', 'cat', f'/data/tombstones/{tombstone}'],
                        timeout=20,
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
            
            result = self._run_adb_command(
                [self.adb_path] + device_args + ['shell', 'getprop', 'sys.boot.reason'],
                timeout=10,
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
            raise RuntimeError(
                "Timeout while communicating with device.\n\n"
                "This can happen if:\n"
                "• Device is waiting for authorization (check your phone)\n"
                "• Device is slow to respond\n"
                "• USB connection is unstable\n\n"
                "Try: Unlock your phone and try again"
            )
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
        
        def scan_in_background():
            """Run device scan in background thread"""
            try:
                devices = self.adb.get_devices()
                # Use after() to safely update GUI from thread
                self.root.after(0, lambda: self._handle_device_scan_result(devices))
            except Exception as e:
                self.root.after(0, lambda: self._handle_device_scan_error(str(e)))
        
        # Start scan in background thread
        threading.Thread(target=scan_in_background, daemon=True).start()
    
    def _handle_device_scan_result(self, devices):
        """Handle device scan results (runs in main thread)"""
        try:
            if not devices:
                messagebox.showinfo(
                    "No Devices Found",
                    "No Android devices detected.\n\n"
                    "Make sure:\n"
                    "• Device is connected via USB\n"
                    "• USB debugging is enabled\n"
                    "• You've authorized this computer on the device\n\n"
                    "Tip: Run 'adb devices' in terminal to check connection"
                )
                self.status_bar.config(text="No devices found")
                self.device_combo.set("No device found")
                self.pull_btn.config(state=tk.DISABLED)
            elif devices[0].startswith('UNAUTHORIZED:'):
                # Device found but not authorized
                device_ids = devices[0].replace('UNAUTHORIZED:', '')
                messagebox.showwarning(
                    "Device Not Authorized",
                    f"Found device: {device_ids}\n\n"
                    "⚠️ The device is NOT authorized for USB debugging.\n\n"
                    "CHECK YOUR PHONE NOW:\n"
                    "• Look for a dialog asking 'Allow USB debugging?'\n"
                    "• Tap 'Allow' or 'OK'\n"
                    "• Check 'Always allow from this computer'\n\n"
                    "After authorizing, click 'Detect Device' again."
                )
                self.status_bar.config(text="⚠️ Device found but not authorized - check your phone!")
                self.device_combo.set(f"⚠️ {device_ids} (UNAUTHORIZED)")
                self.pull_btn.config(state=tk.DISABLED)
            else:
                self.connected_devices = devices
                self.device_combo['values'] = devices
                self.device_combo.current(0)
                self.pull_btn.config(state=tk.NORMAL)
                
                if len(devices) == 1:
                    self.status_bar.config(text=f"✓ Found 1 device: {devices[0]}")
                else:
                    self.status_bar.config(text=f"✓ Found {len(devices)} devices")
        finally:
            self.detect_btn.config(state=tk.NORMAL)
    
    def _handle_device_scan_error(self, error_msg):
        """Handle device scan errors (runs in main thread)"""
        messagebox.showerror("Detection Error", f"Failed to detect devices:\n{error_msg}")
        self.status_bar.config(text="Device detection failed")
        self.detect_btn.config(state=tk.NORMAL)
    
    def pull_logs(self):
        """Pull crash logs from selected device"""
        device_id = self.device_var.get()
        
        if not device_id or device_id == "No device selected" or device_id == "No device found":
            messagebox.showwarning("No Device", "Please detect a device first")
            return
        
        if "UNAUTHORIZED" in device_id:
            messagebox.showwarning(
                "Device Not Authorized",
                "Device is not authorized for USB debugging.\n\n"
                "CHECK YOUR PHONE:\n"
                "• Look for 'Allow USB debugging?' dialog\n"
                "• Tap 'Allow' or 'OK'\n"
                "• Check 'Always allow from this computer'\n\n"
                "After authorizing, click 'Detect Device' again."
            )
            return
        
        # Create progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Pulling Logs from Device")
        progress_window.geometry("500x200")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        tk.Label(
            progress_window,
            text=f"Pulling crash logs from:\n{device_id}",
            font=("Arial", 10, "bold")
        ).pack(pady=10)
        
        tk.Label(
            progress_window,
            text="⚠️ If a dialog appears on your phone, tap 'Allow'",
            font=("Arial", 9),
            fg="#e67e22"
        ).pack(pady=5)
        
        progress_label = tk.Label(progress_window, text="Initializing...", font=("Arial", 9))
        progress_label.pack(pady=5)
        
        progress_bar = ttk.Progressbar(
            progress_window,
            mode='indeterminate',
            length=400
        )
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        # Thread-safe queue for progress updates
        progress_queue = queue.Queue()
        
        def update_progress_from_queue():
            """Check queue and update progress label (runs in main thread)"""
            try:
                while True:
                    message = progress_queue.get_nowait()
                    progress_label.config(text=message)
            except queue.Empty:
                pass
            
            # Check again in 100ms if window still exists
            if progress_window.winfo_exists():
                progress_window.after(100, update_progress_from_queue)
        
        def progress_callback(message):
            """Thread-safe progress callback"""
            progress_queue.put(message)
        
        def pull_in_background():
            """Pull logs in background thread"""
            try:
                progress_callback("Testing connection with device...")
                logs = self.adb.pull_crash_logs(device_id, progress_callback)
                
                # Use after() to safely update GUI from thread
                self.root.after(0, lambda: self._handle_pull_success(logs, device_id, progress_window))
                
            except RuntimeError as e:
                self.root.after(0, lambda: self._handle_pull_error(str(e), progress_window, is_auth_error='not authorized' in str(e).lower()))
            except Exception as e:
                self.root.after(0, lambda: self._handle_pull_unexpected_error(str(e), progress_window))
        
        # Start queue checker and pull thread
        update_progress_from_queue()
        threading.Thread(target=pull_in_background, daemon=True).start()
    
    def _handle_pull_success(self, logs, device_id, progress_window):
        """Handle successful log pull (runs in main thread)"""
        # Update input text
        self.input_text.delete(1.0, tk.END)
        self.input_text.insert(1.0, logs)
        
        if progress_window.winfo_exists():
            progress_window.destroy()
        
        # Show success message
        lines = logs.count('\n')
        log_size_kb = len(logs) / 1024
        
        messagebox.showinfo(
            "Success! 🎉",
            f"Successfully pulled crash logs!\n\n"
            f"📊 Retrieved {lines} lines ({log_size_kb:.1f} KB)\n\n"
            f"Click 'ANALYZE CRASH' to diagnose."
        )
        
        self.status_bar.config(text=f"✓ Logs pulled from {device_id} - ready to analyze")
    
    def _handle_pull_error(self, error_msg, progress_window, is_auth_error=False):
        """Handle pull error (runs in main thread)"""
        if progress_window.winfo_exists():
            progress_window.destroy()
        
        if is_auth_error:
            response = messagebox.askretrycancel(
                "Authorization Required",
                f"{error_msg}\n\n"
                "What to do:\n"
                "1. CHECK YOUR PHONE for the authorization dialog\n"
                "2. Tap 'Allow' or 'OK'\n"
                "3. Click 'Retry' to try again\n\n"
                "Or click 'Cancel' and use 'Detect Device' again."
            )
            
            if response:  # User clicked Retry
                self.root.after(1000, self.pull_logs)
        else:
            messagebox.showerror(
                "Pull Failed",
                f"Failed to pull logs from device:\n\n{error_msg}\n\n"
                f"Troubleshooting:\n"
                f"• Make sure USB debugging is enabled\n"
                f"• Try unlocking your phone screen\n"
                f"• Try a different USB cable/port\n"
                f"• Run 'adb devices' in terminal to verify"
            )
        
        self.status_bar.config(text="⚠️ Log pull failed - see error message")
    
    def _handle_pull_unexpected_error(self, error_msg, progress_window):
        """Handle unexpected error (runs in main thread)"""
        if progress_window.winfo_exists():
            progress_window.destroy()
        
        messagebox.showerror(
            "Unexpected Error",
            f"An unexpected error occurred:\n\n{error_msg}\n\n"
            f"Try:\n"
            f"• Running 'adb kill-server' then 'adb start-server'\n"
            f"• Reconnecting the USB cable\n"
            f"• Restarting PyTomb"
        )
        self.status_bar.config(text="Error during log pull")
    
    def analyze_crash(self):
        """Perform crash analysis"""
        log_text = self.input_text.get(1.0, tk.END)
        
        if not log_text.strip():
            messagebox.showwarning("No Input", "Please paste or load crash log data first.")
            return
        
        # Create progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Analyzing Crash Data")
        progress_window.geometry("450x180")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        # Center the window
        progress_window.update_idletasks()
        x = (progress_window.winfo_screenwidth() // 2) - (450 // 2)
        y = (progress_window.winfo_screenheight() // 2) - (180 // 2)
        progress_window.geometry(f"450x180+{x}+{y}")
        
        tk.Label(
            progress_window,
            text="🧠 Analyzing Crash Data",
            font=("Arial", 12, "bold")
        ).pack(pady=15)
        
        progress_label = tk.Label(
            progress_window,
            text="Scanning for crash patterns...",
            font=("Arial", 9)
        )
        progress_label.pack(pady=5)
        
        progress_bar = ttk.Progressbar(
            progress_window,
            mode='determinate',
            length=350,
            maximum=100
        )
        progress_bar.pack(pady=10)
        
        details_label = tk.Label(
            progress_window,
            text="",
            font=("Arial", 8),
            fg="#7f8c8d"
        )
        details_label.pack(pady=5)
        
        self.analyze_btn.config(state=tk.DISABLED)
        
        def update_progress(value, message, detail=""):
            """Update progress bar and messages"""
            progress_bar['value'] = value
            progress_label.config(text=message)
            details_label.config(text=detail)
            progress_window.update()
        
        def do_analysis():
            try:
                # Step 1: Parse input
                update_progress(10, "Parsing log data...", f"{len(log_text)} characters")
                self.root.after(50)  # Small delay for visual feedback
                
                # Step 2: Initialize analyzer
                update_progress(25, "Loading crash pattern database...", "14+ patterns loaded")
                self.root.after(50)
                
                # Step 3: Scan for patterns
                update_progress(40, "Scanning for kernel errors...", "Searching crash signatures")
                self.root.after(100)
                
                # Step 4: Perform actual analysis
                update_progress(60, "Analyzing patterns...", "Matching against known faults")
                result = self.analyzer.analyze(log_text)
                self.root.after(50)
                
                # Step 5: Build diagnostic report
                update_progress(80, "Building diagnostic report...", f"Confidence: {result.confidence.value}")
                self.root.after(50)
                
                # Step 6: Format output
                update_progress(95, "Formatting results...", f"Component: {result.component}")
                self.display_result(result)
                self.root.after(50)
                
                # Step 7: Complete
                update_progress(100, "Analysis complete!", "✓ Report ready")
                self.root.after(300)
                
                progress_window.destroy()
                
                # Show completion message with result summary
                confidence_icon = {
                    "High": "🟢",
                    "Medium": "🟡",
                    "Low": "🔴"
                }.get(result.confidence.value, "⚪")
                
                self.status_bar.config(
                    text=f"✓ Analysis complete - {confidence_icon} {result.confidence.value} confidence: {result.component}"
                )
                
            except Exception as e:
                progress_window.destroy()
                messagebox.showerror("Analysis Error", f"An error occurred:\n{str(e)}")
                self.status_bar.config(text="Analysis failed")
            finally:
                self.analyze_btn.config(state=tk.NORMAL)
        
        # Start analysis after a brief moment
        self.root.after(100, do_analysis)
    
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

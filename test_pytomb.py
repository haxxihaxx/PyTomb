#!/usr/bin/env python3
"""
PyTomb Test Suite
Tests the crash analyzer with various log samples
"""

import sys
import os
import re
from dataclasses import dataclass
from typing import List
from enum import Enum

# Minimal imports to test analyzer without GUI dependencies


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
            CrashPattern(
                r"Kernel panic|kernel BUG at|Unable to handle kernel",
                "CPU / Kernel subsystem",
                "Critical kernel panic detected - system encountered unrecoverable error",
                "Device requires professional diagnosis. Likely hardware failure or corrupted system partition.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"watchdog.*bite|watchdog.*bark|watchdog.*lockup|apps.*watchdog|Watchdog timer expired|soft lockup|hard lockup",
                "System hang (CPU or driver)",
                "Watchdog timer triggered - system stopped responding",
                "Check for stuck processes or driver issues. May indicate CPU instability or infinite loops in system services.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"ufs.*error|ufs.*timeout|ufshcd.*abort|UFS.*Device reset|ufs.*command.*timeout",
                "UFS internal storage",
                "UFS storage controller reported access failures",
                "Back up all data immediately. Storage hardware degradation detected - repair or replacement needed.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"mmc.*error|mmc.*timeout|mmcblk.*I/O error|mmc.*crc|mmc.*CRC",
                "eMMC internal storage",
                "eMMC storage reported I/O failures during read/write operations",
                "Back up all data immediately. Flash storage is failing and requires replacement.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"I/O error.*mmcblk|I/O error.*sda|blk_update_request.*error",
                "Internal storage (block device)",
                "Block device I/O failures detected in kernel",
                "Storage subsystem is failing. Back up data and prepare for hardware service.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            CrashPattern(
                r"kgsl.*fault|GPU fault|adreno.*crash|GPU page fault|mali.*fault",
                "GPU (Graphics Processing Unit)",
                "GPU encountered page fault or rendering error",
                "Possible GPU driver issue or hardware defect. Check for overheating. May require system update or RMA.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"thermal.*shutdown|thermal.*emergency|thermal.*critical|temperature.*exceeded|THERMAL.*RESET",
                "Thermal management / Cooling system",
                "Device shut down due to excessive temperature",
                "Check ambient conditions. Clean dust from vents. If recurring, thermal paste or cooling hardware may need service.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"PMIC.*error|power.*reset|PMIC.*fault|pmic.*pon|PON.*reason|spmi.*pmic",
                "PMIC (Power Management IC)",
                "Power management IC reported reset or fault condition",
                "Check battery health and charging system. PMIC fault may indicate battery or power delivery issues.",
                Confidence.MEDIUM,
                re.IGNORECASE
            ),
            CrashPattern(
                r"modem.*crash|modem.*error|subsystem.*modem|ssr:.*modem|baseband.*panic|RIL.*crash|FAILED.*modem",
                "Cellular modem / Baseband",
                "Modem subsystem crashed or became unresponsive",
                "May be RF hardware fault, SIM issue, or baseband firmware problem. Check SIM card and carrier signal.",
                Confidence.HIGH,
                re.IGNORECASE
            ),
            CrashPattern(
                r"HW reset|hardware reset|SoC reset|subsystem.*restart|Restarting system|qcom.*restart",
                "SoC / Logic board",
                "System-on-chip initiated hardware reset",
                "Indicates critical system fault. Check for overheating, power instability, or board-level defect.",
                Confidence.MEDIUM,
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
                action="Please paste crash logs to begin analysis."
            )
        
        matches = []
        
        for pattern in self.patterns:
            match = pattern.regex.search(log_text)
            if match:
                evidence_lines = self._extract_evidence(log_text, match)
                matches.append((pattern, match, evidence_lines))
        
        if not matches:
            return self._handle_no_match(log_text)
        
        best_match = max(matches, key=lambda x: self._confidence_score(x[0].confidence))
        pattern, match, evidence_lines = best_match
        
        evidence = [
            f"Pattern: '{match.group(0)}'",
            f"Indicates {pattern.component.lower()} involvement"
        ]
        
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
                return lines[i:min(i+3, len(lines))]
        return []
    
    def _confidence_score(self, confidence: Confidence) -> int:
        """Convert confidence to numeric score for comparison"""
        scores = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
        return scores.get(confidence, 0)
    
    def _handle_no_match(self, log_text: str) -> DiagnosticResult:
        """Handle case where no patterns matched"""
        if re.search(r"reboot|restart|crash", log_text, re.IGNORECASE):
            return DiagnosticResult(
                summary="Device reboot detected, but specific cause unclear from provided logs",
                component="Unknown - insufficient diagnostic data",
                evidence=[
                    "Generic reboot/crash keywords found",
                    "No definitive hardware signature detected"
                ],
                confidence=Confidence.LOW,
                action="Provide more complete logs for diagnosis."
            )
        
        return DiagnosticResult(
            summary="No recognizable crash pattern in provided data",
            component="Indeterminate",
            evidence=["No known error signatures found in input"],
            confidence=Confidence.LOW,
            action="Verify input contains actual crash data."
        )


def test_analyzer():
    """Test the crash analyzer with sample logs"""
    analyzer = AndroidCrashAnalyzer()
    
    test_cases = [
        # Test 1: eMMC storage failure
        {
            "name": "eMMC Storage Failure",
            "log": """
[  142.857291] mmc0: Timeout waiting for hardware interrupt.
[  142.857398] mmc0: I/O error, dev mmcblk0, sector 524288
[  142.857451] Buffer I/O error on dev mmcblk0p1, logical block 65536
""",
            "expected_component": "eMMC internal storage",
            "expected_confidence": Confidence.HIGH
        },
        
        # Test 2: Watchdog timeout
        {
            "name": "Watchdog Timeout",
            "log": """
[  89.245678] watchdog: BUG: soft lockup - CPU#2 stuck for 23s!
[  90.123456] watchdog: hard LOCKUP - CPU#2 stuck for 26s!
""",
            "expected_component": "System hang (CPU or driver)",
            "expected_confidence": Confidence.HIGH
        },
        
        # Test 3: GPU fault
        {
            "name": "GPU Fault",
            "log": """
[  234.567890] kgsl-3d0: |kgsl_iommu_fault_handler| gpu fault ctx 3
[  234.567923] kgsl-3d0: GPU page fault: iova=12340000 flags=0x0
""",
            "expected_component": "GPU (Graphics Processing Unit)",
            "expected_confidence": Confidence.HIGH
        },
        
        # Test 4: Thermal shutdown
        {
            "name": "Thermal Shutdown",
            "log": """
[  456.789012] thermal_zone0: critical temperature reached (105000 mC), shutting down
[  456.789234] thermal shutdown: system halted due to overtemperature
""",
            "expected_component": "Thermal management / Cooling system",
            "expected_confidence": Confidence.HIGH
        },
        
        # Test 5: UFS storage error
        {
            "name": "UFS Storage Error",
            "log": """
[  67.890123] ufshcd-qcom 1d84000.ufshc: ufshcd_err_handler started
[  67.890234] ufshcd-qcom 1d84000.ufshc: UFS Device reset
""",
            "expected_component": "UFS internal storage",
            "expected_confidence": Confidence.HIGH
        },
        
        # Test 6: Modem crash
        {
            "name": "Modem Crash",
            "log": """
[  123.456789] subsys-restart: modem: subsystem_crashed with event: modem
[  123.678123] qcom-q6v5-mss: modem: fatal error received from modem software!
""",
            "expected_component": "Cellular modem / Baseband",
            "expected_confidence": Confidence.HIGH
        },
        
        # Test 7: No recognizable pattern
        {
            "name": "Unknown Pattern",
            "log": """
[  1.234567] Some random log entry
[  2.345678] Another unrelated message
""",
            "expected_component": "Indeterminate",
            "expected_confidence": Confidence.LOW
        },
        
        # Test 8: Empty input
        {
            "name": "Empty Input",
            "log": "",
            "expected_component": "N/A",
            "expected_confidence": Confidence.LOW
        }
    ]
    
    print("=" * 70)
    print("PyTomb Test Suite")
    print("=" * 70)
    print()
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(test_cases, 1):
        print(f"Test {i}: {test['name']}")
        print("-" * 70)
        
        result = analyzer.analyze(test['log'])
        
        # Check component
        component_match = test['expected_component'] in result.component
        confidence_match = result.confidence == test['expected_confidence']
        
        print(f"Expected Component: {test['expected_component']}")
        print(f"Got Component:      {result.component}")
        print(f"Component Match:    {'✓' if component_match else '✗'}")
        print()
        print(f"Expected Confidence: {test['expected_confidence'].value}")
        print(f"Got Confidence:      {result.confidence.value}")
        print(f"Confidence Match:    {'✓' if confidence_match else '✗'}")
        print()
        print(f"Summary: {result.summary[:80]}...")
        print()
        
        if component_match and confidence_match:
            print("✅ PASSED")
            passed += 1
        else:
            print("❌ FAILED")
            failed += 1
        
        print()
    
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = test_analyzer()
    sys.exit(0 if success else 1)

""" 
Pattern Engine

Layer 2 of the Cyber Defense Arsenal.

Job: take a single log line and check it against known attack patterns 
(based on OWASP Top 10 categories and MITRE ATT&CK techniques). Also 
tracks repeated failed logins per IP to flag brute force attempts.
"""

import re 
import time 
from collections import defaultdict, deque

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

SIGNATURES = [ 
    { 
        "name": "ssh_failed_login", 
        "regex": re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:.\d{1,3}){3})", re.I), 
        "severity": "low", 
        "mitre_id": "T1110", 
        "mitre_name": "Brute Force", 
        "description": "Failed SSH login attempt", 
    }, 
    { 
        "name": "ssh_successful_login_after_failures", 
        "regex": re.compile(r"Accepted password for (\S+) from (\d{1,3}(?:.\d{1,3}){3})", re.I), 
        "severity": "medium", 
        "mitre_id": "T1078", 
        "mitre_name": "Valid Accounts", 
        "description": "Successful SSH login (cross-checked against recent failures)", 
    }, 
    { 
        "name": "sql_injection", 
        "regex": re.compile(r"(\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s1|'\s--|\bdrop\b\s+\btable\b|;\s*--)", re.I), 
        "severity": "high", 
        "mitre_id": "T11190", 
        "mitre_name": "Exploit Public-Facing Application", 
        "description": "Possible SQL injection attempt", 
    }, 
    { 
        "name": "xss_attempt", 
        "regex": re.compile(r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=)", re.I), 
        "severity": "medium", 
        "mitre_id": "T1190", 
        "mitre_name": "Exploit Public-Facing Application", 
        "description": "Possible cross-site scripting (XSS) payload", 
    }, 
    { 
        "name": "path_traversal", 
        "regex": re.compile(r"(../../|..\..\|%2e%2e%2f|%2e%2e/)", re.I), 
        "severity": "high", 
        "mitre_id": "T1083", 
        "mitre_name": "File and Directory Discovery", 
        "description": "Possible directory traversal attempt", 
    }, 
    { 
        "name": "command_injection", 
        "regex": re.compile(r";\s*(rm\s+-rf|wget\s|curl\s|nc\s+-e|/bin/sh|/bin/bash)\b", re.I), 
        "severity": "critical", 
        "mitre_id": "T1059", 
        "mitre_name": "Command and Scripting Interpreter", 
        "description": "Possible OS command injection", 
    }, 
    { 
        "name": "sensitive_file_probe", 
        "regex": re.compile(r"(GET|POST)\s+/(.env|wp-config.php|.git/config|id_rsa|.ssh/)", re.I), 
        "severity": "high", 
        "mitre_id": "T1552", 
        "mitre_name": "Unsecured Credentials", 
        "description": "Probe for sensitive configuration or credential files", 
    }, 
]


class PatternEngine: 
    def __init__(self, brute_force_max_attempts=5, brute_force_window_seconds=120): 
        self.brute_force_max_attempts = brute_force_max_attempts 
        self.brute_force_window_seconds = brute_force_window_seconds 
        # ip -> deque of failure timestamps, for stateful brute-force detection 
        self._failures_by_ip = defaultdict(deque)

    def _check_brute_force(self, ip, now):
        window = self._failures_by_ip[ip]
        window.append(now)
        while window and now - window[0] > self.brute_force_window_seconds:
            window.popleft()
        return len(window) >= self.brute_force_max_attempts

    def analyze_line(self, timestamp, line):
        """Returns a list of detection dicts (usually 0 or 1, occasionally more)."""
        detections = []

        for sig in SIGNATURES:
            match = sig["regex"].search(line)
            if not match:
                continue

            detection = {
                "timestamp": timestamp,
                "pattern": sig["name"],
                "severity": sig["severity"],
                "mitre_id": sig["mitre_id"],
                "mitre_name": sig["mitre_name"],
                "description": sig["description"],
                "matched_text": match.group(0)[:200],
                "raw_line": line[:500],
                "source_ip": None,
            }

            if sig["name"] == "ssh_failed_login":
                ip = match.group(2)
                detection["source_ip"] = ip
                if self._check_brute_force(ip, time.time()):
                    detection["pattern"] = "brute_force_ssh"
                    detection["severity"] = "critical"
                    detection["description"] = (
                        f"{self.brute_force_max_attempts}+ failed SSH logins from {ip} "
                        f"within {self.brute_force_window_seconds}s — likely brute force"
                    )
            elif len(match.groups()) >= 2:
                detection["source_ip"] = match.group(2)

            detections.append(detection)

        return detections

    @staticmethod
    def meets_threshold(severity, min_severity):
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 0)

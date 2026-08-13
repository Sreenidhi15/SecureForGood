"""
event_log_scanner.py
====================
Reads the Windows Security Event Log and extracts security-relevant
findings as structured JSON using the finding_schema.

Requires: pywin32 (Windows only), run as Administrator for full log access.

Covered Event IDs:
  4625 - Failed logon attempt
  4672 - Special privileges assigned (privilege escalation)
  4719 - System audit policy changed
  4740 - Account locked out

Usage:
  python event_log_scanner.py --hours 24 --output data/findings.json
"""

import json
import argparse
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# findings_schema is in the same package
from finding_schema import Finding, FindingSource, Severity

# pywin32 is Windows-only
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    WINDOWS = True
except ImportError:
    WINDOWS = False


# ---------------------------------------------------------------------------
# Event ID configuration
# ---------------------------------------------------------------------------

EVENT_CONFIG = {
    4625: {"severity": Severity.HIGH,   "description_template": "Failed logon attempt by account '{account}' from {ip}"},
    4672: {"severity": Severity.MEDIUM, "description_template": "Special privileges assigned to '{account}' (privilege escalation)"},
    4719: {"severity": Severity.HIGH,   "description_template": "System audit policy changed by '{account}'"},
    4740: {"severity": Severity.HIGH,   "description_template": "Account '{account}' locked out from {workstation}"},
}

BRUTE_FORCE_THRESHOLD = 5   # flag if same account fails this many times


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class EventLogScanner:
    """
    Scans the Windows Security Event Log for the past N hours
    and returns a list of Finding objects.
    """

    def __init__(self, hours: int = 24):
        self.hours   = hours
        self.cutoff  = datetime.now(timezone.utc) - timedelta(hours=hours)
        self.findings: list[Finding] = []
        self._counter = defaultdict(int)   # finding_id counters per event type

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        if not WINDOWS:
            print("[WARN] pywin32 not available — running in mock mode.")
            return self._mock_findings()

        print(f"[*] Scanning Security Event Log for the past {self.hours} hours...")
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for event in events:
                self._process_event(event)

        win32evtlog.CloseEventLog(handle)
        self._detect_brute_force()
        print(f"[+] Found {len(self.findings)} security findings.")
        return self.findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_event(self, event) -> None:
        """Parse a single Windows event and append a Finding if relevant."""
        event_id = event.EventID & 0xFFFF
        if event_id not in EVENT_CONFIG:
            return

        # Convert event time to UTC-aware datetime
        event_time = event.TimeGenerated.replace(tzinfo=timezone.utc)
        if event_time < self.cutoff:
            return

        config   = EVENT_CONFIG[event_id]
        strings  = event.StringInserts or []
        raw_data = {f"field_{i}": v for i, v in enumerate(strings)}

        account     = strings[5] if len(strings) > 5 else "UNKNOWN"
        ip          = strings[19] if len(strings) > 19 else "N/A"
        workstation = strings[13] if len(strings) > 13 else "N/A"

        description = config["description_template"].format(
            account=account, ip=ip, workstation=workstation
        )

        self._counter[event_id] += 1
        finding_id = f"EVT-{event_id}-{self._counter[event_id]:03d}"

        self.findings.append(Finding(
            finding_id  = finding_id,
            source      = FindingSource.WINDOWS_EVENT_LOG,
            event_id    = event_id,
            timestamp   = event_time,
            severity    = config["severity"],
            description = description,
            raw_data    = raw_data,
        ))

    def _detect_brute_force(self) -> None:
        """
        Aggregate failed logons per account.
        If an account exceeds BRUTE_FORCE_THRESHOLD failures, add a HIGH finding.
        """
        fail_counts: dict[str, int] = defaultdict(int)
        for f in self.findings:
            if f.event_id == 4625:
                account = f.raw_data.get("field_5", "UNKNOWN")
                fail_counts[account] += 1

        for account, count in fail_counts.items():
            if count >= BRUTE_FORCE_THRESHOLD:
                self._counter[9999] += 1
                self.findings.append(Finding(
                    finding_id  = f"BF-{self._counter[9999]:03d}",
                    source      = FindingSource.WINDOWS_EVENT_LOG,
                    event_id    = None,
                    timestamp   = datetime.now(timezone.utc),
                    severity    = Severity.CRITICAL,
                    description = (
                        f"Possible brute-force attack: account '{account}' "
                        f"had {count} failed logons in the last {self.hours} hours"
                    ),
                    raw_data    = {"account": account, "failure_count": count},
                ))

    def _mock_findings(self) -> list[Finding]:
        """
        Returns realistic sample findings for testing on non-Windows systems.
        """
        now = datetime.now(timezone.utc)
        return [
            Finding(
                finding_id  = "EVT-4625-001",
                source      = FindingSource.WINDOWS_EVENT_LOG,
                event_id    = 4625,
                timestamp   = now,
                severity    = Severity.HIGH,
                description = "Failed logon attempt by account 'svc_backup' from 192.168.1.105",
                raw_data    = {"field_5": "svc_backup", "field_19": "192.168.1.105"},
            ),
            Finding(
                finding_id  = "EVT-4672-001",
                source      = FindingSource.WINDOWS_EVENT_LOG,
                event_id    = 4672,
                timestamp   = now,
                severity    = Severity.MEDIUM,
                description = "Special privileges assigned to 'jsmith' (privilege escalation)",
                raw_data    = {"field_5": "jsmith"},
            ),
            Finding(
                finding_id  = "EVT-4740-001",
                source      = FindingSource.WINDOWS_EVENT_LOG,
                event_id    = 4740,
                timestamp   = now,
                severity    = Severity.HIGH,
                description = "Account 'admin' locked out from WORKSTATION-04",
                raw_data    = {"field_5": "admin", "field_13": "WORKSTATION-04"},
            ),
            Finding(
                finding_id  = "BF-001",
                source      = FindingSource.WINDOWS_EVENT_LOG,
                event_id    = None,
                timestamp   = now,
                severity    = Severity.CRITICAL,
                description = "Possible brute-force attack: account 'svc_backup' had 23 failed logons in the last 24 hours",
                raw_data    = {"account": "svc_backup", "failure_count": 23},
            ),
        ]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SecureForGood — Windows Event Log Scanner")
    parser.add_argument("--hours",  type=int, default=24,                    help="How many hours back to scan (default: 24)")
    parser.add_argument("--output", type=str, default="data/findings.json",  help="Output path for findings JSON")
    args = parser.parse_args()

    scanner  = EventLogScanner(hours=args.hours)
    findings = scanner.scan()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(
            [finding.model_dump(mode="json") for finding in findings],
            f, indent=2, default=str
        )

    print(f"[+] Findings written to {output_path}")


if __name__ == "__main__":
    main()

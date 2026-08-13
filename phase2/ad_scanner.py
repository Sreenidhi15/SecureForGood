"""
ad_scanner.py
=============
Queries Active Directory via LDAP and extracts security-relevant
configuration findings (password policy, privileged group memberships,
stale accounts) as structured Finding objects.

Requires: ldap3
Configure AD connection in your .env file:
  AD_SERVER   = ldap://your-domain-controller
  AD_USER     = service-account@domain.com
  AD_PASSWORD = your-password
  AD_BASE_DN  = DC=yourdomain,DC=com

Usage:
  python ad_scanner.py --output data/ad_findings.json
"""

import json
import os
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from finding_schema import Finding, FindingSource, Severity

try:
    from ldap3 import Server, Connection, ALL, SUBTREE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

load_dotenv()


# ---------------------------------------------------------------------------
# Security thresholds
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH     = 12   # NIST SP 800-63B recommendation
MAX_PASSWORD_AGE_DAYS   = 90
STALE_ACCOUNT_DAYS      = 90   # accounts not logged in for 90+ days

PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
]


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class ADScanner:
    """
    Connects to Active Directory via LDAP and audits security configurations.
    Falls back to mock mode if ldap3 is not available or no server is configured.
    """

    def __init__(self):
        self.server   = os.getenv("AD_SERVER")
        self.user     = os.getenv("AD_USER")
        self.password = os.getenv("AD_PASSWORD")
        self.base_dn  = os.getenv("AD_BASE_DN")
        self.findings: list[Finding] = []
        self._counter = 0

    def _next_id(self, prefix: str = "AD") -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:03d}"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        if not LDAP_AVAILABLE or not self.server:
            print("[WARN] ldap3 not available or AD_SERVER not set — running in mock mode.")
            return self._mock_findings()

        print(f"[*] Connecting to Active Directory at {self.server}...")
        server = Server(self.server, get_info=ALL)
        conn   = Connection(server, self.user, self.password, auto_bind=True)
        print("[+] Connected.")

        self._audit_password_policy(conn)
        self._audit_privileged_groups(conn)
        self._audit_stale_accounts(conn)

        conn.unbind()
        print(f"[+] AD scan complete. Found {len(self.findings)} findings.")
        return self.findings

    # ------------------------------------------------------------------
    # Audit modules
    # ------------------------------------------------------------------

    def _audit_password_policy(self, conn) -> None:
        """Check domain password policy against NIST thresholds."""
        conn.search(
            search_base   = self.base_dn,
            search_filter = "(objectClass=domain)",
            attributes    = ["minPwdLength", "maxPwdAge", "pwdHistoryLength", "lockoutThreshold"],
        )
        if not conn.entries:
            return

        entry = conn.entries[0]
        min_len      = int(entry.minPwdLength.value or 0)
        lockout      = int(entry.lockoutThreshold.value or 0)

        if min_len < MIN_PASSWORD_LENGTH:
            self.findings.append(Finding(
                finding_id  = self._next_id("PWD"),
                source      = FindingSource.PASSWORD_POLICY,
                event_id    = None,
                timestamp   = datetime.now(timezone.utc),
                severity    = Severity.HIGH,
                description = (
                    f"Password minimum length is {min_len} characters — "
                    f"NIST SP 800-63B recommends at least {MIN_PASSWORD_LENGTH}"
                ),
                raw_data    = {"minPwdLength": min_len},
            ))

        if lockout == 0:
            self.findings.append(Finding(
                finding_id  = self._next_id("PWD"),
                source      = FindingSource.PASSWORD_POLICY,
                event_id    = None,
                timestamp   = datetime.now(timezone.utc),
                severity    = Severity.CRITICAL,
                description = "Account lockout policy is disabled — accounts have no brute-force protection",
                raw_data    = {"lockoutThreshold": lockout},
            ))

    def _audit_privileged_groups(self, conn) -> None:
        """Flag privileged groups with more than a reasonable number of members."""
        for group in PRIVILEGED_GROUPS:
            conn.search(
                search_base   = self.base_dn,
                search_filter = f"(&(objectClass=group)(cn={group}))",
                attributes    = ["member"],
            )
            if not conn.entries:
                continue

            members = conn.entries[0].member.values
            count   = len(members)

            if count > 3:
                self.findings.append(Finding(
                    finding_id  = self._next_id("ADG"),
                    source      = FindingSource.ACTIVE_DIRECTORY,
                    event_id    = None,
                    timestamp   = datetime.now(timezone.utc),
                    severity    = Severity.MEDIUM,
                    description = (
                        f"Privileged group '{group}' has {count} members — "
                        "principle of least privilege may be violated"
                    ),
                    raw_data    = {"group": group, "member_count": count},
                ))

    def _audit_stale_accounts(self, conn) -> None:
        """Find enabled user accounts that have not logged in recently."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_ACCOUNT_DAYS)
        cutoff_str = cutoff.strftime("%Y%m%d%H%M%S.0Z")

        conn.search(
            search_base   = self.base_dn,
            search_filter = (
                f"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                f"(lastLogonTimestamp<={cutoff_str}))"
            ),
            attributes    = ["sAMAccountName", "lastLogonTimestamp"],
        )

        if conn.entries:
            accounts = [str(e.sAMAccountName) for e in conn.entries]
            self.findings.append(Finding(
                finding_id  = self._next_id("ADS"),
                source      = FindingSource.ACTIVE_DIRECTORY,
                event_id    = None,
                timestamp   = datetime.now(timezone.utc),
                severity    = Severity.MEDIUM,
                description = (
                    f"{len(accounts)} enabled user accounts have not logged in "
                    f"for more than {STALE_ACCOUNT_DAYS} days — review for deprovisioning"
                ),
                raw_data    = {"stale_accounts": accounts[:10]},  # limit to first 10
            ))

    # ------------------------------------------------------------------
    # Mock mode
    # ------------------------------------------------------------------

    def _mock_findings(self) -> list[Finding]:
        now = datetime.now(timezone.utc)
        return [
            Finding(
                finding_id  = "PWD-001",
                source      = FindingSource.PASSWORD_POLICY,
                event_id    = None,
                timestamp   = now,
                severity    = Severity.HIGH,
                description = "Password minimum length is 8 characters — NIST SP 800-63B recommends at least 12",
                raw_data    = {"minPwdLength": 8},
            ),
            Finding(
                finding_id  = "PWD-002",
                source      = FindingSource.PASSWORD_POLICY,
                event_id    = None,
                timestamp   = now,
                severity    = Severity.CRITICAL,
                description = "Account lockout policy is disabled — accounts have no brute-force protection",
                raw_data    = {"lockoutThreshold": 0},
            ),
            Finding(
                finding_id  = "ADG-001",
                source      = FindingSource.ACTIVE_DIRECTORY,
                event_id    = None,
                timestamp   = now,
                severity    = Severity.MEDIUM,
                description = "Privileged group 'Domain Admins' has 7 members — principle of least privilege may be violated",
                raw_data    = {"group": "Domain Admins", "member_count": 7},
            ),
            Finding(
                finding_id  = "ADS-001",
                source      = FindingSource.ACTIVE_DIRECTORY,
                event_id    = None,
                timestamp   = now,
                severity    = Severity.MEDIUM,
                description = "14 enabled user accounts have not logged in for more than 90 days",
                raw_data    = {"stale_accounts": ["temp_user1", "old_contractor", "test_acct"]},
            ),
        ]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SecureForGood — Active Directory Scanner")
    parser.add_argument("--output", type=str, default="data/ad_findings.json", help="Output path for findings JSON")
    args = parser.parse_args()

    scanner  = ADScanner()
    findings = scanner.scan()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(
            [finding.model_dump(mode="json") for finding in findings],
            f, indent=2, default=str
        )

    print(f"[+] AD findings written to {output_path}")


if __name__ == "__main__":
    main()

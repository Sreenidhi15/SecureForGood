"""
gap_analyzer.py
===============
Compares LLM-mapped findings against a required NIST SP 800-53 control
baseline, flags gaps, and computes a CVSS-aligned risk score per gap.

Baselines available: low, moderate, high (matching NIST impact levels).

Usage:
  python gap_analyzer.py --input data/mapped.json --baseline moderate --output data/gaps.json
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timezone
from baseline_profiles import BASELINES
from risk_scorer import score_gap


# ---------------------------------------------------------------------------
# Gap status constants
# ---------------------------------------------------------------------------

STATUS_MET         = "MET"           # control has evidence with high confidence
STATUS_PARTIAL     = "PARTIAL"       # control has evidence but confidence is low
STATUS_GAP         = "GAP"           # control required but no evidence found
CONFIDENCE_THRESHOLD = 0.70          # below this = PARTIAL, not MET


# ---------------------------------------------------------------------------
# Gap analyzer
# ---------------------------------------------------------------------------

class GapAnalyzer:
    """
    Takes the mapped findings from Phase 3 and the required baseline,
    and produces a structured gap report with risk scores.
    """

    def __init__(self, baseline: str = "moderate"):
        if baseline not in BASELINES:
            raise ValueError(f"Unknown baseline '{baseline}'. Choose from: {list(BASELINES)}")
        self.baseline_name     = baseline
        self.required_controls = BASELINES[baseline]

    def analyze(self, mapped_findings: list[dict]) -> dict:
        """
        Returns a gap report dict covering all required controls.
        """
        # Build a lookup: control_id -> best confidence seen across all findings
        evidence: dict[str, float] = {}
        for finding in mapped_findings:
            for mapping in finding.get("mapped_controls", []):
                cid  = mapping["control_id"]
                conf = mapping.get("confidence", 0.0)
                evidence[cid] = max(evidence.get(cid, 0.0), conf)

        gaps = []
        for control_id in sorted(self.required_controls):
            confidence = evidence.get(control_id, 0.0)

            if confidence >= CONFIDENCE_THRESHOLD:
                status = STATUS_MET
            elif confidence > 0:
                status = STATUS_PARTIAL
            else:
                status = STATUS_GAP

            risk_score, risk_level = score_gap(status, control_id)

            gaps.append({
                "control_id":  control_id,
                "status":      status,
                "confidence":  round(confidence, 2),
                "risk_score":  risk_score,
                "risk_level":  risk_level,
            })

        summary = self._summarize(gaps)

        return {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "baseline":      self.baseline_name,
            "total_required": len(self.required_controls),
            "summary":       summary,
            "gaps":          gaps,
        }

    def _summarize(self, gaps: list[dict]) -> dict:
        counts = {STATUS_MET: 0, STATUS_PARTIAL: 0, STATUS_GAP: 0}
        for g in gaps:
            counts[g["status"]] += 1
        total = len(gaps)
        return {
            "met":          counts[STATUS_MET],
            "partial":      counts[STATUS_PARTIAL],
            "gap":          counts[STATUS_GAP],
            "compliance_pct": round(counts[STATUS_MET] / total * 100, 1) if total else 0,
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SecureForGood — Compliance Gap Analyzer")
    parser.add_argument("--input",    type=str, default="data/mapped.json", help="Mapped findings JSON from Phase 3")
    parser.add_argument("--baseline", type=str, default="moderate",         help="NIST baseline: low, moderate, or high")
    parser.add_argument("--output",   type=str, default="data/gaps.json",   help="Output gap report JSON")
    args = parser.parse_args()

    with open(args.input) as f:
        mapped = json.load(f)

    analyzer = GapAnalyzer(baseline=args.baseline)
    report   = analyzer.analyze(mapped)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    summary = report["summary"]
    print(f"[+] Gap analysis complete.")
    print(f"    MET: {summary['met']}  |  PARTIAL: {summary['partial']}  |  GAP: {summary['gap']}")
    print(f"    Compliance: {summary['compliance_pct']}%")
    print(f"[+] Report written to {output_path}")


if __name__ == "__main__":
    main()

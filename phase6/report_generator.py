"""
report_generator.py
===================
Generates a structured JSON report and a formatted PDF intelligence report
from the Phase 4 gap analysis output.

The PDF is formatted for two audiences:
  - Technical teams: control-level detail, confidence scores, risk scores
  - Non-technical stakeholders: executive summary, plain-English recommendations

Requires: reportlab, openai

Usage:
  python report_generator.py --input data/gaps.json --output reports/
"""

import json
import os
import argparse
from pathlib import Path
from datetime import datetime, timezone
from openai import OpenAI
from dotenv import load_dotenv

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

load_dotenv()


# ---------------------------------------------------------------------------
# Risk level colors for PDF
# ---------------------------------------------------------------------------

RISK_COLORS = {
    "CRITICAL": colors.HexColor("#C0392B"),
    "HIGH":     colors.HexColor("#E67E22"),
    "MEDIUM":   colors.HexColor("#F1C40F"),
    "LOW":      colors.HexColor("#27AE60"),
}


# ---------------------------------------------------------------------------
# Narrative writer (GPT-4)
# ---------------------------------------------------------------------------

class NarrativeWriter:
    """Uses GPT-4 to write a plain-English executive summary from gap data."""

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY not set.")
        self.client = OpenAI(api_key=api_key)

    def write_executive_summary(self, gap_report: dict) -> str:
        summary = gap_report["summary"]
        baseline = gap_report["baseline"].upper()
        top_gaps = [
            g for g in gap_report["gaps"]
            if g["status"] == "GAP" and g["risk_level"] in ("CRITICAL", "HIGH")
        ][:5]

        prompt = f"""
Write a 3-paragraph executive summary for a nonprofit security compliance audit report.

Baseline: NIST SP 800-53 {baseline}
Controls Met: {summary['met']}
Controls Partial: {summary['partial']}
Controls with Gaps: {summary['gap']}
Overall Compliance: {summary['compliance_pct']}%
Top High-Risk Gaps: {', '.join(g['control_id'] for g in top_gaps)}

Write in plain English for a nonprofit executive director with no technical background.
Explain what the numbers mean, what is at risk, and what immediate actions to take.
Do not use jargon. Do not use bullet points. Write in paragraphs.
        """.strip()

        response = self.client.chat.completions.create(
            model       = "gpt-4",
            messages    = [{"role": "user", "content": prompt}],
            temperature = 0.4,
            max_tokens  = 600,
        )
        return response.choices[0].message.content.strip()


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

class PDFBuilder:
    """Builds the formatted PDF report using ReportLab."""

    def __init__(self, output_path: str):
        self.output_path = output_path
        self.styles      = getSampleStyleSheet()
        self._add_custom_styles()

    def _add_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name      = "SectionHeader",
            parent    = self.styles["Heading2"],
            textColor = colors.HexColor("#2C3E50"),
            spaceAfter = 6,
        ))
        self.styles.add(ParagraphStyle(
            name      = "BodyText2",
            parent    = self.styles["Normal"],
            spaceAfter = 8,
            leading   = 16,
        ))

    def build(self, gap_report: dict, executive_summary: str) -> str:
        doc      = SimpleDocTemplate(self.output_path, pagesize=letter,
                                     rightMargin=inch, leftMargin=inch,
                                     topMargin=inch, bottomMargin=inch)
        story    = []
        styles   = self.styles
        now      = datetime.now(timezone.utc).strftime("%B %d, %Y")

        # Title
        story.append(Paragraph("SecureForGood Compliance Audit Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {now} | Baseline: NIST SP 800-53 {gap_report['baseline'].upper()}", styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2C3E50")))
        story.append(Spacer(1, 0.2 * inch))

        # Executive summary
        story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
        for para in executive_summary.split("\n\n"):
            story.append(Paragraph(para.strip(), styles["BodyText2"]))
        story.append(Spacer(1, 0.2 * inch))

        # Summary scorecard
        summary = gap_report["summary"]
        story.append(Paragraph("Compliance Scorecard", styles["SectionHeader"]))
        scorecard_data = [
            ["Metric", "Value"],
            ["Overall Compliance", f"{summary['compliance_pct']}%"],
            ["Controls Met",       str(summary["met"])],
            ["Controls Partial",   str(summary["partial"])],
            ["Controls with Gaps", str(summary["gap"])],
            ["Total Required",     str(gap_report["total_required"])],
        ]
        story.append(self._make_table(scorecard_data))
        story.append(Spacer(1, 0.3 * inch))

        # Gap detail table (top 20 gaps)
        story.append(Paragraph("Gap Analysis Detail", styles["SectionHeader"]))
        gap_data = [["Control ID", "Status", "Confidence", "Risk Score", "Risk Level"]]
        for g in gap_report["gaps"]:
            if g["status"] != "MET":
                gap_data.append([
                    g["control_id"],
                    g["status"],
                    f"{g['confidence']:.0%}",
                    str(g["risk_score"]),
                    g["risk_level"],
                ])
        story.append(self._make_gap_table(gap_data))

        doc.build(story)
        return self.output_path

    def _make_table(self, data: list) -> Table:
        t = Table(data, colWidths=[3 * inch, 2 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ECF0F1")]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("PADDING",     (0, 0), (-1, -1), 6),
        ]))
        return t

    def _make_gap_table(self, data: list) -> Table:
        t = Table(data, colWidths=[1.1*inch, 1.0*inch, 1.0*inch, 1.0*inch, 1.1*inch])
        style = [
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#BDC3C7")),
            ("PADDING",     (0, 0), (-1, -1), 5),
        ]
        # Color-code risk level cells
        for i, row in enumerate(data[1:], start=1):
            risk = row[4] if len(row) > 4 else ""
            color = RISK_COLORS.get(risk, colors.white)
            style.append(("BACKGROUND", (4, i), (4, i), color))
            if risk in ("CRITICAL", "HIGH"):
                style.append(("TEXTCOLOR", (4, i), (4, i), colors.white))
        t.setStyle(TableStyle(style))
        return t


# ---------------------------------------------------------------------------
# Report generator (orchestrates JSON + PDF)
# ---------------------------------------------------------------------------

class ReportGenerator:

    def __init__(self, gaps_path: str = "data/gaps.json", output_dir: str = "reports/"):
        self.gaps_path  = gaps_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> dict:
        with open(self.gaps_path) as f:
            gap_report = json.load(f)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Write structured JSON report
        json_path = self.output_dir / f"audit_report_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump(gap_report, f, indent=2)
        print(f"[+] JSON report written to {json_path}")

        # Generate executive summary via GPT-4
        print("[*] Generating executive summary via GPT-4...")
        writer  = NarrativeWriter()
        summary = writer.write_executive_summary(gap_report)

        # Build PDF
        pdf_path = self.output_dir / f"audit_report_{timestamp}.pdf"
        builder  = PDFBuilder(str(pdf_path))
        builder.build(gap_report, summary)
        print(f"[+] PDF report written to {pdf_path}")

        return {"json": str(json_path), "pdf": str(pdf_path)}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SecureForGood — Report Generator")
    parser.add_argument("--input",  type=str, default="data/gaps.json", help="Gap analysis JSON from Phase 4")
    parser.add_argument("--output", type=str, default="reports/",       help="Output directory")
    args = parser.parse_args()

    generator = ReportGenerator(gaps_path=args.input, output_dir=args.output)
    paths     = generator.generate()
    print(f"[+] Done. Reports at: {paths}")


if __name__ == "__main__":
    main()

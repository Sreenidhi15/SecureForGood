"""
orchestrator.py
===============
LangChain agentic pipeline that autonomously orchestrates Phases 2 through 6
end to end without manual intervention.

Agents:
  ScannerAgent    — runs Phase 2 (Event Log + AD scanning)
  MapperAgent     — runs Phase 3 (GPT-4 control mapping)
  GapAgent        — runs Phase 4 (gap analysis + risk scoring)
  ReportAgent     — runs Phase 6 (report generation)
  OrchestratorAgent — coordinates all agents, handles retries

Usage:
  python orchestrator.py --baseline moderate --output reports/
"""

import json
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Add parent directory to path so we can import phase modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder


# ---------------------------------------------------------------------------
# Agent tools — each wraps one phase module
# ---------------------------------------------------------------------------

@tool
def run_event_log_scan(hours: int = 24) -> str:
    """
    Scans Windows Security Event Log for the past N hours.
    Returns the path to the findings JSON file.
    """
    from phase2.event_log_scanner import EventLogScanner
    import json

    scanner  = EventLogScanner(hours=hours)
    findings = scanner.scan()
    output   = "data/findings_evtlog.json"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w") as f:
        json.dump([fi.model_dump(mode="json") for fi in findings], f, indent=2, default=str)

    return f"Event log scan complete. {len(findings)} findings written to {output}"


@tool
def run_ad_scan() -> str:
    """
    Scans Active Directory for security configuration issues.
    Returns the path to the AD findings JSON file.
    """
    from phase2.ad_scanner import ADScanner
    import json

    scanner  = ADScanner()
    findings = scanner.scan()
    output   = "data/findings_ad.json"
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w") as f:
        json.dump([fi.model_dump(mode="json") for fi in findings], f, indent=2, default=str)

    return f"AD scan complete. {len(findings)} findings written to {output}"


@tool
def merge_findings() -> str:
    """
    Merges event log and AD findings into a single file.
    Returns the path to the merged findings JSON.
    """
    import json
    combined = []

    for path in ["data/findings_evtlog.json", "data/findings_ad.json"]:
        if Path(path).exists():
            with open(path) as f:
                combined.extend(json.load(f))

    output = "data/findings.json"
    with open(output, "w") as f:
        json.dump(combined, f, indent=2)

    return f"Merged {len(combined)} total findings into {output}"


@tool
def run_control_mapping() -> str:
    """
    Maps all findings to NIST SP 800-53 controls using GPT-4.
    Returns the path to the mapped findings JSON.
    """
    from phase3.control_mapper import ControlMapper
    import json

    with open("data/findings.json") as f:
        findings = json.load(f)

    mapper  = ControlMapper()
    results = mapper.map_all(findings)

    output = "data/mapped.json"
    with open(output, "w") as f:
        json.dump(results, f, indent=2)

    return f"Control mapping complete. {len(results)} findings mapped. Written to {output}"


@tool
def run_gap_analysis(baseline: str = "moderate") -> str:
    """
    Runs compliance gap analysis against the specified NIST baseline.
    Returns the path to the gap report JSON.
    """
    from phase4.gap_analyzer import GapAnalyzer
    import json

    with open("data/mapped.json") as f:
        mapped = json.load(f)

    analyzer = GapAnalyzer(baseline=baseline)
    report   = analyzer.analyze(mapped)

    output = "data/gaps.json"
    with open(output, "w") as f:
        json.dump(report, f, indent=2)

    summary = report["summary"]
    return (
        f"Gap analysis complete. "
        f"MET: {summary['met']} | PARTIAL: {summary['partial']} | GAP: {summary['gap']} | "
        f"Compliance: {summary['compliance_pct']}%. Written to {output}"
    )


@tool
def run_report_generation(output_dir: str = "reports") -> str:
    """
    Generates the final JSON and PDF intelligence report.
    Returns the paths to the generated report files.
    """
    from phase6.report_generator import ReportGenerator

    generator = ReportGenerator(gaps_path="data/gaps.json", output_dir=output_dir)
    paths     = generator.generate()
    return f"Reports generated: {paths}"


# ---------------------------------------------------------------------------
# Orchestrator agent
# ---------------------------------------------------------------------------

ORCHESTRATOR_SYSTEM = """
You are the SecureForGood Orchestration Agent.

Your job is to autonomously run a full security compliance audit pipeline in this order:
1. Run the Windows Event Log scan
2. Run the Active Directory scan
3. Merge the findings
4. Run GPT-4 control mapping
5. Run compliance gap analysis
6. Generate the final intelligence report

Use the tools provided for each step. After each step, confirm it succeeded before proceeding.
If a step fails, retry once before reporting the error.
When all steps are complete, provide a short summary of the audit results.
"""


def build_orchestrator(llm) -> AgentExecutor:
    tools = [
        run_event_log_scan,
        run_ad_scan,
        merge_findings,
        run_control_mapping,
        run_gap_analysis,
        run_report_generation,
    ]

    prompt = ChatPromptTemplate.from_messages([
        ("system", ORCHESTRATOR_SYSTEM),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])

    agent = create_openai_tools_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=15)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SecureForGood — Agentic Orchestrator")
    parser.add_argument("--baseline", type=str, default="moderate", help="NIST baseline: low, moderate, high")
    parser.add_argument("--output",   type=str, default="reports/",  help="Output directory for reports")
    args = parser.parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError("OPENAI_API_KEY not set in .env")

    llm           = ChatOpenAI(model="gpt-4", temperature=0)
    orchestrator  = build_orchestrator(llm)

    task = (
        f"Run the full SecureForGood compliance audit pipeline. "
        f"Use the '{args.baseline}' NIST baseline and write reports to '{args.output}'."
    )

    print(f"\n[*] Starting autonomous audit pipeline — baseline: {args.baseline}\n")
    result = orchestrator.invoke({"input": task})
    print(f"\n[+] Pipeline complete.\n{result['output']}")


if __name__ == "__main__":
    main()

# SecureForGood — AI-Powered Compliance Auditing for Nonprofits 

> Automates enterprise-grade security auditing for organizations that cannot afford it. Scans Windows security configurations, maps findings to NIST SP 800-53 controls using GPT-4, identifies compliance gaps, and generates plain-English reports for both technical teams and nonprofit leadership.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![NIST SP 800-53](https://img.shields.io/badge/NIST-SP%20800--53%20Rev%205-green)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![LangChain](https://img.shields.io/badge/LangChain-Agentic-orange)](https://www.langchain.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4-purple)](https://openai.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem

Nonprofits, legal aid organizations, community health clinics, and small public-sector agencies handle sensitive data every day — donor records, legal case files, health information, immigration documents. Most of them have no security team, no compliance budget, and no way to know whether their systems meet basic standards.

A professional security audit costs tens of thousands of dollars. This tool makes that audit free and automatic.

---

## What It Does

- Automates enterprise security configuration scanning and maps findings to NIST SP 800-53 compliance controls using GPT-4, reducing manual audit effort by hours
- Identifies compliance gaps and generates risk scores to help under-resourced organizations prioritize security fixes without expensive consultants
- Produces structured PDF and JSON intelligence reports readable by both technical teams and non-technical stakeholders such as nonprofit directors and board members

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agentic Orchestration Layer                   │
│              (LangChain — Phase 5: Agent Controller)            │
└─────────┬──────────────┬──────────────┬──────────────┬──────────┘
          │              │              │              │
          ▼              ▼              ▼              ▼
   ┌─────────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────┐
   │  Phase 1    │ │ Phase 2  │ │   Phase 3    │ │   Phase 4    │
   │ NIST Parser │ │ Scanner  │ │ LLM Control  │ │    Gap       │
   │ SQLite FTS5 │ │ Win Logs │ │   Mapper     │ │  Analyzer    │
   │  Database   │ │ AD Config│ │  GPT-4 +     │ │ Risk Scorer  │
   └─────────────┘ └──────────┘ │  Confidence  │ └──────────────┘
                                └──────────────┘
                                        │
                                        ▼
                            ┌───────────────────────┐
                            │        Phase 6         │
                            │   Report Generator     │
                            │  JSON + PDF (ReportLab)│
                            └───────────────────────┘
```

---

## Project Phases

### Phase 1 — NIST Control Database
**Status: Complete**

Downloads and parses the official NIST SP 800-53 Rev 5 OSCAL JSON, stores 1000+ controls in SQLite with FTS5 full-text search, and exposes a ControlDatabase class used by all downstream phases.

```
phase1/
└── nist_parser.py
```

---

### Phase 2 — Windows Security Scanner
**Status: In Progress**

Reads Windows Security Event Logs and Active Directory configurations, extracts structured security findings as normalized JSON. Covers failed logons (4625), privilege escalation (4672), policy changes (4719), account lockouts (4740), password policy, and AD group memberships.

```
phase2/
├── event_log_scanner.py
├── ad_scanner.py
└── finding_schema.py
```

---

### Phase 3 — LLM Control Mapper
**Status: Planned**

Uses GPT-4 to reason over each finding and identify the most relevant NIST SP 800-53 control IDs. Returns confidence scores (0.0 to 1.0) and natural-language rationale for each mapping. Results are cached against the Phase 1 SQLite database.

```
phase3/
├── control_mapper.py
├── prompt_templates.py
└── cache_layer.py
```

---

### Phase 4 — Compliance Gap Analyzer
**Status: Planned**

Compares mapped findings against a required-control baseline, flags controls with missing or insufficient evidence, and computes a CVSS-aligned risk score per gap.

```
phase4/
├── gap_analyzer.py
├── risk_scorer.py
└── baseline_profiles.py
```

---

### Phase 5 — Agentic Workflow Layer
**Status: Planned**

Builds a LangChain multi-agent pipeline that autonomously orchestrates Phases 2 through 4 end to end without manual intervention. Agents: ScannerAgent, MapperAgent, GapAnalyzerAgent, OrchestratorAgent.

```
phase5/
├── orchestrator.py
├── scanner_agent.py
├── mapper_agent.py
└── gap_agent.py
```

---

### Phase 6 — Intelligence Report Generator
**Status: Planned**

Uses GPT-4 to write professional audit narratives and generates both a structured JSON report for technical teams and a formatted PDF for nonprofit directors and board members. Sections include Executive Summary, Control Status, Gap Analysis, Risk Heat Map, and Remediation Roadmap.

```
phase6/
├── report_generator.py
├── narrative_writer.py
├── pdf_builder.py
└── templates/
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Compliance Data | NIST SP 800-53 Rev 5 OSCAL JSON (public domain) |
| Database | SQLite with FTS5 full-text search |
| LLM Reasoning | OpenAI GPT-4 |
| Agentic Framework | LangChain |
| Windows Scanning | pywin32, ldap3 |
| PDF Generation | ReportLab |
| Data Validation | Pydantic |

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Windows 10/11 or Windows Server (for Phase 2 live scanning; mock mode available on all platforms)
- An OpenAI API key (for Phases 3 and 6)

### Installation

```bash
git clone https://github.com/Sreenidhi15/ai-security-control-analyzer.git
cd ai-security-control-analyzer

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your OpenAI API key.

### Run Phase 1

```bash
python phase1/nist_parser.py --refresh
python phase1/nist_parser.py --lookup AC-2
python phase1/nist_parser.py --search "account management"
```

---

## Sample Output

**Finding (Phase 2)**
```json
{
  "finding_id": "EVT-4625-001",
  "event_id": 4625,
  "severity": "HIGH",
  "description": "23 failed logon attempts from 192.168.1.105 within 10 minutes"
}
```

**Control Mapping (Phase 3)**
```json
{
  "control_id": "AC-7",
  "title": "Unsuccessful Logon Attempts",
  "confidence": 0.97,
  "rationale": "Finding directly reflects a violation of AC-7 lockout policy thresholds."
}
```

**Gap Report (Phase 4)**
```json
{
  "control_id": "AC-7",
  "status": "GAP",
  "risk_score": 8.4,
  "risk_level": "HIGH",
  "recommendation": "Enforce account lockout after 5 failed attempts per AC-7(a)."
}
```

---

## Roadmap

- [x] Phase 1: NIST SP 800-53 control database with SQLite/FTS5
- [ ] Phase 2: Windows Event Log and AD scanner
- [ ] Phase 3: GPT-4 control mapping with confidence scoring
- [ ] Phase 4: Gap analysis and CVSS-aligned risk scoring
- [ ] Phase 5: LangChain agentic orchestration layer
- [ ] Phase 6: JSON and PDF intelligence report generation
- [ ] Stretch: ISO 27001 and SOC 2 dual-mapping support
- [ ] Stretch: GitHub Actions CI/CD for automated test runs

---

## Author

**Sreenidhi Ramani**
M.S. Electrical and Computer Engineering, Northeastern University

Research Assistant, CactiLab — firmware security, embedded vulnerability research, fuzzing pipelines

[GitHub](https://github.com/Sreenidhi15) · [LinkedIn](https://linkedin.com/in/sreenidhi-ramani)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

NIST SP 800-53 data is from the [NIST OSCAL Content Repository](https://github.com/usnistgov/oscal-content) and is in the public domain.

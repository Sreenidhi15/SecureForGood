"""
control_mapper.py
=================
Uses GPT-4 to map each security finding to the most relevant
NIST SP 800-53 Rev 5 control IDs, with confidence scores and rationale.

Results are cached in SQLite so repeated runs do not burn API credits.

Usage:
  python control_mapper.py --input data/findings.json --output data/mapped.json
"""

import json
import hashlib
import sqlite3
import argparse
import os
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv

from prompt_templates import SYSTEM_PROMPT, build_mapping_prompt

load_dotenv()

CACHE_DB = "data/mapping_cache.db"


# ---------------------------------------------------------------------------
# SQLite cache layer
# ---------------------------------------------------------------------------

class MappingCache:
    """
    Caches GPT-4 mapping responses keyed by a hash of the finding description.
    Avoids redundant API calls for identical or near-identical findings.
    """

    def __init__(self, db_path: str = CACHE_DB):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                hash TEXT PRIMARY KEY,
                finding_id TEXT,
                response TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        self.conn.commit()

    def _hash(self, description: str) -> str:
        return hashlib.sha256(description.encode()).hexdigest()

    def get(self, description: str) -> dict | None:
        row = self.conn.execute(
            "SELECT response FROM cache WHERE hash = ?",
            (self._hash(description),)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def set(self, description: str, response: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (hash, finding_id, response) VALUES (?, ?, ?)",
            (self._hash(description), response.get("finding_id", ""), json.dumps(response))
        )
        self.conn.commit()

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# Control mapper
# ---------------------------------------------------------------------------

class ControlMapper:
    """
    Sends each finding to GPT-4 and returns structured control mappings.
    """

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY not set. Add it to your .env file.")
        self.client = OpenAI(api_key=api_key)
        self.cache  = MappingCache()

    def map_finding(self, finding: dict) -> dict:
        """Map a single finding to NIST controls. Uses cache if available."""
        cached = self.cache.get(finding["description"])
        if cached:
            print(f"  [cache] {finding['finding_id']}")
            return cached

        print(f"  [GPT-4] {finding['finding_id']} — calling API...")
        prompt = build_mapping_prompt(finding)

        response = self.client.chat.completions.create(
            model       = "gpt-4",
            messages    = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature = 0.1,   # low temp for consistent, deterministic output
            max_tokens  = 500,
        )

        raw_text = response.choices[0].message.content.strip()

        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            # Fallback: wrap in error finding so pipeline does not break
            result = {
                "finding_id": finding["finding_id"],
                "mapped_controls": [],
                "error": f"JSON parse failed: {raw_text[:200]}",
            }

        self.cache.set(finding["description"], result)
        return result

    def map_all(self, findings: list[dict]) -> list[dict]:
        """Map a list of findings. Returns list of mapping results."""
        print(f"[*] Mapping {len(findings)} findings to NIST SP 800-53 controls...")
        results = [self.map_finding(f) for f in findings]
        self.cache.close()
        print(f"[+] Mapping complete.")
        return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SecureForGood — LLM Control Mapper")
    parser.add_argument("--input",  type=str, default="data/findings.json", help="Input findings JSON")
    parser.add_argument("--output", type=str, default="data/mapped.json",   help="Output mapped findings JSON")
    args = parser.parse_args()

    with open(args.input) as f:
        findings = json.load(f)

    mapper  = ControlMapper()
    results = mapper.map_all(findings)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Mapped findings written to {output_path}")


if __name__ == "__main__":
    main()

"""
risk_scorer.py
==============
Computes a CVSS-aligned risk score (0.0 to 10.0) for each compliance gap.

Score = Impact x Likelihood, scaled to 10.
- Impact is derived from the control family (AC, SI, AU, etc.)
- Likelihood is derived from gap status (GAP > PARTIAL > MET)
"""

# Impact weights by control family (based on security criticality)
FAMILY_IMPACT: dict[str, float] = {
    "AC": 0.9,   # Access Control — high impact
    "IA": 0.9,   # Identification and Authentication
    "SI": 0.85,  # System and Information Integrity
    "SC": 0.85,  # System and Communications Protection
    "AU": 0.75,  # Audit and Accountability
    "CM": 0.75,  # Configuration Management
    "IR": 0.70,  # Incident Response
    "SA": 0.65,  # System and Services Acquisition
    "RA": 0.65,  # Risk Assessment
    "CP": 0.60,  # Contingency Planning
    "MA": 0.55,  # Maintenance
    "MP": 0.55,  # Media Protection
    "PE": 0.50,  # Physical and Environmental Protection
    "PS": 0.50,  # Personnel Security
    "AT": 0.45,  # Awareness and Training
    "PL": 0.40,  # Planning
    "PM": 0.35,  # Program Management
}

DEFAULT_IMPACT = 0.60

# Likelihood weights by gap status
LIKELIHOOD: dict[str, float] = {
    "GAP":     0.95,
    "PARTIAL": 0.55,
    "MET":     0.05,
}

# Risk level thresholds
RISK_LEVELS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.0, "LOW"),
]


def score_gap(status: str, control_id: str) -> tuple[float, str]:
    """
    Returns (risk_score, risk_level) for a single gap entry.
    risk_score is rounded to 1 decimal place, 0.0 to 10.0.
    """
    family     = control_id.split("-")[0].upper()
    impact     = FAMILY_IMPACT.get(family, DEFAULT_IMPACT)
    likelihood = LIKELIHOOD.get(status, 0.0)
    score      = round(impact * likelihood * 10, 1)

    level = "LOW"
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            level = label
            break

    return score, level

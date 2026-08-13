"""
baseline_profiles.py
====================
NIST SP 800-53 Rev 5 required control sets for Low, Moderate, and High
impact systems. These are the controls that must have evidence in the
gap analysis.

Source: NIST SP 800-53B (Control Baselines for Information Systems)
"""

# Low impact baseline — minimum controls for low-risk systems
LOW_BASELINE = {
    "AC-1", "AC-2", "AC-3", "AC-7", "AC-8", "AC-14", "AC-17", "AC-18", "AC-19", "AC-20",
    "AU-1", "AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-11", "AU-12",
    "CM-1", "CM-2", "CM-4", "CM-5", "CM-6", "CM-7", "CM-8",
    "CP-1", "CP-2", "CP-3", "CP-4", "CP-9", "CP-10",
    "IA-1", "IA-2", "IA-4", "IA-5", "IA-7", "IA-8",
    "IR-1", "IR-2", "IR-4", "IR-5", "IR-6", "IR-7",
    "MA-1", "MA-2", "MA-5",
    "MP-1", "MP-2", "MP-3", "MP-4", "MP-6",
    "PE-1", "PE-2", "PE-3", "PE-6", "PE-8", "PE-12", "PE-13", "PE-14", "PE-15",
    "PL-1", "PL-2", "PL-4",
    "PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8",
    "RA-1", "RA-2", "RA-3", "RA-5",
    "SA-1", "SA-2", "SA-3", "SA-4", "SA-8", "SA-9",
    "SC-1", "SC-5", "SC-7", "SC-12", "SC-13", "SC-15", "SC-28",
    "SI-1", "SI-2", "SI-3", "SI-4", "SI-5", "SI-12",
}

# Moderate impact baseline — adds controls for systems handling sensitive data
MODERATE_BASELINE = LOW_BASELINE | {
    "AC-4", "AC-5", "AC-6", "AC-11", "AC-12", "AC-16", "AC-21",
    "AU-4", "AU-5", "AU-7", "AU-10",
    "CM-3", "CM-9", "CM-10", "CM-11",
    "CP-6", "CP-7", "CP-8",
    "IA-3", "IA-6", "IA-11",
    "IR-3", "IR-8",
    "MA-3", "MA-4", "MA-6",
    "MP-5", "MP-7",
    "PE-4", "PE-5", "PE-9", "PE-10", "PE-11", "PE-16", "PE-17",
    "PL-8",
    "RA-4",
    "SA-5", "SA-10", "SA-11", "SA-15", "SA-16", "SA-17",
    "SC-2", "SC-3", "SC-4", "SC-8", "SC-10", "SC-16", "SC-17", "SC-18", "SC-19",
    "SC-20", "SC-21", "SC-22", "SC-23", "SC-24", "SC-39",
    "SI-6", "SI-7", "SI-8", "SI-10", "SI-11", "SI-16",
}

# High impact baseline — adds controls for critical national security systems
HIGH_BASELINE = MODERATE_BASELINE | {
    "AC-2", "AC-6", "AC-17", "AC-18",
    "AU-9", "AU-10", "AU-14",
    "CP-2", "CP-6", "CP-7",
    "IA-2", "IA-5",
    "MA-4", "MA-5",
    "SC-7", "SC-8", "SC-28",
    "SI-2", "SI-3", "SI-7",
}

BASELINES: dict[str, set] = {
    "low":      LOW_BASELINE,
    "moderate": MODERATE_BASELINE,
    "high":     HIGH_BASELINE,
}

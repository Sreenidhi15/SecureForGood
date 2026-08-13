"""
finding_schema.py
=================
Pydantic data model for a normalized security finding.
All scanners (Event Log, AD) output findings in this format
so downstream phases have a consistent schema to work with.
"""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class FindingSource(str, Enum):
    WINDOWS_EVENT_LOG    = "Windows Security Event Log"
    ACTIVE_DIRECTORY     = "Active Directory"
    PASSWORD_POLICY      = "Password Policy"


class Finding(BaseModel):
    finding_id:  str            = Field(..., description="Unique finding identifier, e.g. EVT-4625-001")
    source:      FindingSource  = Field(..., description="Where the finding came from")
    event_id:    Optional[int]  = Field(None, description="Windows Event ID if applicable")
    timestamp:   datetime       = Field(..., description="When the event occurred (UTC)")
    severity:    Severity       = Field(..., description="Assessed severity level")
    description: str            = Field(..., description="Human-readable summary of the finding")
    raw_data:    dict[str, Any] = Field(default_factory=dict, description="Raw event fields for traceability")

    class Config:
        use_enum_values = True

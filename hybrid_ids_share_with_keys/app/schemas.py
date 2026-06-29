from typing import Any

from pydantic import BaseModel


class AnalyzeResponse(BaseModel):
    filename: str
    generated_csv: str
    flows_analyzed: int
    attack_count: int
    benign_count: int
    attack_rate: float

    official_binary_decision: str = "UNKNOWN"
    prediction_summary: dict[str, Any] = {}
    attack_type_summary: dict[str, Any] = {}

    binary_summary: dict[str, Any] = {}
    multiclass_summary: dict[str, Any] = {}
    zero_day_summary: dict[str, Any] = {}
    zero_day_details: list[dict[str, Any]] = []
    rule_result: dict[str, Any] = {}
    incident_response: dict[str, Any] = {}

    results: list[dict[str, Any]] = []
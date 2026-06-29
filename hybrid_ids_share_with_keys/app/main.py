import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from app.inference import analyze_flow_csv
from app.pcap_rules import run_pcap_rules
from app.ir_agent import (
    build_incident_response,
    call_openrouter_triage,
    create_ir_ticket,
    execute_demo_action,
    get_ir_status,
    initialize_ir_data,
    read_ir_report,
)
from app.schemas import AnalyzeResponse
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"
OUTPUTS_DIR = BASE_DIR / "outputs"

UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Hybrid IDS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

initialize_ir_data()


class LlmTriageRequest(BaseModel):
    analysis_result: dict[str, Any]
    analyst_context: dict[str, Any] = {}
    asset_context: dict[str, Any] = {}


class IrActionRequest(BaseModel):
    action_type: str
    target: str
    incident_id: str | None = None
    details: str | None = None


class IrTicketRequest(BaseModel):
    incident_id: str | None = None
    title: str
    priority: str = "Medium"
    assignee: str = "SOC-Tier1"



def _save_upload(file: UploadFile) -> Path:
    dst = UPLOADS_DIR / file.filename
    with open(dst, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return dst


def _resolve_cicflowmeter_function():
    try:
        import app.cicflowmeter_runner as runner
    except Exception as e:
        raise RuntimeError(f"Could not import app.cicflowmeter_runner: {e}")

    candidate_names = [
        "generate_flow_csv_from_pcap",
        "generate_flow_csv",
        "run_cicflowmeter",
        "pcap_to_csv",
        "process_pcap",
        "convert_pcap_to_csv",
    ]

    for name in candidate_names:
        fn = getattr(runner, name, None)
        if callable(fn):
            return fn, name

    raise RuntimeError(
        "No supported CICFlowMeter function was found in app.cicflowmeter_runner. "
        "Expected one of: generate_flow_csv_from_pcap, generate_flow_csv, run_cicflowmeter, "
        "pcap_to_csv, process_pcap, convert_pcap_to_csv"
    )


def _generate_csv_from_pcap(pcap_path: Path) -> Path:
    fn, fn_name = _resolve_cicflowmeter_function()

    try:
        result = fn(str(pcap_path))
    except TypeError:
        try:
            result = fn(str(pcap_path), str(OUTPUTS_DIR))
        except Exception as e:
            raise RuntimeError(f"CICFlowMeter function {fn_name} failed: {e}") from e
    except Exception as e:
        raise RuntimeError(f"CICFlowMeter function {fn_name} failed: {e}") from e

    if isinstance(result, dict):
        for key in ["csv_path", "generated_csv", "output_csv", "path"]:
            if key in result:
                return Path(result[key])

    if isinstance(result, str):
        return Path(result)

    raise RuntimeError(f"Unsupported return value from {fn_name}: {type(result)}")


def _validate_extension(filename: str, forced_mode: str | None = None):
    ext = Path(filename).suffix.lower()

    if forced_mode == "csv":
        if ext != ".csv":
            raise HTTPException(status_code=400, detail="This endpoint accepts CSV files only.")
        return ext

    if forced_mode == "pcap":
        if ext not in [".pcap", ".pcapng"]:
            raise HTTPException(status_code=400, detail="This endpoint accepts PCAP / PCAPNG files only.")
        return ext

    if ext not in [".pcap", ".pcapng", ".csv"]:
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .csv files are supported.")

    return ext


def _safe_run_packet_rules(pcap_path: str):
    try:
        return run_pcap_rules(pcap_path)
    except Exception as e:
        return {
            "status": "error",
            "engine": "dpkt_pcap_rules",
            "message": f"Packet rules failed: {e}",
            "summary": {
                "total_alerts": 0,
                "packets_processed": 0,
                "processing_time_sec": 0.0,
                "window_size_sec": 2.0,
                "dos_threshold_per_ip": 0,
                "dos_threshold_aggregated": 0,
                "average_packet_rate": 0.0,
                "attack_type_summary": {},
                "top_sources": [],
            },
            "sample_alerts": [],
        }


async def _run_analysis(file: UploadFile, forced_mode: str | None = None):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    ext = _validate_extension(file.filename, forced_mode=forced_mode)
    saved_path = _save_upload(file)

    if ext == ".csv":
        packet_rule_result = {
            "status": "skipped",
            "engine": "dpkt_pcap_rules",
            "message": "Packet rules are skipped for CSV uploads.",
            "summary": {
                "total_alerts": 0,
                "packets_processed": 0,
                "processing_time_sec": 0.0,
                "window_size_sec": 2.0,
                "dos_threshold_per_ip": 0,
                "dos_threshold_aggregated": 0,
                "average_packet_rate": 0.0,
                "attack_type_summary": {},
                "top_sources": [],
            },
            "sample_alerts": [],
        }

        csv_path = saved_path
    else:
        with ThreadPoolExecutor(max_workers=2) as executor:
            packet_future = executor.submit(_safe_run_packet_rules, str(saved_path))
            csv_future = executor.submit(_generate_csv_from_pcap, saved_path)

            try:
                csv_path = csv_future.result()
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"PCAP to CSV conversion failed: {e}")

            if not csv_path.exists():
                raise HTTPException(status_code=500, detail=f"Generated CSV not found: {csv_path}")

            results, meta = analyze_flow_csv(str(csv_path))
            packet_rule_result = packet_future.result()

            summary = meta.get("summary", {})
            return {
                "filename": file.filename,
                "generated_csv": str(csv_path),
                "flows_analyzed": summary.get("flows_analyzed", 0),
                "attack_count": summary.get("attack_count", 0),
                "benign_count": summary.get("benign_count", 0),
                "attack_rate": summary.get("attack_rate", 0.0),
                "official_binary_decision": summary.get("official_binary_decision", "UNKNOWN"),
                "prediction_summary": summary.get("prediction_summary", {}),
                "attack_type_summary": summary.get("attack_type_summary", {}),
                "binary_summary": meta.get("binary_summary", {}),
                "multiclass_summary": meta.get("multiclass_summary", {}),
                "zero_day_summary": meta.get("zero_day_summary", {}),
                "zero_day_details": meta.get("zero_day_details", [])[:500],
                "rule_result": packet_rule_result,
                "incident_response": build_incident_response({
                    "filename": file.filename,
                    "generated_csv": str(csv_path),
                    "flows_analyzed": summary.get("flows_analyzed", 0),
                    "attack_count": summary.get("attack_count", 0),
                    "benign_count": summary.get("benign_count", 0),
                    "attack_rate": summary.get("attack_rate", 0.0),
                    "official_binary_decision": summary.get("official_binary_decision", "UNKNOWN"),
                    "prediction_summary": summary.get("prediction_summary", {}),
                    "attack_type_summary": summary.get("attack_type_summary", {}),
                    "binary_summary": meta.get("binary_summary", {}),
                    "multiclass_summary": meta.get("multiclass_summary", {}),
                    "zero_day_summary": meta.get("zero_day_summary", {}),
                    "zero_day_details": meta.get("zero_day_details", [])[:500],
                    "rule_result": packet_rule_result,
                    "results": results[:500],
                }),
                "results": results[:500],
            }

    results, meta = analyze_flow_csv(str(csv_path))
    summary = meta.get("summary", {})

    return {
        "filename": file.filename,
        "generated_csv": str(csv_path),
        "flows_analyzed": summary.get("flows_analyzed", 0),
        "attack_count": summary.get("attack_count", 0),
        "benign_count": summary.get("benign_count", 0),
        "attack_rate": summary.get("attack_rate", 0.0),
        "official_binary_decision": summary.get("official_binary_decision", "UNKNOWN"),
        "prediction_summary": summary.get("prediction_summary", {}),
        "attack_type_summary": summary.get("attack_type_summary", {}),
        "binary_summary": meta.get("binary_summary", {}),
        "multiclass_summary": meta.get("multiclass_summary", {}),
        "zero_day_summary": meta.get("zero_day_summary", {}),
        "zero_day_details": meta.get("zero_day_details", [])[:500],
        "rule_result": packet_rule_result,
        "incident_response": build_incident_response({
            "filename": file.filename,
            "generated_csv": str(csv_path),
            "flows_analyzed": summary.get("flows_analyzed", 0),
            "attack_count": summary.get("attack_count", 0),
            "benign_count": summary.get("benign_count", 0),
            "attack_rate": summary.get("attack_rate", 0.0),
            "official_binary_decision": summary.get("official_binary_decision", "UNKNOWN"),
            "prediction_summary": summary.get("prediction_summary", {}),
            "attack_type_summary": summary.get("attack_type_summary", {}),
            "binary_summary": meta.get("binary_summary", {}),
            "multiclass_summary": meta.get("multiclass_summary", {}),
            "zero_day_summary": meta.get("zero_day_summary", {}),
            "zero_day_details": meta.get("zero_day_details", [])[:500],
            "rule_result": packet_rule_result,
            "results": results[:500],
        }),
        "results": results[:500],
    }


@app.get("/")
def root():
    return {"message": "Hybrid IDS backend is running."}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_file(file: UploadFile = File(...)):
    return await _run_analysis(file, forced_mode=None)


@app.post("/analyze-csv", response_model=AnalyzeResponse)
async def analyze_csv(file: UploadFile = File(...)):
    return await _run_analysis(file, forced_mode="csv")


@app.post("/analyze-pcap", response_model=AnalyzeResponse)
async def analyze_pcap(file: UploadFile = File(...)):
    return await _run_analysis(file, forced_mode="pcap")

@app.post("/incident-response/llm")
def generate_llm_incident_response(payload: LlmTriageRequest):
    markdown = call_openrouter_triage(
        analysis_result=payload.analysis_result,
        analyst_context=payload.analyst_context,
        asset_context=payload.asset_context,
    )
    return {"llm_markdown_response": markdown}


@app.get("/incident-response/status")
def incident_response_status():
    return get_ir_status()


@app.post("/incident-response/execute-action")
def incident_response_execute_action(payload: IrActionRequest):
    try:
        return execute_demo_action(
            action_type=payload.action_type,
            target=payload.target,
            incident_id=payload.incident_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/incident-response/tickets")
def incident_response_create_ticket(payload: IrTicketRequest):
    return create_ir_ticket(
        incident_id=payload.incident_id,
        title=payload.title,
        priority=payload.priority,
        assignee=payload.assignee,
    )


@app.get("/incident-response/reports/{report_id}")
def incident_response_report(report_id: str):
    try:
        return PlainTextResponse(read_ir_report(report_id), media_type="text/markdown")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# Compatibility aliases for the uploaded React IR demo project.
@app.get("/api/status")
def api_status_alias():
    return get_ir_status()


@app.post("/api/execute-action")
def api_execute_action_alias(payload: IrActionRequest):
    return incident_response_execute_action(payload)


@app.post("/api/tickets")
def api_ticket_alias(payload: IrTicketRequest):
    return incident_response_create_ticket(payload)


@app.get("/api/reports/{report_id}")
def api_report_alias(report_id: str):
    return incident_response_report(report_id)

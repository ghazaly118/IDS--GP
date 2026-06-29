from pathlib import Path
import os
import subprocess
import time

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUTS_DIR = BASE_DIR / "outputs"
OUTPUTS_DIR.mkdir(exist_ok=True)

CICFLOW_BIN = Path(
    os.getenv(
        "CICFLOWMETER_BIN",
        r"C:/Users/amoha/OneDrive/Desktop/gp/gp/cicflowmeter_custom/bin/CICFlowMeter.bat",
    )
)

def run_cicflowmeter(pcap_path: str) -> str:
    pcap_file = Path(pcap_path).resolve()

    if not pcap_file.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    if not CICFLOW_BIN.exists():
        raise FileNotFoundError(f"CICFlowMeter.bat not found: {CICFLOW_BIN}")

    output_dir = OUTPUTS_DIR.resolve()
    output_dir.mkdir(exist_ok=True)

    existing_csvs = set(output_dir.glob("*_Flow.csv"))

    cmd = f'"{CICFLOW_BIN}" "{pcap_file}" "{output_dir}"'

    print("Running CICFlowMeter CLI...")
    print("Command:", cmd)
    print("Working directory:", CICFLOW_BIN.parent)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=True,
        cwd=str(CICFLOW_BIN.parent)   # أهم سطر
    )

    print("CICFlowMeter stdout:")
    print(result.stdout)

    if result.stderr:
        print("CICFlowMeter stderr:")
        print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(f"CICFlowMeter failed with exit code {result.returncode}")

    timeout_seconds = 30
    start = time.time()

    while time.time() - start < timeout_seconds:
        current_csvs = set(output_dir.glob("*_Flow.csv"))
        new_csvs = list(current_csvs - existing_csvs)

        if new_csvs:
            latest_csv = max(new_csvs, key=lambda p: p.stat().st_mtime)
            if latest_csv.exists() and latest_csv.stat().st_size > 0:
                print("Generated CSV:", latest_csv)
                return str(latest_csv)

        all_csvs = list(output_dir.glob("*_Flow.csv"))
        if all_csvs:
            latest_csv = max(all_csvs, key=lambda p: p.stat().st_mtime)
            if latest_csv.exists() and latest_csv.stat().st_size > 0:
                print("Generated CSV (fallback):", latest_csv)
                return str(latest_csv)

        time.sleep(1)

    found = list(output_dir.glob("*"))
    raise RuntimeError(
        f"CSV file was not generated in {output_dir}. Found files: {[str(f.name) for f in found]}"
    )
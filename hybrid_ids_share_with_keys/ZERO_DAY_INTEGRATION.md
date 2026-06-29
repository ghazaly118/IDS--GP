# Zero-Day Autoencoder Integration

This version adds a zero-day anomaly stage to the Hybrid IDS workflow.

## New workflow

```text
PCAP / CSV
→ CICFlowMeter CSV features
→ Binary IDS model
→ Conditional multiclass attack classifier
→ Zero-Day Autoencoder anomaly detector
→ Incident Response Agent
```

## What the zero-day model does

The uploaded notebook trains an autoencoder using benign network flows. During inference, the autoencoder reconstructs each flow. The system calculates reconstruction error for every row:

```text
reconstruction_error = mean((scaled_input - reconstructed_input)^2)
```

If the reconstruction error is higher than the saved threshold, the row is flagged as:

```text
POSSIBLE_ZERO_DAY
```

## Required artifacts

Copy these files from the Kaggle notebook output folder:

```text
/kaggle/working/zero_day_autoencoder_parquet/autoencoder_zero_day.keras
/kaggle/working/zero_day_autoencoder_parquet/scaler.joblib
/kaggle/working/zero_day_autoencoder_parquet/meta.json
```

Put them here in the project:

```text
models/zero_day_autoencoder/autoencoder_zero_day.keras
models/zero_day_autoencoder/scaler.joblib
models/zero_day_autoencoder/meta.json
```

You can also use a custom location with:

```powershell
$env:ZERO_DAY_MODEL_DIR="C:\path\to\zero_day_autoencoder"
```

## Files added/changed

```text
app/zero_day_detector.py      New zero-day inference module
app/inference.py              Calls zero-day detector after binary/multiclass
app/main.py                   Returns zero_day_summary and zero_day_details
app/schemas.py                Adds zero-day response fields
app/ir_agent.py               Uses zero-day evidence in severity and recommendations
ui/streamlit_app.py           Adds Zero-Day Detection tab and cards
models/zero_day_autoencoder/  Placeholder folder for artifacts
```

## How to run

```powershell
cd C:\Users\Lenovo\Desktop\hybrid_ids_zero_day_final
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Second terminal:

```powershell
cd C:\Users\Lenovo\Desktop\hybrid_ids_zero_day_final
.\.venv\Scripts\Activate.ps1
streamlit run ui/streamlit_app.py
```

## What to say in the discussion

> We added a zero-day detection stage based on an autoencoder trained on benign flow behavior. The model calculates reconstruction error for each network flow. If the error exceeds the saved threshold, the traffic is treated as anomalous and marked as possible zero-day or unknown attack. This result is then passed to the Incident Response Agent, which increases severity and recommends verification and containment steps without executing dangerous actions automatically.

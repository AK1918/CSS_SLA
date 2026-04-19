# Patient Data Integrity Demo

Simple terminal demo that shows basic integrity (SHA-256) and confidentiality (AES-256) concepts.

Setup

1. Create and activate a virtual environment (recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1  
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

Run

```powershell
py patient_data_system.py
```

Notes

- This is a demo. Keys and data are kept in-memory and are not secure for production.
- The AES code uses simple space-padding for the demo and is NOT recommended for real deployments.

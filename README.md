# SOC Assistant CLI 🛡️

An AI-powered security analyst CLI tool designed to help human SOC analysts triage, investigate, and document security alerts. It normalizes alert payloads (JSON or plain text logs), passes them to Claude via the Anthropic API, returns structured, schema-validated analyses, and formats them beautifully in the terminal and as Markdown reports.

---

## Features

- **Input Normalization**: Ingests JSON alerts or raw log text via files (`--file`) or interactive copy-paste (`--paste`). Normalizes keys such as IPs, hostnames, users, processes, and rule IDs.
- **Structured Claude Analysis**: Uses Claude (default: `claude-sonnet-4-5`) to produce high-fidelity assessments (Severity, MITRE ATT&CK Mapping, False Positive probability, Next Actions, and Investigative Questions).
- **Rich Terminal UI**: Renders assessments using color-coded badges, tables, and borders (powered by the `rich` library).
- **Robust Schema Validation**: Employs Pydantic to guarantee that Claude's output strictly adheres to the requested JSON format. If it fails validation, it performs an auto-retry by feeding the validation error back to Claude.
- **Incident Reporting**: Generates clean, ready-to-paste Markdown reports (`--save report.md`) for ticketing systems (e.g., Jira, ServiceNow).
- **Audit Trails**: Logs all investigations to `./reports/audit.jsonl` (viewable directly via the `logs` command).

---

## Project Structure

```
soc-assistant/
├── soc_assistant/
│   ├── __init__.py
│   ├── cli.py         # Click CLI commands (analyze, logs)
│   ├── ingest.py      # Input normalization & regex heuristics
│   ├── analyzer.py    # Anthropic API call, structured system prompt, retry mechanism
│   ├── models.py      # Pydantic schemas (Alert, Analysis, AuditEntry)
│   ├── render.py      # Terminal formatting (rich) & Markdown reports
│   └── storage.py     # JSONL audit log management
├── tests/             # Pytest suite
├── reports/           # Generated reports & audit log (gitignored)
├── .env.example
├── pyproject.toml
└── README.md
```

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/avikengineer007/AI-Security-operations-center-SOC_Assistant.git
   cd AI-Security-operations-center-SOC_Assistant
   ```
2. **Create a virtual environment and activate it**:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Unix/macOS:
   source .venv/bin/activate
   ```
3. **Install the package in editable mode**:
   ```bash
   pip install -e .[dev]
   ```
4. **Configure your API Key**:
   Copy `.env.example` to `.env` and enter your Anthropic API Key:
   ```env
   ANTHROPIC_API_KEY=your_actual_api_key_here
   ```

---

## Usage

### 1. Analyze an Alert from a File
```bash
soc-assistant analyze --file path/to/alert.json
```

### 2. Analyze an Alert from Copied Text (stdin)
```bash
soc-assistant analyze --paste
```
*Note: Type or paste your alert, then press `Ctrl+D` (Unix) or `Ctrl+Z` then `Enter` (Windows) to run the analysis.*

### 3. Generate a Markdown Report
```bash
soc-assistant analyze --file path/to/alert.json --save reports/incident-01.md
```

### 4. Overriding the Claude Model
```bash
soc-assistant analyze --file path/to/alert.json --model claude-3-5-haiku-20241022
```

### 5. Skip Audit Logging
```bash
soc-assistant analyze --file path/to/alert.json --no-log
```

### 6. View Investigation History
```bash
soc-assistant logs --last 5
```

---

## Development & Testing

Run unit tests:
```bash
pytest
```

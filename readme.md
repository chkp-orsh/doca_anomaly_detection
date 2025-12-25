AI AGENT ANOMALY DETECTOR
========================

EXECUTIVE SUMMARY
-----------------
The AI Agent Anomaly Detector is a behavior-based security detection framework designed to identify anomalous or risky activity originating from AI agents and AI-enabled processes in enterprise environments.

Instead of relying on signatures, the system builds behavioral baselines for AI processes and continuously detects deviations such as:
- New or unauthorized AI agents
- Suspicious network communication (new domains, IPs, ports)
- Abnormal model file access or modification
- Unexpected child process spawning
- Excessive data transfer
- New users executing known AI workloads

The detector integrates with Azure Data Explorer (Kusto), supports privacy-preserving obfuscation, and is intended for SOC, threat hunting, and AI risk governance use cases.

------------------------------------------------------------

OVERVIEW
--------
The AI Agent Anomaly Detector analyzes endpoint telemetry to detect AI-related processes and their behavior over time. It uses a baseline-and-deviation model to distinguish normal AI activity from suspicious or potentially malicious behavior.

The system operates in multiple modes:
- Bootstrap: build or extend baselines
- Detect: identify anomalies
- Collect: store raw telemetry
- Train: rebuild baselines from historical data

------------------------------------------------------------

CORE DESIGN
-----------
Detection is based on two correlated queries:

1. AI PROCESS BEHAVIOR
   - Identifies AI processes using:
     - Model files (e.g. .pt, .onnx, .gguf)
     - AI runtimes (Torch, TensorFlow, ONNX, etc.)
     - LLM API communication
     - AI-related command-line arguments
   - Aggregates:
     - Network domains, IPs, ports
     - Files and directories accessed
     - File modification details
     - Runtime statistics

2. CHILD PROCESS SPAWNING
   - Tracks child processes spawned by AI parent processes
   - Detects:
     - New child processes
     - Unusual command-line arguments
     - First-time spawn behavior

------------------------------------------------------------

BASELINE MODEL
--------------
Baselines are built per unique combination of:

(Machine Name, Process Name, Normalized Arguments, Process Signer)

Each baseline tracks:
- Spawned processes and arguments
- Contacted domains, IPs, and ports
- Accessed files and directories
- Modified model files
- Users running the process
- Network transfer statistics

Baselines support:
- Frequency thresholds (learning phase)
- Time-based decay of old behavior
- Incremental merging across runs

------------------------------------------------------------

ANOMALY TYPES
-------------
The detector raises alerts for the following conditions:

- New AI agent not present in baseline
- AI agent still in learning phase
- New user running a known AI process
- New network domains, IPs, or ports
- New directories or files accessed
- Excessive data transfer compared to baseline
- First-time model file modification
- Model file modified by a new or unauthorized user
- Model file modified with unusual arguments
- New or unusual child process spawning

------------------------------------------------------------

SEVERITY LEVELS
---------------
INFO     - Learning phase or informational
LOW      - New but low-risk behavior
MEDIUM   - Suspicious deviation
HIGH     - Strong anomaly
CRITICAL - Likely compromise or policy violation

------------------------------------------------------------

PRIVACY AND OBFUSCATION
----------------------
To protect sensitive data:
- Machine names and usernames are AES-encrypted at rest
- Encryption key is derived from the output directory
- Baselines are automatically de-obfuscated when loaded

------------------------------------------------------------

MODES OF OPERATION
------------------

BOOTSTRAP
---------
Builds or extends the baseline using historical data.

Example:
python AIModelAndDetect8.py \
  --cluster <cluster_url> \
  --database <database_name> \
  --tenant <tenant_table> \
  --output-dir ./output \
  --mode bootstrap \
  --bootstrap-count 7

This mode:
- Collects data over multiple periods
- Merges with existing baselines if present
- Applies frequency and decay logic

------------------------------------------------------------

DETECT
------
Runs anomaly detection using an existing baseline.

Example:
python AIModelAndDetect8.py \
  --cluster <cluster_url> \
  --database <database_name> \
  --tenant <tenant_table> \
  --output-dir ./output \
  --mode detect

This mode:
- Compares current behavior to baseline
- Generates alerts
- Saves results to CSV

------------------------------------------------------------

COLLECT
-------
Collects raw telemetry without detection.

Example:
python AIModelAndDetect8.py \
  --cluster <cluster_url> \
  --database <database_name> \
  --tenant <tenant_table> \
  --output-dir ./output \
  --mode collect \
  --lookback-count 3

------------------------------------------------------------

TRAIN
-----
Rebuilds a baseline from previously collected raw data.

Example:
python AIModelAndDetect8.py \
  --cluster <cluster_url> \
  --database <database_name> \
  --tenant <tenant_table> \
  --output-dir ./output \
  --mode train

------------------------------------------------------------

OUTPUT STRUCTURE
----------------
output/
  baselines/
    baseline_latest.json
    baseline_YYYYMMDD_HHMMSS.json
  alerts/
    alerts_YYYYMMDD_HHMMSS.csv
    all_alerts.csv
  raw_collections/
    process_YYYYMMDD.csv
    child_YYYYMMDD.csv

------------------------------------------------------------

DEPENDENCIES
------------
- Python 3.9+
- pandas
- azure-kusto-data
- cryptography
- Azure CLI authentication

------------------------------------------------------------

RECOMMENDED USAGE
-----------------
1. Run bootstrap for 7–14 days
2. Allow agents to exit learning phase
3. Run daily detection
4. Investigate HIGH and CRITICAL alerts
5. Allow baseline to evolve via frequency and decay

------------------------------------------------------------

DISCLAIMER
----------
This system detects behavioral anomalies, not confirmed malicious activity.
All alerts should be reviewed by a qualified security analyst before action.

# ai_anomaly_static.py
# Central place for static configuration and mappings used by the AI Anomaly Detector.

from __future__ import annotations
# ai_anomaly_static.py

import re

# ============================================================
# Model / tokenizer / config extensions (Python-side)
# ============================================================
MODEL_FILE_EXTENSIONS = {
    "gguf", "ggml", "bin", "pt", "pth", "ckpt", "safetensors", "onnx",
    "tflite", "pb", "h5", "pkl", "joblib", "mlmodel", "engine", "plan",
    "params", "weights"
}

TOKENIZER_AND_CONFIG_EXTENSIONS = {
    "json", "yaml", "yml", "txt", "model", "spm", "tiktoken", "vocab"
}

# Optional: identify “model-ish” files by name patterns (Python-side)
MODEL_FILENAME_KEYWORDS = {
    "model", "weights", "checkpoint", "ckpt", "tokenizer", "vocab", "merges",
    "config", "adapter", "lora", "qlora"
}

# ============================================================
# Suspicious cmdline keywords (Python-side)
# Keep this “small and high-signal” to avoid false positives.
# ============================================================
SUSPICIOUS_CMDLINE_KEYWORDS = {
    # data access/exfil-ish
    "exfil", "upload", "curl ", "wget ", "scp ", "sftp ", "rsync ",
    # credential/secret-ish
    "token", "apikey", "api_key", "secret", "passwd", "password", "bearer ",
    # persistence / tool abuse
    "powershell", "cmd.exe", "rundll32", "reg add", "schtasks", "wmic",
    # AI-specific misuse (tune to your environment)
    "prompt injection", "jailbreak", "system prompt", "steal prompt",
    "dump", "extract", "leak"
}

# ============================================================
# Known AI serving process names / interpreters (Python-side)
# These are used in detection logic, *not* in the Kusto query.
# ============================================================
KNOWN_AI_SERVING_PROCESS_NAMES = {
    "ollama.exe", "ollama",
    "lmstudio.exe", "lm studio",
    "text-generation-launcher", "text-generation-server",
    "vllm", "vllm.exe",
    "tritonserver", "tritonserver.exe",
    "torchserve", "torchserve.exe",
    "tgi", "tgi.exe",
    "llama-server", "llama-server.exe",
    "koboldcpp.exe", "koboldcpp",
    "oobabooga", "webui",
    "open-webui", "openwebui",
    "litellm", "litellm.exe",
}

GENERIC_INTERPRETER_PROCESS_NAMES = {
    "python.exe", "python",
    "node.exe", "node",
    "java.exe", "java",
    "ruby.exe", "ruby",
    "perl.exe", "perl",
    "pwsh.exe", "powershell.exe", "powershell",
    "cmd.exe", "bash", "zsh", "sh"
}

# ============================================================
# Regex patterns (compile once)
# Use these for command-line normalization, model path detection, etc.
# ============================================================
REGEX_PATTERNS = {
    # Replace GUIDs / hashes (tune if too aggressive)
    "guid": re.compile(r"\b[0-9a-fA-F]{8}\b-(?:[0-9a-fA-F]{4}\b-){3}[0-9a-fA-F]{12}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),

    # Windows user profile normalization (you already normalize paths; this helps)
    "user_profile": re.compile(r"(?i)\\users\\[^\\]+\\"),
}

# Optional: model-ish paths (if you want Python-side path scoring)
MODEL_PATH_PATTERNS = [
    re.compile(r"(?i)\\models?\\"),
    re.compile(r"(?i)\\ollama\\"),
    re.compile(r"(?i)\\lm\s*studio\\"),
    re.compile(r"(?i)\\huggingface\\"),
]

# ai_anomaly_static.py

TOOL_PROCESS_NAMES = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "zsh", "sh",
    "python.exe", "python", "node.exe", "node", "java.exe", "java",
    "curl", "wget", "scp", "sftp", "ssh", "kubectl", "helm", "az", "aws", "gcloud"
]

COMMON_DEV_OR_BROWSER_PROCESSES = [
    "chrome.exe", "msedge.exe", "firefox.exe", "code.exe", "idea64.exe",
    "pycharm64.exe", "explorer.exe"
]

LOCALHOST_ADDRESSES = ["127.0.0.1", "::1"]

COMMON_AI_SERVING_PORTS = [11434, 7860, 5000, 5001, 8000, 8001, 8080, 8888, 8889, 443, 9000, 9001, 3000]

LLM_API_PATH_FRAGMENTS = ["/sse", "/mcp/v1", "/events", "/chat/completions", "/v1/chat", "/v1/completions"]
LLM_API_DOMAINS = [
    "api.openai.com", "openai.azure.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.mistral.ai", "api.cohere.ai", "api.groq.com", "openrouter.ai",
    "api-inference.huggingface.co", "api.replicate.com", "api.stability.ai", "litellm"
]

KNOWN_AI_SERVING_PROCESS_NAMES = ["open-webui", "litellm", "vllm", "ollama", "torchserve", "oobabooga", "koboldcpp", "lmstudio"]
GENERIC_INTERPRETER_PROCESS_NAMES = ["python", "python3", "node", "npm", "java", "dotnet", "dotnet.exe", "go", "uvicorn", "gunicorn"]

AI_CMDLINE_KEYWORDS = ["mcp_server", "mcp-server", "--model", "inference", "serve", "server", "llm", "embeddings"]

AI_MODULE_FILENAME_PATTERNS = ["torch_cpu", "torch_cuda", "transformers", "tokenizers", "llama", "tensorrt", "cudart", "cublas", "cudnn"]
AI_MODULE_PATH_PATTERNS = ["torch", "transformers", "tokenizers", "onnx", "checkpoints", "models", "litellm", "fastchat", "vicuna"]

MODEL_FILE_EXTENSIONS = ["ckpt", "pt", "pth", "safetensors", "onnx", "pb", "tflite", "gguf", "ggml", "h5", "pkl", "model"]
TOKENIZER_AND_CONFIG_EXTENSIONS = ["json", "yaml", "yml", "tokenizer", "spm", "bpe", "vocab"]

# ============================================================
# Severity thresholds (Python-side)
# Centralizes “policy knobs”
# ============================================================
SEVERITY_THRESHOLDS = {
    # Example knobs — tune to your telemetry
    "excessive_transfer_mb_critical": 50,      # >= 50MB sent
    "new_files_medium": 50,                    # 50+ new files
    "new_domains_high": 3,                     # 3+ new domains
    "new_ports_medium": 1,
    "signer_changed_default": "HIGH",
    "signer_changed_if_unsigned": "CRITICAL",
    "min_ai_score" : 7,
}

__all__ = [
    "MODEL_FILE_EXTENSIONS",
    "TOKENIZER_AND_CONFIG_EXTENSIONS",
    "MODEL_FILENAME_KEYWORDS",
    "SUSPICIOUS_CMDLINE_KEYWORDS",
    "KNOWN_AI_SERVING_PROCESS_NAMES",
    "GENERIC_INTERPRETER_PROCESS_NAMES",
    "REGEX_PATTERNS",
    "MODEL_PATH_PATTERNS",
    "SEVERITY_THRESHOLDS",
    "ALERT_CLASSIFICATION",
    "ALERT_RUNBOOKS",
]


# ============================================================
# MITRE ATT&CK + AI Risk Taxonomy Mapping
# ============================================================
ALERT_CLASSIFICATION = {
    "ALERT_NEW_AI_AGENT_NOT_IN_BASELINE": {
        "mitre": ["T1059"],
        "ai_risk": ["Shadow AI", "Unauthorized AI Deployment"],
        "confidence": "Medium",
    },
    "ALERT_AI_AGENT_IN_LEARNING_PHASE": {
        "mitre": [],
        "ai_risk": ["Baseline Learning"],
        "confidence": "Low",
    },
    "ALERT_NEW_USER_FOR_PROCESS": {
        "mitre": ["T1078"],
        "ai_risk": ["Unauthorized AI Usage", "Privilege Abuse"],
        "confidence": "High",
    },
    "ALERT_NEW_DOMAINS": {
        "mitre": ["T1071.001"],
        "ai_risk": ["Data Exfiltration", "Unapproved AI Provider"],
        "confidence": "High",
    },
    "ALERT_NEW_IPS": {
        "mitre": ["T1071"],
        "ai_risk": ["Data Exfiltration"],
        "confidence": "High",
    },
    "ALERT_NEW_PORTS": {
        "mitre": ["T1046"],
        "ai_risk": ["Unapproved Service Exposure", "Suspicious Connectivity"],
        "confidence": "Medium",
    },
    "ALERT_NEW_DIRECTORIES": {
        "mitre": ["T1083"],
        "ai_risk": ["Sensitive Data Discovery"],
        "confidence": "Medium",
    },
    "ALERT_ACCESSING_MANY_NEW_FILES": {
        "mitre": ["T1005"],
        "ai_risk": ["Bulk Data Access"],
        "confidence": "Medium",
    },
    "ALERT_NEW_FILE_EXTENSIONS": {
        "mitre": ["T1005"],
        "ai_risk": ["Sensitive Data Access"],
        "confidence": "Medium",
    },
    "ALERT_EXCESSIVE_TRANSFER": {
        "mitre": ["T1041"],
        "ai_risk": ["Sensitive Data Leakage"],
        "confidence": "Critical",
    },
    "ALERT_NEW_MODEL_FILE_MODIFICATION": {
        "mitre": ["T1565.001"],
        "ai_risk": ["Model Poisoning", "Model Integrity Violation"],
        "confidence": "Critical",
    },
    "ALERT_MODEL_FILE_MODIFIED_BY_NEW_USER": {
        "mitre": ["T1078", "T1565.001"],
        "ai_risk": ["Unauthorized Model Access", "Model Poisoning"],
        "confidence": "Critical",
    },
    "ALERT_MODEL_FILE_MODIFIED_WITH_UNUSUAL_ARGS": {
        "mitre": ["T1059", "T1565.001"],
        "ai_risk": ["Model Tampering", "Model Backdooring"],
        "confidence": "High",
    },
    "ALERT_NEW_SPAWNED_PROCESS": {
        "mitre": ["T1106", "T1059"],
        "ai_risk": ["AI Agent Abuse", "Post-Exploitation"],
        "confidence": "High",
    },

    # NOTE: your code currently uses this exact string; keep it consistent
    "SALERT_PAWNED_PROCESS_UNUSUAL_ARGS": {
        "mitre": ["T1059"],
        "ai_risk": ["Living-off-the-Land via AI"],
        "confidence": "High",
    },

    # If you add signer-change:
    "ALERT_PROCESS_SIGNER_CHANGED": {
        "mitre": ["T1553.002"],  # Code Signing
        "ai_risk": ["Binary Integrity", "Execution Trust Change"],
        "confidence": "High",
    },
}

# ============================================================
# SOC RUNBOOKS PER ALERT TYPE
# ============================================================
ALERT_RUNBOOKS = {
    "ALERT_NEW_AI_AGENT_NOT_IN_BASELINE": {
        "summary": "New AI-related process detected that has no prior baseline.",
        "triage": [
            "Confirm whether AI usage is expected on this host",
            "Validate process path and signer",
            "Verify the user is allowed to run AI workloads",
        ],
        "investigation": [
            "Review command-line arguments",
            "Review contacted domains/IPs and data volume",
            "Check recent installs or deployments on the host",
        ],
        "response": [
            "Monitor if legitimate",
            "Escalate if unauthorized or unexpected",
        ],
    },
    "ALERT_AI_AGENT_IN_LEARNING_PHASE": {
        "summary": "AI process is still learning baseline behavior.",
        "triage": ["No immediate action unless other anomalies exist."],
        "investigation": ["Monitor until learning completes."],
        "response": ["None (informational)."],
    },
    "ALERT_NEW_USER_FOR_PROCESS": {
        "summary": "Known AI process executed by a new user.",
        "triage": [
            "Verify user role / authorization",
            "Check for recent credential or privilege changes",
        ],
        "investigation": [
            "Review authentication logs and endpoints accessed",
            "Look for lateral movement indicators",
        ],
        "response": [
            "Revoke access if unauthorized",
            "Escalate to IR if privilege abuse suspected",
        ],
    },
    "ALERT_NEW_DOMAINS": {
        "summary": "AI process contacted new external domains.",
        "triage": [
            "Reputation check for domain",
            "Determine if domain is approved AI provider",
        ],
        "investigation": [
            "Inspect bytes sent/received for exfil",
            "Correlate with recent file/model access",
        ],
        "response": [
            "Block domain if malicious",
            "Contain host if data exfil suspected",
        ],
    },
    "ALERT_NEW_IPS": {
        "summary": "AI process contacted new IP addresses.",
        "triage": [
            "Reputation/ASN check for IP",
            "Check if IP belongs to known provider / internal range",
        ],
        "investigation": ["Correlate with data transfer + file access"],
        "response": ["Block/contain if suspicious"],
    },
    "ALERT_NEW_PORTS": {
        "summary": "AI process used new network port(s) not seen in baseline.",
        "triage": ["Check whether port is standard for known AI serving stack"],
        "investigation": ["Verify service and destination on that port"],
        "response": ["Escalate if port indicates tunneling / unusual service exposure"],
    },
    "ALERT_NEW_DIRECTORIES": {
        "summary": "AI process accessed new directories not present in baseline.",
        "triage": ["Determine sensitivity of the new directories"],
        "investigation": ["Review file access patterns and user authorization"],
        "response": ["Escalate if sensitive data discovery suspected"],
    },
    "ALERT_ACCESSING_MANY_NEW_FILES": {
        "summary": "AI process accessed many new files compared to baseline.",
        "triage": ["Check if this is a bulk export/training job"],
        "investigation": ["Identify file types and sensitivity; correlate with network activity"],
        "response": ["Contain and escalate if sensitive data involved"],
    },
    "ALERT_NEW_FILE_EXTENSIONS": {
        "summary": "AI process accessed new file extensions not seen in baseline.",
        "triage": ["Assess whether extensions are sensitive or executable"],
        "investigation": ["Review filenames, paths, and related processes"],
        "response": ["Escalate if access indicates credential/code harvesting"],
    },
    "ALERT_EXCESSIVE_TRANSFER": {
        "summary": "AI process transferred significantly more data than baseline.",
        "triage": ["Identify destination and accessed data source(s)"],
        "investigation": ["Determine if training/export/exfil; check DLP context"],
        "response": ["Isolate host if data loss suspected; escalate to IR"],
    },
    "ALERT_NEW_MODEL_FILE_MODIFICATION": {
        "summary": "Model file modified for the first time.",
        "triage": ["Identify model and business owner; validate modifying user"],
        "investigation": ["Check for poisoning/backdoor indicators; preserve artifact"],
        "response": ["Lock/restore model; escalate to IR immediately"],
    },
    "ALERT_MODEL_FILE_MODIFIED_BY_NEW_USER": {
        "summary": "Model file modified by a user not previously associated with it.",
        "triage": ["Confirm user authorization; check change ticket"],
        "investigation": ["Review command-line and modification lineage"],
        "response": ["Revoke access if unauthorized; escalate to IR"],
    },
    "ALERT_MODEL_FILE_MODIFIED_WITH_UNUSUAL_ARGS": {
        "summary": "Model file modified using unusual command-line arguments.",
        "triage": ["Compare args to baseline and expected workflows"],
        "investigation": ["Validate integrity; check for backdoor/poisoning behavior"],
        "response": ["Restore known-good model; escalate to IR"],
    },
    "ALERT_NEW_SPAWNED_PROCESS": {
        "summary": "AI process spawned a new child process never seen before.",
        "triage": ["Identify child process; check LOLBin/admin tooling usage"],
        "investigation": ["Analyze full parent/child chain and related network activity"],
        "response": ["Contain if suspicious; escalate to IR"],
    },
    "SALERT_PAWNED_PROCESS_UNUSUAL_ARGS": {
        "summary": "AI process spawned a child process with unusual arguments.",
        "triage": ["Review child args vs baseline"],
        "investigation": ["Check for exfil/tool abuse"],
        "response": ["Escalate if args indicate abuse"],
    },
    "ALERT_PROCESS_SIGNER_CHANGED": {
        "summary": "Process signature changed for same machine/process/args.",
        "triage": ["Compare old vs new signer; check if signer became UNKNOWN/UNSIGNED"],
        "investigation": ["Verify file hash, path, and install/update source"],
        "response": ["Escalate if signer downgrade or unexpected publisher"],
    },
}

__all__ = ["ALERT_CLASSIFICATION", "ALERT_RUNBOOKS"]

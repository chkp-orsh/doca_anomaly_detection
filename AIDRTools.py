from __future__ import annotations

import socket
from datetime import datetime
import pandas as pd
import numpy as np
import json
import re
import hashlib
from datetime import datetime
from ai_anomaly_defs import REGEX_PATTERNS, MODEL_PATH_PATTERNS

def format_alert_as_checkpoint_log(alert, anomaly, detector):
    """Format anomaly as Check Point-style log entry"""
    import socket
    from datetime import datetime
    
    # Parse timestamp
    try:
        ts_int = int(alert['timestamp'])
        dt = datetime.fromtimestamp(ts_int)
        time_str = dt.strftime('%d%b%Y-%H:%M:%S')
    except:
        time_str = "UNKNOWN"
    
    # Generate HLL key (hash of alert)
    hll_key = int(hashlib.sha1(f"{alert['timestamp']}{alert['machine']}{alert['process']}".encode()).hexdigest()[:8], 16)
    
    # Map severity to numeric
    severity_map = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    severity_numeric = severity_map.get(anomaly.get('severity', 'MEDIUM'), 2)
    
    # Map confidence to level
    conf_score = anomaly.get('confidence_score', 0.0)
    if conf_score >= 0.8:
        conf_level = "HIGH"
    elif conf_score >= 0.5:
        conf_level = "MEDIUM"
    else:
        conf_level = "LOW"
    
    # Build log entry
    log_parts = []
    log_parts.append(f"==>Version: 1")
    log_parts.append(f"Time: {time_str}")
    log_parts.append(f"Flags: 0x24000")
    log_parts.append(f"Direction: internal")
    log_parts.append(f"Connection")
    log_parts.append(f"HLL Key: {hll_key}")
    log_parts.append(f"OriginSicName: \"CN=AIAnomalyDetector,O=CheckPoint\"")
    log_parts.append(f"Origin: {alert.get('machine', 'UNKNOWN')[:50]}")
    log_parts.append(f"LogId: 256")
    log_parts.append(f"Action: detect")
    log_parts.append(f"Interface: \"AI-Agent-Monitor\"")
    
    # Dynamic fields in ['key': value] format
    fields = []
    fields.append(f"['suppressed_logs': 0]")
    fields.append(f"['product': \"AI Agent Anomaly Detection\"]")
    fields.append(f"['process': \"{alert.get('process', 'UNKNOWN')}\"]")
    fields.append(f"['machine': \"{detector._deobfuscate_machine_name(alert.get('machine', 'UNKNOWN'))}\"]")
    fields.append(f"['user': \"{detector._deobfuscate_user_name(alert.get('user', 'UNKNOWN'))}\"]")
    fields.append(f"['signer': \"{alert.get('signer', 'UNKNOWN')}\"]")
    fields.append(f"['pid': {alert.get('pid', 0)}]")
    fields.append(f"['process_args': \"{alert.get('process_args', '')[:100]}\"]")
    
    # Network context if available
    observed = anomaly.get('observed', {})
    if observed.get('contacted_domains'):
        domains = observed['contacted_domains'][:3]
        fields.append(f"['contacted_domains': \"{', '.join(str(d) for d in domains)}\"]")
    
    if observed.get('contacted_ips'):
        ips = observed['contacted_ips'][:3]
        fields.append(f"['contacted_ips': \"{', '.join(str(i) for i in ips)}\"]")
    
    if observed.get('network_bytes_sent', 0) > 0:
        fields.append(f"['network_bytes_sent': {observed['network_bytes_sent']}]")
    
    # Protection details
    fields.append(f"['protection_type': \"AI Behavioral Analytics\"]")
    fields.append(f"['conn_direction': \"AI-Agent\"]")
    fields.append(f"['Protection_Name': \"{anomaly.get('type', 'UNKNOWN')}\"]")
    
    # Risk classification
    mitre = anomaly.get('mitre_attack', [])
    ai_risk = anomaly.get('ai_risk', [])
    if ai_risk:
        fields.append(f"['malware_family': \"{','.join(ai_risk)}\"]")
    
    # Severity and confidence
    fields.append(f"['rep_risk': \"{int(conf_score * 100)}\"]")
    fields.append(f"['Severity': {anomaly.get('severity', 'MEDIUM')}]")
    fields.append(f"['Confidence_Level': {conf_level}]")
    fields.append(f"['confidence_score': {conf_score:.2f}]")
    fields.append(f"['hll_key': {hll_key}]")
    
    # MITRE ATT&CK
    if mitre:
        fields.append(f"['mitre_attack': \"{','.join(mitre)}\"]")
    
    # Alert description and reason
    fields.append(f"['Description': \"{anomaly.get('details', '')[:200]}\"]")
    
    # Build reason from anomaly context
    baseline_context = anomaly.get('baseline_context', {})
    reason_parts = []
    reason_parts.append(f"AI Agent: {alert.get('process', 'UNKNOWN')}")
    reason_parts.append(f"on {detector._deobfuscate_machine_name(alert.get('machine', 'UNKNOWN'))}")
    
    if baseline_context.get('occurrence_count'):
        reason_parts.append(f"seen {baseline_context['occurrence_count']} times before")
    
    reason_parts.append(anomaly.get('details', '')[:300])
    
    fields.append(f"['reason': \"{' - '.join(reason_parts)}\"]")
    
    # Combine all parts
    log_entry = " ".join(log_parts) + " " + " ".join(fields) + " <=="
    
    return log_entry
    

def normalize_filename(filename):
    """Normalize filenames to remove variable parts"""
    if not filename or pd.isna(filename):
        return ""
    
    import re
    filename = str(filename).strip()
    
    if '\\' in filename or '/' in filename:
        filename = filename.split('\\')[-1].split('/')[-1]
    
    filename = filename.lower()
    filename = re.sub(r'(\D+)\d+(\.\w+)$', r'\1<NUM>\2', filename)
    filename = re.sub(r'_\d{3,}', '_<NUM>', filename)
    filename = re.sub(r'[0-9a-f]{32,}', '<HASH>', filename, flags=re.IGNORECASE)
    filename = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<GUID>', filename, flags=re.IGNORECASE)
    filename = re.sub(r'\d{8}_\d{6}', '<TIMESTAMP>', filename)
    
    return filename.strip()
    
def normalize_process_args_ef(args):
    """Normalize process arguments by removing ephemeral values"""
    if not args or not str(args).strip():
        return ""
    
    normalized = str(args).strip()
    
    # Import patterns
    from ai_anomaly_defs import EPHEMERAL_PATTERNS
    import re
    
    # Apply ephemeral pattern masking
    for pattern, replacement in EPHEMERAL_PATTERNS:
        #normalized = re.sub(pattern, replacement, normalized, flags=re.IGNORECASE)
        normalized = re.sub(pattern, replacement, normalized)  # No flags parameter
    
    # Existing normalization...
    # (keep your existing path, PID, timestamp normalization)
    
    return normalized


def normalize_process_args(args):
    if not args or pd.isna(args):
        return ""

    import re
    args = str(args)

    # Defensive normalization for volatile compound IDs
    args = re.sub(
        r'(--native_msg_channel=)[^\s]+',
        r'\1<GUID_CHANNEL>',
        args,
        flags=re.IGNORECASE
    )
        
    args = re.sub(
        r'--native_msg_channel=[^ ]*<NUM>[^ ]*',
        '--native_msg_channel=<GUID_CHANNEL>',
        args,
        flags=re.IGNORECASE
    )    
    # Replace full GUIDs anywhere in token
    args = REGEX_PATTERNS["guid"].sub("<GUID>", args)

    # Hashes
    args = REGEX_PATTERNS["sha256"].sub("<SHA256>", args)
    args = REGEX_PATTERNS["sha1"].sub("<SHA1>", args)
    args = REGEX_PATTERNS["md5"].sub("<MD5>", args)

    # Only now do numeric/path/etc replacement
    args = re.sub(r'\b\d{4,}\b', '<NUM>', args)
    args = re.sub(r'[A-Za-z]:\\[^\s]+', '<PATH>', args, flags=re.IGNORECASE)
    args = re.sub(r'/[^\s]+\.(pt|pkl|onnx|h5|bin|gguf|pth|safetensors)', '<MODELFILE>', args)
    args = re.sub(r'/[^\s/]+/[^\s]+', '<PATH>', args)
    args = re.sub(r'\d{8}_\d{6}', '<TIMESTAMP>', args)
    args = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', args)
    args = re.sub(r':\d{4,5}', ':<PORT>', args)
    args = re.sub(r'0x[0-9a-f]+', '<HEX>', args, flags=re.IGNORECASE)

    args = normalize_process_args_ef(args)
    return args.strip()

    
    
def normalize_process_args_old( args):
    """Extract stable command pattern"""
    if not args or pd.isna(args):
        return ""
    
    import re
    args = str(args)
    
    args = REGEX_PATTERNS["guid"].sub("<GUID>", args)
    args = REGEX_PATTERNS["sha256"].sub("<SHA256>", args)
    args = REGEX_PATTERNS["sha1"].sub("<SHA1>", args)
    args = REGEX_PATTERNS["md5"].sub("<MD5>", args)
    
    args = re.sub(r'\b\d{4,}\b', '<NUM>', args)
    args = re.sub(r'[A-Za-z]:\\[^\s]+', '<PATH>', args, flags=re.IGNORECASE)
    args = re.sub(r'/[^\s]+\.(pt|pkl|onnx|h5|bin|gguf|pth|safetensors)', '<MODELFILE>', args)
    args = re.sub(r'/[^\s/]+/[^\s]+', '<PATH>', args)
    args = re.sub(r'\d{8}_\d{6}', '<TIMESTAMP>', args)
    args = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', args)
    args = re.sub(r':\d{4,5}', ':<PORT>', args)
    args = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', args, flags=re.IGNORECASE)
    args = re.sub(r'0x[0-9a-f]+', '<HEX>', args, flags=re.IGNORECASE)
    
    args=normalize_process_args_ef(args)
    return args.strip()
    
def normalize_directory_path( path):
    """Normalize directory paths"""
    if not path or pd.isna(path):
        return ""
    
    import re
    path = str(path).lower()
    
    path = REGEX_PATTERNS["user_profile"].sub(r"\\users\\<USER>\\", path)
    path = re.sub(r'\\device\\harddiskvolume\d+', r'\\device\\harddiskvolume<VOL>', path)
    path = re.sub(r'c:\\users\\[^\\]+', r'c:\\users\\<USER>', path, flags=re.IGNORECASE)
    path = re.sub(r'/home/[^/]+', r'/home/<USER>', path)
    path = re.sub(r'_mei\d+', r'_mei<NUM>', path)
    path = re.sub(r'\\temp\d+', r'\temp<NUM>', path)
    path = re.sub(r'\b20\d{2}-\d{2}\b', '<DATE>', path)
    path = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '<DATE>', path)
    path = re.sub(r'[0-9a-f]{32,}(_\d+)?', '<HASH>', path, flags=re.IGNORECASE)
    path = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<GUID>', path, flags=re.IGNORECASE)
    path = re.sub(r'[_\\]v?\d+\.\d+(\.\d+)?', r'\<VER>', path)
    path = re.sub(r'[_\\]\d+$', '', path)
    
    return path.strip()


def normalize_signer( signer):
    """Normalize signer"""
    if not signer or pd.isna(signer) or str(signer).strip() == '':
        return 'ERR:NOT-REPORTED'
    return str(signer).strip()

def safe_parse_list(value):
    """Safely parse a value"""
    if value is None:
        return []
    
    if isinstance(value, list):
        return value
    
    if isinstance(value, (list, tuple, set)):
        return list(value)
    
    if isinstance(value, str):
        try:
            parsed = eval(value)
            return parsed if isinstance(parsed, list) else [parsed]
        except:
            return []
    
    return [value]
        
        
def to_json_str(v, max_len: int = 20000) -> str:
    """Safe stringify for CSV"""
    if v is None:
        return ""
    try:
        if isinstance(v, set):
            v = list(v)
        if isinstance(v, (dict, list, tuple)):
            s = json.dumps(v, ensure_ascii=False, separators=(",", ":"), default=str)
        else:
            s = str(v)
    except Exception:
        s = str(v)

    if max_len and len(s) > max_len:
        return s[:max_len] + "...(truncated)"
    return s
    
    
def make_json_serializable( obj):
    """Convert non-serializable objects to JSON-compatible types"""
    import numpy as np
    
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif pd.isna(obj):
        return None
    elif isinstance(obj, (datetime, pd.Timestamp)):
        return str(obj)
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [make_json_serializable(item) for item in obj]
    else:
        return obj
        
        
def get_current_date():
        """Get current date as string"""
        return datetime.now().strftime('%Y-%m-%d')

def days_since( date_str):
    """Calculate days between date_str and today"""
    try:
        past = datetime.strptime(date_str, '%Y-%m-%d')
        now = datetime.now()
        return (now - past).days
    except:
        return 999
        

def _normalize_spawned_process_name( name: str | None) -> str:
    """Normalize spawned child process names that contain run-specific IDs.
    Example: msib42.tmp / msi35c4.tmp -> msi*.tmp
    """
    if not name:
        return ""
    n = str(name).strip()
    # common MSI temp binaries: msi<hex>.tmp (case-insensitive)
    if re.match(r"^msi[0-9a-f]+\.tmp$", n, flags=re.IGNORECASE):
        return "msi*.tmp"
    return n.lower()

import re
from collections import Counter
from typing import Optional, Tuple, Dict, Any, List


def lcp(strings: List[str]) -> str:
    """Longest common prefix."""
    if not strings:
        return ""
    s1 = min(strings)
    s2 = max(strings)
    i = 0
    while i < len(s1) and i < len(s2) and s1[i].lower() == s2[i].lower():
        i += 1
    return s1[:i]


def lcsuffix(strings: List[str]) -> str:
    """Longest common suffix."""
    if not strings:
        return ""
    rev = [s[::-1] for s in strings]
    return lcp(rev)[::-1]


def looks_variable_token(token: str) -> bool:
    """
    Evidence the varying part is run-specific:
    digits, hex, guid-ish, mixed alnum but not typical 'word'.
    """
    t = (token or "").strip()
    if not t:
        return False

    if re.fullmatch(r"[0-9]+", t):  # running number
        return True

    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) >= 3:  # hex-ish
        return True

    if re.fullmatch(r"[0-9a-fA-F-]{8,}", t):  # guid-ish / long id-ish
        return True

    # mixed alnum with high digit ratio
    digits = sum(ch.isdigit() for ch in t)
    if len(t) >= 6 and digits / len(t) >= 0.5:
        return True

    return False


def try_learn_name_template(
    names: List[str],
    *,
    min_total: int = 10,
    min_distinct: int = 3,
    min_prefix: int = 3,
    min_suffix: int = 3,
    min_coverage: float = 0.7,
    require_same_extension: bool = True
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Learn a regex template from observed names, only if strongly supported.
    Returns (regex_pattern, meta) or (None, None).
    """
    if not names:
        return None, None

    counts = Counter([n for n in names if n])
    total = sum(counts.values())
    distinct = len(counts)

    if total < min_total or distinct < min_distinct:
        return None, None

    uniq = list(counts.keys())

    if require_same_extension:
        exts = {(n.rsplit(".", 1)[1].lower() if "." in n else "") for n in uniq}
        if len(exts) > 1:
            return None, None

    prefix = lcp(uniq)
    suffix = lcsuffix(uniq)

    # safety: avoid overly broad templates
    if len(prefix) < min_prefix or len(suffix) < min_suffix:
        return None, None
    if len(prefix) + len(suffix) >= min(len(u) for u in uniq):
        return None, None

    good = 0
    covered = 0

    for n, c in counts.items():
        n_low = n.lower()
        if not (n_low.startswith(prefix.lower()) and n_low.endswith(suffix.lower())):
            continue
        mid = n[len(prefix):len(n) - len(suffix)]
        covered += c
        if looks_variable_token(mid):
            good += c

    if covered == 0:
        return None, None

    variable_ratio = good / covered
    coverage_ratio = covered / total

    if coverage_ratio < min_coverage or variable_ratio < 0.8:
        return None, None

    # Constrained variable token; adjust char-class if needed
    pattern = r"(?i)^" + re.escape(prefix) + r"[0-9a-zA-Z-]{1,64}" + re.escape(suffix) + r"$"

    meta = {
        "prefix": prefix,
        "suffix": suffix,
        "total": total,
        "distinct": distinct,
        "coverage_ratio": coverage_ratio,
        "variable_ratio": variable_ratio,
    }
    return pattern, meta


def match_any_template(name: str, templates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Return the template dict that matches `name`, or None.
    Expected template format: {"pattern": "<regex>", "meta": {...}}
    """
    n = (name or "").strip()
    if not n:
        return None
    for t in templates or []:
        pat = t.get("pattern")
        if pat and re.match(pat, n):
            return t
    return None

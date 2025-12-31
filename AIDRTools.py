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
    
    
def normalize_process_args( args):
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
import pandas as pd
import numpy as np
from scipy import stats as scipy_stats
import json
import argparse
import os
import time
from datetime import datetime, timedelta
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder, ClientRequestProperties
from azure.kusto.data.helpers import dataframe_from_result_table
from collections import defaultdict
from difflib import SequenceMatcher
import warnings
warnings.filterwarnings('ignore')
import pprint
import random
import ast
import hashlib

import ai_anomaly_defs
from ai_anomaly_defs import REGEX_PATTERNS
from ai_anomaly_defs import (
    ALERT_CLASSIFICATION, ALERT_RUNBOOKS,
    MODEL_FILE_EXTENSIONS, TOKENIZER_AND_CONFIG_EXTENSIONS,
    SUSPICIOUS_CMDLINE_KEYWORDS,
    KNOWN_AI_SERVING_PROCESS_NAMES, GENERIC_INTERPRETER_PROCESS_NAMES,
    REGEX_PATTERNS, MODEL_PATH_PATTERNS,
    SEVERITY_THRESHOLDS,
)

from ai_anomaly_defs import (
    TOOL_PROCESS_NAMES, COMMON_DEV_OR_BROWSER_PROCESSES, LOCALHOST_ADDRESSES,
    COMMON_AI_SERVING_PORTS, LLM_API_PATH_FRAGMENTS, LLM_API_DOMAINS,
    KNOWN_AI_SERVING_PROCESS_NAMES, GENERIC_INTERPRETER_PROCESS_NAMES,
    AI_CMDLINE_KEYWORDS, AI_MODULE_FILENAME_PATTERNS, AI_MODULE_PATH_PATTERNS,
    MODEL_FILE_EXTENSIONS, TOKENIZER_AND_CONFIG_EXTENSIONS
)

def clean_set(domains):
    return {str(d).strip() for d in domains if d is not None and str(d).strip()}


class StatisticalModelHelper:
    """Helper class for statistical calculations and scoring"""
    
    @staticmethod
    def calculate_z_score(value, mean, std):
        """Calculate z-score, handling edge cases"""
        if std == 0 or pd.isna(std):
            return 0.0
        return (value - mean) / std
    
    @staticmethod
    def z_score_to_confidence(z_score, cap_at=5.0):
        """Convert z-score to confidence (0-1), capping extreme values"""
        z_capped = min(abs(z_score), cap_at)
        return z_capped / cap_at
    
    @staticmethod
    def calculate_probability(count, total):
        """Convert frequency to probability with Laplace smoothing"""
        if total == 0:
            return 0.0
        return (count + 1) / (total + 2)
    
    @staticmethod
    def novelty_score(item, baseline_items, threshold=0.85):
        """
        Calculate how novel an item is compared to baseline
        Returns: (is_novel, confidence_score, best_match)
        """
        if not baseline_items:
            return True, 1.0, None
        
        item_lower = str(item).lower().strip()
        max_similarity = 0.0
        best_match = None
        
        for baseline_item in baseline_items:
            baseline_lower = str(baseline_item).lower().strip()
            similarity = SequenceMatcher(None, item_lower, baseline_lower).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
                best_match = baseline_item
        
        is_novel = max_similarity < threshold
        confidence = 1.0 - max_similarity if is_novel else 0.0
        
        return is_novel, confidence, best_match
    
    @staticmethod
    def adaptive_threshold(baseline_items, default=0.85):
        """Calculate adaptive similarity threshold based on baseline diversity"""
        if not baseline_items or len(baseline_items) < 2:
            return default
        
        items_list = list(baseline_items)[:100]
        similarities = []
        
        for i in range(len(items_list)):
            for j in range(i+1, min(i+10, len(items_list))):
                sim = SequenceMatcher(None, 
                                    str(items_list[i]).lower(), 
                                    str(items_list[j]).lower()).ratio()
                similarities.append(sim)
        
        if not similarities:
            return default
        
        median_sim = np.median(similarities)
        adaptive = min(median_sim + 0.15, 0.95)
        return max(adaptive, 0.70)


class AIAgentAnomalyDetector:
    """Statistical anomaly detection for AI agents"""
    
    def __init__(self, cluster_url, database, tenant_id, output_dir):
        self.cluster_url = cluster_url
        self.database = database
        self.tenant_id = tenant_id
        self.output_dir = output_dir
        self.stats_helper = StatisticalModelHelper()
        
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'baselines'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'alerts'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'raw_collections'), exist_ok=True)
        
        self.kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(cluster_url)
        self.client = KustoClient(self.kcsb)

    def _to_json_str(self, v, max_len: int = 20000) -> str:
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
    
    def _alert_id(self, alert: dict, anomaly: dict) -> str:
        key = f"{alert.get('timestamp')}|{alert.get('machine')}|{alert.get('process')}|{alert.get('pid')}|{anomaly.get('type')}|{anomaly.get('details')}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    
    def _make_json_serializable(self, obj):
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
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._make_json_serializable(item) for item in obj]
        else:
            return obj
    
    def _get_obfuscation_key(self):
        """Extract obfuscation key from output_dir"""
        key = os.path.basename(os.path.normpath(self.output_dir))
        if not key:
            key = "default_key"
        import hashlib
        return hashlib.sha256(key.encode()).digest()

    def _obfuscate_value(self, value):
        """Encrypt a value using AES"""
        if not value or value in ['UNKNOWN', 'UNSIGNED', 'ERR:NOT-REPORTED']:
            return value
        
        from cryptography.fernet import Fernet
        import base64
        
        key_bytes = self._get_obfuscation_key()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        cipher = Fernet(fernet_key)
        
        encrypted = cipher.encrypt(value.encode('utf-8'))
        return f"ENC_{base64.urlsafe_b64encode(encrypted).decode()}"

    def _deobfuscate_value(self, obfuscated):
        """Decrypt a value"""
        if not obfuscated or not obfuscated.startswith('ENC_'):
            return obfuscated
        
        from cryptography.fernet import Fernet
        import base64
        
        try:
            encrypted_data = obfuscated[4:]
            
            key_bytes = self._get_obfuscation_key()
            fernet_key = base64.urlsafe_b64encode(key_bytes)
            cipher = Fernet(fernet_key)
            
            decrypted = cipher.decrypt(base64.urlsafe_b64decode(encrypted_data))
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"⚠️ Decryption failed: {e}")
            return obfuscated

    def _obfuscate_machine_name(self, machine):
        return self._obfuscate_value(machine)

    def _deobfuscate_machine_name(self, machine):
        return self._deobfuscate_value(machine)

    def _obfuscate_user_name(self, user):
        return self._obfuscate_value(user)

    def _deobfuscate_user_name(self, user):
        return self._deobfuscate_value(user)
        
    def _enrich_anomaly(self, anomaly):
        alert_type = anomaly.get("type")

        classification = ai_anomaly_defs.ALERT_CLASSIFICATION.get(alert_type, {})
        anomaly["mitre_attack"] = classification.get("mitre", [])
        anomaly["ai_risk"] = classification.get("ai_risk", [])
        anomaly["confidence"] = classification.get("confidence", "Unknown")

        anomaly["soc_runbook"] = ai_anomaly_defs.ALERT_RUNBOOKS.get(alert_type, {
            "summary": "No runbook defined.",
            "triage": [],
            "investigation": [],
            "response": []
        })

        return anomaly

    def _make_anomaly(
        self,
        *,
        type: str,
        severity: str,
        details: str,
        row=None,
        baseline=None,
        df_children=None,
        normalized_args="",
        occurrence_count=0,
        baseline_context=None,
        extra=None,
        confidence_score=0.0
    ) -> dict:
        """Build anomaly with statistical confidence"""

        baseline_context = baseline_context or {}
        extra = extra or {}

        machine = row.get("MachineName") if row is not None else ""
        process = row.get("ProcessName") if row is not None else ""
        user = row.get("UserName", "UNKNOWN") if row is not None else "UNKNOWN"
        signer = self._normalize_signer(row.get("ProcessSigner")) if row is not None else "ERR:NOT-REPORTED"
        pid = int(row.get("Pid", 0)) if row is not None and pd.notna(row.get("Pid")) else None

        anomaly = {
            "type": type,
            "severity": severity,
            "details": details,
            "confidence_score": float(confidence_score),

            "machine": machine,
            "process": process,
            "pid": pid,
            "user": user,
            "signer": signer,

            "baseline_context": baseline_context,

            "observed": {
                "process_dir": row.get("ProcessDir") if row is not None else None,
                "process_args": str(row.get("ProcessArgs", ""))[:2000] if row is not None else "",
                "normalized_args": normalized_args,
                "contacted_domains": self._safe_parse_list(row.get("contacted_domains")) if row is not None else [],
                "contacted_ips": self._safe_parse_list(row.get("contacted_ips")) if row is not None else [],
                "contacted_ports": self._safe_parse_list(row.get("contacted_ports")) if row is not None else [],
                "accessed_files": self._safe_parse_list(row.get("accessed_files")) if row is not None else [],
                "accessed_dirs": self._safe_parse_list(row.get("accessed_dirs")) if row is not None else [],
                "modified_model_files": self._safe_parse_list(row.get("modified_model_files")) if row is not None else [],
                "network_bytes_sent": int(row.get("NetworkBytesSent_sum", 0)) if row is not None else 0,
                "network_bytes_received": int(row.get("NetworkBytesReceived_sum", 0)) if row is not None else 0,
                "ai_score": float(row.get("aiScore_avg", 0)) if row is not None else 0.0,
            }
        }

        if baseline:
            anomaly["baseline_snapshot"] = {
                "occurrence_count": occurrence_count,
                "baseline_users": list(baseline.get("users", set())),
                "baseline_domains": list(baseline.get("contacted_domains", set())),
                "baseline_dirs": list(baseline.get("accessed_dirs", set())),
                "baseline_spawned_processes": list(baseline.get("spawned_processes", set())),
            }

        anomaly.update(extra)
        
        model_path_hits = []
        for d in anomaly["observed"].get("accessed_dirs", []):
            if any(p.search(d) for p in MODEL_PATH_PATTERNS):
                model_path_hits.append(d)
                if len(model_path_hits) >= 10:
                    break

        anomaly["observed"]["model_path_hits"] = model_path_hits

        return self._enrich_anomaly(anomaly)
    
    def _normalize_filename(self, filename):
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
    
    def _execute_query(self, query, max_tries=5, sleepTimeinSecs=30):
        for trys in range(0, max_tries):
            try:
                query = f"set servertimeout = 10m;\nset query_results_cache_max_age = 0d;\n{query}"
                properties = ClientRequestProperties()
                properties.set_option(ClientRequestProperties.request_timeout_option_name, timedelta(minutes=15))
                response = self.client.execute(self.database, query, properties=properties)
                df = dataframe_from_result_table(response.primary_results[0])
                if df is None:
                    print(f"⚠️ Query returned None. tenant={self.tenant_id}")
                    return pd.DataFrame()
                return df
            except Exception as e:
                str_error = str(e).lower()
                substrings = ["Failed to resolve table expression","Access denied","Failed to obtain Az","Az login", "access", "connection", "network"]
    
                print(f"❌ Query error: {e}")
                if any(sub.lower() in str_error for sub in substrings):
                    print(f"Retrying {trys}...")
                    time.sleep(sleepTimeinSecs)
                else:    
                    print(f"❌ Fatal query error")
                    print(query)
                    raise
    
    def _normalize_process_args(self, args):
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
        
    def _normalize_directory_path(self, path):
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

    def _safe_parse_list(self, value):
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
    
    def _normalize_signer(self, signer):
        """Normalize signer"""
        if not signer or pd.isna(signer) or str(signer).strip() == '':
            return 'ERR:NOT-REPORTED'
        return str(signer).strip()
    
    def _get_current_date(self):
        """Get current date as string"""
        return datetime.now().strftime('%Y-%m-%d')

    def _days_since(self, date_str):
        """Calculate days between date_str and today"""
        try:
            past = datetime.strptime(date_str, '%Y-%m-%d')
            now = datetime.now()
            return (now - past).days
        except:
            return 999

    def collect_ai_process_data(self, lookback_value=1, lookback_unit='day'):
        """Query 1: Collect AI process behavior"""
        if lookback_unit == 'hour':
            start_time = f"ago({lookback_value}h)"
            end_time = f"ago({lookback_value - 1}h)"
        else:
            if lookback_value == 0:
                start_time = f"startofday(now())"
                end_time = f"now()"
            else:
                start_time = f"startofday(ago({lookback_value}d))"
                end_time = f"endofday(ago({lookback_value}d))"
                
        def _kusto_dynamic_str_list(items):
            escaped = [str(x).replace('\\', '\\\\').replace('"', '\\"') for x in items]
            return 'dynamic(["' + '","'.join(escaped) + '"])'

        def _kusto_dynamic_num_list(items):
            return "dynamic([" + ",".join(str(int(x)) for x in items) + "])"
                
        print(f"\n📊 Query 1: AI process behavior from {lookback_value} {lookback_unit}(s) ago... on tenant {self.tenant_id}")
                
        query = f"""set servertimeout = 10m;
set query_results_cache_max_age = 0d;
set maxmemoryconsumptionperiterator=16106127360;
let longNetworkCon=15m;let InterestingProcessRunTime=15m;
let processIgnoreList=dynamic(["setup.exe","ms-teams.exe"]);
let ToolProcessNames = {_kusto_dynamic_str_list(TOOL_PROCESS_NAMES)};
let CommonDevOrBrowserProcesses = {_kusto_dynamic_str_list(COMMON_DEV_OR_BROWSER_PROCESSES)};
let LocalhostAddresses = {_kusto_dynamic_str_list(LOCALHOST_ADDRESSES)};
let CommonAIServingPorts = {_kusto_dynamic_num_list(COMMON_AI_SERVING_PORTS)};
let LLMApiPathFragments = {_kusto_dynamic_str_list(LLM_API_PATH_FRAGMENTS)};
let LLMApiDomains = {_kusto_dynamic_str_list(LLM_API_DOMAINS)};
let KnownAIServingProcessNames = {_kusto_dynamic_str_list(KNOWN_AI_SERVING_PROCESS_NAMES)};
let GenericInterpreterProcessNames = {_kusto_dynamic_str_list(GENERIC_INTERPRETER_PROCESS_NAMES)};
let AICmdlineKeywords = {_kusto_dynamic_str_list(AI_CMDLINE_KEYWORDS)};
let AIModuleFileNamePatterns = {_kusto_dynamic_str_list(AI_MODULE_FILENAME_PATTERNS)};
let AIModulePathPatterns = {_kusto_dynamic_str_list(AI_MODULE_PATH_PATTERNS)};
let ModelFileExtensions = {_kusto_dynamic_str_list(MODEL_FILE_EXTENSIONS)};
let TokenizerAndConfigExtensions = {_kusto_dynamic_str_list(TOKENIZER_AND_CONFIG_EXTENSIONS)};
let FileNameSearch = array_concat(KnownAIServingProcessNames, GenericInterpreterProcessNames, CommonDevOrBrowserProcesses, AIModuleFileNamePatterns);
let FileDirSearch = array_concat(LLMApiPathFragments, AIModulePathPatterns);
let ExtSearch = array_concat(ModelFileExtensions, TokenizerAndConfigExtensions);
let SuspiciousArgs = dynamic(["copy", "move", "xcopy", "robocopy", "scp", "curl", "wget", "invoke-webrequest", "download", "upload", "exfil", "compress", "zip", "7z"]);
let SuspiciousDirs = dynamic(["temp", "tmp", "downloads", "desktop", "documents", "users"]);
database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
| where OpTimeSecondsUTC between ({start_time} .. {end_time})
| extend FileExtension = tolower(extract(@"\\.([^.]+)$", 1, FileName))
| where tolower(FileName) has_any (FileNameSearch) or tolower(FileDir) has_any (FileDirSearch) 
or tolower(ProcessArgs) has_any (AICmdlineKeywords) 
or tolower(ProcessDir) has_any (LLMApiPathFragments) 
or tolower(ProcessDir) has_any (FileDirSearch) 
or tolower(ProcessName) has_any (GenericInterpreterProcessNames) 
or tolower(ProcessName) has_any (CommonDevOrBrowserProcesses) 
or tolower(ProcessName) has_any (ToolProcessNames) or tolower(ProcessName) has_any(FileNameSearch)
or (FileExtension in (ExtSearch) and FileSize > 500) or tolower(NetworkPath) has_any (AIModulePathPatterns) or tolower(NetworkDomain) in (LLMApiDomains) 
or tolong(NetworkDestPort) in (CommonAIServingPorts) or tolong(NetworkSrcPort) in (CommonAIServingPorts) or tolong(NetworkDestPort) between (3000..3100) or tolong(NetworkSrcPort) between (3000..3100)
or ((NetworkDestIP in (LocalhostAddresses) or NetworkSrcIP in (LocalhostAddresses)) and NetworkConnectionDirection == "Incoming")
| extend hasModelFile = toint(FileExtension in (ModelFileExtensions) and FileSize > 50000000),
hasTokenizerOrConfig = toint(FileExtension in (TokenizerAndConfigExtensions)),
hasAiRuntimeFile = toint(FileName has_any (AIModuleFileNamePatterns)), hasAiRuntimePath = toint(FileDir has_any (AIModulePathPatterns) or NetworkPath has_any (AIModulePathPatterns)), isKnownAIServingProcess = toint(ProcessName has_any (KnownAIServingProcessNames)), 
isGenericInterpreter = toint(ProcessName has_any (GenericInterpreterProcessNames)), 
isToolProcess = toint(ProcessName has_any (ToolProcessNames)), 
hasAiCmdline = toint(ProcessArgs has_any (AICmdlineKeywords)),
talksToLLMApi = toint(NetworkDomain in (LLMApiDomains) and NetworkPath has_any (LLMApiPathFragments)), 
usesAIServingPort = toint(NetworkDestPort in (CommonAIServingPorts) or NetworkSrcPort in (CommonAIServingPorts)),
hasLocalhostInbound = toint((NetworkDestIP in (LocalhostAddresses) or NetworkSrcIP in (LocalhostAddresses)) and NetworkConnectionDirection == "Incoming"), hasLongConnection = coalesce(toint(unixtime_seconds_todatetime(NetworkConnectionCloseTime) - unixtime_seconds_todatetime(NetworkConnectionStartTime) > longNetworkCon), 0), hasSuspiciousArgs = toint(tolower(ProcessArgs) has_any (SuspiciousArgs)), 
isSuspiciousDir = toint(tolower(FileDir) has_any (SuspiciousDirs)or tolower(ProcessDir) has_any (SuspiciousDirs)),
isLargeFile = toint(FileSize > 100000)
| extend aiScore = 5 * hasModelFile + 3 * hasTokenizerOrConfig + 4 * (hasAiRuntimeFile + hasAiRuntimePath) + 3 * isKnownAIServingProcess + 2 * hasAiCmdline + 2 * talksToLLMApi + 1 * usesAIServingPort + 1 * hasLocalhostInbound + 2 * hasLongConnection
| where aiScore > {SEVERITY_THRESHOLDS["min_ai_score"]}
| summarize event_count = count(),
PidCreationTime = take_any(PidCreationTime),
NetworkBytesSent_sum = sum(NetworkBytesSent),
NetworkBytesReceived_sum = sum(NetworkBytesReceived),
contacted_domains = make_set(NetworkDomain), contacted_ips = make_set(NetworkDestIP), contacted_ports = make_set(NetworkDestPort), network_paths = make_set(NetworkPath), accessed_files = make_set(FileName), accessed_dirs = make_set(FileDir),
accessed_extensions = make_set(FileExtension),
modified_files = make_set_if(FileName, isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0),
modified_model_files = make_set_if(FileName,isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0 and FileExtension in (ModelFileExtensions)), 
file_mod_details = make_bag_if(pack("file", FileName, "user", UserName, "args", ProcessArgs), isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0), 
model_files_count = countif(hasModelFile == 1), 
large_file_count = countif(FileSize > 100000),
llm_api_count = countif(talksToLLMApi == 1),
non_llm_count = countif(isnotempty(NetworkDomain) and talksToLLMApi == 0), 
suspicious_dir_count = countif(tolower(FileDir) has_any (SuspiciousDirs)), 
suspicious_args_count = countif(tolower(ProcessArgs) has_any (SuspiciousArgs)),
aiScore_avg = avg(aiScore),
ProcessDir = take_any(ProcessDir), 
ProcessArgs = take_any(ProcessArgs), 
UserName = take_any(UserName)
by MachineName, ProcessName, Pid, CreationTime, ProcessSigner
| order by aiScore_avg desc
|take 1000
|lookup (
database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
| where OpTimeSecondsUTC between ({start_time} .. {end_time})
and RecordType == "Process" and ProcessOp == "Stopped"
|project CloseTimeLocal=OpTimeLocal,CloseTimeUTC= OpTimeSecondsUTC,CreationTime, PidCreationTime
)
on PidCreationTime
|extend hasLongrunTime=toint(CloseTimeUTC-todatetime(CreationTime)>InterestingProcessRunTime)
|extend aiScore_avg= iff (hasLongrunTime>0, aiScore_avg+3*hasLongrunTime,aiScore_avg)
|order by aiScore_avg desc
|project-reorder aiScore_avg
"""
            
        df = self._execute_query(query)
        
        if df is None:
            print(f"⚠️ Query returned None for {self.tenant_id}")
            return pd.DataFrame()
        
        print(f"✅ Collected {len(df)} AI processes for {self.tenant_id}")
        return df
    
    def collect_child_spawning_data(self, ai_parent_pct_list, lookback_value=1, lookback_unit='day'):
        """Query 2: Get children"""
        
        if lookback_unit == 'hour':
            start_time = f"ago({lookback_value}h)"
            end_time = f"ago({lookback_value - 1}h)"
        else:   
            if lookback_value == 0:
                start_time = f"startofday(now())"
                end_time = f"now()"
            else:               
                start_time = f"startofday(ago({lookback_value}d))"
                end_time = f"endofday(ago({lookback_value}d))"
                
        if not ai_parent_pct_list:
            return pd.DataFrame()
        
        parent_array = ', '.join([f'"{pct}"' for pct in ai_parent_pct_list])
        
        query = f"""set servertimeout = 10m;
set query_results_cache_max_age = 0d;
let AIParents = dynamic([{parent_array}]);
database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
| where OpTimeSecondsUTC between ({start_time} .. {end_time})
| where ProcessPPidCreationTime in (AIParents)
| project MachineName, ParentProcessName, ProcessPPidCreationTime, ProcessName, ProcessArgs, ProcessDir, ProcessSigner, ParentProcessSigner
| take 10000"""
       
        df = self._execute_query(query)
        print(f"✅ Collected {len(df)} children for {self.tenant_id}")

        if df is None:
            print(f"⚠️ Query returned None for {self.tenant_id}")
            return pd.DataFrame()
        return df
    
    def build_baseline(self, df_process_list, df_children_list):
        """Build baseline with statistical modeling"""
        print("\n🔨 Building statistical baselines...")
        
        df_process = pd.concat(df_process_list, ignore_index=True) if df_process_list else pd.DataFrame()
        df_children = pd.concat(df_children_list, ignore_index=True) if df_children_list else pd.DataFrame()
        
        baselines = defaultdict(lambda: {
            'spawned_processes': set(),
            'spawned_args': set(),
            'spawned_with_args': set(),
            'contacted_domains': set(),
            'contacted_ips': set(),
            'contacted_ports': set(),
            'network_paths': set(),
            'accessed_files': set(),
            'accessed_dirs': set(),
            'accessed_extensions': set(),
            'users': set(),
            'process_args': set(),
            'file_operations': {},
            'stats': {
                'instances': 0,
                'bytes_sent_mean': 0.0,
                'bytes_sent_std': 0.0,
                'bytes_sent_p50': 0.0,
                'bytes_sent_p95': 0.0,
                'bytes_sent_p99': 0.0,
                'bytes_received_mean': 0.0,
                'bytes_received_std': 0.0,
                'bytes_received_p95': 0.0,
                'domain_count_mean': 0.0,
                'domain_count_std': 0.0,
                'domain_count_p95': 0.0,
                'file_count_mean': 0.0,
                'file_count_std': 0.0,
                'dir_count_mean': 0.0,
                'dir_count_std': 0.0,
                'children_count_mean': 0.0,
                'children_count_std': 0.0,
            },
            'occurrence_count': 0
        })
        
        # Build from process data
        for _, row in df_process.iterrows():
            normalized_args = self._normalize_process_args(row.get('ProcessArgs'))
            user = row.get('UserName', 'UNKNOWN')
            signer = self._normalize_signer(row.get('ProcessSigner'))
            key = (row['MachineName'], row['ProcessName'], normalized_args, signer)
            
            if 'detection_reason' not in baselines[key]:
                reason_details = {
                    'first_detected': self._get_current_date(),
                    'ai_score': float(row.get('aiScore_avg', 0)) if pd.notna(row.get('aiScore_avg')) else 0,
                    'detection_triggers': [],
                    'example_behavior': {}
                }
                
                if row.get('model_files_count', 0) > 0:
                    reason_details['detection_triggers'].append(f"Model files ({row.get('model_files_count', 0)} files)")
                
                if row.get('llm_api_count', 0) > 0:
                    reason_details['detection_triggers'].append(f"LLM API calls ({row.get('llm_api_count', 0)})")
                    domains = self._safe_parse_list(row.get('contacted_domains'))
                    reason_details['example_behavior']['llm_domains'] = list(set(domains))[:3]
                
                if row.get('suspicious_args_count', 0) > 0:
                    reason_details['detection_triggers'].append("Suspicious arguments")
                
                reason_details['example_behavior']['process_dir'] = row.get('ProcessDir', '')
                
                baselines[key]['detection_reason'] = reason_details
            
            domains_raw = row.get('contacted_domains')
            if isinstance(domains_raw, list):
                baselines[key]['contacted_domains'].update([d for d in domains_raw if d])
            elif pd.notna(domains_raw):
                try:
                    domains = self._safe_parse_list(domains_raw)
                    baselines[key]['contacted_domains'].update([d for d in domains if d])
                except: pass
            
            ips_raw = row.get('contacted_ips')
            if isinstance(ips_raw, list):
                baselines[key]['contacted_ips'].update([d for d in ips_raw if d])
            elif pd.notna(ips_raw):
                try:
                    ips = self._safe_parse_list(ips_raw)
                    baselines[key]['contacted_ips'].update([d for d in ips if d])
                except: pass
            
            ports_raw = row.get('contacted_ports')
            if isinstance(ports_raw, list):
                baselines[key]['contacted_ports'].update([str(p) for p in ports_raw if p])
            elif pd.notna(ports_raw):
                try:
                    ports = self._safe_parse_list(ports_raw)
                    baselines[key]['contacted_ports'].update([str(p) for p in ports if p])
                except: pass
            
            network_path_raw = row.get('network_paths')
            if isinstance(network_path_raw, list):
                baselines[key]['network_paths'].update([p for p in network_path_raw if p])
            elif pd.notna(network_path_raw):
                try:
                    paths = self._safe_parse_list(network_path_raw)
                    baselines[key]['network_paths'].update([p for p in paths if p])
                except: pass
            
            a_fs = row.get('accessed_files')
            if isinstance(a_fs, list):
                try:
                    baselines[key]['accessed_files'].update([self._normalize_filename(f) for f in a_fs if f])
                except: pass

            dirs = row.get('accessed_dirs')
            if isinstance(dirs, list):
                try:
                    baselines[key]['accessed_dirs'].update([self._normalize_directory_path(d) for d in dirs if d])
                except: pass
            
            exts = row.get('accessed_extensions')
            if isinstance(exts, list):
                try:
                    baselines[key]['accessed_extensions'].update([e for e in exts if e])
                except: pass
            
            if pd.notna(row.get('UserName')):
                baselines[key]['users'].add(row['UserName'])
            
            if pd.notna(row.get('ProcessArgs')):
                baselines[key]['process_args'].add(row['ProcessArgs'])
            
            if pd.notna(row.get('file_mod_details')):
                try:
                    ops = self._safe_parse_list(row['file_mod_details'])
                    if not isinstance(ops, list):
                        ops = [ops]
                    
                    for op in ops:
                        filename_raw = op.get('file')
                        if not filename_raw:
                            continue
                        
                        filename = self._normalize_filename(filename_raw)
                        
                        if filename not in baselines[key]['file_operations']:
                            baselines[key]['file_operations'][filename] = {
                                'operations': set(),
                                'users': set(),
                                'process_args': set()
                            }
                        
                        if op.get('user'):
                            baselines[key]['file_operations'][filename]['users'].add(op['user'])
                        if op.get('args'):
                            norm_args = self._normalize_process_args(op['args'])
                            baselines[key]['file_operations'][filename]['process_args'].add(norm_args)
                except Exception as e:
                    pass
        
        # Build from child data
        for _, child_row in df_children.iterrows():
            parent_match = df_process[
                (df_process['MachineName'] == child_row['MachineName']) &
                (df_process['PidCreationTime'] == child_row['ProcessPPidCreationTime'])
            ]
            
            if len(parent_match) == 0:
                continue
            
            parent = parent_match.iloc[0]
            
            normalized_parent_args = self._normalize_process_args(parent.get('ProcessArgs'))
            parent_signer = self._normalize_signer(parent.get('ProcessSigner'))
            key = (child_row['MachineName'], parent['ProcessName'], normalized_parent_args, parent_signer)
                        
            child_process = child_row.get('ProcessName')
            child_args_normalized = self._normalize_process_args(child_row.get('ProcessArgs'))
            
            if child_process:
                baselines[key]['spawned_processes'].add(child_process)
                baselines[key]['spawned_with_args'].add((child_process, child_args_normalized))
            
            if child_row.get('ProcessArgs'):
                baselines[key]['spawned_args'].add(child_row['ProcessArgs'])
        
        # Compute statistical measures
        print("📊 Computing statistical models...")
        for key in baselines:
            machine, process, normalized_args, signer = key
    
            matching_rows = df_process[
                (df_process['MachineName'] == machine) & 
                (df_process['ProcessName'] == process) &
                (df_process['ProcessArgs'].apply(lambda x: self._normalize_process_args(x)) == normalized_args) &
                (df_process['ProcessSigner'].apply(lambda x: self._normalize_signer(x)) == signer)
            ]
                    
            if len(matching_rows) > 0:
                bytes_sent = matching_rows['NetworkBytesSent_sum'].fillna(0)
                bytes_received = matching_rows['NetworkBytesReceived_sum'].fillna(0)
                
                baselines[key]['stats'] = {
                    'instances': len(matching_rows),
                    'bytes_sent_mean': float(bytes_sent.mean()),
                    'bytes_sent_std': float(bytes_sent.std()) if len(bytes_sent) > 1 else 0.0,
                    'bytes_sent_p50': float(bytes_sent.quantile(0.50)),
                    'bytes_sent_p95': float(bytes_sent.quantile(0.95)),
                    'bytes_sent_p99': float(bytes_sent.quantile(0.99)),
                    'bytes_received_mean': float(bytes_received.mean()),
                    'bytes_received_std': float(bytes_received.std()) if len(bytes_received) > 1 else 0.0,
                    'bytes_received_p95': float(bytes_received.quantile(0.95)),
                    'domain_count_mean': 0.0,
                    'domain_count_std': 0.0,
                    'domain_count_p95': 0.0,
                    'file_count_mean': 0.0,
                    'file_count_std': 0.0,
                    'dir_count_mean': 0.0,
                    'dir_count_std': 0.0,
                    'children_count_mean': 0.0,
                    'children_count_std': 0.0,
                }
                
                domain_counts = []
                for _, row in matching_rows.iterrows():
                    domains = self._safe_parse_list(row.get('contacted_domains'))
                    domain_counts.append(len([d for d in domains if d]))
                
                if domain_counts:
                    baselines[key]['stats']['domain_count_mean'] = float(np.mean(domain_counts))
                    baselines[key]['stats']['domain_count_std'] = float(np.std(domain_counts)) if len(domain_counts) > 1 else 0.0
                    baselines[key]['stats']['domain_count_p95'] = float(np.percentile(domain_counts, 95))
                
                file_counts = []
                dir_counts = []
                for _, row in matching_rows.iterrows():
                    files = self._safe_parse_list(row.get('accessed_files'))
                    dirs = self._safe_parse_list(row.get('accessed_dirs'))
                    file_counts.append(len([f for f in files if f]))
                    dir_counts.append(len([d for d in dirs if d]))
                
                if file_counts:
                    baselines[key]['stats']['file_count_mean'] = float(np.mean(file_counts))
                    baselines[key]['stats']['file_count_std'] = float(np.std(file_counts)) if len(file_counts) > 1 else 0.0
                
                if dir_counts:
                    baselines[key]['stats']['dir_count_mean'] = float(np.mean(dir_counts))
                    baselines[key]['stats']['dir_count_std'] = float(np.std(dir_counts)) if len(dir_counts) > 1 else 0.0
                
                children_counts = []
                for _, row in matching_rows.iterrows():
                    children = df_children[
                        (df_children['MachineName'] == machine) &
                        (df_children['ProcessPPidCreationTime'] == row['PidCreationTime'])
                    ]
                    children_counts.append(len(children))
                
                if children_counts:
                    baselines[key]['stats']['children_count_mean'] = float(np.mean(children_counts))
                    baselines[key]['stats']['children_count_std'] = float(np.std(children_counts)) if len(children_counts) > 1 else 0.0
                
                occurrence_count = 0
                for df in df_process_list:
                    period_matches = df[
                        (df['MachineName'] == machine) & 
                        (df['ProcessName'] == process) &
                        (df['ProcessArgs'].apply(lambda x: self._normalize_process_args(x)) == normalized_args) &
                        (df['ProcessSigner'].apply(lambda x: self._normalize_signer(x)) == signer)
                    ]
                    if len(period_matches) > 0:
                        occurrence_count += 1
                
                baselines[key]['occurrence_count'] = occurrence_count
        
        print(f"✅ Built statistical baselines for {len(baselines)} combinations")
        return dict(baselines)
    
    def save_baseline(self, baselines):
        """Save baseline to JSON"""
        baselines_json = {}
        
        for key, baseline in baselines.items():
            machine, process, normalized_args, signer = key
            obf_machine = self._obfuscate_machine_name(machine)
            
            try:
                def safe_convert_list(items, field_name):
                    result = []
                    for item in items:
                        if callable(item):
                            continue
                        result.append(str(item) if item is not None else None)
                    return result
                
                def safe_convert_tuples(items, field_name):
                    result = []
                    for t in items:
                        if callable(t):
                            continue
                        tuple_list = []
                        for item in t:
                            if callable(item):
                                tuple_list.append(str(item))
                            else:
                                tuple_list.append(item)
                        result.append(tuple_list)
                    return result
                
                baselines_json[f"{obf_machine}||{process}||{normalized_args}||{signer}"] = {
                    'spawned_processes': safe_convert_list(baseline['spawned_processes'], 'spawned_processes'),
                    'spawned_args': safe_convert_list(baseline['spawned_args'], 'spawned_args'),
                    'spawned_with_args': safe_convert_tuples(baseline.get('spawned_with_args', set()), 'spawned_with_args'),
                    'contacted_domains': safe_convert_list(baseline['contacted_domains'], 'contacted_domains'),
                    'contacted_ips': safe_convert_list(baseline['contacted_ips'], 'contacted_ips'),
                    'contacted_ports': safe_convert_list(baseline['contacted_ports'], 'contacted_ports'),
                    'network_paths': safe_convert_list(baseline['network_paths'], 'network_paths'),
                    'accessed_files': safe_convert_list(baseline['accessed_files'], 'accessed_files'),
                    'accessed_dirs': safe_convert_list(baseline['accessed_dirs'], 'accessed_dirs'),
                    'accessed_extensions': safe_convert_list(baseline['accessed_extensions'], 'accessed_extensions'),
                    'users': [self._obfuscate_user_name(u) for u in baseline['users']],
                    'process_args': safe_convert_list(baseline['process_args'], 'process_args'),
                    'file_operations': {
                        fname: {
                            'operations': safe_convert_list(fdata['operations'], f'file_operations[{fname}].operations'),
                            'users': [self._obfuscate_user_name(u) for u in fdata['users']],
                            'process_args': safe_convert_list(fdata['process_args'], f'file_operations[{fname}].process_args')
                        } for fname, fdata in baseline.get('file_operations', {}).items()
                    },
                    'accessed_dirs_meta': baseline.get('accessed_dirs_meta', {}),
                    'contacted_domains_meta': baseline.get('contacted_domains_meta', {}),
                    'file_operations_meta': baseline.get('file_operations_meta', {}),
                    'stats': baseline['stats'],
                    'occurrence_count': baseline.get('occurrence_count', 0),
                    'detection_reason': baseline.get('detection_reason', {}) 
                }
            except Exception as e:
                print(f"❌ Error processing key: {key}, Error: {e}")
                raise
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, 'baselines', f'baseline_{timestamp}.json')
        
        with open(filepath, 'w') as f:
            json.dump(baselines_json, f, indent=2)
        
        latest_path = os.path.join(self.output_dir, 'baselines', 'baseline_latest.json')
        with open(latest_path, 'w') as f:
            json.dump(baselines_json, f, indent=2)
        
        print(f"💾 Saved statistical baseline to {filepath}")
        return filepath
    
    def load_baseline(self):
        """Load baseline from JSON"""
        filepath = os.path.join(self.output_dir, 'baselines', 'baseline_latest.json')
        
        if not os.path.exists(filepath):
            print(f"⚠️ No baseline found")
            return {}
        
        with open(filepath, 'r') as f:
            baselines_json = json.load(f)
        
        baselines = {}
        for key_str, baseline in baselines_json.items():
            parts = key_str.split('||')
            if len(parts) == 3:
                machine, process, normalized_args = parts
                signer = 'unsaved'
            elif len(parts) == 4:
                machine, process, normalized_args, signer = parts
            elif len(parts) == 5:
                machine, process, normalized_args, user, signer = parts
            
            real_machine = self._deobfuscate_machine_name(machine)
            
            stats = baseline.get('stats', {})
            if 'bytes_sent_std' not in stats:
                stats.update({
                    'bytes_sent_std': 0.0,
                    'bytes_sent_p50': stats.get('bytes_sent_mean', 0.0),
                    'bytes_sent_p95': stats.get('bytes_sent_mean', 0.0),
                    'bytes_sent_p99': stats.get('bytes_sent_mean', 0.0),
                    'bytes_received_std': 0.0,
                    'bytes_received_p95': 0.0,
                    'domain_count_mean': 0.0,
                    'domain_count_std': 0.0,
                    'domain_count_p95': 0.0,
                    'file_count_mean': 0.0,
                    'file_count_std': 0.0,
                    'dir_count_mean': 0.0,
                    'dir_count_std': 0.0,
                    'children_count_mean': 0.0,
                    'children_count_std': 0.0,
                })
                
            baselines[(real_machine, process, normalized_args, signer)] = {
                'spawned_processes': set(baseline['spawned_processes']),
                'spawned_args': set(baseline['spawned_args']),
                'spawned_with_args': set(tuple(t) for t in baseline.get('spawned_with_args', [])),
                'contacted_domains': set(baseline['contacted_domains']),
                'contacted_ips': set(baseline['contacted_ips']),
                'contacted_ports': set(baseline['contacted_ports']),
                'network_paths': set(baseline['network_paths']),
                'accessed_files': set(baseline['accessed_files']),
                'accessed_dirs': set(baseline['accessed_dirs']),
                'accessed_extensions': set(baseline['accessed_extensions']),
                'users': set(self._deobfuscate_user_name(u) for u in baseline['users']),
                'process_args': set(baseline['process_args']),
                'file_operations': {
                    fname: {
                        'operations': set(fdata['operations']),
                        'users': set(self._deobfuscate_user_name(u) for u in fdata['users']),
                        'process_args': set(fdata['process_args'])
                    } for fname, fdata in baseline.get('file_operations', {}).items()
                },
                'accessed_dirs_meta': baseline.get('accessed_dirs_meta', {}),
                'contacted_domains_meta': baseline.get('contacted_domains_meta', {}),
                'file_operations_meta': baseline.get('file_operations_meta', {}),
                'stats': stats,
                'occurrence_count': baseline.get('occurrence_count', 0),
                'detection_reason': baseline.get('detection_reason', {}) 
            }

        print(f"✅ Loaded statistical baseline for {len(baselines)} combinations")
        return baselines
    
    def detect_anomalies(self, df_process, df_children, baselines, min_occurrences=3):
        """Detect anomalies using statistical models"""
        print(f"\n🔍 Detecting anomalies with statistical models...")
        
        if df_process is None or len(df_process) == 0:
            print("⚠️ No process data")
            return pd.DataFrame()
    
        if not baselines:
            print("⚠️ No baselines")
            return pd.DataFrame()
        
        all_alerts = []
        matched_keys = 0
        unmatched_keys = 0
        
        try:
            for _, row in df_process.iterrows():
                normalized_args = self._normalize_process_args(row.get('ProcessArgs'))
                user = row.get('UserName', 'UNKNOWN')
                signer = self._normalize_signer(row.get('ProcessSigner'))
                key = (row['MachineName'], row['ProcessName'], normalized_args, signer)
                
                # Check signer change
                same_triplet_signers = [
                    k[3] for k in baselines.keys()
                    if k[0] == row['MachineName'] and k[1] == row['ProcessName'] and k[2] == normalized_args
                ]

                if same_triplet_signers and signer not in same_triplet_signers:
                    severity = SEVERITY_THRESHOLDS.get("signer_changed_default", "HIGH")
                    if signer.upper() in ("UNKNOWN", "UNSIGNED", "N/A", "ERR:NOT-REPORTED"):
                        severity = SEVERITY_THRESHOLDS.get("signer_changed_if_unsigned", "MEDIUM")

                    event_time = row.get('CreationTime')
                    alert_timestamp = str(int(event_time)) if event_time and pd.notna(event_time) else "UNKNOWN"

                    all_alerts.append({
                        "timestamp": alert_timestamp,
                        "machine": row["MachineName"],
                        "process": row["ProcessName"],
                        "pid": int(row["Pid"]) if pd.notna(row["Pid"]) else 0,
                        "user": user,
                        "signer": signer,
                        "process_args": str(row.get("ProcessArgs", ""))[:200],
                        "anomaly_count": 1,
                        "max_confidence_score": 0.95,
                        "baseline_context": {
                            "status": "SIGNER_CHANGED"
                        },
                        'anomalies': [
                            self._make_anomaly(
                                type="ALERT_PROCESS_SIGNER_CHANGED",
                                severity=severity,
                                details=f"Signer changed: '{signer}' not in baseline",
                                row=row,
                                baseline=None,
                                normalized_args=normalized_args,
                                occurrence_count=0,
                                confidence_score=0.95,
                                extra={"current_signer": signer, "baseline_signers": list(set(same_triplet_signers))[:10]}
                            )
                        ]
                    })
                    continue
                
                if key not in baselines:
                    unmatched_keys += 1
                    similar_processes = [k for k in baselines.keys() if k[1] == row['ProcessName']]
                    confidence = 0.8 if similar_processes else 1.0
                    
                    event_time = row.get('CreationTime')
                    alert_timestamp = str(int(event_time)) if event_time and pd.notna(event_time) else "UNKNOWN"
                    
                    all_alerts.append({
                        'timestamp': alert_timestamp,
                        'machine': row['MachineName'],
                        'process': row['ProcessName'],
                        'pid': int(row['Pid']) if pd.notna(row['Pid']) else 0,
                        'user': user,
                        'signer': signer,
                        'process_args': str(row.get('ProcessArgs', ''))[:200],
                        'anomaly_count': 1,
                        'max_confidence_score': confidence,
                        'anomalies': [
                            self._make_anomaly(
                                type="ALERT_NEW_AI_AGENT_NOT_IN_BASELINE",
                                severity="LOW",
                                details=f"AI agent not in baseline: {row['ProcessName']}",
                                row=row,
                                baseline=None,
                                normalized_args=normalized_args,
                                occurrence_count=0,
                                confidence_score=confidence
                            )
                        ]
                    })
                    continue
         
                baseline = baselines[key]
                occurrence_count = baseline.get('occurrence_count', 0)
                
                if occurrence_count < min_occurrences:
                    event_time = row.get('CreationTime')
                    alert_timestamp = str(int(event_time)) if event_time and pd.notna(event_time) else "UNKNOWN"
                    learning_confidence = occurrence_count / min_occurrences
                    
                    all_alerts.append({
                        'timestamp': alert_timestamp,
                        'machine': row['MachineName'],
                        'process': row['ProcessName'],
                        'pid': int(row['Pid']) if pd.notna(row['Pid']) else 0,
                        'user': user,
                        'signer': signer,
                        'process_args': str(row.get('ProcessArgs', ''))[:200],
                        'anomaly_count': 1,
                        'max_confidence_score': learning_confidence,
                        'anomalies': [
                            self._make_anomaly(
                                type="ALERT_AI_AGENT_IN_LEARNING_PHASE",
                                severity="INFO",
                                details=f"Learning: {row['ProcessName']} seen {occurrence_count}/{min_occurrences}",
                                row=row,
                                baseline=baseline,
                                normalized_args=normalized_args,
                                occurrence_count=occurrence_count,
                                confidence_score=learning_confidence
                            )
                        ]
                    })
                    continue
                
                matched_keys += 1
                anomalies = []
                
                event_time = row.get('CreationTime')
                alert_timestamp = str(int(event_time)) if event_time and pd.notna(event_time) else "UNKNOWN"
                
                # USER CHECK
                baseline_users = baseline.get('users', set())
                if user not in baseline_users:
                    user_confidence = 1.0 if len(baseline_users) > 0 else 0.5
                    
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_USER_FOR_PROCESS",
                            severity="HIGH",
                            details=f"NEW user: {user}",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=user_confidence,
                            extra={"current_user": user, "baseline_users": list(baseline_users)[:10]}
                        )
                    )
                
                # NEW DOMAINS (adaptive threshold)
                domains_raw = row.get('contacted_domains')
                current_domains = clean_set(self._safe_parse_list(domains_raw))
                baseline_domains = baseline.get('contacted_domains', set())
                
                domain_threshold = self.stats_helper.adaptive_threshold(baseline_domains, 0.90)
                
                truly_new_domains = []
                domain_confidences = []
                for domain in current_domains:
                    is_novel, confidence, match = self.stats_helper.novelty_score(domain, baseline_domains, domain_threshold)
                    if is_novel:
                        truly_new_domains.append(domain)
                        domain_confidences.append(confidence)
                
                if truly_new_domains:
                    avg_confidence = np.mean(domain_confidences) if domain_confidences else 0.8
                    severity = "HIGH" if len(truly_new_domains) >= SEVERITY_THRESHOLDS.get("new_domains_high", 5) else "MEDIUM"
                    
                    anomalies.append(self._make_anomaly(
                        type="ALERT_NEW_DOMAINS",
                        severity=severity,
                        details=f"{len(truly_new_domains)} new domains",
                        row=row,
                        baseline=baseline,
                        normalized_args=normalized_args,
                        occurrence_count=occurrence_count,
                        confidence_score=float(avg_confidence),
                        extra={"new_domains": truly_new_domains[:10]}
                    ))
                
                # EXCESSIVE TRANSFER (Z-score)
                bytes_sent = row.get('NetworkBytesSent_sum', 0)
                mean_sent = baseline['stats'].get('bytes_sent_mean', 0)
                std_sent = baseline['stats'].get('bytes_sent_std', 0)
                p99_sent = baseline['stats'].get('bytes_sent_p99', 0)
                
                if mean_sent > 0 and std_sent > 0:
                    z_score = self.stats_helper.calculate_z_score(bytes_sent, mean_sent, std_sent)
                    
                    if z_score > 3.0:
                        confidence = self.stats_helper.z_score_to_confidence(z_score, 6.0)
                        severity = "CRITICAL" if bytes_sent > p99_sent else "HIGH"
                        
                        anomalies.append(
                            self._make_anomaly(
                                type="ALERT_EXCESSIVE_TRANSFER",
                                severity=severity,
                                details=f"Sent {bytes_sent/1e6:.1f}MB (z={z_score:.1f})",
                                row=row,
                                baseline=baseline,
                                normalized_args=normalized_args,
                                occurrence_count=occurrence_count,
                                confidence_score=float(confidence),
                                extra={"z_score": f"{z_score:.2f}", "bytes_sent": int(bytes_sent)}
                            )
                        )
                
                # NEW DIRECTORIES (adaptive)
                dirs_raw = row.get('accessed_dirs')
                dirs_list = self._safe_parse_list(dirs_raw)
                current_dirs = set(self._normalize_directory_path(d) for d in dirs_list if d)
                baseline_dirs = set(self._normalize_directory_path(d) for d in baseline.get('accessed_dirs', set()))
                
                IGNORE_DIRS = {'appdata\\local\\temp', '/tmp'}
                dir_threshold = self.stats_helper.adaptive_threshold(baseline_dirs, 0.85)
                
                truly_new_dirs = []
                dir_confidences = []
                for curr_dir in current_dirs:
                    if any(p in curr_dir.lower() for p in IGNORE_DIRS):
                        continue
                    is_novel, confidence, match = self.stats_helper.novelty_score(curr_dir, baseline_dirs, dir_threshold)
                    if is_novel:
                        truly_new_dirs.append(curr_dir)
                        dir_confidences.append(confidence)
                
                if truly_new_dirs:
                    avg_confidence = np.mean(dir_confidences) if dir_confidences else 0.7
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_DIRECTORIES",
                            severity="MEDIUM",
                            details=f"{len(truly_new_dirs)} new directories",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=float(avg_confidence),
                            extra={"new_directories": truly_new_dirs[:10]}
                        )
                    )
                
                # NEW IPS
                ips_raw = row.get('contacted_ips')
                current_ips = set(ip for ip in self._safe_parse_list(ips_raw) if ip and str(ip).strip())
                baseline_ips = baseline.get('contacted_ips', set())
                
                new_ips = current_ips - baseline_ips
                if new_ips:
                    ip_confidence = 1.0 if len(baseline_ips) > 0 else 0.8
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_IPS",
                            severity="HIGH",
                            details=f"{len(new_ips)} new IP(s)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=ip_confidence,
                            extra={"new_ips": list(new_ips)[:10]}
                        )
                    )
                
                # NEW PORTS
                ports_raw = row.get('contacted_ports')
                current_ports = set(str(p) for p in self._safe_parse_list(ports_raw) if p and str(p).strip())
                baseline_ports = baseline.get('contacted_ports', set())
                
                new_ports = current_ports - baseline_ports
                if new_ports:
                    port_confidence = 0.7
                    severity = "MEDIUM" if len(new_ports) >= SEVERITY_THRESHOLDS.get("new_ports_medium", 3) else "LOW"
                    
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_PORTS",
                            severity=severity,
                            details=f"{len(new_ports)} new port(s)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=port_confidence,
                            extra={"new_ports": list(new_ports)[:10]}
                        )
                    )
                
                # [Continue with remaining detection types...]
                # MODEL FILE MODIFICATIONS
                mod_files_raw = row.get('modified_model_files')
                modified_raw = [f for f in self._safe_parse_list(mod_files_raw) if f]
                modified = {self._normalize_filename(f): f for f in modified_raw}
                
                mod_details_raw = row.get('file_mod_details')
                mod_details = self._safe_parse_list(mod_details_raw)
                baseline_file_ops = baseline.get('file_operations', {})
                
                for norm_file, original_file in modified.items():
                    file_mod_info = None
                    for detail in mod_details:
                        if detail.get('file') == original_file:
                            file_mod_info = detail
                            break
                    
                    mod_user = file_mod_info.get('user') if file_mod_info else None
                    
                    file_in_baseline = False
                    for baseline_file in baseline_file_ops.keys():
                        if SequenceMatcher(None, norm_file.lower(), baseline_file.lower()).ratio() >= 0.90:
                            file_in_baseline = True
                            break
                    
                    if not file_in_baseline:
                        anomalies.append(
                            self._make_anomaly(
                                type="ALERT_NEW_MODEL_FILE_MODIFICATION",
                                severity="CRITICAL",
                                details=f"FIRST TIME: {original_file}",
                                row=row,
                                baseline=baseline,
                                normalized_args=normalized_args,
                                occurrence_count=occurrence_count,
                                confidence_score=0.98,
                                extra={"file": original_file}
                            )
                        )
                
                # CHILD SPAWNING
                children_of_this = df_children[
                    (df_children['MachineName'] == row['MachineName']) &
                    (df_children['ProcessPPidCreationTime'] == row['PidCreationTime'])
                ]

                baseline_spawned = baseline.get('spawned_with_args', set())

                for _, child in children_of_this.iterrows():
                    child_process = child.get('ProcessName')
                    if not child_process or not str(child_process).strip():
                        continue
                    
                    child_args_norm = self._normalize_process_args(child.get('ProcessArgs'))
                    exact_match = (child_process, child_args_norm) in baseline_spawned
                    
                    if not exact_match:
                        baseline_args = [args for proc, args in baseline_spawned if proc == child_process]
                            
                        if not baseline_args:
                            anomalies.append(
                                self._make_anomaly(
                                    type="ALERT_NEW_SPAWNED_PROCESS",
                                    severity="CRITICAL",
                                    details=f"Never spawned: {child_process}",
                                    row=row,
                                    baseline=baseline,
                                    normalized_args=normalized_args,
                                    occurrence_count=occurrence_count,
                                    confidence_score=0.95,
                                    extra={"child_process": child_process}
                                )
                            )

                if anomalies:
                    max_confidence = max(a.get('confidence_score', 0.0) for a in anomalies)
                    
                    all_alerts.append({
                        'timestamp': alert_timestamp,
                        'machine': row['MachineName'],
                        'process': row['ProcessName'],
                        'pid': int(row['Pid']) if pd.notna(row['Pid']) else 0,
                        'user': user,
                        'signer': signer,
                        'process_args': str(row.get('ProcessArgs', ''))[:200],
                        'anomaly_count': len(anomalies),
                        'max_confidence_score': float(max_confidence),
                        'baseline_context': {
                            'status': 'ACTIVE_DETECTION',
                            'occurrence_count': occurrence_count
                        },
                        'anomalies': anomalies
                    })
        
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            if all_alerts:
                return pd.DataFrame(all_alerts)
            return pd.DataFrame()
        
        print(f"\n📊 Summary: {matched_keys + unmatched_keys} checked, {matched_keys} matched, {unmatched_keys} new")
              
        if all_alerts:
            print(f"🚨 {len(all_alerts)} alerts")
            confidences = [a.get('max_confidence_score', 0) for a in all_alerts]
            if confidences:
                print(f"  📈 Confidence: {min(confidences):.2f}-{max(confidences):.2f}, avg: {np.mean(confidences):.2f}")
            return pd.DataFrame(all_alerts)
        
        print("✅ No anomalies")
        return pd.DataFrame()
    
    def save_alerts(self, alerts_df):
        """Save alerts with confidence scores"""
        if len(alerts_df) == 0:
            print("No alerts")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, 'alerts', f'alerts_{timestamp}.csv')
        
        alerts_flat = []
        for _, alert in alerts_df.iterrows():
            for anomaly in alert['anomalies']:
                flat_alert = {
                    'timestamp': alert['timestamp'],
                    'machine': self._obfuscate_machine_name(alert['machine']),
                    'process': alert['process'],
                    'pid': alert['pid'],
                    'user': self._obfuscate_user_name(alert['user']),
                    'signer': alert.get('signer', 'UNKNOWN'),
                    'confidence_score': anomaly.get('confidence_score', 0.0),
                    'alert_max_confidence': alert.get('max_confidence_score', 0.0),
                    'severity': anomaly.get('severity', 'UNKNOWN'),
                    'anomaly_type': anomaly.get('type', 'UNKNOWN'),
                    'details': anomaly.get('details', ''),
                    'mitre_attack': ",".join(anomaly.get("mitre_attack", [])),
                    'ai_risk': ",".join(anomaly.get("ai_risk", [])),
                    'observed_json': self._to_json_str(anomaly.get("observed", {})),
                    'baseline_context_json': self._to_json_str(anomaly.get("baseline_context", {})),
                    'anomaly_json': self._to_json_str(anomaly),
                }
                
                flat_alert["alert_id"] = self._alert_id(alert, anomaly)
                alerts_flat.append(flat_alert)
        
        df_flat = pd.DataFrame(alerts_flat)
        df_flat.to_csv(filepath, index=False)
        
        master = os.path.join(self.output_dir, 'alerts', 'all_alerts.csv')
        if os.path.exists(master):
            df_flat.to_csv(master, mode='a', header=False, index=False)
        else:
            df_flat.to_csv(master, index=False)
        
        print(f"💾 Saved {len(alerts_flat)} alerts to {filepath}")
        
        if 'confidence_score' in df_flat.columns:
            high = len(df_flat[df_flat['confidence_score'] >= 0.8])
            med = len(df_flat[(df_flat['confidence_score'] >= 0.5) & (df_flat['confidence_score'] < 0.8)])
            low = len(df_flat[df_flat['confidence_score'] < 0.5])
            print(f"  📊 High (≥0.8): {high}, Med (0.5-0.8): {med}, Low (<0.5): {low}")
    
    def merge_baselines_with_frequency_and_decay(self, existing, new_process, new_children, 
                                                   min_occurrences=3, decay_days=30, critical_decay=90):
        """Merge with frequency filtering and decay (your existing method - kept as is)"""
        # Your existing merge logic here - not modified
        pass  # Replace with your existing implementation


def execute(cluster, database, tenant, output_dir, mode, lookback_unit='day', 
            lookback_count=1, bootstrap_count=7, delay_seconds=5, baseline_offset=0):
    """Execute workflow"""
    detector = AIAgentAnomalyDetector(cluster, database, tenant, output_dir)
    
    print("="*80)
    print(f"🤖 AI Anomaly Detection (Statistical) for {tenant}")
    print("="*80)
    
    if mode == 'bootstrap':
        print(f"\n📁 Collecting {bootstrap_count} {lookback_unit}(s) + building baseline")
        
        all_process = []
        all_children = []
        successful = 0
        start_period = bootstrap_count + baseline_offset
        end_period = baseline_offset
        
        for period in range(start_period, end_period, -1):
            try:
                print(f"\n[{start_period - period + 1}/{bootstrap_count}] Period {period}...")

                df_proc = detector.collect_ai_process_data(period, lookback_unit)
                if len(df_proc) > 0:
                    ai_parents = df_proc['PidCreationTime'].unique().tolist()
                    df_child = detector.collect_child_spawning_data(ai_parents, period, lookback_unit)
                else:
                    df_child = pd.DataFrame()
                    
                if len(df_proc) > 0:
                    all_process.append(df_proc)
                    successful += 1
                if len(df_child) > 0:
                    all_children.append(df_child)
                
                if period > 1:
                    time.sleep(delay_seconds)
                    
            except Exception as e:
                print(f"❌ Error: {e}")
        
        print(f"\n✅ Collected {successful} periods")
        
        if all_process:
            existing_baseline = detector.load_baseline()
            
            if existing_baseline:
                print(f"📚 Merging with existing baseline...")
                existing_baseline = detector.merge_baselines_with_frequency_and_decay(
                    existing_baseline, all_process, all_children, min_occurrences=3, 
                    decay_days=30, critical_decay=90
                )
                detector.save_baseline(existing_baseline)
            else:
                baselines = detector.build_baseline(all_process, all_children)
                detector.save_baseline(baselines)
        else:
            print("⚠️ No data collected")
    
    elif mode == 'train':
        print("\n🔨 Rebuilding baseline from saved collections...")
        raw_dir = os.path.join(output_dir, 'raw_collections')
        
        if not os.path.exists(raw_dir):
            print("⚠️ No raw collections")
            return
        
        proc_files = sorted([f for f in os.listdir(raw_dir) if f.startswith('process_')])
        child_files = sorted([f for f in os.listdir(raw_dir) if f.startswith('child_')])
        
        if not proc_files:
            print("⚠️ No data")
            return
        
        all_proc = [pd.read_csv(os.path.join(raw_dir, f)) for f in proc_files]
        all_child = [pd.read_csv(os.path.join(raw_dir, f)) for f in child_files] if child_files else []
        
        baselines = detector.build_baseline(all_proc, all_child)
        detector.save_baseline(baselines)
    
    elif mode == 'detect':
        baselines = detector.load_baseline()
        
        if not baselines:
            print("⚠️ No baseline. Run bootstrap first.")
            return
        
        detect_period = 0 if lookback_unit == 'day' else 1
        df_proc = detector.collect_ai_process_data(detect_period, lookback_unit)
        
        if df_proc is not None and len(df_proc) > 0:
            ai_parents = df_proc['PidCreationTime'].unique().tolist()
            df_child = detector.collect_child_spawning_data(ai_parents, detect_period, lookback_unit)
        else:
            df_child = pd.DataFrame()
        
        if (df_proc is not None and len(df_proc) > 0) or (df_child is not None and len(df_child) > 0):
            alerts = detector.detect_anomalies(df_proc, df_child, baselines, min_occurrences=3)
            
            if alerts is not None and len(alerts) > 0:
                detector.save_alerts(alerts)
                print("\n" + "="*80)
                print(f"🚨 ALERTS")
                print("="*80)
    
    elif mode == 'collect':
        print(f"\n📅 Collecting {lookback_count} {lookback_unit}(s)")
        
        for period in range(lookback_count, 0, -1):
            try:
                detect_period = 0 if lookback_unit == 'day' else 1
                df_proc = detector.collect_ai_process_data(detect_period, lookback_unit)
                df_child = detector.collect_child_spawning_data(detect_period, lookback_unit)
                
                if lookback_unit == 'hour':
                    ts = (datetime.now() - timedelta(hours=period)).strftime('%Y%m%d_%H%M%S')
                else:
                    ts = (datetime.now() - timedelta(days=period)).strftime('%Y%m%d')
                
                raw_dir = os.path.join(detector.output_dir, 'raw_collections')
                if len(df_proc) > 0:
                    df_proc.to_csv(os.path.join(raw_dir, f'process_{ts}.csv'), index=False)
                if len(df_child) > 0:
                    df_child.to_csv(os.path.join(raw_dir, f'child_{ts}.csv'), index=False)
                
                print(f"   💾 Period {period}")
                if period > 1:
                    time.sleep(2)
            except Exception as e:
                print(f"   ❌ Error: {e}")
    
    print("\n✅ Complete!")


def main():
    parser = argparse.ArgumentParser(description='AI Anomaly Detection with Statistical Models')
    parser.add_argument('--cluster', required=True)
    parser.add_argument('--database', required=True)
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--mode', choices=['train', 'detect', 'collect', 'bootstrap'], default='bootstrap')
    parser.add_argument('--lookback-unit', choices=['hour', 'day'], default='day')
    parser.add_argument('--lookback-count', type=int, default=1)
    parser.add_argument('--bootstrap-count', type=int, default=7)
    parser.add_argument('--delay-seconds', type=int, default=5)
    args = parser.parse_args()
    
    execute(args.cluster, args.database, args.tenant, args.output_dir, args.mode,
            args.lookback_unit, args.lookback_count, args.bootstrap_count, args.delay_seconds)


if __name__ == '__main__':
    main()


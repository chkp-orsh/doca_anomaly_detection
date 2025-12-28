import pandas as pd
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



#set servertimeout = 10m;
#set query_results_cache_max_age = 0d;
#set maxmemoryconsumptionperiterator=16106127360

import ast

def clean_set(domains):
    return {str(d).strip() for d in domains if d is not None and str(d).strip()}



class AIAgentAnomalyDetector:
    """
    Set-based anomaly detection for AI agents using two-query approach:
    - Query 1: AI process behavior (network, files) using original scoring logic
    - Query 2: Child process spawning by AI parents
    - Detection: Compare sets (spawned processes, domains, IPs, files) against baseline
    """
    
    def __init__(self, cluster_url, database, tenant_id, output_dir):
        self.cluster_url = cluster_url
        self.database = database
        self.tenant_id = tenant_id
        self.output_dir = output_dir
        
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'baselines'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'alerts'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'raw_collections'), exist_ok=True)
        
        self.kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(cluster_url)
        self.client = KustoClient(self.kcsb)


        
    def _to_json_str(self, v, max_len: int = 20000) -> str:
        """Safe stringify for CSV: list/dict/set -> compact JSON; truncate."""
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
        # Pad or hash to exactly 32 bytes for AES-256
        import hashlib
        return hashlib.sha256(key.encode()).digest()  

    def _obfuscate_value(self, value):
        """Encrypt a value using AES"""
        if not value or value in ['UNKNOWN', 'UNSIGNED', 'ERR:NOT-REPORTED']:
            return value
        
        from cryptography.fernet import Fernet
        import base64
        
        # Create Fernet key from output_dir
        key_bytes = self._get_obfuscation_key()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        cipher = Fernet(fernet_key)
        
        # Encrypt
        encrypted = cipher.encrypt(value.encode('utf-8'))
        return f"ENC_{base64.urlsafe_b64encode(encrypted).decode()}"

    def _deobfuscate_value(self, obfuscated):
        """Decrypt a value"""
        if not obfuscated or not obfuscated.startswith('ENC_'):
            return obfuscated  # Not encrypted or special value
        
        from cryptography.fernet import Fernet
        import base64
        
        try:
            # Remove ENC_ prefix
            encrypted_data = obfuscated[4:]
            
            key_bytes = self._get_obfuscation_key()
            fernet_key = base64.urlsafe_b64encode(key_bytes)
            cipher = Fernet(fernet_key)
            
            # Decrypt
            decrypted = cipher.decrypt(base64.urlsafe_b64decode(encrypted_data))
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"⚠️ Decryption failed for {obfuscated[:20]}: {e}")
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
        extra=None
    ) -> dict:
        """
        Build a fully detailed anomaly and ALWAYS enrich it.
        """

        baseline_context = baseline_context or {}
        extra = extra or {}

        # Core identity
        machine = row.get("MachineName") if row is not None else ""
        process = row.get("ProcessName") if row is not None else ""
        user = row.get("UserName", "UNKNOWN") if row is not None else "UNKNOWN"
        signer = self._normalize_signer(row.get("ProcessSigner")) if row is not None else "ERR:NOT-REPORTED"
        pid = int(row.get("Pid", 0)) if row is not None and pd.notna(row.get("Pid")) else None

        anomaly = {
            "type": type,
            "severity": severity,
            "details": details,

            # Identity
            "machine": machine,
            "process": process,
            "pid": pid,
            "user": user,
            "signer": signer,

            # Context
            "baseline_context": baseline_context,

            # Observed behavior (max detail, safe)
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

        # Optional: baseline snapshot
        if baseline:
            anomaly["baseline_snapshot"] = {
                "occurrence_count": occurrence_count,
                "baseline_users": list(baseline.get("users", set())),
                "baseline_domains": list(baseline.get("contacted_domains", set())),
                "baseline_dirs": list(baseline.get("accessed_dirs", set())),
                "baseline_spawned_processes": list(baseline.get("spawned_processes", set())),
            }

        # Optional: caller extras
        anomaly.update(extra)
        
        model_path_hits = []
        for d in anomaly["observed"].get("accessed_dirs", []):
            if any(p.search(d) for p in MODEL_PATH_PATTERNS):
                model_path_hits.append(d)
                if len(model_path_hits) >= 10:
                    break

        anomaly["observed"]["model_path_hits"] = model_path_hits

        # 🔐 ALWAYS enrich here
        return self._enrich_anomaly(anomaly)
    
        
    def _normalize_filename(self, filename):
        """Normalize filenames to remove variable parts"""
        if not filename or pd.isna(filename):
            return ""
        
        import re
        filename = str(filename).strip()
        
        # Extract just the filename if full path provided
        if '\\' in filename or '/' in filename:
            filename = filename.split('\\')[-1].split('/')[-1]
        
        filename = filename.lower()
        
        # Remove trailing numbers: cache0000.bin → cache<NUM>.bin
        filename = re.sub(r'(\D+)\d+(\.\w+)$', r'\1<NUM>\2', filename)
        
        # Remove numbers in middle: file_1234_data.bin → file_<NUM>_data.bin
        filename = re.sub(r'_\d{3,}', '_<NUM>', filename)
        
        # Remove hex patterns (32+ chars)
        filename = re.sub(r'[0-9a-f]{32,}', '<HASH>', filename, flags=re.IGNORECASE)
        
        # Remove GUIDs
        filename = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<GUID>', filename, flags=re.IGNORECASE)
        
        # Remove timestamps: 20240315_143022
        filename = re.sub(r'\d{8}_\d{6}', '<TIMESTAMP>', filename)
        
        return filename.strip()
    
    
        
    def _execute_query(self, query, max_tries=5, sleepTimeinSecs=30):
        trys=0
        
        #print ("=============")
        #print (query)
        #print ("=============")
        for trys in range(0,max_tries):
            try:
                str_error = None
                query = f"set servertimeout = 10m;\nset query_results_cache_max_age = 0d;\n{query}"
                properties = ClientRequestProperties()
                properties.set_option(ClientRequestProperties.request_timeout_option_name, timedelta(minutes=15))
                response = self.client.execute(self.database, query, properties=properties)
                df = dataframe_from_result_table(response.primary_results[0])
                if df is None:
                    print(f"⚠️ Query returned None (treating as empty). tenant={self.tenant_id}, lookback={lookback_value} {lookback_unit}")
                    return pd.DataFrame()
                return df
            except Exception as e:
                str_error = str(e).lower()
                
                #look if it is a DB error, they are usually temporary, so wait some time and try again
                substrings =["Failed to resolve table expression","Access denied","Failed to obtain Az","Az login", "access", "connection", "network"]
    
                print(f"❌ Query error: 1 {e}")
                if any(sub.lower() in str_error for sub in substrings):
                #str_conn_err in str_error:
                    print (f"eeeeeeeeeeeeeeeeeeeee traying again {trys}")
                    time.sleep (sleepTimeinSecs)
                    print (f"eeeeeeeeeeeeeeeeeeeee {trys} After Sleep {sleepTimeinSecs}")
                    pass
                else:    
                    print(f"❌ Query error: 2 {e}")
                    print ("eeeeeeeeeeeeeeeeeeeee")
                    print (query)
                    print ("eeeeeeeeeeeeeeeeeeeee")
                    raise
    
    def _normalize_process_args(self, args):
        """Extract stable command pattern, remove variable parts"""
        if not args or pd.isna(args):
            return ""
        
        import re
        args = str(args)
        
        args = REGEX_PATTERNS["guid"].sub("<GUID>", args)
        args = REGEX_PATTERNS["sha256"].sub("<SHA256>", args)
        args = REGEX_PATTERNS["sha1"].sub("<SHA1>", args)
        args = REGEX_PATTERNS["md5"].sub("<MD5>", args)
        
        # Remove large numbers (>1000) - these are sizes, IDs, memory values
        args = re.sub(r'\b\d{4,}\b', '<NUM>', args)
        
        # Remove file paths
        args = re.sub(r'[A-Za-z]:\\[^\s]+', '<PATH>', args, flags=re.IGNORECASE)
        args = re.sub(r'/[^\s]+\.(pt|pkl|onnx|h5|bin|gguf|pth|safetensors)', '<MODELFILE>', args)
        args = re.sub(r'/[^\s/]+/[^\s]+', '<PATH>', args)  # Generic paths
        
        # Remove timestamps and dates
        args = re.sub(r'\d{8}_\d{6}', '<TIMESTAMP>', args)
        args = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', args)
        
        # Remove port numbers
        args = re.sub(r':\d{4,5}', ':<PORT>', args)
        
        # Remove GUIDs/UUIDs
        args = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', args, flags=re.IGNORECASE)
        
        # Remove hex addresses
        args = re.sub(r'0x[0-9a-f]+', '<HEX>', args, flags=re.IGNORECASE)
    
        return args.strip()
    
    
    

        
    def _normalize_directory_path(self, path):
        """Normalize directory paths"""
        if not path or pd.isna(path):
            return ""
        
        import re
        path = str(path).lower()
        
        # NEW: Normalize Windows volume numbers - they change between boots
        path = REGEX_PATTERNS["user_profile"].sub(r"\\users\\<USER>\\", path)
        path = re.sub(r'\\device\\harddiskvolume\d+', r'\\device\\harddiskvolume<VOL>', path)
    
        
        # Normalize user directories
        #path = re.sub(r'c:\\users\\[^\\]+', r'c:\users\<USER>', path, flags=re.IGNORECASE
        path = re.sub(r'c:\\users\\[^\\]+', r'c:\\users\\<USER>', path, flags=re.IGNORECASE)

        path = re.sub(r'/home/[^/]+', r'/home/<USER>', path)
        
        # Remove temp directory numbers: _mei228202 → _mei<NUM>
        path = re.sub(r'_mei\d+', r'_mei<NUM>', path)
        path = re.sub(r'\\temp\d+', r'\temp<NUM>', path)
        
        # Remove date patterns: 2020-08, 2017-04 → <DATE>
        path = re.sub(r'\b20\d{2}-\d{2}\b', '<DATE>', path)
        path = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '<DATE>', path)
        
        # Remove hashes (32+ hex)
        path = re.sub(r'[0-9a-f]{32,}(_\d+)?', '<HASH>', path, flags=re.IGNORECASE)
        
        # Remove GUIDs
        path = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<GUID>', path, flags=re.IGNORECASE)
        
        # Remove version numbers
        path = re.sub(r'[_\\]v?\d+\.\d+(\.\d+)?', r'\<VER>', path)
        
        # Remove trailing numbers: _61, _184 → (empty)
        path = re.sub(r'[_\\]\d+$', '', path)
        
        return path.strip()
        

    
    def _safe_parse_list(self, value):
        """Safely parse a value that might be a string, list, or other object"""
        
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
        
        # Single object (dict, etc.)
        return [value]
    
    def _normalize_signer(self, signer):
        """Normalize signer - handle empty/None values"""
        if not signer or pd.isna(signer) or str(signer).strip() == '':
            return 'ERR:NOT-REPORTED'
        return str(signer).strip()
    
    def _get_current_date(self):
        """Get current date as string for tracking"""
        return datetime.now().strftime('%Y-%m-%d')

    def _days_since(self, date_str):
        """Calculate days between date_str and today"""
        try:
            past = datetime.strptime(date_str, '%Y-%m-%d')
            now = datetime.now()
            return (now - past).days
        except:
            return 999  # Very old if can't parse  


    def collect_ai_process_data(self, lookback_value=1, lookback_unit='day'):
        """
        Query 1: Collect AI process behavior using original detection logic
        Returns aggregated data per process instance with sets of domains, IPs, files
        """
        if lookback_unit == 'hour':
            start_time = f"ago({lookback_value}h)"
            end_time = f"ago({lookback_value - 1}h)"
        else:
            if lookback_value == 0:
                # Today so far
                start_time = f"startofday(now())"
                end_time = f"now()"
            else:
                start_time = f"startofday(ago({lookback_value}d))"
                end_time = f"endofday(ago({lookback_value}d))"
                
        def _kusto_dynamic_str_list(items):
            # -> dynamic(["a","b"])
            escaped = [str(x).replace('\\', '\\\\').replace('"', '\\"') for x in items]
            return 'dynamic(["' + '","'.join(escaped) + '"])'

        def _kusto_dynamic_num_list(items):
            # -> dynamic([1,2,3])
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
let SuspiciousDirs = dynamic(["temp", "tmp", "downloads", "desktop", "documents", "userlet ToolProcessNames s"]);
database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
| where OpTimeSecondsUTC between ({start_time} .. {end_time})
| extend FileExtension = tolower(extract(@"\\.([^.]+)$", 1, FileName))
//|where tolower(ProcessName) !in (processIgnoreList)
| where tolower(FileName) has_any (FileNameSearch) or tolower(FileDir) has_any (FileDirSearch) 
or tolower(ProcessArgs) has_any (AICmdlineKeywords) 
//or tolower(ParentProcessArgs) has_any (AICmdlineKeywords) 
or tolower(ProcessDir) has_any (LLMApiPathFragments) 
or tolower(ProcessDir) has_any (FileDirSearch) 
//or tolower(ParentProcessDir) has_any (LLMApiPathFragments) 
//or tolower(ParentProcessDir) has_any (FileDirSearch) 
or tolower(ProcessName) has_any (GenericInterpreterProcessNames) 
or tolower(ProcessName) has_any (CommonDevOrBrowserProcesses) 
or tolower(ProcessName) has_any (ToolProcessNames) or tolower  (ProcessName) has_any(FileNameSearch)  //or ParentProcessName has_any (FileNameSearch)
//or tolower(ParentProcessName) has_any (GenericInterpreterProcessNames) 
//or tolower(ParentProcessName) has_any (CommonDevOrBrowserProcesses) or tolower(ParentProcessName) has_any (ToolProcessNames)
 or (FileExtension in (ExtSearch) and FileSize > 500) or tolower(NetworkPath) has_any (AIModulePathPatterns) or tolower(NetworkDomain) in (LLMApiDomains) 
or tolong(NetworkDestPort) in (CommonAIServingPorts) or tolong(NetworkSrcPort) in (CommonAIServingPorts)  or tolong(NetworkDestPort) between (3000..3100) or tolong (NetworkSrcPort) between (3000..3100)
or ((NetworkDestIP in (LocalhostAddresses) or NetworkSrcIP in (LocalhostAddresses)) and NetworkConnectionDirection == "Incoming")
| extend hasModelFile = toint(FileExtension in (ModelFileExtensions) and FileSize > 50000000),
 hasTokenizerOrConfig = toint(FileExtension in (TokenizerAndConfigExtensions)),
 hasAiRuntimeFile = toint(FileName has_any (AIModuleFileNamePatterns)), hasAiRuntimePath = toint(FileDir has_any (AIModulePathPatterns) or NetworkPath has_any (AIModulePathPatterns)), isKnownAIServingProcess = toint(ProcessName has_any (KnownAIServingProcessNames)), 
 isGenericInterpreter = toint(ProcessName has_any (GenericInterpreterProcessNames)
// or ParentProcessName has_any (GenericInterpreterProcessNames)
), 
 isToolProcess = toint(ProcessName has_any (ToolProcessNames) 
 //or ParentProcessName has_any (ToolProcessNames)
 ), 
 hasAiCmdline = toint(ProcessArgs has_any (AICmdlineKeywords) //or ParentProcessArgs has_any (AICmdlineKeywords)
 ),
 talksToLLMApi = toint(NetworkDomain in (LLMApiDomains) and NetworkPath has_any (LLMApiPathFragments)), 
usesAIServingPort = toint(NetworkDestPort in (CommonAIServingPorts) or NetworkSrcPort in (CommonAIServingPorts)
//or(tolong(NetworkDestPort) between (3000..3100) or tolong (NetworkSrcPort) between (3000..3100))
 ),
 hasLocalhostInbound = toint((NetworkDestIP in (LocalhostAddresses) or NetworkSrcIP in (LocalhostAddresses)) and NetworkConnectionDirection == "Incoming"), hasLongConnection = coalesce(toint(unixtime_seconds_todatetime(NetworkConnectionCloseTime) - unixtime_seconds_todatetime(NetworkConnectionStartTime) > longNetworkCon), 0), hasSuspiciousArgs = toint(tolower(ProcessArgs) has_any (SuspiciousArgs) //or tolower(ParentProcessArgs) has_any (SuspiciousArgs)
 ), 
 isSuspiciousDir = toint(tolower(FileDir) has_any (SuspiciousDirs)or tolower(ProcessDir) has_any (SuspiciousDirs) 
// or tolower(ParentProcessDir) has_any (SuspiciousDirs)
 ),
 isLargeFile = toint(FileSize > 100000)
| extend aiScore = 5 * hasModelFile + 3 * hasTokenizerOrConfig + 4 * (hasAiRuntimeFile + hasAiRuntimePath) + 3 * isKnownAIServingProcess + 2 * hasAiCmdline + 2 * talksToLLMApi + 1 * usesAIServingPort + 1 * hasLocalhostInbound + 2 * hasLongConnection
| where aiScore > {SEVERITY_THRESHOLDS["min_ai_score"]}
| summarize event_count = count(),
            PidCreationTime = take_any(PidCreationTime),
            NetworkBytesSent_sum = sum(NetworkBytesSent),
            NetworkBytesReceived_sum = sum(NetworkBytesReceived),
            contacted_domains = make_set(NetworkDomain), contacted_ips = make_set(NetworkDestIP), contacted_ports = make_set(NetworkDestPort), network_paths = make_set(NetworkPath), accessed_files = make_set(FileName), accessed_dirs = make_set(FileDir),
            accessed_extensions = make_set(FileExtension),
            modified_files = make_set_if(FileName,
            isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0),
            modified_model_files = make_set_if(FileName,isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0 and FileExtension in (ModelFileExtensions)), 
            file_mod_details = make_bag_if(pack("file", FileName, "user", UserName, "args", ProcessArgs),
            isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0), 
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
     by MachineName, ProcessName, Pid, CreationTime,  ProcessSigner
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

   
        #print ("=============")
        #print (query)
        #print ("=============")
        

            
        df = self._execute_query(query)
        
        if df is None:
            print(f"⚠️ Query returned None for {self.tenant_id}")
            return pd.DataFrame()
        
        print(f"✅ Collected {len(df)} AI process  for {self.tenant_id}")
        return df
    
    def collect_child_spawning_data(self, ai_parent_pct_list, lookback_value=1, lookback_unit='day'):
        """Query 2: Get children where ProcessPPidCreationTime matches AI parents"""
        
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
        
        # Build KQL array
        #print ("collect_child_spawning_data 7")
        parent_array = ', '.join([f'"{pct}"' for pct in ai_parent_pct_list])
        #print ("collect_child_spawning_data 8")
        #pprint.pprint (parent_array)
        
        query = f"""set servertimeout = 10m;
    set query_results_cache_max_age = 0d;
    let AIParents = dynamic([{parent_array}]);
    database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
    | where OpTimeSecondsUTC between ({start_time} .. {end_time})
    | where ProcessPPidCreationTime in (AIParents)
    //| where PidCreationTime in (AIParents)
    | project MachineName, ParentProcessName, ProcessPPidCreationTime, ProcessName, ProcessArgs, ProcessDir, ProcessSigner, ParentProcessSigner
    | take 10000"""
       
        #print ("===========")
        #print ("collect_child_spawning_data 9")
        df = self._execute_query(query)
        #print ("collect_child_spawning_data 10")
        print(f"✅ Collected {len(df)} children of AI process  for {self.tenant_id}")

        if df is None:
            print(f"⚠️ Query returned None for {self.tenant_id}")
            return pd.DataFrame()
        return df
    

    
    def build_baseline(self, df_process_list, df_children_list):
        """Build baseline sets from collected data"""
        print("\n🔨 Building behavioral baselines...")
        
        # Combine all collections
        df_process = pd.concat(df_process_list, ignore_index=True) if df_process_list else pd.DataFrame()
        df_children = pd.concat(df_children_list, ignore_index=True) if df_children_list else pd.DataFrame()
        
        baselines = defaultdict(lambda: {
            'spawned_processes': set(),
            'spawned_args': set(),
            'spawned_with_args': set(),  # ← ADD THIS (tuples of (process, normalized_args))
            'contacted_domains': set(),
            'contacted_ips': set(),
            'contacted_ports': set(),
            'network_paths': set(),
            'accessed_files': set(),
            'accessed_dirs': set(),
            'accessed_extensions': set(),
            'users': set(),
            'process_args': set(),
            'file_operations': {},  # NEW: Track file modifications
            'stats': {'instances': 0, 'avg_bytes_sent': 0, 'max_bytes_sent': 0},
            'occurrence_count': 0  # NEW: Track how many times this combination was seen
        })
        
        # Build from process data
        for _, row in df_process.iterrows():
            #key = (row['MachineName'], row['ProcessName'])
            normalized_args = self._normalize_process_args(row.get('ProcessArgs'))
            user = row.get('UserName', 'UNKNOWN')
            signer = self._normalize_signer(row.get('ProcessSigner'))
            key = (row['MachineName'], row['ProcessName'], normalized_args, signer)
            
            
            if 'detection_reason' not in baselines[key]:
                # Build reason from query results
                reason_details = {
                    'first_detected': self._get_current_date(),
                    'ai_score': float(row.get('aiScore_avg', 0)) if pd.notna(row.get('aiScore_avg')) else 0,
                    'detection_triggers': [],
                    'example_behavior': {}
                }
                
                # Determine what triggered detection
                ai_score = row.get('aiScore_avg', 0)
                
                if row.get('model_files_count', 0) > 0:
                    reason_details['detection_triggers'].append(f"Model files ({row.get('model_files_count', 0)} files)")
                
                if row.get('llm_api_count', 0) > 0:
                    reason_details['detection_triggers'].append(f"LLM API calls ({row.get('llm_api_count', 0)})")
                    # Add example domains
                    domains = self._safe_parse_list(row.get('contacted_domains'))
                    reason_details['example_behavior']['llm_domains'] = list(set(domains))[:3]
                
                if row.get('suspicious_args_count', 0) > 0:
                    reason_details['detection_triggers'].append("Suspicious arguments")
                
                # Add process details
                reason_details['example_behavior']['process_dir'] = row.get('ProcessDir', '')
                
                # Store it
                baselines[key]['detection_reason'] = reason_details
            
            
            domains_raw = row.get('contacted_domains')
            
            if isinstance(domains_raw, list):
                baselines[key]['contacted_domains'].update([d for d in domains_raw if d])
            elif pd.notna(domains_raw):
                try:
                    domains = self._safe_parse_list(domains_raw)
                    baselines[key]['contacted_domains'].update([d for d in domains if d])
                except: pass
            
            IPs_raw = row.get('contacted_ips')
            if isinstance(IPs_raw, list):
                baselines[key]['contacted_ips'].update([d for d in IPs_raw if d])
            elif pd.notna(IPs_raw):
                try:
                    domains = self._safe_parse_list(IPs_raw)
                    baselines[key]['contacted_ips'].update([d for d in IPs_raw if d])
                except: pass            
            
            
            if pd.notna(row.get('contacted_ports')):
                try:
                    ports = eval(row['contacted_ports'])
                    baselines[key]['contacted_ports'].update([str(p) for p in ports if p])
                except: pass
                
            ports_raw = row.get('contacted_ports')
            if isinstance(ports_raw, list):
                baselines[key]['contacted_ports'].update([d for d in IPs_raw if d])
            elif pd.notna(ports_raw):
                try:
                    domains = self._safe_parse_list(ports_raw)
                    baselines[key]['contacted_ports'].update([d for d in IPs_raw if d])
                except: pass            
            
            
            if pd.notna(row.get('network_paths')):
                try:
                    paths = eval(row['network_paths'])
                    baselines[key]['network_paths'].update([p for p in paths if p])
                except: pass
                
            network_path_raw = row.get('network_paths')
            if isinstance(network_path_raw, list):
                baselines[key]['network_paths'].update([d for d in IPs_raw if d])
            elif pd.notna(network_path_raw):
                try:
                    domains = self._safe_parse_list(network_path_raw)
                    baselines[key]['network_paths'].update([d for d in IPs_raw if d])
                except: pass            
               
          
            a_fs=row.get('accessed_files')
            #if pd.notna(row.get('accessed_files')):
            if isinstance(a_fs,list):
                try:
                    #files = eval(row['accessed_files'])
                    #baselines[key]['accessed_files'].update([f for f in a_fs if f])
                    baselines[key]['accessed_files'].update([self._normalize_filename(f) for f in a_fs if f])

                except: pass


            #if pd.notna(row.get('accessed_dirs')):
            dirs = row.get('accessed_dirs')
            if isinstance(dirs, list):
                try:
                    #dirs = eval(row['accessed_dirs'])
                    #baselines[key]['accessed_dirs'].update([d for d in dirs if d])
                    #baselines[key]['accessed_dirs'].update([d for d in dirs if d])
                    #baselines[key]['accessed_dirs'].update([d for d in dirs if d])
                    baselines[key]['accessed_dirs'].update([self._normalize_directory_path(d) for d in dirs if d])
                except: pass
            
            exts=row.get('accessed_extensions')
            if isinstance(exts, list):
            #if pd.notna(row.get('accessed_extensions')):
                try:
                    #exts = eval(row['accessed_extensions'])
                    baselines[key]['accessed_extensions'].update([e for e in exts if e])
                except: pass
            
            if pd.notna(row.get('UserName')):
                baselines[key]['users'].add(row['UserName'])
            
            if pd.notna(row.get('ProcessArgs')):
                baselines[key]['process_args'].add(row['ProcessArgs'])
            
            # NEW: Build file operation baseline
            if pd.notna(row.get('file_mod_details')):  # FIX: was 'file_ops_details'
                try:
                    ops = self._safe_parse_list(row['file_mod_details'])
                    if not isinstance(ops, list):
                        ops = [ops]
                    
                    for op in ops:
                        filename_raw = op.get('file')
                        if not filename_raw:
                            continue
                        
                        # FIX: Normalize filename for baseline
                        filename = self._normalize_filename(filename_raw)
                        
                        if filename not in baselines[key]['file_operations']:
                            baselines[key]['file_operations'][filename] = {
                                'operations': set(),
                                'users': set(),
                                'process_args': set()
                            }
                        
                        # Track which operations happened on this file
                        # Note: FileOpMask bit flags: Create=2, Write=16, Delete=4
                        # Based on query: binary_and(FileOpMask, 38970) checks for modifications
                        if op.get('user'):
                            baselines[key]['file_operations'][filename]['users'].add(op['user'])
                        if op.get('args'):
                            norm_args = self._normalize_process_args(op['args'])
                            baselines[key]['file_operations'][filename]['process_args'].add(norm_args)
                except Exception as e:
                    print(f"Warning: Could not parse file_mod_details: {e}")
                    pass
                        
            

            # Build from child data - need to match with parent instances
        for _, child_row in df_children.iterrows():
            # Find the parent in df_process using PidCreationTime matching
            parent_match = df_process[
                (df_process['MachineName'] == child_row['MachineName']) &
                (df_process['PidCreationTime'] == child_row['ProcessPPidCreationTime'])
            ]
            
            if len(parent_match) == 0:
                continue  # No parent found, skip
            
            parent = parent_match.iloc[0]
            
            # Build key using PARENT's args and user
            normalized_parent_args = self._normalize_process_args(parent.get('ProcessArgs'))
            parent_signer = self._normalize_signer(parent.get('ProcessSigner'))
            key = (child_row['MachineName'], parent['ProcessName'], normalized_parent_args, parent_signer)
                        
            # Add child's process and args
            child_process = child_row.get('ProcessName')
            child_args_normalized = self._normalize_process_args(child_row.get('ProcessArgs'))
            
            if child_process:
                baselines[key]['spawned_processes'].add(child_process)
                baselines[key]['spawned_with_args'].add((child_process, child_args_normalized))
            
            if child_row.get('ProcessArgs'):
                baselines[key]['spawned_args'].add(child_row['ProcessArgs'])

        
        # Compute numeric stats
        for key in baselines:
            #machine, process = key
            machine, process, normalized_args, signer = key
    
            matching_rows = df_process[
                (df_process['MachineName'] == machine) & 
                (df_process['ProcessName'] == process) &
                (df_process['ProcessArgs'].apply(lambda x: self._normalize_process_args(x)) == normalized_args) &
                (df_process['ProcessSigner'].apply(lambda x: self._normalize_signer(x)) == signer)
            ]
                    
            if len(matching_rows) > 0:
                baselines[key]['stats'] = {
                    'instances': len(matching_rows),
                    'avg_bytes_sent': float(matching_rows['NetworkBytesSent_sum'].mean()),
                    'max_bytes_sent': float(matching_rows['NetworkBytesSent_sum'].max())
                }
                # COUNT OCCURRENCES: How many different DataFrames (periods) was this key seen in?
                occurrence_count = 0
                for df in df_process_list:
                    # Check if this key exists in this specific DataFrame (period)
                    period_matches = df[
                        (df['MachineName'] == machine) & 
                        (df['ProcessName'] == process) &
                        (df['ProcessArgs'].apply(lambda x: self._normalize_process_args(x)) == normalized_args) &
                        (df['ProcessSigner'].apply(lambda x: self._normalize_signer(x)) == signer)
                    ]
                    if len(period_matches) > 0:
                        occurrence_count += 1
                
                baselines[key]['occurrence_count'] = occurrence_count
                
        print(f"✅ Built baselines for {len(baselines)} (machine, process) combinations for {self.tenant_id}")
        return dict(baselines)
    
    def save_baseline(self, baselines):
        """Save baseline to JSON"""
        baselines_json = {}
        
        for key, baseline in baselines.items():
            machine, process, normalized_args, signer = key
            
                    # Obfuscate only when saving
            obf_machine = self._obfuscate_machine_name(machine)
            #obf_user = self._obfuscate_user_name(user)
            
            try:
                # Convert each field and test it
                def safe_convert_list(items, field_name):
                    """Convert and validate a list field"""
                    result = []
                    for item in items:
                        if callable(item):
                            print(f"⚠️ WARNING: Found callable in {field_name}: {item}")
                            continue  # Skip callables
                        result.append(str(item) if item is not None else None)
                    return result
                
                def safe_convert_tuples(items, field_name):
                    """Convert list of tuples"""
                    result = []
                    for t in items:
                        if callable(t):
                            print(f"⚠️ WARNING: Found callable tuple in {field_name}: {t}")
                            continue
                        # Convert tuple to list, ensuring no callables inside
                        tuple_list = []
                        for item in t:
                            if callable(item):
                                print(f"⚠️ WARNING: Found callable in tuple in {field_name}: {item}")
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
                                    'stats': {
                                        'instances': int(baseline['stats'].get('instances', 0)) if not pd.isna(baseline['stats'].get('instances', 0)) else 0,
                                        'avg_bytes_sent': float(baseline['stats'].get('avg_bytes_sent', 0)) if not pd.isna(baseline['stats'].get('avg_bytes_sent', 0)) else 0.0,
                                        'max_bytes_sent': float(baseline['stats'].get('max_bytes_sent', 0)) if not pd.isna(baseline['stats'].get('max_bytes_sent', 0)) else 0.0
                                    },
                                    'occurrence_count': baseline.get('occurrence_count', 0),
                                    'detection_reason': baseline.get('detection_reason', {}) 
                                }
                            
            except Exception as e:
                print(f"❌ Error processing key: {key}")
                print(f"Error: {e}")
                # Print what's in this baseline entry
                for field_name, field_value in baseline.items():
                    if isinstance(field_value, set):
                        print(f"  {field_name}: set with {len(field_value)} items")
                        for item in list(field_value)[:3]:
                            print(f"    - {type(item)}: {repr(item)[:100]}")
                    elif isinstance(field_value, dict):
                        print(f"  {field_name}: dict with {len(field_value)} keys")
                    else:
                        print(f"  {field_name}: {type(field_value)}")
                raise
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, 'baselines', f'baseline_{timestamp}.json')
        
        with open(filepath, 'w') as f:
            json.dump(baselines_json, f, indent=2)
        
        latest_path = os.path.join(self.output_dir, 'baselines', 'baseline_latest.json')
        with open(latest_path, 'w') as f:
            json.dump(baselines_json, f, indent=2)
        
        print(f"💾 Saved baseline to {filepath}")
        return filepath
    
    
  
    
    def load_baseline(self):
        """Load baseline from JSON"""
        filepath = os.path.join(self.output_dir, 'baselines', 'baseline_latest.json')
        
        if not os.path.exists(filepath):
            print(f"⚠️ load_baseline  No baseline found for {self.tenant_id}")
            return {}
        
        with open(filepath, 'r') as f:
            baselines_json = json.load(f)
        
        baselines = {}
        for key_str, baseline in baselines_json.items():
            parts = key_str.split('||')
            if len(parts) == 3:  # Old format without signer
                machine, process, normalized_args = parts
                signer = 'unsaved'
            elif len(parts) == 4:  # New format without user
                machine, process, normalized_args, signer = parts
            elif len(parts) == 5:  # Old format with user (for backward compatibility)
                machine, process, normalized_args, user, signer = parts

            
            real_machine = self._deobfuscate_machine_name(machine)
            
                
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
                    'users': set(self._deobfuscate_user_name(u) for u in baseline['users']),  # De-obfuscate
                    'process_args': set(baseline['process_args']),
                    'file_operations': {
                        fname: {
                            'operations': set(fdata['operations']),
                            'users': set(self._deobfuscate_user_name(u) for u in fdata['users']),  # De-obfuscate
                            'process_args': set(fdata['process_args'])
                        } for fname, fdata in baseline.get('file_operations', {}).items()
                    },
                    # NEW: Load metadata (with defaults for backward compatibility)
                    'accessed_dirs_meta': baseline.get('accessed_dirs_meta', {}),
                    'contacted_domains_meta': baseline.get('contacted_domains_meta', {}),
                    'file_operations_meta': baseline.get('file_operations_meta', {}),
                    'stats': baseline['stats'],
                    'occurrence_count': baseline.get('occurrence_count', 0),
                    'detection_reason': baseline.get('detection_reason', {}) 
                }
                

        print(f"✅ Loaded baseline for {len(baselines)} combinations for {self.tenant_id}")
        return baselines
        
    def _find_similar_baseline(self, new_item, baseline_items, threshold=0.85):
        """Check if new_item is similar to anything in baseline_items"""
        from difflib import SequenceMatcher
        
        new_item_lower = str(new_item).lower().strip()
        
        for baseline_item in baseline_items:
            baseline_item_lower = str(baseline_item).lower().strip()
            similarity = SequenceMatcher(None, new_item_lower, baseline_item_lower).ratio()
            if similarity >= threshold:
                return True, baseline_item, similarity
        
        return False, None, 0.0


    def detect_anomalies(self, df_process, df_children, baselines, min_occurrences=3):
        """Detect anomalies by comparing against baseline sets using fuzzy similarity"""
        print(f"\n🔍 Detecting anomalies for {self.tenant_id}...")
        
        if df_process is None or len(df_process) == 0:
            print("⚠️ No process data to analyze")
            return pd.DataFrame()
    
        if baselines is None or len(baselines) == 0:
            print("⚠️ No baselines available")
            return pd.DataFrame()
            
           # DEBUG: Show what keys exist in baseline
        print(f"\n🔍 DEBUG: Baseline has {len(baselines)} keys")
        for i, (key, _) in enumerate(baselines.items()):
            if i < 3:  # Show first 3
                machine, process, norm_args, signer = key
                print(f"  Baseline key {i+1}: machine={machine[:50]}, process={process}, signer={signer}")
            
        all_alerts = []
        matched_keys = 0
        unmatched_keys = 0
        
        try:
            # Process each AI process instance
            for _, row in df_process.iterrows():
                normalized_args = self._normalize_process_args(row.get('ProcessArgs'))
                user = row.get('UserName', 'UNKNOWN')
                signer = self._normalize_signer(row.get('ProcessSigner'))
                key = (row['MachineName'], row['ProcessName'], normalized_args, signer)
                
                if unmatched_keys + matched_keys < 3:  # Show first 3
                    print(f"\n🔍 DEBUG: Looking for key:")
                    print(f"  machine={row['MachineName'][:50]}")
                    print(f"  process={row['ProcessName']}")
                    print(f"  user={user[:50]}")
                    print(f"  signer={signer}")
                
                # --- NEW: detect signer change for same machine+process+args ---
                same_triplet_signers = [
                    k[3] for k in baselines.keys()
                    if k[0] == row['MachineName']
                    and k[1] == row['ProcessName']
                    and k[2] == normalized_args
                ]

                if same_triplet_signers and signer not in same_triplet_signers:
                    # Choose severity policy
                    severity = SEVERITY_THRESHOLDS["signer_changed_default"]
                    if signer.upper() in ("UNKNOWN", "UNSIGNED", "N/A", "ERR:NOT-REPORTED"):
                        severity = SEVERITY_THRESHOLDS["signer_changed_if_unsigned"]

                    # Create an alert immediately (or append as anomaly if you’re already building anomalies)
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
                        "baseline_context": {
                            "matched_triplet": f"{row['MachineName']} | {row['ProcessName']} | {normalized_args[:80]}",
                            "baseline_signers_for_triplet": list(set(same_triplet_signers))[:10],
                            "current_signer": signer,
                            "status": "SIGNER_CHANGED"
                        },
                        'anomalies': [
                                self._make_anomaly(
                                    type="ALERT_PROCESS_SIGNER_CHANGED",
                                    severity=severity,
                                    details=(
                                        f"Signer changed for {row['ProcessName']} on {row['MachineName']}: "
                                        f"'{signer}' not in baseline signers {list(set(same_triplet_signers))[:5]}"
                                    ),
                                    row=row,
                                    baseline=None,  # baseline exists for other signer(s), but not for this exact key
                                    normalized_args=normalized_args,
                                    occurrence_count=0,
                                    baseline_context={
                                        "status": "SIGNER_CHANGED",
                                        "baseline_signers_for_triplet": list(set(same_triplet_signers))[:10],
                                        "current_signer": signer
                                    },
                                    extra={
                                        "process_name": row["ProcessName"],
                                        "current_signer": signer,
                                        "baseline_signers_for_triplet": list(set(same_triplet_signers))[:10],
                                        "normalized_args": normalized_args[:200],
                                    }
                                )
                            ]
                    })
                    # Optional: continue so you don't also emit NEW_AI_AGENT_NOT_IN_BASELINE
                    continue

                
                
                if key not in baselines:
                    unmatched_keys += 1
                    if unmatched_keys <= 3:  # Show first 3 misses
                        print(f"  ❌ NOT FOUND in baseline!")
                        
                    # Create LOW severity alert for new AI agent not in baseline
                    machine, process, norm_args,  signer = key
                    
                    # Gather details about this unknown agent
                    domains_raw = row.get('contacted_domains')
                    current_domains = list(clean_set(self._safe_parse_list(domains_raw)))[:10]
                    
                    ips_raw = row.get('contacted_ips')
                    current_ips = list(set(ip for ip in self._safe_parse_list(ips_raw) if ip and str(ip).strip()))[:10]
                    
                    ports_raw = row.get('contacted_ports')
                    current_ports = list(set(str(p) for p in self._safe_parse_list(ports_raw) if p and str(p).strip()))[:5]
                    
                    dirs_raw = row.get('accessed_dirs')
                    dirs_list = self._safe_parse_list(dirs_raw)
                    current_dirs = [self._normalize_directory_path(d) for d in dirs_list if d][:10]
                    
                    # Get event time
                    event_time = row.get('CreationTime')
                    if event_time and pd.notna(event_time):
                        alert_timestamp = str(int(event_time))
                    else:
                        alert_timestamp = "UNKNOWN"
                    
                    # Create the alert with full context
                    all_alerts.append({
                        'timestamp': alert_timestamp,
                        'machine': machine,
                        'process': process,
                        'pid': int(row['Pid']) if pd.notna(row['Pid']) else 0,
                        'user': user,
                        'signer': signer,
                        'process_args': str(row.get('ProcessArgs', ''))[:200],
                        'anomaly_count': 1,
                        'baseline_context': {  # NEW: Add what was searched for
                                'searched_key': f"{machine} | {process} | {user} | {signer}",
                                'searched_normalized_args': norm_args[:100],
                                'key_found': False,
                                'occurrence_count': 0
                        },
                        'anomalies': [
                                        self._make_anomaly(
                                            type="ALERT_NEW_AI_AGENT_NOT_IN_BASELINE",
                                            severity="LOW",
                                            details=f"AI agent not in baseline: {process} (user: {user}, signer: {signer})",
                                            row=row,
                                            baseline=None,  # <-- no baseline exists for this path
                                            normalized_args=norm_args,
                                            occurrence_count=0,
                                            baseline_context={
                                                "searched_key": f"{machine} | {process} | {user} | {signer}",
                                                "searched_normalized_args": norm_args[:100],
                                                "key_found": False,
                                                "occurrence_count": 0
                                            },
                                            extra={
                                                # Keep your existing “max detail” fields (optional, but matches your current output)
                                                "process_name": process,
                                                "process_dir": row.get("ProcessDir", "UNKNOWN"),
                                                "process_args_full": str(row.get("ProcessArgs", ""))[:500],
                                                "normalized_args": norm_args[:200],

                                                "ai_score": float(row.get("aiScore_avg", 0)) if pd.notna(row.get("aiScore_avg")) else 0,
                                                "event_count": int(row.get("event_count", 0)) if pd.notna(row.get("event_count")) else 0,
                                                "network_bytes_sent": int(row.get("NetworkBytesSent_sum", 0)) if pd.notna(row.get("NetworkBytesSent_sum")) else 0,
                                                "network_bytes_received": int(row.get("NetworkBytesReceived_sum", 0)) if pd.notna(row.get("NetworkBytesReceived_sum")) else 0,

                                                "contacted_domains": current_domains,
                                                "contacted_ips": current_ips,
                                                "contacted_ports": current_ports,
                                                "accessed_directories_sample": current_dirs,
                                                "accessed_extensions": list(self._safe_parse_list(row.get("accessed_extensions")))[:10],

                                                "why_detected_as_ai": "Scored as AI agent but no baseline exists for this combination",
                                                "baseline_key_searched": f"{process} | {user} | {signer} | ...",
                                                "total_baselines_available": len(baselines),
                                            }
                                        )
                                    ]
                    })
                    continue  # Skip to next process
                         
         
                baseline = baselines[key]
                occurrence_count = baseline.get('occurrence_count', 0)
                
                if occurrence_count < min_occurrences:
                    # Agent is in "learning phase" - skip anomaly detection
                    if unmatched_keys + matched_keys < min_occurrences:
                        print(f"  📚 Learning phase: {row['ProcessName']} (occurrences: {occurrence_count}/{min_occurrences})")
                        
                        event_time = row.get('CreationTime')
                        if event_time and pd.notna(event_time):
                            alert_timestamp = str(int(event_time))
                        else:
                            alert_timestamp = "UNKNOWN"
                        
                        all_alerts.append({
                            'timestamp': alert_timestamp,
                            'machine': row['MachineName'],
                            'process': row['ProcessName'],
                            'pid': int(row['Pid']) if pd.notna(row['Pid']) else 0,
                            'user': user,
                            'signer': signer,
                            'process_args': str(row.get('ProcessArgs', ''))[:200],
                            'anomaly_count': 1,
                            'baseline_context': {
                                'searched_key': f"{row['MachineName']} | {row['ProcessName']} | {user} | {signer}",
                                'searched_normalized_args': normalized_args[:100],
                                'key_found': True,
                                'occurrence_count': occurrence_count,
                                'min_required': min_occurrences,
                                'status': 'LEARNING'
                            },
                            'anomalies': [
                                self._make_anomaly(
                                    type="ALERT_AI_AGENT_IN_LEARNING_PHASE",
                                    severity="INFO",
                                    details=f"Agent learning: {row['ProcessName']} seen {occurrence_count}/{min_occurrences} times",
                                    row=row,
                                    baseline=baseline,  # baseline exists here
                                    normalized_args=normalized_args,
                                    occurrence_count=occurrence_count,
                                    baseline_context={
                                        "searched_key": f"{row['MachineName']} | {row['ProcessName']} | {user} | {signer}",
                                        "searched_normalized_args": normalized_args[:100],
                                        "key_found": True,
                                        "occurrence_count": occurrence_count,
                                        "min_required": min_occurrences,
                                        "status": "LEARNING"
                                    },
                                    extra={
                                        "process_name": row["ProcessName"],
                                        "days_until_active": min_occurrences - occurrence_count
                                    }
                                )
                            ]
                        })
                    continue  # ← Skip anomaly detection for this agent
                
                matched_keys += 1
                if matched_keys <= min_occurrences:
                    print(f"  ✅ FOUND in baseline!")
                

    

                anomalies = []  # Collect ALL anomalies for this instance
                
                # Use actual event time, not now()
                event_time = row.get('CreationTime')
                if event_time and pd.notna(event_time):
                    alert_timestamp = str(int(event_time))  # Store as Unix timestamp string
                else:
                    alert_timestamp = "UNKNOWN"
                    
                # ===== NEW: Check if user is in baseline =====
                baseline_users = baseline.get('users', set())
                if user not in baseline_users:
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_USER_FOR_PROCESS",
                            severity="HIGH",
                            details=f"Process {row['ProcessName']} run by NEW user: {user}",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "NEW_USER"
                            },
                            extra={
                                "current_user": user,
                                "baseline_users": list(baseline_users)[:10]
                            }
                        )
                    )
    
                
                
                # ===== Check NEW DOMAINS (with similarity) =====
                domains_raw = row.get('contacted_domains')
                current_domains = clean_set(self._safe_parse_list(domains_raw))
                baseline_domains = baseline.get('contacted_domains', set())
                
                truly_new_domains = []
                for domain in current_domains:
                    is_similar, match, sim_score = self._find_similar_baseline(
                        domain, 
                        baseline_domains, 
                        threshold=0.90  # High precision for domains
                    )
                    if not is_similar:
                        truly_new_domains.append(domain)
                
                if truly_new_domains:
                    severity = "MEDIUM"
                    if len(truly_new_domains) >= SEVERITY_THRESHOLDS["new_domains_high"]:
                        severity = "HIGH"
                    anomalies.append(self._make_anomaly(
                        type="ALERT_NEW_DOMAINS",
                        severity=severity,
                        details=f"Contacted {len(truly_new_domains)} new domains",
                        row=row,
                        baseline=baseline,
                        normalized_args=normalized_args,
                        occurrence_count=occurrence_count,
                        baseline_context={"status": "ACTIVE_DETECTION"},
                        extra={"new_domains": truly_new_domains}
                    ))
                
                # ===== Check NEW IPS (exact match - IPs don't have variations) =====
                ips_raw = row.get('contacted_ips')
                current_ips = set(ip for ip in self._safe_parse_list(ips_raw) if ip and str(ip).strip())
                baseline_ips = baseline.get('contacted_ips', set())
                
                new_ips = current_ips - baseline_ips
                if new_ips:
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_IPS",
                            severity="HIGH",
                            details=f"Contacted {len(new_ips)} new IP(s)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "NEW_IPS"
                            },
                            extra={
                                "new_ips": list(new_ips),
                                "baseline_ips_sample": list(baseline_ips)[:10]
                            }
                        )
                    )
                                        

                
                # ===== Check NEW PORTS (exact match) =====
                ports_raw = row.get('contacted_ports')
                current_ports = set(str(p) for p in self._safe_parse_list(ports_raw) if p and str(p).strip())
                baseline_ports = baseline.get('contacted_ports', set())
                
                new_ports = current_ports - baseline_ports
                if new_ports:
                    severity = "LOW"
                    if len(new_ports) >= SEVERITY_THRESHOLDS["new_ports_medium"]:
                        severity = "MEDIUM"
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_PORTS",
                            severity=severity,
                            details=f"Connected to {len(new_ports)} new port(s)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "NEW_PORTS"
                            },
                            extra={
                                "new_ports": list(new_ports),
                                "baseline_ports": list(baseline_ports)[:20]
                            }
                        )
)
                
                # ===== Check NEW DIRECTORIES (with similarity) =====
                dirs_raw = row.get('accessed_dirs')
                dirs_list = self._safe_parse_list(dirs_raw)
                current_dirs = set(self._normalize_directory_path(d) for d in dirs_list if d)
                baseline_dirs = set(self._normalize_directory_path(d) for d in baseline.get('accessed_dirs', set()))
                
                # Ignore common temp/cache directories
                IGNORE_DIR_PATTERNS = {
                    'appdata\\local\\temp',
                    'appdata\\local\\microsoft\\windows\\inetcache',
                    '/tmp',
                    '/var/tmp',
                    'appdata\\roaming\\microsoft\\windows\\recent'
                }
                
                truly_new_dirs = []
                for curr_dir in current_dirs:
                    # Skip ignored patterns
                    if any(pattern in curr_dir.lower() for pattern in IGNORE_DIR_PATTERNS):
                        continue
                    
                    is_similar, match, sim_score = self._find_similar_baseline(
                        curr_dir, 
                        baseline_dirs, 
                        threshold=0.85  # Allow minor variations in paths
                    )
                    if not is_similar:
                        truly_new_dirs.append(curr_dir)
                
                if truly_new_dirs:
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_DIRECTORIES",
                            severity="MEDIUM",
                            details=f"Accessed {len(truly_new_dirs)} genuinely new directory(ies)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "NEW_DIRECTORIES"
                            },
                            extra={
                                "new_directories": truly_new_dirs[:20],
                                "baseline_directories_sample": list(baseline_dirs)[:10]
                            }
                        )
)
                
                
                
                # ===== Check EXCESSIVE TRANSFER =====
                avg_sent = baseline['stats'].get('avg_bytes_sent', 0)
                mb_sent = row['NetworkBytesSent_sum'] / 1e6
                if avg_sent > 0 and row['NetworkBytesSent_sum'] > avg_sent * 10:
                    severity = "HIGH"
                    if mb_sent >= SEVERITY_THRESHOLDS["excessive_transfer_mb_critical"]:
                        severity = "CRITICAL"
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_EXCESSIVE_TRANSFER",
                            severity="CRITICAL",
                            details=(
                                f"Sent {row['NetworkBytesSent_sum']/1e6:.1f}MB "
                                f"vs avg {avg_sent/1e6:.1f}MB"
                            ),
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "EXCESSIVE_TRANSFER"
                            },
                            extra={
                                # Explicit values for analyst clarity
                                "bytes_sent": int(row.get("NetworkBytesSent_sum", 0)),
                                "baseline_avg_bytes_sent": int(avg_sent)
                            }
                        )
                    )
                    
                # ===== Check NEW FILE EXTENSIONS =====
                exts_raw = row.get('accessed_extensions')
                current_exts = set(e for e in self._safe_parse_list(exts_raw) if e and str(e).strip())
                baseline_exts = baseline.get('accessed_extensions', set())

                new_exts = current_exts - baseline_exts
                # Filter out common/harmless extensions
                COMMON_EXTS = {'txt', 'log', 'tmp', 'cache', 'json', 'xml', 'yml', 'yaml'}
                suspicious_exts = new_exts - COMMON_EXTS

                if suspicious_exts:
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_FILE_EXTENSIONS",
                            severity="MEDIUM",
                            details=f"Accessed {len(suspicious_exts)} new file extension(s)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "NEW_FILE_EXTENSIONS"
                            },
                            extra={
                                "new_extensions": list(suspicious_exts),
                                "baseline_extensions": list(baseline_exts)[:20]
                            }
                        )
                    )

                # ===== Check NEW FILES ACCESSED (with normalization and similarity) =====
                files_raw = row.get('accessed_files')
                files_list = self._safe_parse_list(files_raw)
                current_files = set(self._normalize_filename(f) for f in files_list if f)
                baseline_files = baseline.get('accessed_files', set())

                truly_new_files = []
                for curr_file in current_files:
                    is_similar, match, sim_score = self._find_similar_baseline(
                        curr_file,
                        baseline_files,
                        threshold=0.80  # Lenient for filenames
                    )
                    if not is_similar:
                        truly_new_files.append(curr_file)

                # Only alert if accessing many new files (could be normal for some apps)
                if len(truly_new_files) >= SEVERITY_THRESHOLDS["new_files_medium"]:
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_ACCESSING_MANY_NEW_FILES",
                            severity="MEDIUM",
                            details=f"Accessed {len(truly_new_files)} new files",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "MANY_NEW_FILES"
                            },
                            extra={
                                "new_files_sample": truly_new_files[:20],
                                "baseline_files_sample": list(baseline_files)[:20]
                            }
                        )
                    )




                # ===== Check MODEL FILE MODIFICATIONS =====
                mod_files_raw = row.get('modified_model_files')
                modified_raw = [f for f in self._safe_parse_list(mod_files_raw) if f]
                modified = {self._normalize_filename(f): f for f in modified_raw}  # Map normalized -> original
                
                # Get modification details
                mod_details_raw = row.get('file_mod_details')
                mod_details = self._safe_parse_list(mod_details_raw)
                baseline_file_ops = baseline.get('file_operations', {})
                
                for norm_file, original_file in modified.items():
                    # Get details for THIS file
                    file_mod_info = None
                    for detail in mod_details:
                        if detail.get('file') == original_file:
                            file_mod_info = detail
                            break
                    
                    mod_user = file_mod_info.get('user') if file_mod_info else None
                    mod_args = file_mod_info.get('args') if file_mod_info else None
                    
                    # Check if file exists in baseline with SIMILARITY
                    file_in_baseline = False
                    matching_baseline_file = None
                    
                    for baseline_file in baseline_file_ops.keys():
                        similarity = SequenceMatcher(None, norm_file.lower(), baseline_file.lower()).ratio()
                        if similarity >= 0.90:  # Very high threshold for model files
                            file_in_baseline = True
                            matching_baseline_file = baseline_file
                            break
                    
                    if not file_in_baseline:
                        # File NEVER modified before
                        domains = row.get('contacted_domains')
                        ips = row.get('contacted_ips')
                        anomalies.append(
                            self._make_anomaly(
                                type="ALERT_NEW_MODEL_FILE_MODIFICATION",
                                severity="CRITICAL",
                                details=f"FIRST TIME MODIFICATION: Model file {original_file} has never been modified before",
                                row=row,
                                baseline=baseline,
                                normalized_args=normalized_args,
                                occurrence_count=occurrence_count,
                                baseline_context={
                                    "status": "ACTIVE_DETECTION",
                                    "reason": "FIRST_MODEL_MODIFICATION"
                                },
                                extra={
                                    # File identity
                                    "file": original_file,
                                    "normalized_file": norm_file,
                                    "file_type": original_file.split('.')[-1] if '.' in original_file else "unknown",

                                    # Modification context
                                    "modifying_user": mod_user,
                                    "modifying_process": row["ProcessName"],
                                    "modifying_process_args": str(row.get("ProcessArgs", ""))[:500],
                                    "modifying_pid": int(row["Pid"]) if pd.notna(row["Pid"]) else None,

                                    # Network context (explicitly kept)
                                    "contacted_domains": (
                                        list(ast.literal_eval(domains))[:10]
                                        if isinstance(domains, str)
                                        else list(domains)[:10] if isinstance(domains, (list, tuple))
                                        else []
                                    ),
                                    "network_bytes_sent": int(row.get("NetworkBytesSent_sum", 0)),

                                    # Baseline reference
                                    "all_baseline_model_files_ever_modified": list(baseline_file_ops.keys())[:20],
                                    "baseline_normal_users": list(baseline.get("users", set()))[:10]
                                }
                            )
                        )
                    else:
                        # File was modified before - check if by NEW USER or with UNUSUAL ARGS
                        file_baseline = baseline_file_ops[matching_baseline_file]
                        
                        # Check USER
                        if mod_user and mod_user not in file_baseline.get('users', set()):
                            # But only alert if user is NOT in the overall baseline for this process
                            baseline_users = baseline.get('users', set())
                            severity = 'CRITICAL' if mod_user not in baseline_users else 'MEDIUM'
                            
                            anomalies.append(
                                self._make_anomaly(
                                    type="ALERT_MODEL_FILE_MODIFIED_BY_NEW_USER",
                                    severity=severity,
                                    details=(
                                        f"Model file {original_file} modified by "
                                        f"{'UNAUTHORIZED' if severity == 'CRITICAL' else 'unusual'} user {mod_user}"
                                    ),
                                    row=row,
                                    baseline=baseline,
                                    normalized_args=normalized_args,
                                    occurrence_count=occurrence_count,
                                    baseline_context={
                                        "status": "ACTIVE_DETECTION",
                                        "reason": "MODEL_MODIFIED_BY_NEW_USER",
                                        "file_user_authorization": (
                                            "UNAUTHORIZED" if severity == "CRITICAL" else "UNUSUAL"
                                        )
                                    },
                                    extra={
                                        # File identity
                                        "file": original_file,
                                        "normalized_file": norm_file,

                                        # Actor / process details (kept exactly as you had)
                                        "current_user": mod_user,
                                        "current_process": row["ProcessName"],

                                        # Baseline context you wanted surfaced
                                        "baseline_authorized_users_for_file": list(file_baseline.get("users", set())),
                                        "baseline_all_users_for_process": list(baseline_users)[:10],

                                        # Network context you explicitly included
                                        "network_bytes_sent": int(row.get("NetworkBytesSent_sum", 0)),
                                    }
                                )
                            )
                        # Check ARGS similarity
                        if mod_args:
                            baseline_args = file_baseline.get('process_args', set())
                            if baseline_args:
                                norm_current = self._normalize_process_args(mod_args)
                                max_sim = 0
                                best_match = None
                                for baseline_arg in baseline_args:
                                    sim = SequenceMatcher(None, norm_current, baseline_arg).ratio()
                                    if sim > max_sim:
                                        max_sim = sim
                                        best_match = baseline_arg
                                
                                # Lower threshold to 0.5 to reduce false positives
                                if max_sim < 0.5:
                                    anomalies.append(
                                        self._make_anomaly(
                                            type="ALERT_MODEL_FILE_MODIFIED_WITH_UNUSUAL_ARGS",
                                            severity="HIGH",
                                            details=(
                                                f"Model file {original_file} modified with unusual arguments "
                                                f"(similarity: {max_sim:.2f})"
                                            ),
                                            row=row,
                                            baseline=baseline,
                                            normalized_args=normalized_args,
                                            occurrence_count=occurrence_count,
                                            baseline_context={
                                                "status": "ACTIVE_DETECTION",
                                                "reason": "UNUSUAL_MODEL_ARGS"
                                            },
                                            extra={
                                                # File identity
                                                "file": original_file,
                                                "normalized_file": norm_file,

                                                # Argument analysis
                                                "current_args": str(mod_args)[:500],
                                                "similarity_to_best_baseline": f"{max_sim:.2f}",
                                                "best_matching_baseline_arg": (
                                                    str(best_match)[:200] if best_match else None
                                                ),

                                                # Actor context
                                                "modifying_user": mod_user,
                                                "modifying_process": row["ProcessName"]
                                            }
                                        )
                                    )

                    # ===== Check CHILD SPAWNING =====
                    children_of_this = df_children[
                        (df_children['MachineName'] == row['MachineName']) &
                        (df_children['ProcessPPidCreationTime'] == row['PidCreationTime'])
                    ]

                    baseline_spawned = baseline.get('spawned_with_args', set())

                    for _, child in children_of_this.iterrows():
                        child_process = child.get('ProcessName')
                        child_args = child.get('ProcessArgs')
                        
                        # Skip empty
                        if not child_process or not str(child_process).strip():
                            continue
                        
                        child_args_norm = self._normalize_process_args(child_args)
                        
                        # Check if this (process, args) combo exists in baseline
                        exact_match = (child_process, child_args_norm) in baseline_spawned
                        
                        if not exact_match:
                            # No exact match - check similarity with baseline args for this process
                            baseline_args_for_proc = [args for proc, args in baseline_spawned if proc == child_process]
                                
                            if not baseline_args_for_proc:
                                anomalies.append(
                                    self._make_anomaly(
                                        type="ALERT_NEW_SPAWNED_PROCESS",
                                        severity="CRITICAL",
                                        details=f"Never spawned: {child_process}",
                                        row=row,                 # parent process row
                                        baseline=baseline,
                                        normalized_args=normalized_args,
                                        occurrence_count=occurrence_count,
                                        baseline_context={
                                            "status": "ACTIVE_DETECTION",
                                            "reason": "NEW_SPAWNED_PROCESS"
                                        },
                                        extra={
                                            "child_process": child_process,
                                            "child_args": str(child_args)[:200] if child_args else ""
                                        }
                                    )
                                )
                            else:
                                # Process was spawned before - check arg similarity
                                max_similarity = 0
                                for baseline_arg in baseline_args_for_proc:
                                    sim = SequenceMatcher(None, child_args_norm, baseline_arg).ratio()
                                    max_similarity = max(max_similarity, sim)
                                
                                # Only alert if args are very different (threshold 0.7)
                                if max_similarity < 0.7:
                                    anomalies.append(
                                        self._make_anomaly(
                                            type="SALERT_SPAWNED_PROCESS_UNUSUAL_ARGS",
                                            severity="HIGH",
                                            details=(
                                                f"Spawned {child_process} with unusual arguments "
                                                f"(similarity: {max_similarity:.2f})"
                                            ),
                                            row=row,                       # parent process row
                                            baseline=baseline,
                                            normalized_args=normalized_args,
                                            occurrence_count=occurrence_count,
                                            baseline_context={
                                                "status": "ACTIVE_DETECTION",
                                                "reason": "SPAWNED_PROCESS_UNUSUAL_ARGS"
                                            },
                                            extra={
                                                # Child process details
                                                "child_process": child_process,
                                                "child_normalized_args": child_args_norm,
                                                "child_actual_args": (
                                                    str(child_args)[:200] if child_args else ""
                                                ),

                                                # Similarity analysis
                                                "similarity_score": f"{max_similarity:.2f}",
                                                "most_similar_baseline": (
                                                    str(baseline_args_for_proc[0])[:100]
                                                    if baseline_args_for_proc else ""
                                                )
                                            }
                                        )
                                    )

                    # ONE alert per process instance with ALL anomalies
                    if anomalies:
                        all_alerts.append({
                            'timestamp': alert_timestamp,
                            'machine': row['MachineName'],
                            'process': row['ProcessName'],
                            'pid': int(row['Pid']) if pd.notna(row['Pid']) else 0,
                            'user': user,
                            'signer': signer,
                            'process_args': str(row.get('ProcessArgs', ''))[:200],
                            'anomaly_count': len(anomalies),
                            'baseline_context': {  # NEW: Show what baseline was used
                                'matched_key': f"{row['MachineName']} | {row['ProcessName']} | {user} | {signer}",
                                'matched_normalized_args': normalized_args[:100],
                                'key_found': True,
                                'occurrence_count': occurrence_count,
                                'status': 'ACTIVE_DETECTION',
                                'baseline_dirs_count': len(baseline.get('accessed_dirs', set())),
                                'baseline_domains_count': len(baseline.get('contacted_domains', set())),
                                'baseline_spawned_processes': list(baseline.get('spawned_processes', set()))[:5],
                                'baseline_users': list(baseline.get('users', set()))[:3],
                                'detection_reason': baseline.get('detection_reason', {})
                            },
                            'anomalies': anomalies
                        })
        
        
        except Exception as e:
            print(f"❌ Error during anomaly detection: {e}")
            import traceback
            traceback.print_exc()
            # Return whatever alerts we collected before the error
            if all_alerts:
                return pd.DataFrame(all_alerts)
            return pd.DataFrame()
        
        print(f"\n📊 Detection Summary:")
        print(f"  Total process instances checked: {matched_keys + unmatched_keys}")
        print(f"  Matched with baseline: {matched_keys}")
        print(f"  No baseline found: {unmatched_keys}")        

              
        if all_alerts:
            print(f"🚨 Detected {len(all_alerts)} process instances with anomalies")
            return pd.DataFrame(all_alerts)
        
        print("✅ No anomalies detected")
        return pd.DataFrame()
    
    
    
    
    
    
    
 
        
 
    
    def save_alerts(self, alerts_df):
        """Save alerts to CSV"""
        if len(alerts_df) == 0:
            print(f"No alerts for {self.tenant_id}")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, 'alerts', f'alerts_{timestamp}.csv')
        
        alerts_flat = []
        for _, alert in alerts_df.iterrows():
            for anomaly in alert['anomalies']:
                # Extract all fields from anomaly dict
                flat_alert = {
                    'timestamp': alert['timestamp'],
                    'machine': self._obfuscate_machine_name(alert['machine']),  # ✅ Obfuscate
                    'process': alert['process'],
                    'pid': alert['pid'],
                    'user': self._obfuscate_user_name(alert['user']),  # ✅ Obfuscate
                    'signer': alert.get('signer', 'UNKNOWN'),
                    'baseline_key': alert.get('baseline_context', {}).get('matched_key', 'N/A'),  # NEW
                    'baseline_occurrence_count': alert.get('baseline_context', {}).get('occurrence_count', 0),  # NEW
                    'baseline_status': alert.get('baseline_context', {}).get('status', 'UNKNOWN'),  # NEW
                    'severity': anomaly.get('severity', 'UNKNOWN'),
                    'anomaly_type': anomaly.get('type', 'UNKNOWN'),
                    'details': anomaly.get('details', ''),
                    'mitre_attack': ",".join(anomaly.get("mitre_attack", [])),
                    'ai_risk': ",".join(anomaly.get("ai_risk", [])),
                    'confidence': anomaly.get("confidence", "Unknown"),
                        # Rich payloads for SOC/IR
                    'observed_json': self._to_json_str(anomaly.get("observed", {})),
                    'baseline_snapshot_json': self._to_json_str(anomaly.get("baseline_snapshot", {})),
                    'children_sample_json': self._to_json_str(anomaly.get("children_sample", [])),
                    'baseline_context_json': self._to_json_str(anomaly.get("baseline_context", {})),

                    # Full anomaly record (best for SOAR/IR rehydration)
                    'anomaly_json': self._to_json_str(anomaly),
                    }
                
                flat_alert["alert_id"] = self._alert_id(alert, anomaly)
                # Add all other anomaly fields as JSON
                extra_fields = {}
                for k, v in anomaly.items():
                    if k not in ['type', 'severity', 'details']:
                        # Obfuscate user-related fields
                        if 'user' in k.lower() and isinstance(v, str):
                            v = self._obfuscate_user_name(v)  # ✅ Obfuscate user fields
                        elif isinstance(v, (list, set)):
                            # Obfuscate user lists
                            if 'user' in k.lower():
                                v = [self._obfuscate_user_name(str(x)) for x in v]  # ✅ Obfuscate user lists
                            else:
                                v = [str(x) for x in v]
                        elif hasattr(v, 'item'):  # numpy scalar
                            v = v.item()
                        else:
                            v = str(v)
                        extra_fields[k] = v
                
                flat_alert['anomaly_data'] = json.dumps(extra_fields)
                alerts_flat.append(flat_alert)
        
        df_flat = pd.DataFrame(alerts_flat)
        df_flat.to_csv(filepath, index=False)
        
        master = os.path.join(self.output_dir, 'alerts', 'all_alerts.csv')
        if os.path.exists(master):
            df_flat.to_csv(master, mode='a', header=False, index=False)
        else:
            df_flat.to_csv(master, index=False)
        
        print(f"💾 Saved {len(alerts_flat)} alerts to {filepath} for {self.tenant_id}")
    
    
    def merge_baselines_with_frequency_and_decay(
                                                self, 
                                                existing_baseline, 
                                                new_process_data, 
                                                new_children_data,
                                                min_occurrences=3,# Lower = more permissive, Higher = stricter
                                                                        # 3 = Good balance for daily updates
                                                decay_days=30, # Directories/domains not seen in 30 days are removed
                                                                        # Shorter = cleaner baseline, Longer = fewer false positive
                                                critical_items_decay_days=90
                                                ):
        """
        Merge new data into baseline with:
        1. Frequency threshold: Items must appear N times to be added
        2. Time-based decay: Items not seen in X days are removed
        
        Args:
            existing_baseline: Current baseline dict
            new_process_data: List of process DataFrames
            new_children_data: List of children DataFrames
            min_occurrences: Minimum times item must appear to be added
            decay_days: Days after which directories/domains expire
            critical_items_decay_days: Days for critical items (file_operations, spawned processes)
        """
        print(f"\n🔄 Merging baselines:")
        print(f"  📊 Frequency threshold: {min_occurrences} occurrences")
        print(f"  ⏰ Decay period: {decay_days} days (critical items: {critical_items_decay_days} days)")
        
        current_date = self._get_current_date()
        
        # Build new baseline from recent data
        new_baseline = self.build_baseline(new_process_data, new_children_data)
        
        # Combine all process data for frequency counting
        all_process_df = pd.concat(new_process_data, ignore_index=True) if new_process_data else pd.DataFrame()
        
        stats = {
            'new_keys': 0,
            'expired_dirs': 0,
            'expired_domains': 0,
            'expired_file_ops': 0,
            'added_dirs': 0,
            'added_domains': 0,
            'skipped_rare_dirs': 0,
            'skipped_rare_domains': 0
        }
        
        # Process each key in new baseline
        for key, new_data in new_baseline.items():
            if key not in existing_baseline:
                # Brand new process combination - add with metadata
                existing_baseline[key] = new_data
                
                # Initialize occurrence_count to 1 (first time seeing this combination)
                existing_baseline[key]['occurrence_count'] = 1
                
                # Initialize metadata for all items
                existing_baseline[key]['accessed_dirs_meta'] = {
                    d: {'first_seen': current_date, 'last_seen': current_date, 'count': 1}
                    for d in new_data['accessed_dirs']
                }
                existing_baseline[key]['contacted_domains_meta'] = {
                    d: {'first_seen': current_date, 'last_seen': current_date, 'count': 1}
                    for d in new_data['contacted_domains']
                }
                existing_baseline[key]['file_operations_meta'] = {
                    fname: {'first_seen': current_date, 'last_seen': current_date}
                    for fname in new_data.get('file_operations', {}).keys()
                }
                
                stats['new_keys'] += 1
                print(f"  ✨ New (learning): {key[1]} (signer: {key[3]}) on {key[0]} - occurrence 1/{min_occurrences}")
                continue
            
            # Existing key - merge with frequency filtering and decay
            baseline = existing_baseline[key]
            baseline['occurrence_count'] = baseline.get('occurrence_count', 0) + 1            
    
            current_count = baseline['occurrence_count']
            if current_count == min_occurrences:
                print(f"  🎯 Promoted to active detection: {key[1]} on {key[0]} (reached {min_occurrences} occurrences)")
    
            
            # Initialize metadata dicts if they don't exist (backward compatibility)
            if 'accessed_dirs_meta' not in baseline:
                baseline['accessed_dirs_meta'] = {
                    d: {'first_seen': current_date, 'last_seen': current_date, 'count': 1}
                    for d in baseline['accessed_dirs']
                }
            if 'contacted_domains_meta' not in baseline:
                baseline['contacted_domains_meta'] = {
                    d: {'first_seen': current_date, 'last_seen': current_date, 'count': 1}
                    for d in baseline['contacted_domains']
                }
            if 'file_operations_meta' not in baseline:
                baseline['file_operations_meta'] = {
                    fname: {'first_seen': current_date, 'last_seen': current_date}
                    for fname in baseline.get('file_operations', {}).keys()
                }
            for d in list(baseline.get('accessed_dirs', set())):
                baseline['accessed_dirs_meta'].setdefault(d, {
                    'first_seen': current_date,
                    'last_seen': current_date,
                    'count': 1
                })

            for dom in list(baseline.get('contacted_domains', set())):
                baseline['contacted_domains_meta'].setdefault(dom, {
                    'first_seen': current_date,
                    'last_seen': current_date,
                    'count': 1
                })
                
            # Repair missing file_operations_meta entries (handles partial meta dicts)
            baseline.setdefault('file_operations_meta', {})
            for fname in list(baseline.get('file_operations', {}).keys()):
                baseline['file_operations_meta'].setdefault(fname, {
                    'first_seen': current_date,
                    'last_seen': current_date
                })

            # --- Repair partial meta dicts (prevents KeyError drift) ---
            baseline.setdefault('accessed_dirs_meta', {})
            for d in list(baseline.get('accessed_dirs', set())):
                baseline['accessed_dirs_meta'].setdefault(d, {'first_seen': current_date, 'last_seen': current_date, 'count': 1})

            baseline.setdefault('contacted_domains_meta', {})
            for dom in list(baseline.get('contacted_domains', set())):
                baseline['contacted_domains_meta'].setdefault(dom, {'first_seen': current_date, 'last_seen': current_date, 'count': 1})

            baseline.setdefault('file_operations_meta', {})
            for fname in list(baseline.get('file_operations', {}).keys()):
                baseline['file_operations_meta'].setdefault(fname, {'first_seen': current_date, 'last_seen': current_date})



            # === DECAY: Remove old items ===
            # Remove expired directories
            expired_dirs = []
            for dir_path, meta in list(baseline['accessed_dirs_meta'].items()):
                days = self._days_since(meta['last_seen'])
                if days > decay_days:
                    expired_dirs.append(dir_path)
                    baseline['accessed_dirs'].discard(dir_path)
                    del baseline['accessed_dirs_meta'][dir_path]
                    stats['expired_dirs'] += 1
            
            if expired_dirs:
                print(f"  🗑️ Expired {len(expired_dirs)} old directories for {key[1]}")
            
            # Remove expired domains
            expired_domains = []
            for domain, meta in list(baseline['contacted_domains_meta'].items()):
                days = self._days_since(meta['last_seen'])
                if days > decay_days:
                    expired_domains.append(domain)
                    baseline['contacted_domains'].discard(domain)
                    del baseline['contacted_domains_meta'][domain]
                    stats['expired_domains'] += 1
            
            if expired_domains:
                print(f"  🗑️ Expired {len(expired_domains)} old domains for {key[1]}")
            
            # Remove expired file operations (longer decay period)
            expired_files = []
            for fname, meta in list(baseline.get('file_operations_meta', {}).items()):
                days = self._days_since(meta['last_seen'])
                if days > critical_items_decay_days:
                    expired_files.append(fname)
                    baseline['file_operations'].pop(fname, None)
                    del baseline['file_operations_meta'][fname]
                    stats['expired_file_ops'] += 1
            
            if expired_files:
                print(f"  🗑️ Expired {len(expired_files)} old file operations for {key[1]}")
            
            # === FREQUENCY FILTERING: Count occurrences in new data ===
            if len(all_process_df) > 0:
                normalized_args, signer = key[2], key[3]
                matching_rows = all_process_df[
                    (all_process_df['MachineName'] == key[0]) & 
                    (all_process_df['ProcessName'] == key[1]) &
                    (all_process_df['ProcessSigner'].apply(lambda x: self._normalize_signer(x)) == signer) &
                    (all_process_df['ProcessArgs'].apply(lambda x: self._normalize_process_args(x)) == normalized_args)
                ]
                
                # Count directory frequencies
                dir_counts = {}
                for _, row in matching_rows.iterrows():
                    dirs = self._safe_parse_list(row.get('accessed_dirs'))
                    for d in dirs:
                        norm_dir = self._normalize_directory_path(d)
                        if norm_dir:
                            dir_counts[norm_dir] = dir_counts.get(norm_dir, 0) + 1
                
                # Add or update directories
                for norm_dir, count in dir_counts.items():
                    if norm_dir in baseline['accessed_dirs']:
                        baseline['accessed_dirs_meta'].setdefault(norm_dir, {
                            'first_seen': current_date,
                            'last_seen': current_date,
                            'count': 0
                        })
                        baseline['accessed_dirs_meta'][norm_dir]['last_seen'] = current_date
                        baseline['accessed_dirs_meta'][norm_dir]['count'] = baseline['accessed_dirs_meta'][norm_dir].get('count', 0) + count
                    elif count >= min_occurrences:
                        # New and frequent enough - add it
                        baseline['accessed_dirs'].add(norm_dir)
                        baseline['accessed_dirs_meta'][norm_dir] = {
                            'first_seen': current_date,
                            'last_seen': current_date,
                            'count': count
                        }
                        stats['added_dirs'] += 1
                    else:
                        # Too rare - skip
                        stats['skipped_rare_dirs'] += 1
                
                # Count domain frequencies
                domain_counts = {}
                for _, row in matching_rows.iterrows():
                    domains = self._safe_parse_list(row.get('contacted_domains'))
                    for d in domains:
                        if d and str(d).strip():
                            domain_counts[d] = domain_counts.get(d, 0) + 1
                
                # Add or update domains
                for domain, count in domain_counts.items():
                    if domain in baseline['contacted_domains']:
                        baseline['contacted_domains_meta'].setdefault(domain, {
                            'first_seen': current_date,
                            'last_seen': current_date,
                            'count': 0
                        })
                        baseline['contacted_domains_meta'][domain]['last_seen'] = current_date
                        baseline['contacted_domains_meta'][domain]['count'] = baseline['contacted_domains_meta'][domain].get('count', 0) + count
                    elif count >= min_occurrences:
                        # New and frequent enough - add it
                        baseline['contacted_domains'].add(domain)
                        baseline['contacted_domains_meta'][domain] = {
                            'first_seen': current_date,
                            'last_seen': current_date,
                            'count': count
                        }
                        stats['added_domains'] += 1
                    else:
                        # Too rare - skip
                        stats['skipped_rare_domains'] += 1
            
            # === Merge other items (less risky, no frequency threshold) ===
            # Always merge: spawned processes, users
            baseline['spawned_processes'].update(new_data['spawned_processes'])
            baseline['spawned_with_args'].update(new_data['spawned_with_args'])
            baseline['spawned_args'].update(new_data['spawned_args'])
            baseline['users'].update(new_data['users'])
            baseline['process_args'].update(new_data['process_args'])
            
            # Merge: IPs, ports, paths, files, extensions (less security-critical)
            baseline['contacted_ips'].update(new_data['contacted_ips'])
            baseline['contacted_ports'].update(new_data['contacted_ports'])
            baseline['network_paths'].update(new_data['network_paths'])
            baseline['accessed_files'].update(new_data['accessed_files'])
            baseline['accessed_extensions'].update(new_data['accessed_extensions'])
            
            # Merge file operations and update metadata
            for fname, fdata in new_data.get('file_operations', {}).items():
                if fname in baseline['file_operations']:
                    baseline['file_operations'][fname]['operations'].update(fdata['operations'])
                    baseline['file_operations'][fname]['users'].update(fdata['users'])
                    baseline['file_operations'][fname]['process_args'].update(fdata['process_args'])
                    baseline['file_operations_meta'].setdefault(fname, {
                        'first_seen': current_date,
                        'last_seen': current_date
                    })
                    baseline['file_operations_meta'][fname]['last_seen'] = current_date
                else:
                    baseline['file_operations'][fname] = fdata
                    baseline['file_operations_meta'][fname] = {
                        'first_seen': current_date,
                        'last_seen': current_date
                    }
            
            # Update stats
            baseline['stats']['instances'] += new_data['stats']['instances']
        
        # Print summary
        print(f"\n📈 Merge Summary:")
        print(f"  ✨ New process combinations: {stats['new_keys']}")
        print(f"  ➕ Added directories: {stats['added_dirs']}")
        print(f"  ➕ Added domains: {stats['added_domains']}")
        print(f"  ⏭️ Skipped rare directories: {stats['skipped_rare_dirs']}")
        print(f"  ⏭️ Skipped rare domains: {stats['skipped_rare_domains']}")
        print(f"  🗑️ Expired directories: {stats['expired_dirs']}")
        print(f"  🗑️ Expired domains: {stats['expired_domains']}")
        print(f"  🗑️ Expired file operations: {stats['expired_file_ops']}")
        
        return existing_baseline


def execute(cluster, database, tenant, output_dir, mode, lookback_unit='day', 
            lookback_count=1, bootstrap_count=7, delay_seconds=5, baseline_offset=0):
    """Execute anomaly detection workflow"""
    detector = AIAgentAnomalyDetector(cluster, database, tenant, output_dir)
    
    print("="*80)
    print(f"🤖 AI Agent Anomaly 10 Detection for {tenant}")
    print("="*80)
    
    if mode == 'bootstrap':
        print(f"\n🔄 Collecting {bootstrap_count} {lookback_unit}(s) + building baseline")
        
        all_process = []
        all_children = []
        successful = 0
        start_period = bootstrap_count + baseline_offset
        end_period = baseline_offset
        
        for period in range(start_period, end_period, -1):
            try:
                #print(f"\n[{bootstrap_count - period + 1}/{bootstrap_count}] Period {period}...")
                print(f"\n[{start_period - period + 1}/{bootstrap_count}] Period {period}...")

                detect_period = 0 if lookback_unit == 'day' else 1
                df_proc = detector.collect_ai_process_data(period, lookback_unit)
                #print ("3.1 finished collecting processes")
                if len(df_proc) > 0:
                    #print ("3.12 finished collecting processes")
                    ai_parents = df_proc['PidCreationTime'].unique().tolist()
                    #print ("3.13 finished collecting processes")

                    df_child = detector.collect_child_spawning_data(ai_parents, period, lookback_unit)
                    #print ("3.14 finished collecting processes")
                else:
                    #print ("3.15 finished collecting processes")
                    df_child = pd.DataFrame()
                    #print ("3.2 finished collecting child processes")
                if len(df_proc) > 0:
                    #print ("3.3 finished collecting child processes")
                    all_process.append(df_proc)
                    #print ("3.4 finished collecting child processes")
                    successful += 1
                if len(df_child) > 0:
                    #print ("3.5 finished collecting child processes")
                    all_children.append(df_child)
                
                if period > 1:
                    #print ("3.6 finished collecting child processes")
                    time.sleep(delay_seconds)
                    #print (f"3.7 finished collecting child processes Sleeping {delay_seconds} for tenant {tenant}")
                    
            except Exception as e:
                print(f"❌ Error: 5 {e}")
                #print ("eeeeeeeeeeeeeeeeeeeee")
                #print (query)
                #print ("eeeeeeeeeeeeeeeeeeeee")
        
        print(f"\n✅ Collected {successful} periods for {tenant}")
        
        #if all_process:
        #    baselines = detector.build_baseline(all_process, all_children)
        #    detector.save_baseline(baselines)
        if all_process:
            # Load existing baseline if it exists
            existing_baseline = detector.load_baseline()
            
            if existing_baseline:
                print(f"📚 Found existing baseline with {len(existing_baseline)} combinations - merging with new data...")
                # Build baseline from new data
                existing_baseline = detector.merge_baselines_with_frequency_and_decay(
                        existing_baseline,
                        all_process,
                        all_children,
                        min_occurrences=3,        # Must appear 3+ times
                        decay_days=30,            # Directories/domains expire after 30 days
                        critical_items_decay_days=90  # File operations expire after 90 days
                    )
                
                detector.save_baseline(existing_baseline)
            else:
                    # No existing baseline - create new one
                baselines = detector.build_baseline(all_process, all_children)
                detector.save_baseline(baselines)        
        else:
            print(f"⚠️  No data collected for {tenant}")
    
    elif mode == 'train':
        print("\n🔨 Rebuilding baseline from saved collections... for {tenant}")
        raw_dir = os.path.join(output_dir, 'raw_collections')
        
        if not os.path.exists(raw_dir):
            print("⚠️  No raw collections found for {tenant}")
            return
        
        proc_files = sorted([f for f in os.listdir(raw_dir) if f.startswith('process_')])
        child_files = sorted([f for f in os.listdir(raw_dir) if f.startswith('child_')])
        
        if not proc_files:
            print("⚠️  No data")
            return
        
        all_proc = [pd.read_csv(os.path.join(raw_dir, f)) for f in proc_files]
        all_child = [pd.read_csv(os.path.join(raw_dir, f)) for f in child_files] if child_files else []
        
        baselines = detector.build_baseline(all_proc, all_child)
        detector.save_baseline(baselines)
    
    elif mode == 'detect':
        baselines = detector.load_baseline()
        
        if not baselines:
            print("⚠️  No baseline. Run bootstrap first.")
            return
        
        detect_period = 0 if lookback_unit == 'day' else 1
        df_proc = detector.collect_ai_process_data(detect_period, lookback_unit)
        
        # Get AI parent IDs and query for their children
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
                print(f"🚨 ALERTS for {tenant}")
                pprint.pp(alerts)
                print("="*80)
                for _, alert in alerts.iterrows():
                    print(f"\n {alert['process']} on {alert['machine']}")
                    print(f"  PID: {alert['pid']} | User: {alert['user']} | Signer: {alert.get('signer', 'UNKNOWN')}")
                    #print(f"  Type: {alert['type']}")
                    #print(f"  Details: {alert['details']}")
                    
    
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
                print(f"   ❌ Error: 4 {e}")
    
    print("\n✅ Complete!")


def main():
    parser = argparse.ArgumentParser(description='AI Agent Anomaly Detection')
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
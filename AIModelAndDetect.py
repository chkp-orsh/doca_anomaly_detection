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
from collections import Counter

import warnings
warnings.filterwarnings('ignore')
import pprint
import random
import ast
import hashlib
import StatisticalModelHelper
import AIDRTools

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



class AIAgentAnomalyDetector:
    """Statistical anomaly detection for AI agents"""
    
    def __init__(self, cluster_url, database, tenant_id, output_dir):
        self.cluster_url = cluster_url
        self.database = database
        self.tenant_id = tenant_id
        self.output_dir = output_dir
        self.stats_helper = StatisticalModelHelper.StatisticalModelHelper()
        
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'baselines'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'alerts'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'raw_collections'), exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'stats'), exist_ok=True)
        
        self.kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(cluster_url)
        self.client = KustoClient(self.kcsb)


    
    def _alert_id(self, alert: dict, anomaly: dict) -> str:
        key = f"{alert.get('timestamp')}|{alert.get('machine')}|{alert.get('process')}|{alert.get('pid')}|{anomaly.get('type')}|{anomaly.get('details')}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    
    def _normalize_filename(self, filename):
        return AIDRTools.normalize_filename(filename)
    
    def _normalize_process_args(self, args):
        return AIDRTools.normalize_process_args(args)
    
    def _normalize_directory_path(self, path):
        return AIDRTools.normalize_directory_path(path)
    
    def _normalize_signer(self, signer):
        return AIDRTools.normalize_signer(signer)
    
    def _safe_parse_list(self, value):
        return AIDRTools.safe_parse_list(value)
    
    def _to_json_str(self, v, max_len=20000):
        return AIDRTools.to_json_str(v, max_len)
    
    def _get_current_date(self):
        return AIDRTools.get_current_date()
    
    def _days_since(self, date_str):
        return AIDRTools.days_since(date_str)
    
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
    

    def _period_window(self, lookback_value=1, lookback_unit='day'):
        """Return (period_start_dt, period_end_dt) used for labeling collection windows."""
        now = datetime.now()
        if lookback_unit == 'hour':
            # lookback_value=1 means previous full hour
            end_dt = (now - timedelta(hours=lookback_value-1)).replace(minute=0, second=0, microsecond=0)
            start_dt = end_dt - timedelta(hours=1)
            return start_dt, end_dt
        # day
        if lookback_value == 0:
            start_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_dt = now
        else:
            day = (now - timedelta(days=lookback_value)).date()
            start_dt = datetime.combine(day, datetime.min.time())
            end_dt = datetime.combine(day, datetime.max.time()).replace(microsecond=0)
        return start_dt, end_dt

    def _agent_reason_from_row(self, row: pd.Series) -> str:
        """Derive a human-readable reason string for why this row/agent was collected."""
        reasons = []
        try:
            if int(row.get('model_files_count', 0) or 0) > 0:
                reasons.append(f"Model files ({int(row.get('model_files_count', 0))})")
        except Exception:
            pass
        try:
            if int(row.get('llm_api_count', 0) or 0) > 0:
                reasons.append(f"LLM API calls ({int(row.get('llm_api_count', 0))})")
        except Exception:
            pass
        try:
            if int(row.get('suspicious_args_count', 0) or 0) > 0:
                reasons.append("Suspicious arguments")
        except Exception:
            pass
        try:
            if int(row.get('suspicious_dir_count', 0) or 0) > 0:
                reasons.append("Suspicious directory")
        except Exception:
            pass
        # Fallback: aiScore only
        if not reasons:
            try:
                score = float(row.get('aiScore_avg', 0) or 0)
                reasons.append(f"aiScore={score:.2f}")
            except Exception:
                reasons.append("aiScore")
        return "; ".join(reasons)

    def record_collection_stats(self, lookback_value=1, lookback_unit='day', df_proc: pd.DataFrame | None = None):
        """Append per-period collection stats for this tenant (two CSVs under output_dir/stats)."""
        df_proc = df_proc if df_proc is not None else pd.DataFrame()
        period_start, period_end = self._period_window(lookback_value, lookback_unit)

        # An "agent" here is the same key used in the baseline: (MachineName, ProcessName, normalized_args, signer)
        agent_rows = []
        if not df_proc.empty:
            for _, row in df_proc.iterrows():
                agent_rows.append({
                    "machine": self._obfuscate_machine_name(str(row.get("MachineName", ""))),
                    "process": str(row.get("ProcessName", "")),
                    "normalized_args": self._normalize_process_args(row.get("ProcessArgs")),
                    "signer": self._normalize_signer(row.get("ProcessSigner")),
                    "user": self._obfuscate_user_name(str(row.get("UserName", "UNKNOWN"))),
                    "ai_score": float(row.get("aiScore_avg", 0) or 0),
                    "reason_added": self._agent_reason_from_row(row),
                })

        df_agents = pd.DataFrame(agent_rows)

        # Total agents = unique baseline keys in this period
        total_agents = 0
        if not df_agents.empty:
            total_agents = int(df_agents.drop_duplicates(subset=["machine", "process", "normalized_args", "signer"]).shape[0])

        stats_dir = os.path.join(self.output_dir, "stats")
        os.makedirs(stats_dir, exist_ok=True)

        # CSV 1: per-period summary
        summary_path = os.path.join(stats_dir, "collection_summary.csv")
        summary_row = pd.DataFrame([{
            "period_start": period_start.isoformat(sep=" ", timespec="seconds"),
            "period_end": period_end.isoformat(sep=" ", timespec="seconds"),
            "lookback_unit": lookback_unit,
            "lookback_value": int(lookback_value),
            "total_agents": total_agents,
            "rows_returned": int(len(df_proc) if df_proc is not None else 0),
        }])
        if os.path.exists(summary_path):
            summary_row.to_csv(summary_path, mode="a", header=False, index=False)
        else:
            summary_row.to_csv(summary_path, index=False)

        # CSV 2: per-agent per period
        agents_path = os.path.join(stats_dir, "collection_agents.csv")
        if not df_agents.empty:
            df_agents.insert(0, "period_start", period_start.isoformat(sep=" ", timespec="seconds"))
            df_agents.insert(1, "period_end", period_end.isoformat(sep=" ", timespec="seconds"))
            if os.path.exists(agents_path):
                df_agents.to_csv(agents_path, mode="a", header=False, index=False)
            else:
                df_agents.to_csv(agents_path, index=False)
        else:
            # still create file with headers for convenience
            if not os.path.exists(agents_path):
                pd.DataFrame(columns=[
                    "period_start","period_end","machine","process","normalized_args","signer","user","ai_score","reason_added"
                ]).to_csv(agents_path, index=False)

        print(f"🧾 Stats saved: {summary_path} and {agents_path}")

    def select_ai_parents_for_child_query(self, df_proc: pd.DataFrame, max_parents: int = 500) -> list:
        """
        Select a bounded set of parent PidCreationTime values for the child query.
        Uses 'capability' signals (LLM API, model files, AI ports, localhost inbound, etc.)
        rather than generic interpreters.
        """
        if df_proc is None or df_proc.empty:
            return []

        df = df_proc.copy()

        # Ensure expected columns exist
        for col in [
            "llm_api_count", "model_files_count", "ai_serving_port_count",
            "localhost_inbound_count", "suspicious_args_count", "suspicious_dir_count",
            "aiScore_avg", "event_count", "PidCreationTime"
        ]:
            if col not in df.columns:
                df[col] = 0

        # Convert to numeric safely
        for col in [
            "llm_api_count", "model_files_count", "ai_serving_port_count",
            "localhost_inbound_count", "suspicious_args_count", "suspicious_dir_count",
            "aiScore_avg", "event_count"
        ]:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        # Capability score (tune weights as you like)
        df["capability_score"] = 0
        df.loc[df["llm_api_count"] > 0, "capability_score"] += 6          # strong: talks to LLM API
        df.loc[df["ai_serving_port_count"] > 0, "capability_score"] += 5  # strong: AI serving ports
        df.loc[df["model_files_count"] > 0, "capability_score"] += 4      # strong: model artifacts
        df.loc[df["localhost_inbound_count"] > 0, "capability_score"] += 2
        df.loc[df["suspicious_args_count"] > 0, "capability_score"] += 1
        df.loc[df["suspicious_dir_count"] > 0, "capability_score"] += 1

        # Candidate gate: any real capability, not just noise
        df["is_ai_capable_candidate"] = (
            (df["llm_api_count"] > 0) |
            (df["ai_serving_port_count"] > 0) |
            (df["model_files_count"] > 0) |
            (df["capability_score"] >= 5)
        )

        candidates = df[df["is_ai_capable_candidate"]].copy()
        if candidates.empty:
            # fall back to top by aiScore_avg if you want *some* coverage
            candidates = df.sort_values(["aiScore_avg", "event_count"], ascending=False).head(max_parents)

        candidates = candidates.sort_values(
            ["capability_score", "aiScore_avg", "event_count"],
            ascending=[False, False, False]
        )

        # Return unique parent keys
        parents = (
            candidates["PidCreationTime"]
            .dropna()
            .astype(str)
            .drop_duplicates()
            .head(int(max_parents))
            .tolist()
        )
        return parents


    def attach_children_count(self, df_proc: pd.DataFrame, df_child: pd.DataFrame) -> pd.DataFrame:
        """
        Adds children_count per parent into df_proc by matching:
          df_proc.PidCreationTime <-> df_child.ProcessPPidCreationTime
        """
        if df_proc is None or df_proc.empty:
            return df_proc

        out = df_proc.copy()
        out["children_count"] = 0

        if df_child is None or df_child.empty:
            return out

        if "MachineName" not in df_child.columns or "ProcessPPidCreationTime" not in df_child.columns:
            return out

        counts = (
            df_child.groupby(["MachineName", "ProcessPPidCreationTime"])
            .size()
            .reset_index(name="children_count")
        )

        merged = out.merge(
            counts,
            how="left",
            left_on=["MachineName", "PidCreationTime"],
            right_on=["MachineName", "ProcessPPidCreationTime"],
            suffixes=("", "_y")
        )

        merged["children_count"] = merged["children_count_y"].fillna(merged["children_count"]).fillna(0).astype(int)
        merged.drop(columns=[c for c in ["ProcessPPidCreationTime", "children_count_y"] if c in merged.columns], inplace=True)
        return merged


    def add_stage2_flags(self, df_proc: pd.DataFrame) -> pd.DataFrame:
        """
        Adds:
          - capability_score
          - is_ai_capable_candidate
          - is_agentic (children_count>0)
          - shadow_agent_candidate (capable + agentic)
        """
        if df_proc is None or df_proc.empty:
            return df_proc

        df = df_proc.copy()

        for col in [
            "llm_api_count", "model_files_count", "ai_serving_port_count", "localhost_inbound_count",
            "suspicious_args_count", "suspicious_dir_count", "children_count", "aiScore_avg", "event_count"
        ]:
            if col not in df.columns:
                df[col] = 0

        for col in [
            "llm_api_count", "model_files_count", "ai_serving_port_count", "localhost_inbound_count",
            "suspicious_args_count", "suspicious_dir_count", "children_count", "aiScore_avg", "event_count"
        ]:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        df["capability_score"] = 0
        df.loc[df["llm_api_count"] > 0, "capability_score"] += 6
        df.loc[df["ai_serving_port_count"] > 0, "capability_score"] += 5
        df.loc[df["model_files_count"] > 0, "capability_score"] += 4
        df.loc[df["localhost_inbound_count"] > 0, "capability_score"] += 2
        df.loc[df["suspicious_args_count"] > 0, "capability_score"] += 1
        df.loc[df["suspicious_dir_count"] > 0, "capability_score"] += 1

        df["is_ai_capable_candidate"] = (
            (df["llm_api_count"] > 0) |
            (df["ai_serving_port_count"] > 0) |
            (df["model_files_count"] > 0) |
            (df["capability_score"] >= 5)
        )

        df["is_agentic"] = df["children_count"] > 0
        df["shadow_agent_candidate"] = df["is_ai_capable_candidate"] & df["is_agentic"]

        return df




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
| where aiScore >= {SEVERITY_THRESHOLDS["min_ai_score"]}
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
            ai_serving_port_count = countif(usesAIServingPort == 1),
            localhost_inbound_count = countif(hasLocalhostInbound == 1),
            long_connection_count = countif(hasLongConnection == 1),
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
        """Build baseline with statistical modeling"""
        print("\n🔨 Building statistical baselines...")
        
        df_process = pd.concat(df_process_list, ignore_index=True) if df_process_list else pd.DataFrame()
        df_children = pd.concat(df_children_list, ignore_index=True) if df_children_list else pd.DataFrame()
        
        baselines = defaultdict(lambda: {
            'spawned_processes': set(),
            'spawned_args': set(),
            'spawned_with_args': set(),
            'spawned_process_name_counts': Counter(),
            'spawned_process_templates': [],
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
        
        # Build from child data (check if df_children has data and columns)
        if not df_children.empty and 'MachineName' in df_children.columns:
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
                    baselines[key]['spawned_process_name_counts'][child_process] += 1
                
                if child_row.get('ProcessArgs'):
                    baselines[key]['spawned_args'].add(child_row['ProcessArgs'])
                                                
            # NEW: Track normalized process directories
                if pd.notna(row.get('ProcessDir')):
                    norm_proc_dir = self._normalize_directory_path(row['ProcessDir'])
                    if norm_proc_dir:
                        if 'process_dirs' not in baselines[key]:
                            baselines[key]['process_dirs'] = set()
                        baselines[key]['process_dirs'].add(norm_proc_dir)
            
        else:
            print("  ⚠️ No child process data available")
        
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
                
                # Children count statistics (check if df_children has data)
                children_counts = []
                if not df_children.empty and 'MachineName' in df_children.columns:
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
        
        # Learn spawned process name templates from evidence (generic, robust)
        for key, b in baselines.items():
            counts = b.get('spawned_process_name_counts')
            if not counts:
                continue

            names = []
            for n, c in counts.items():
                names.extend([n] * c)

            pattern, meta = AIDRTools.try_learn_name_template(
                names,
                min_total=5,     # tune to your baseli ne window size
                min_distinct=3,
                min_coverage=0.6
            )
            if pattern:
                b['spawned_process_templates'].append({'pattern': pattern, 'meta': meta})
                print(f"IIIIIIIIIIIII [BASELINE] Learned template for {key}: {pattern} meta={meta}")

        
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
                    'process_dirs': safe_convert_list(baseline.get('process_dirs', set()), 'process_dirs'),
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
                    'detection_reason': baseline.get('detection_reason', {}),
                    'spawned_process_templates': baseline.get('spawned_process_templates', []),
                    'spawned_process_name_counts': dict(baseline.get('spawned_process_name_counts', {})),                    
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
                'process_dirs': set(baseline.get('process_dirs', [])),
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
                'detection_reason': baseline.get('detection_reason', {}),
                'spawned_process_templates': baseline.get('spawned_process_templates', []),
                'spawned_process_name_counts': Counter(baseline.get('spawned_process_name_counts', {})),

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
                    
                    # Calculate distance from baseline using tuple comparison
                    confidence, severity, distance_details = self.stats_helper.calculate_agent_distance(
                        key, 
                        baselines.keys()
                    )
                    
                    event_time = row.get('CreationTime')
                    alert_timestamp = str(int(event_time)) if event_time and pd.notna(event_time) else "UNKNOWN"
                    
                    # Gather context about the new agent
                    domains_raw = row.get('contacted_domains')
                    current_domains = list(clean_set(self._safe_parse_list(domains_raw)))[:10]
                    
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
                                type="EVENT_NEW_AI_AGENT_NOT_IN_BASELINE",
                                severity=severity,
                                details=f"New AI agent not in baseline: {row['ProcessName']} - {distance_details.get('reason', 'unknown')}",
                                row=row,
                                baseline=None,
                                normalized_args=normalized_args,
                                occurrence_count=0,
                                confidence_score=confidence,
                                extra={
                                    "distance_analysis": distance_details,
                                    "new_agent_key": {
                                        "machine": row['MachineName'][:50],
                                        "process": row['ProcessName'],
                                        "args_preview": normalized_args[:100],
                                        "signer": signer
                                    },
                                    "contacted_domains_sample": current_domains,
                                    "total_baseline_agents": len(baselines)
                                }
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
                                type="LOG_AI_AGENT_IN_LEARNING_PHASE",
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
                
                # In detect_anomalies(), after finding baseline match:

                # Check if ProcessDir is in baseline
                if 'process_dirs' not in baseline:
                    baseline['process_dirs'] = set()

                baseline_dirs = baseline.get('process_dirs', set())
                current_dir = self._normalize_directory_path(row.get('ProcessDir', ''))

                if current_dir and current_dir not in baseline_dirs:
                    # Check similarity to existing dirs
                    is_novel, confidence, best_match = self.stats_helper.novelty_score(
                        current_dir,
                        baseline_dirs,
                        threshold=0.85
                    )
                    
                    if is_novel:
                        severity = "CRITICAL"  # Process running from new location!
                        
                        # Extra critical if it's a suspicious location
                        SUSPICIOUS_PATHS = ['temp', 'tmp', 'downloads', 'public', 'appdata\\local\\temp']
                        if any(susp in current_dir.lower() for susp in SUSPICIOUS_PATHS):
                            severity = "CRITICAL"
                            confidence = min(confidence + 0.1, 1.0)
                        
                        anomalies.append(
                            self._make_anomaly(
                                type="ALERT_PROCESS_RUNNING_FROM_NEW_LOCATION",
                                severity=severity,
                                details=f"Process {row['ProcessName']} running from NEW location: {current_dir}",
                                row=row,
                                baseline=baseline,
                                normalized_args=normalized_args,
                                occurrence_count=occurrence_count,
                                confidence_score=confidence,
                                extra={
                                    "current_process_dir": current_dir,
                                    "baseline_process_dirs": list(baseline_dirs)[:10],
                                    "is_suspicious_location": any(susp in current_dir.lower() for susp in SUSPICIOUS_PATHS)
                                }
                            )
                        )
                
                
                
                
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
                
                # NEW IPS (with subnet and geo-location scoring)
                ips_raw = row.get('contacted_ips')
                current_ips = set(ip for ip in self._safe_parse_list(ips_raw) if ip and str(ip).strip())
                baseline_ips = baseline.get('contacted_ips', set())
                
                new_ips = current_ips - baseline_ips
                if new_ips:
                    # Score each new IP individually
                    ip_alerts = []
                    for new_ip in new_ips:
                        severity, confidence, details = self.stats_helper.score_new_ip(new_ip, baseline_ips)
                        ip_alerts.append({
                            "ip": new_ip,
                            "severity": severity,
                            "confidence": confidence,
                            "details": details
                        })
                    
                    # Use highest severity/confidence for overall alert
                    max_severity = "CRITICAL" if any(a["severity"] == "CRITICAL" for a in ip_alerts) else \
                                   "HIGH" if any(a["severity"] == "HIGH" for a in ip_alerts) else \
                                   "MEDIUM" if any(a["severity"] == "MEDIUM" for a in ip_alerts) else "LOW"
                    max_confidence = max(a["confidence"] for a in ip_alerts)
                    
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_IPS",
                            severity=max_severity,
                            details=f"{len(new_ips)} new IP(s): subnet/geo analysis",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=max_confidence,
                            extra={
                                "new_ips_analysis": ip_alerts[:10],  # Detailed analysis for each IP
                                "baseline_ips_sample": list(baseline_ips)[:5],
                                "scoring_method": "subnet_and_geolocation"
                            }
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
                
                # ===== Check NEW FILE EXTENSIONS =====
                exts_raw = row.get('accessed_extensions')
                current_exts = set(e for e in self._safe_parse_list(exts_raw) if e and str(e).strip())
                baseline_exts = baseline.get('accessed_extensions', set())

                new_exts = current_exts - baseline_exts
                COMMON_EXTS = {'txt', 'log', 'tmp', 'cache', 'json', 'xml', 'yml', 'yaml'}
                suspicious_exts = new_exts - COMMON_EXTS

                if suspicious_exts:
                    SUSPICIOUS_EXT_TYPES = {'exe', 'dll', 'bat', 'ps1', 'vbs', 'js', 'py', 'sh'}
                    high_risk_exts = suspicious_exts & SUSPICIOUS_EXT_TYPES
                    ext_confidence = 0.9 if high_risk_exts else 0.7
                    
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_NEW_FILE_EXTENSIONS",
                            severity="MEDIUM",
                            details=f"Accessed {len(suspicious_exts)} new file extension(s)",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=ext_confidence,
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "NEW_FILE_EXTENSIONS"
                            },
                            extra={
                                "new_extensions": list(suspicious_exts),
                                "high_risk_extensions": list(high_risk_exts) if high_risk_exts else [],
                                "baseline_extensions": list(baseline_exts)[:20]
                            }
                        )
                    )

                # ===== Check NEW FILES ACCESSED =====
                files_raw = row.get('accessed_files')
                files_list = self._safe_parse_list(files_raw)
                current_files = set(self._normalize_filename(f) for f in files_list if f)
                baseline_files = baseline.get('accessed_files', set())

                file_threshold = self.stats_helper.adaptive_threshold(baseline_files, default=0.80)

                truly_new_files = []
                file_confidences = []
                for curr_file in current_files:
                    is_novel, confidence, match = self.stats_helper.novelty_score(
                        curr_file, baseline_files, threshold=file_threshold
                    )
                    if is_novel:
                        truly_new_files.append(curr_file)
                        file_confidences.append(confidence)

                if len(truly_new_files) >= SEVERITY_THRESHOLDS.get("new_files_medium", 10):
                    avg_confidence = np.mean(file_confidences) if file_confidences else 0.6
                    
                    anomalies.append(
                        self._make_anomaly(
                            type="ALERT_ACCESSING_MANY_NEW_FILES",
                            severity="MEDIUM",
                            details=f"Accessed {len(truly_new_files)} new files (threshold: {file_threshold:.2f})",
                            row=row,
                            baseline=baseline,
                            normalized_args=normalized_args,
                            occurrence_count=occurrence_count,
                            confidence_score=float(avg_confidence),
                            baseline_context={
                                "status": "ACTIVE_DETECTION",
                                "reason": "MANY_NEW_FILES",
                                "adaptive_threshold": f"{file_threshold:.2f}"
                            },
                            extra={
                                "new_files_sample": truly_new_files[:20],
                                "file_confidences": [f"{c:.2f}" for c in file_confidences[:10]],
                                "baseline_files_sample": list(baseline_files)[:20]
                            }
                        )
                    )
                
                
                
                # ===== Check MODEL FILE MODIFICATIONS =====
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
                    mod_args = file_mod_info.get('args') if file_mod_info else None
                    
                    file_in_baseline = False
                    matching_baseline_file = None
                    
                    for baseline_file in baseline_file_ops.keys():
                        similarity = SequenceMatcher(None, norm_file.lower(), baseline_file.lower()).ratio()
                        if similarity >= 0.90:
                            file_in_baseline = True
                            matching_baseline_file = baseline_file
                            break
                    
                    if not file_in_baseline:
                        # FIRST TIME modification - NEVER modified before
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
                                confidence_score=0.98,
                                baseline_context={
                                    "status": "ACTIVE_DETECTION",
                                    "reason": "FIRST_MODEL_MODIFICATION"
                                },
                                extra={
                                    "file": original_file,
                                    "normalized_file": norm_file,
                                    "file_type": original_file.split('.')[-1] if '.' in original_file else "unknown",
                                    "modifying_user": mod_user,
                                    "modifying_process": row["ProcessName"],
                                    "modifying_process_args": str(row.get("ProcessArgs", ""))[:500],
                                    "modifying_pid": int(row["Pid"]) if pd.notna(row["Pid"]) else None,
                                    "contacted_domains": (
                                        list(ast.literal_eval(domains))[:10]
                                        if isinstance(domains, str)
                                        else list(domains)[:10] if isinstance(domains, (list, tuple))
                                        else []
                                    ),
                                    "network_bytes_sent": int(row.get("NetworkBytesSent_sum", 0)),
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
                            user_mod_confidence = 0.95 if severity == 'CRITICAL' else 0.75
                            
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
                                    confidence_score=user_mod_confidence,
                                    baseline_context={
                                        "status": "ACTIVE_DETECTION",
                                        "reason": "MODEL_MODIFIED_BY_NEW_USER",
                                        "file_user_authorization": (
                                            "UNAUTHORIZED" if severity == "CRITICAL" else "UNUSUAL"
                                        )
                                    },
                                    extra={
                                        "file": original_file,
                                        "normalized_file": norm_file,
                                        "current_user": mod_user,
                                        "current_process": row["ProcessName"],
                                        "baseline_authorized_users_for_file": list(file_baseline.get("users", set())),
                                        "baseline_all_users_for_process": list(baseline_users)[:10],
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
                                    args_confidence = 1.0 - max_sim
                                    
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
                                            confidence_score=args_confidence,
                                            baseline_context={
                                                "status": "ACTIVE_DETECTION",
                                                "reason": "UNUSUAL_MODEL_ARGS"
                                            },
                                            extra={
                                                "file": original_file,
                                                "normalized_file": norm_file,
                                                "current_args": str(mod_args)[:500],
                                                "similarity_to_best_baseline": f"{max_sim:.2f}",
                                                "best_matching_baseline_arg": (
                                                    str(best_match)[:200] if best_match else None
                                                ),
                                                "modifying_user": mod_user,
                                                "modifying_process": row["ProcessName"]
                                            }
                                        )
                                    )



          
          
                # CHILD SPAWNING (check if df_children has data)
                # ===== Check CHILD SPAWNING =====
                if not df_children.empty and 'MachineName' in df_children.columns:
                    children_of_this = df_children[
                        (df_children['MachineName'] == row['MachineName']) &
                        (df_children['ProcessPPidCreationTime'] == row['PidCreationTime'])
                    ]

                    baseline_spawned = baseline.get('spawned_with_args', set())

                    for _, child in children_of_this.iterrows():
                        child_process = child.get('ProcessName')
                        child_args = child.get('ProcessArgs')
                        #exact_match = (child_process, child_args_norm) in baseline_spawned
                        
                        if not child_process or not str(child_process).strip():
                            continue

                         # NEW: Check whitelist patterns
                        from ai_anomaly_defs import WHITELISTED_CHILD_PATTERNS
                        is_whitelisted = False
                        for pattern in WHITELISTED_CHILD_PATTERNS:
                            # Check parent process match
                            if 'parent_process' in pattern:
                                if pattern['parent_process'] not in row['ProcessName']:
                                    continue
                            
                            # Check parent dir match
                            if 'parent_dir_contains' in pattern:
                                parent_dir = row.get('ProcessDir', '')
                                if pattern['parent_dir_contains'] not in parent_dir:
                                    continue
                            
                            # Check child process match
                            if 'child_process' in pattern:
                                if pattern['child_process'] != child_process:
                                    continue
                            
                            # Check arg patterns
                            if 'arg_contains' in pattern:
                                if all(p in str(child_args) for p in pattern['arg_contains']):
                                    is_whitelisted = True
                                    break
                        
                        if is_whitelisted:
                            continue  # Skip whitelisted combinations
                        
                        
                        child_args_norm = self._normalize_process_args(child_args)
                        exact_match = (child_process, child_args_norm) in baseline_spawned
                        
                        if not exact_match:
                            templates = baseline.get('spawned_process_templates', [])
                            matched_template = AIDRTools.match_any_template(child_process, templates)

                            if matched_template:
                                continue  # treat as known-variable child name


                            # Backward-compatible fallback: infer from old baseline data
                            if not templates:
                                # build evidence from existing fields
                                seen = set(baseline.get('spawned_processes', set()))
                                if not seen:
                                    seen = {proc for (proc, _args) in baseline.get('spawned_with_args', set())}

                                # only attempt inference if enough distinct variants exist
                                if len(seen) >= 5:
                                    pattern, meta = AIDRTools.try_learn_name_template(
                                        list(seen),
                                        min_total=5,       # here total==distinct; we’re being conservative with len(seen)>=5
                                        min_distinct=5,
                                        min_coverage=0.7
                                    )
                                    if pattern and AIDRTools.match_any_template(child_process, [{'pattern': pattern, 'meta': meta}]):
                                        continue

                            
                            
                            baseline_args_for_proc = [args for proc, args in baseline_spawned if proc == child_process]
                                
                            if not baseline_args_for_proc:
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
                                best_baseline_arg = None
                                for baseline_arg in baseline_args_for_proc:
                                    sim = SequenceMatcher(None, child_args_norm, baseline_arg).ratio()
                                    if sim > max_similarity:
                                        max_similarity = sim
                                        best_baseline_arg = baseline_arg
                                # Skip alerting on AWS metadata service queries
                                if child_process == "curl" and "169.254.169.254" in str(child_args):
                                    # Check if baseline also has metadata queries
                                    has_metadata_baseline = any(
                                        "169.254.169.254" in str(baseline_arg) 
                                        for baseline_arg in baseline_args_for_proc
                                    )
                                    if has_metadata_baseline:
                                        continue  # This is normal AWS metadata behavior
                                
                                
                                if max_similarity < 0.5:
                                    spawn_confidence = 1.0 - max_similarity
                                    
                                    anomalies.append(
                                        self._make_anomaly(
                                            type="ALERT_SPAWNED_PROCESS_UNUSUAL_ARGS",
                                            severity="HIGH",
                                            details=(
                                                f"Spawned {child_process} with unusual arguments "
                                                f"(similarity: {max_similarity:.2f})"
                                            ),
                                            row=row,
                                            baseline=baseline,
                                            normalized_args=normalized_args,
                                            occurrence_count=occurrence_count,
                                            confidence_score=spawn_confidence,
                                            baseline_context={
                                                "status": "ACTIVE_DETECTION",
                                                "reason": "SPAWNED_PROCESS_UNUSUAL_ARGS"
                                            },
                                            extra={
                                                "child_process": child_process,
                                                "child_normalized_args": child_args_norm,
                                                "child_actual_args": str(child_args)[:200] if child_args else "",
                                                "similarity_score": f"{max_similarity:.2f}",
                                                "most_similar_baseline": (
                                                    str(best_baseline_arg)[:100]
                                                    if best_baseline_arg else ""
                                                )
                                            }
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
        
        # NEW: Save in Check Point log format
        log_filepath = os.path.join(self.output_dir, 'alerts', f'alerts_{timestamp}.log')
        with open(log_filepath, 'w', encoding='utf-8') as log_file:
            for _, alert in alerts_df.iterrows():
                for anomaly in alert['anomalies']:
                    log_entry = AIDRTools.format_alert_as_checkpoint_log(alert, anomaly, self)
                    log_file.write(log_entry + '\n')
        
        print(f"💾 Saved {len(alerts_flat)} alerts in Check Point format to {log_filepath}")
    
        
        if 'confidence_score' in df_flat.columns:
            high = len(df_flat[df_flat['confidence_score'] >= 0.8])
            med = len(df_flat[(df_flat['confidence_score'] >= 0.5) & (df_flat['confidence_score'] < 0.8)])
            low = len(df_flat[df_flat['confidence_score'] < 0.5])
            print(f"  📊 High (≥0.8): {high}, Med (0.5-0.8): {med}, Low (<0.5): {low}")
    
    

    def merge_baselines_with_frequency_and_decay(
        self, 
        existing_baseline, 
        new_process_data, 
        new_children_data,
        min_occurrences=3,
        decay_days=30,
        critical_items_decay_days=90):
        """
        Merge new data into baseline with:
        1. Frequency threshold: Items must appear N times to be added
        2. Time-based decay: Items not seen in X days are removed
        3. Incremental statistical updates: Combines old + new statistics
        """
        print(f"\n🔄 Merging baselines:")
        print(f"  📊 Frequency threshold: {min_occurrences} occurrences")
        print(f"  ⏰ Decay period: {decay_days} days (critical items: {critical_items_decay_days} days)")
        
        current_date = self._get_current_date()
        
        # Build new baseline from recent data
        new_baseline = self.build_baseline(new_process_data, new_children_data)
        
        # Combine all NEW process data only (for frequency counting and new stats calculation)
        all_new_process_df = pd.concat(new_process_data, ignore_index=True) if new_process_data else pd.DataFrame()
        all_new_children_df = pd.concat(new_children_data, ignore_index=True) if new_children_data else pd.DataFrame()
        
        stats = {
            'new_keys': 0,
            'expired_dirs': 0,
            'expired_domains': 0,
            'expired_file_ops': 0,
            'added_dirs': 0,
            'added_domains': 0,
            'skipped_rare_dirs': 0,
            'skipped_rare_domains': 0,
            'stats_updated': 0
        }
        
        # Process each key in new baseline
        for key, new_data in new_baseline.items():
            if key not in existing_baseline:
                # Brand new process combination - add with metadata
                existing_baseline[key] = new_data
                
                # Initialize occurrence_count to 1
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
            
            # Repair missing entries
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
                
            baseline.setdefault('file_operations_meta', {})
            for fname in list(baseline.get('file_operations', {}).keys()):
                baseline['file_operations_meta'].setdefault(fname, {
                    'first_seen': current_date,
                    'last_seen': current_date
                })

            # === DECAY: Remove old items ===
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
            if len(all_new_process_df) > 0:
                normalized_args, signer = key[2], key[3]
                matching_rows = all_new_process_df[
                    (all_new_process_df['MachineName'] == key[0]) & 
                    (all_new_process_df['ProcessName'] == key[1]) &
                    (all_new_process_df['ProcessSigner'].apply(lambda x: self._normalize_signer(x)) == signer) &
                    (all_new_process_df['ProcessArgs'].apply(lambda x: self._normalize_process_args(x)) == normalized_args)
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
                        baseline['accessed_dirs'].add(norm_dir)
                        baseline['accessed_dirs_meta'][norm_dir] = {
                            'first_seen': current_date,
                            'last_seen': current_date,
                            'count': count
                        }
                        stats['added_dirs'] += 1
                    else:
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
                        baseline['contacted_domains'].add(domain)
                        baseline['contacted_domains_meta'][domain] = {
                            'first_seen': current_date,
                            'last_seen': current_date,
                            'count': count
                        }
                        stats['added_domains'] += 1
                    else:
                        stats['skipped_rare_domains'] += 1
            
            # === Merge other items ===
            baseline['spawned_processes'].update(new_data['spawned_processes'])
            baseline['spawned_with_args'].update(new_data['spawned_with_args'])
            baseline['spawned_args'].update(new_data['spawned_args'])
            
            from collections import Counter
            baseline.setdefault('spawned_process_name_counts', Counter())
            baseline['spawned_process_name_counts'].update(new_data.get('spawned_process_name_counts', Counter()))

            baseline.setdefault('spawned_process_templates', [])
            names = []
            for n, c in baseline['spawned_process_name_counts'].items():
                names.extend([n] * c)

            pattern, meta = AIDRTools.try_learn_name_template(
                names,
                min_total=5,
                min_distinct=3,
                min_coverage=0.6
            )
            if pattern:
                baseline['spawned_process_templates'] = [{'pattern': pattern, 'meta': meta}]
                        
            baseline['users'].update(new_data['users'])
            baseline['process_args'].update(new_data['process_args'])
            
            baseline['contacted_ips'].update(new_data['contacted_ips'])
            baseline['contacted_ports'].update(new_data['contacted_ports'])
            baseline['network_paths'].update(new_data['network_paths'])
            baseline['accessed_files'].update(new_data['accessed_files'])
            baseline['accessed_extensions'].update(new_data['accessed_extensions'])
            # In merge_baselines(), with other set merges:
            baseline['process_dirs'] = baseline.get('process_dirs', set())
            baseline['process_dirs'].update(new_data.get('process_dirs', set()))
            
            # Merge file operations
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
            
            # Update instance count (this is used for weighted average)
            old_instances = baseline['stats'].get('instances', 0)
            new_instances = new_data['stats'].get('instances', 0)
            total_instances = old_instances + new_instances
            baseline['stats']['instances'] = total_instances
        
        # === NEW: INCREMENTAL STATISTICAL UPDATES ===
        print("\n📊 Incrementally updating statistical models...")
        
        for key in existing_baseline.keys():
            machine, process, normalized_args, signer = key
            
            # Check if this key has new data
            if key in new_baseline:
                old_stats = existing_baseline[key]['stats']
                new_stats = new_baseline[key]['stats']
                
                old_n = old_stats.get('instances', 0)
                new_n = new_stats.get('instances', 0)
                total_n = old_n + new_n
                
                if total_n == 0:
                    continue
                
                # Weighted average for means
                def weighted_mean(old_mean, old_n, new_mean, new_n):
                    if old_n + new_n == 0:
                        return 0.0
                    return (old_mean * old_n + new_mean * new_n) / (old_n + new_n)
                
                # Combined variance (using parallel algorithm)
                def combined_variance(old_mean, old_var, old_n, new_mean, new_var, new_n):
                    if old_n + new_n <= 1:
                        return 0.0
                    
                    # Mean difference
                    delta = new_mean - old_mean
                    
                    # Combined variance formula
                    combined_var = (
                        (old_n * old_var + new_n * new_var) / (old_n + new_n) +
                        (old_n * new_n * delta * delta) / ((old_n + new_n) * (old_n + new_n))
                    )
                    return combined_var
                
                # Update bytes sent statistics
                old_mean_sent = old_stats.get('bytes_sent_mean', 0)
                new_mean_sent = new_stats.get('bytes_sent_mean', 0)
                updated_mean_sent = weighted_mean(old_mean_sent, old_n, new_mean_sent, new_n)
                
                old_std_sent = old_stats.get('bytes_sent_std', 0)
                new_std_sent = new_stats.get('bytes_sent_std', 0)
                combined_var_sent = combined_variance(
                    old_mean_sent, old_std_sent ** 2, old_n,
                    new_mean_sent, new_std_sent ** 2, new_n
                )
                updated_std_sent = np.sqrt(combined_var_sent)
                
                existing_baseline[key]['stats']['bytes_sent_mean'] = float(updated_mean_sent)
                existing_baseline[key]['stats']['bytes_sent_std'] = float(updated_std_sent)
                
                # For percentiles, use weighted interpolation (approximate)
                old_p50 = old_stats.get('bytes_sent_p50', old_mean_sent)
                new_p50 = new_stats.get('bytes_sent_p50', new_mean_sent)
                existing_baseline[key]['stats']['bytes_sent_p50'] = float(weighted_mean(old_p50, old_n, new_p50, new_n))
                
                old_p95 = old_stats.get('bytes_sent_p95', old_mean_sent)
                new_p95 = new_stats.get('bytes_sent_p95', new_mean_sent)
                existing_baseline[key]['stats']['bytes_sent_p95'] = float(weighted_mean(old_p95, old_n, new_p95, new_n))
                
                old_p99 = old_stats.get('bytes_sent_p99', old_mean_sent)
                new_p99 = new_stats.get('bytes_sent_p99', new_mean_sent)
                existing_baseline[key]['stats']['bytes_sent_p99'] = float(weighted_mean(old_p99, old_n, new_p99, new_n))
                
                # Update bytes received statistics
                old_mean_recv = old_stats.get('bytes_received_mean', 0)
                new_mean_recv = new_stats.get('bytes_received_mean', 0)
                updated_mean_recv = weighted_mean(old_mean_recv, old_n, new_mean_recv, new_n)
                
                old_std_recv = old_stats.get('bytes_received_std', 0)
                new_std_recv = new_stats.get('bytes_received_std', 0)
                combined_var_recv = combined_variance(
                    old_mean_recv, old_std_recv ** 2, old_n,
                    new_mean_recv, new_std_recv ** 2, new_n
                )
                updated_std_recv = np.sqrt(combined_var_recv)
                
                existing_baseline[key]['stats']['bytes_received_mean'] = float(updated_mean_recv)
                existing_baseline[key]['stats']['bytes_received_std'] = float(updated_std_recv)
                
                old_p95_recv = old_stats.get('bytes_received_p95', old_mean_recv)
                new_p95_recv = new_stats.get('bytes_received_p95', new_mean_recv)
                existing_baseline[key]['stats']['bytes_received_p95'] = float(weighted_mean(old_p95_recv, old_n, new_p95_recv, new_n))
                
                # Update domain count statistics
                old_domain_mean = old_stats.get('domain_count_mean', 0)
                new_domain_mean = new_stats.get('domain_count_mean', 0)
                existing_baseline[key]['stats']['domain_count_mean'] = float(weighted_mean(old_domain_mean, old_n, new_domain_mean, new_n))
                
                old_domain_std = old_stats.get('domain_count_std', 0)
                new_domain_std = new_stats.get('domain_count_std', 0)
                combined_var_domains = combined_variance(
                    old_domain_mean, old_domain_std ** 2, old_n,
                    new_domain_mean, new_domain_std ** 2, new_n
                )
                existing_baseline[key]['stats']['domain_count_std'] = float(np.sqrt(combined_var_domains))
                
                old_domain_p95 = old_stats.get('domain_count_p95', old_domain_mean)
                new_domain_p95 = new_stats.get('domain_count_p95', new_domain_mean)
                existing_baseline[key]['stats']['domain_count_p95'] = float(weighted_mean(old_domain_p95, old_n, new_domain_p95, new_n))
                
                # Update file count statistics
                old_file_mean = old_stats.get('file_count_mean', 0)
                new_file_mean = new_stats.get('file_count_mean', 0)
                existing_baseline[key]['stats']['file_count_mean'] = float(weighted_mean(old_file_mean, old_n, new_file_mean, new_n))
                
                old_file_std = old_stats.get('file_count_std', 0)
                new_file_std = new_stats.get('file_count_std', 0)
                combined_var_files = combined_variance(
                    old_file_mean, old_file_std ** 2, old_n,
                    new_file_mean, new_file_std ** 2, new_n
                )
                existing_baseline[key]['stats']['file_count_std'] = float(np.sqrt(combined_var_files))
                
                # Update dir count statistics
                old_dir_mean = old_stats.get('dir_count_mean', 0)
                new_dir_mean = new_stats.get('dir_count_mean', 0)
                existing_baseline[key]['stats']['dir_count_mean'] = float(weighted_mean(old_dir_mean, old_n, new_dir_mean, new_n))
                
                old_dir_std = old_stats.get('dir_count_std', 0)
                new_dir_std = new_stats.get('dir_count_std', 0)
                combined_var_dirs = combined_variance(
                    old_dir_mean, old_dir_std ** 2, old_n,
                    new_dir_mean, new_dir_std ** 2, new_n
                )
                existing_baseline[key]['stats']['dir_count_std'] = float(np.sqrt(combined_var_dirs))
                
                # Update children count statistics
                old_children_mean = old_stats.get('children_count_mean', 0)
                new_children_mean = new_stats.get('children_count_mean', 0)
                existing_baseline[key]['stats']['children_count_mean'] = float(weighted_mean(old_children_mean, old_n, new_children_mean, new_n))
                
                old_children_std = old_stats.get('children_count_std', 0)
                new_children_std = new_stats.get('children_count_std', 0)
                combined_var_children = combined_variance(
                    old_children_mean, old_children_std ** 2, old_n,
                    new_children_mean, new_children_std ** 2, new_n
                )
                existing_baseline[key]['stats']['children_count_std'] = float(np.sqrt(combined_var_children))
                
                stats['stats_updated'] += 1
        
        # Print summary
        print(f"\n📈 Merge Summary:")
        print(f"  ✨ New process combinations: {stats['new_keys']}")
        print(f"  ➕ Added directories: {stats['added_dirs']}")
        print(f"  ➕ Added domains: {stats['added_domains']}")
        print(f"  ⭐ Skipped rare directories: {stats['skipped_rare_dirs']}")
        print(f"  ⭐ Skipped rare domains: {stats['skipped_rare_domains']}")
        print(f"  🗑️ Expired directories: {stats['expired_dirs']}")
        print(f"  🗑️ Expired domains: {stats['expired_domains']}")
        print(f"  🗑️ Expired file operations: {stats['expired_file_ops']}")
        print(f"  📊 Statistics updated (incremental): {stats['stats_updated']} baselines")
        
        return existing_baseline    
    
    
    


def execute(cluster, database, tenant, output_dir, mode, lookback_unit='day', 
            lookback_count=1, bootstrap_count=7, delay_seconds=5, baseline_offset=0):
    """Execute workflow"""
    detector = AIAgentAnomalyDetector(cluster, database, tenant, output_dir)
    
    print("="*80)
    print(f"🤖 AI Anomaly Detection 16 (Statistical) for {tenant}")
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
                if df_proc is not None and len(df_proc) > 0:
                    ai_parents = detector.select_ai_parents_for_child_query(df_proc, max_parents=500)
                    df_child = detector.collect_child_spawning_data(ai_parents, period, lookback_unit) if ai_parents else pd.DataFrame()
                    df_proc = detector.attach_children_count(df_proc, df_child)
                    df_proc = detector.add_stage2_flags(df_proc)
                    
                else:
                    df_child = pd.DataFrame()

                # NEW: persist per-period collection stats
                detector.record_collection_stats(period, lookback_unit, df_proc)
                    
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
                    decay_days=30, critical_items_decay_days=90
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
            ai_parents = detector.select_ai_parents_for_child_query(df_proc, max_parents=500)
            df_child = detector.collect_child_spawning_data(ai_parents, detect_period, lookback_unit) if ai_parents else pd.DataFrame()
            df_proc = detector.attach_children_count(df_proc, df_child)
            df_proc = detector.add_stage2_flags(df_proc)
        else:
            df_child = pd.DataFrame()

        # NEW: persist per-period collection stats (detect run)
        detector.record_collection_stats(detect_period, lookback_unit, df_proc)

        # Stage-2 focus: AI-capable + agentic
        df_proc_focus = df_proc
        if df_proc is not None and not df_proc.empty and "shadow_agent_candidate" in df_proc.columns:
            # Keep agentic candidates, plus "very high" raw score rows as a backstop
            min_ai_score = int(SEVERITY_THRESHOLDS.get("min_ai_score", 7))
            df_proc_focus = df_proc[(df_proc["shadow_agent_candidate"]) | (df_proc["aiScore_avg"] >= min_ai_score)].copy()

        
        
        if (df_proc is not None and len(df_proc) > 0) or (df_child is not None and len(df_child) > 0):
            #alerts = detector.detect_anomalies(df_proc, df_child, baselines, min_occurrences=3)
            alerts = detector.detect_anomalies(df_proc_focus, df_child, baselines, min_occurrences=3)

            
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

                # NEW: persist per-period collection stats
                detector.record_collection_stats(period, lookback_unit, df_proc)
                
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


import os
import re
import json
import time
import pprint
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from openai import AzureOpenAI

import pandas as pd
import analyzer_defs
import ai_anomaly_defs
from ai_anomaly_defs import (
    KNOWN_AI_SERVING_PROCESS_NAMES,
    GENERIC_INTERPRETER_PROCESS_NAMES,
    TOOL_PROCESS_NAMES,
    COMMON_DEV_OR_BROWSER_PROCESSES,
    LLM_API_DOMAINS,
    LLM_API_PATH_FRAGMENTS,
    COMMON_AI_SERVING_PORTS,
    AI_CMDLINE_KEYWORDS,
    AI_MODULE_PATH_PATTERNS,
    AI_MODULE_FILENAME_PATTERNS,
    MODEL_PATH_PATTERNS,
    ALERT_CLASSIFICATION,
)
from analyzer_defs import (LLM_PROVIDER,
                           LLM_MODEL,
                           OPENAI_API_KEY,
                           OLLAMA_URL,
                           OLLAMA_MODEL,
                           VIRUSTOTAL_API_KEY,
                           ABUSEIPDB_API_KEY,
                           ANTHROPIC_API_KEY,
                           AZURE_OPENAI_ENDPOINT,
                           AZURE_OPENAI_API_KEY,
                           AZURE_OPENAI_DEPLOYMENT,
                           AZURE_OPENAI_API_VERSION,
                           COMPANY_REPUTATION_URL,
                           CACHE_TTL_SHORT,CACHE_TTL_LONG)


# =============================================================================
# Utilities
# =============================================================================

def _maybe_generate_pdf(report: dict, json_path: str) -> None:
    status = str(report.get("recommended_status") or report.get("status") or "").upper()
    print(f"  🔍 PDF check: status='{status}', path={json_path}")
    if status == "CLOSED":
        return
    try:
        from incident_report_pdf import generate_pdf
    except ImportError:
        return
    pdf_path = json_path.replace(".json", ".pdf")
    tenant = report.get("domain_name") or "ACME"
    print(f"  🖨️  Generating PDF → {pdf_path} (tenant={tenant})")
    try:
        generate_pdf(report, pdf_path, tenant_id=tenant)
    except Exception as e:
        print(f"  ⚠️eeeeeeeeeeee  PDF generation failed for {json_path}: {e}")

def make_json_serializable(obj: Any) -> Any:
    """Convert sets / numpy / pandas types into JSON-safe structures."""
    if isinstance(obj, set):
        return sorted(list(obj))
    if isinstance(obj, (list, tuple)):
        return [make_json_serializable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): make_json_serializable(v) for k, v in obj.items()}
    try:
        import numpy as np
        if isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        if isinstance(obj, (np.ndarray,)):
            return obj.tolist()
    except Exception:
        pass
    return obj


def _safe_json_loads(s: Any) -> Optional[dict]:
    if s is None or (isinstance(s, float) and pd.isna(s)):
        return None
    if isinstance(s, dict):
        return s
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(s[start:end + 1])
            except Exception:
                return None
    return None


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def _looks_like_ip(x: str) -> bool:
    if not x or not isinstance(x, str):
        return False
    m = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", x.strip())
    if not m:
        return False
    parts = x.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _is_private_ip(ip: str) -> bool:
    if not _looks_like_ip(ip):
        return False
    a, b, c, d = [int(x) for x in ip.split(".")]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def _extract_suspicious_files_from_anomaly_json(g: pd.DataFrame) -> Dict[str, List[str]]:
    modified = set()
    accessed = set()

    if "anomaly_json" not in g.columns:
        return {"modified_files": [], "accessed_files": []}

    for _, row in g.iterrows():
        aj = _safe_json_loads(row.get("anomaly_json"))
        if not isinstance(aj, dict):
            continue
        preview = aj.get("preview")
        if not isinstance(preview, dict):
            continue
        for f in preview.get("modified_files") or []:
            if f:
                modified.add(str(f))
        for f in preview.get("accessed_files") or []:
            if f:
                accessed.add(str(f))

    return {
        "modified_files": sorted(modified),
        "accessed_files": sorted(accessed),
    }


# =============================================================================
# Clients
# =============================================================================

class VirusTotalClient:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.enabled = api_key is not None

    def get_domain_report(self, domain: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/domains/{domain}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                attrs = data.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'categories': attrs.get('categories', {}),
                    'reputation': attrs.get('reputation', 0)
                }
            elif response.status_code == 404:
                return {'positives': 0, 'total': 0, 'note': 'Not found in VT'}
            else:
                return {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def get_ip_report(self, ip: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/ip_addresses/{ip}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                attrs = data.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'country': attrs.get('country', 'Unknown'),
                    'as_owner': attrs.get('as_owner', 'Unknown')
                }
            elif response.status_code == 404:
                return {'positives': 0, 'total': 0, 'note': 'Not found in VT'}
            else:
                return {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def get_file_report(self, file_hash: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                attrs = data.get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'type_description': attrs.get('type_description', 'Unknown'),
                    'names': attrs.get('names', [])[:5]
                }
            elif response.status_code == 404:
                return {'positives': 0, 'total': 0, 'note': 'Not found in VT'}
            else:
                return {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}


class AbuseIPDBClient:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.enabled = api_key is not None

    def check_ip(self, ip: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(f"{self.base_url}/check", headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                    'totalReports': data.get('totalReports', 0),
                    'countryCode': data.get('countryCode', 'Unknown'),
                    'usageType': data.get('usageType', 'Unknown'),
                    'isWhitelisted': data.get('isWhitelisted', False)
                }
            else:
                return {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}


class CompanyReputationClient:
    def __init__(self, api_url: Optional[str]):
        self.api_url = api_url
        self.enabled = api_url is not None

    def check_domain(self, domain: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            response = requests.get(f"{self.api_url}/domain/{domain}", timeout=10)
            return response.json() if response.status_code == 200 else {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def check_ip(self, ip: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            response = requests.get(f"{self.api_url}/ip/{ip}", timeout=10)
            return response.json() if response.status_code == 200 else {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}

    def check_file(self, file_hash: str) -> Optional[Dict]:
        if not self.enabled:
            return None
        try:
            import requests
            response = requests.get(f"{self.api_url}/file/{file_hash}", timeout=10)
            return response.json() if response.status_code == 200 else {'error': f"HTTP {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}


class LLMClient:
    def __init__(self, provider: str = LLM_PROVIDER, model: str = LLM_MODEL):
        self.provider = provider.lower().replace("_openai", "") if "azure" in provider.lower() else provider.lower()
        self.model = model
        self.api_key    = None
        self.endpoint   = None
        self.deployment = None
        self.api_version = None
        self.enabled    = False

        print(f"__init__ provider: {provider} → normalised: {self.provider}")

        if self.provider == 'anthropic':
            self.api_key = ANTHROPIC_API_KEY
            self.enabled = bool(self.api_key)
        elif self.provider == 'openai':
            self.api_key = OPENAI_API_KEY
            self.enabled = bool(self.api_key)
        elif self.provider == 'ollama':
            self.enabled = True
        elif self.provider == 'azure':
            self.api_key     = AZURE_OPENAI_API_KEY
            self.endpoint    = AZURE_OPENAI_ENDPOINT
            self.deployment  = AZURE_OPENAI_DEPLOYMENT
            self.api_version = AZURE_OPENAI_API_VERSION
            self.enabled     = all([self.api_key, self.endpoint, self.deployment])
            print(f"   AZURE_OPENAI_API_KEY set: {bool(self.api_key)}")
            print(f"   AZURE_OPENAI_DEPLOYMENT: {self.deployment}")
            print(f"   AZURE_OPENAI_API_VERSION: {self.api_version}")
            print(f"   AZURE_OPENAI_ENDPOINT: {self.endpoint}")
        else:
            print(f"   ⚠️  Unknown provider '{self.provider}' — will fall back to Ollama")
            self.provider = 'ollama'
            self.enabled  = True

        print(f"   LLM Provider: {self.provider}")
        print(f"   LLM Model: {self.model}")
        print(f"   Enabled: {self.enabled}")

    def _build_text_summary(self, report: Dict) -> str:
        incident_id = report.get("incident_id", "unknown")
        status = report.get("status", "UNKNOWN")
        sev = (report.get("severity") or {}).get("risk_level")
        classification = (report.get("verdict") or {}).get("classification")
        raw_alert = report.get("raw_alert") or {}
        user = raw_alert.get("UserName") or raw_alert.get("user") or "unknown user"
        host = raw_alert.get("DeviceName") or raw_alert.get("hostname") or "unknown host"
        domain = raw_alert.get("DomainName")
        procs = report.get("processes") or {}
        child = procs.get("child_process") or {}
        parent = procs.get("parent_process") or {}
        child_name = child.get("name") or child.get("process_name") or "unknown process"
        parent_name = parent.get("name") or parent.get("process_name") or "unknown parent"
        anomalies = report.get("anomalies") or []
        anomaly_types = [a.get("type") for a in anomalies if a.get("type")]
        anomaly_types = sorted(set(anomaly_types))
        enr = (report.get("enrichment") or {}).get("summary", {})
        total_mal = enr.get("total_malicious", 0)
        total_susp = enr.get("total_suspicious", 0)
        highest_risk = enr.get("highest_risk")

        parts = []
        parts.append(f"Incident {incident_id} is {status}.")
        if sev or classification:
            parts.append(f"Verdict: {classification or 'UNKNOWN'}; Severity: {sev or 'UNKNOWN'}.")
        parts.append(f"Observed activity on {host} for {user}: {child_name} spawned by {parent_name}.")
        if domain:
            parts.append(f"Domain observed in alert: {domain}.")
        if anomaly_types:
            parts.append(f"Anomalies: {', '.join(anomaly_types)}.")
        else:
            parts.append("No anomalies were recorded.")
        if total_mal or total_susp:
            parts.append(
                f"Threat intelligence results: {total_mal} malicious and {total_susp} suspicious indicators."
            )
            if highest_risk:
                artifact = highest_risk.get("artifact")
                source = highest_risk.get("source")
                if artifact:
                    parts.append(f"Highest risk indicator: {artifact} (source: {source}).")
        else:
            parts.append("No malicious or suspicious indicators found in threat intelligence.")
        return " ".join(parts)

    def analyze(self, prompt: str, max_tokens: int = 4000) -> Optional[str]:
        if not self.enabled:
            return None
        print(f"Analyze: {self.provider}")
        try:
            if self.provider == 'azure':
                response = self._analyze_azure(prompt, max_tokens)
            elif self.provider == 'anthropic':
                response = self._analyze_anthropic(prompt, max_tokens)
            elif self.provider == 'openai':
                response = self._analyze_openai(prompt, max_tokens)
            elif self.provider == 'ollama':
                max_tokens = min(int(max_tokens or 900), 900)
                response = self._analyze_ollama(prompt, max_tokens)
            else:
                return None

            if (self.provider == 'azure'
                    and isinstance(response, str)
                    and response.startswith("LLM Error")):
                print(f"⚠️  Azure failed ({response}) — falling back to Ollama")
                return self._analyze_ollama(prompt, min(int(max_tokens or 900), 900))
            return response
        except Exception as e:
            err = f"LLM Error ({self.provider}): {str(e)}"
            if self.provider == 'azure':
                print(f"⚠️  Azure exception ({e}) — falling back to Ollama")
                try:
                    return self._analyze_ollama(prompt, min(int(max_tokens or 900), 900))
                except Exception as e2:
                    return f"LLM Error (ollama fallback): {str(e2)}"
            return err

    def _analyze_azure(self, prompt: str, max_tokens: int) -> str:
        print(f"_analyze_azure, api_key:{self.api_key}")
        print(f"_analyze_azure, api_version:{self.api_version}")
        print(f"_analyze_azure, azure_endpoint:{self.endpoint}")
        print(f"_analyze_azure, deployment:{self.deployment}")
        client = AzureOpenAI(
            api_key=self.api_key,
            azure_endpoint=self.endpoint,
            api_version="2025-04-01-preview"
        )
        print("after client")
        pprint.pprint(client)
        print("Calling response: ")
        response = client.chat.completions.create(
            model=self.deployment,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens
        )
        print(f"Azure response: ")
        print(response.choices[0].message.content)
        return response.choices[0].message.content

    def _analyze_anthropic(self, prompt: str, max_tokens: int) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def _analyze_openai(self, prompt: str, max_tokens: int) -> str:
        import openai
        client = openai.OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens
        )
        return response.choices[0].message.content

    def _analyze_ollama(self, prompt: str, max_tokens: int) -> str:
        import requests
        print(f"_analyze_ollama: max_tokens {max_tokens}")
        try:
            health_check = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
            if health_check.status_code != 200:
                return "Ollama Error: Service not running. Start with: ollama serve"
        except requests.exceptions.RequestException:
            return "Ollama Error: Cannot connect to localhost:11434. Start with: ollama serve"
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": 0.1}
            },
            timeout=5000
        )
        if response.status_code == 200:
            print("Ollama OK")
            return response.json().get('response', '')
        else:
            return f"Ollama Error: HTTP {response.status_code}"


# =============================================================================
# Analyzer
# =============================================================================

@dataclass
class IncidentGroupKey:
    machine: str
    process: str
    pid: int
    creation_time: int


class IncidentAnalyzer2:

    def __init__(self):
        self.vt_key = analyzer_defs.VIRUSTOTAL_API_KEY
        self.abuse_key = analyzer_defs.ABUSEIPDB_API_KEY
        self.vt_client = VirusTotalClient(self.vt_key) if self.vt_key else None
        self.abuse_client = AbuseIPDBClient(self.abuse_key) if self.abuse_key else None

        print(f"Init: provider: {analyzer_defs.LLM_PROVIDER}, model: {analyzer_defs.LLM_MODEL}")
        self.llm_client = LLMClient(
            provider=analyzer_defs.LLM_PROVIDER,
            model=analyzer_defs.LLM_MODEL
        )
        self._cache: Dict[Tuple[str, str], Tuple[float, Any]] = {}
        self.cache_ttl_long = 24 * 60 * 60

        provider = getattr(analyzer_defs, "LLM_PROVIDER", "ollama")
        model = getattr(analyzer_defs, "LLM_MODEL", None)
        if provider == "openai" and not getattr(analyzer_defs, "OPENAI_API_KEY", None):
            provider = "ollama"
        if provider == "anthropic" and not getattr(analyzer_defs, "ANTHROPIC_API_KEY", None):
            provider = "ollama"
        if provider == "ollama":
            model = model or getattr(analyzer_defs, "OLLAMA_MODEL", "llama3")
        elif provider == "openai":
            model = model or getattr(analyzer_defs, "OPENAI_MODEL", "gpt-4o-mini")
        elif provider == "anthropic":
            model = model or getattr(analyzer_defs, "ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

    # -------------------------------------------------------------------------
    # AI agent classification context
    # -------------------------------------------------------------------------

    def _extract_ai_agent_context(self, inc: Dict, anomalies: List[Dict]) -> Dict:
        """
        Answers: WHY was this process flagged as an AI agent to begin with?

        Directly cross-references the incident's process name, path, contacted domains,
        contacted ports, and command-line args against the definition lists in
        ai_anomaly_defs that the detection query itself uses. This is the only
        reliable way to get non-empty, non-invented matches — if the alert fired,
        at least one of these lists must have matched.

        Returns:
          ai_risk_categories          : risk tags from ALERT_CLASSIFICATION (e.g. "Shadow AI")
          matched_artifacts           : list of {value, matched_list, match_type} — NEVER empty
                                        if the alert exists (the detection guarantees a match)
          classification_alert_details: per-alert context for deep-dive
        """
        matched: List[Dict] = []

        def _add(value: str, list_name: str, match_type: str = "exact") -> None:
            entry = {"value": value, "matched_list": list_name, "match_type": match_type}
            if entry not in matched:
                matched.append(entry)

        # ── Normalise incident fields ─────────────────────────────────────
        process_name = str(inc.get("process") or "").strip()
        process_name_lower = process_name.lower()
        process_dir  = str(inc.get("process_dir") or "").lower()

        # Domains: from incident (JSON path) + from baseline_relevant_json in anomalies
        contacted_domains: List[str] = [
            str(d).lower() for d in (inc.get("contacted_domains") or []) if d
        ]
        for a in anomalies or []:
            for d in ((a.get("baseline_relevant_json") or {}).get("new_domains") or []):
                s = str(d).lower()
                if s and s not in contacted_domains:
                    contacted_domains.append(s)

        # Ports: from incident (JSON path) + from baseline_relevant_json in anomalies
        contacted_ports: List[int] = []
        for p in (inc.get("contacted_ports") or []):
            try: contacted_ports.append(int(p))
            except (ValueError, TypeError): pass
        for a in anomalies or []:
            for p in ((a.get("baseline_relevant_json") or {}).get("new_ports") or []):
                try:
                    pi = int(p)
                    if pi not in contacted_ports:
                        contacted_ports.append(pi)
                except (ValueError, TypeError):
                    pass

        # Args: collect child_args and observed_args across all anomalies
        all_args = " ".join(filter(None, [
            str(a.get("child_args") or "")
            + " " + str((a.get("baseline_relevant_json") or {}).get("observed_args") or "")
            for a in (anomalies or [])
        ])).lower()

        # ── 1. Process name vs definition lists ───────────────────────────
        # Normalise: strip path separators, lowercase, try both with and without .exe
        def _name_matches(candidate: str) -> bool:
            c = candidate.lower().strip()
            return process_name_lower in (c, c + ".exe", c.replace(".exe", ""))

        for name in KNOWN_AI_SERVING_PROCESS_NAMES:
            if _name_matches(name):
                _add(process_name, "KNOWN_AI_SERVING_PROCESS_NAMES")
                break

        for name in GENERIC_INTERPRETER_PROCESS_NAMES:
            if _name_matches(name):
                _add(process_name, "GENERIC_INTERPRETER_PROCESS_NAMES")
                break

        for name in TOOL_PROCESS_NAMES:
            if _name_matches(name):
                _add(process_name, "TOOL_PROCESS_NAMES")
                break

        for name in COMMON_DEV_OR_BROWSER_PROCESSES:
            if _name_matches(name):
                _add(process_name, "COMMON_DEV_OR_BROWSER_PROCESSES")
                break

        # ── 2. Contacted domains vs LLM_API_DOMAINS ───────────────────────
        for domain in contacted_domains:
            for api_domain in LLM_API_DOMAINS:
                if api_domain.lower() in domain:
                    _add(domain, "LLM_API_DOMAINS", "substring")
                    break   # one match per contacted domain is enough

        # ── 3. Contacted ports vs COMMON_AI_SERVING_PORTS ────────────────
        for port in contacted_ports:
            if port in COMMON_AI_SERVING_PORTS:
                _add(str(port), "COMMON_AI_SERVING_PORTS")

        # ── 4. Process dir vs MODEL_PATH_PATTERNS (compiled regexes) ─────
        if process_dir:
            for pattern in MODEL_PATH_PATTERNS:
                if pattern.search(process_dir):
                    _add(process_dir, "MODEL_PATH_PATTERNS", "regex")
                    break

        # ── 5. Process dir vs AI_MODULE_PATH_PATTERNS (strings) ──────────
        if process_dir:
            for fragment in AI_MODULE_PATH_PATTERNS:
                if fragment.lower() in process_dir:
                    _add(fragment, "AI_MODULE_PATH_PATTERNS", "substring")
                    break

        # ── 6. Command-line args vs LLM_API_PATH_FRAGMENTS ───────────────
        if all_args:
            for fragment in LLM_API_PATH_FRAGMENTS:
                if fragment.lower() in all_args:
                    _add(fragment, "LLM_API_PATH_FRAGMENTS", "substring")

        # ── 7. Command-line args vs AI_CMDLINE_KEYWORDS ──────────────────
        if all_args:
            for keyword in AI_CMDLINE_KEYWORDS:
                if keyword.lower() in all_args:
                    _add(keyword, "AI_CMDLINE_KEYWORDS", "substring")

        # ── 8. Accessed filenames vs AI_MODULE_FILENAME_PATTERNS ─────────
        # e.g. torch_cpu.dll, cudnn_ops64_9.dll, tokenizer.json → strong AI signal
        for fpath in (inc.get("accessed_files") or []):
            basename = re.split(r"[/\\]", str(fpath))[-1].lower()
            for pattern in AI_MODULE_FILENAME_PATTERNS:
                if pattern.lower() in basename:
                    _add(basename, "AI_MODULE_FILENAME_PATTERNS", "substring")
                    break   # one match per file is enough

        # ── 9. Accessed dirs vs AI_MODULE_PATH_PATTERNS + MODEL_PATH_PATTERNS ──
        # e.g. .cache/huggingface/hub/..., venv/.../torch → strong AI signal
        for dpath in (inc.get("accessed_dirs") or []):
            dpath_lower = str(dpath).lower()
            matched_dir = False
            for fragment in AI_MODULE_PATH_PATTERNS:
                if fragment.lower() in dpath_lower:
                    _add(dpath_lower, "AI_MODULE_PATH_PATTERNS", "substring")
                    matched_dir = True
                    break
            if not matched_dir:
                for pattern in MODEL_PATH_PATTERNS:
                    if pattern.search(dpath_lower):
                        _add(dpath_lower, "MODEL_PATH_PATTERNS", "regex")
                        break

        # ── Collect ai_risk tags + classification alert details ───────────
        ai_risks: List[str] = []
        classification_details: List[Dict] = []

        AI_CLASSIFICATION_KEYWORDS = (
            "AI_AGENT", "NEW_AI", "LEARNING_PHASE", "LOG_AI",
            "EVENT_NEW", "SHADOW_AI", "AGENT_BASELINE",
        )

        for a in anomalies or []:
            alert_type = str(a.get("anomaly_type") or a.get("type") or "")
            for risk in (a.get("ai_risk") or []):
                rs = str(risk).strip()
                if rs and rs not in ai_risks:
                    ai_risks.append(rs)
            if any(kw in alert_type.upper() for kw in AI_CLASSIFICATION_KEYWORDS):
                entry: Dict = {"alert_type": alert_type}
                if a.get("details"):
                    entry["details"] = a["details"]
                if a.get("reason"):
                    entry["reason"] = a["reason"]
                runbook = a.get("soc_runbook") or {}
                if isinstance(runbook, dict) and runbook.get("detection_reason"):
                    entry["detection_reason"] = runbook["detection_reason"]
                classification_details.append(entry)

        if ai_risks and not classification_details:
            classification_details.append({
                "note": "Inferred from ai_risk tags — no explicit classification alert.",
                "ai_risk_categories": ai_risks,
            })

        # ── Guarantee non-empty matched_artifacts ─────────────────────────
        # The alert exists because something matched the definitions.
        # If all the runtime checks above found nothing (e.g. process name was
        # normalised differently at detection time), surface the ai_risk tags
        # and alert types as the last-resort explanation rather than returning [].
        if not matched:
            for rs in ai_risks:
                _add(rs, "ai_risk (from alert)", "tag")
            for cd in classification_details:
                at = cd.get("alert_type") or ""
                if at:
                    _add(at, "alert_type", "tag")

        return {
            "ai_risk_categories":          ai_risks,
            "matched_artifacts":           matched,     # [{value, matched_list, match_type}]
            "classification_alert_details": classification_details,
        }

    # -------------------------------------------------------------------------
    # AI deployment type classification (deterministic)
    # -------------------------------------------------------------------------

    def _classify_ai_deployment_type(
        self,
        matched_artifacts: List[Dict],
        ai_risks: List[str],
        process_name: str,
        process_dir: str = "",
    ) -> Dict:
        """
        Classifies whether the AI process is shadow AI, a legitimate enterprise
        app using AI, or a developer/agent tool — inferred directly from the
        definition lists that caused the alert to fire.

        Returns:
          type   : "shadow_ai" | "enterprise_ai" | "dev_tool" | "unknown"
          reason : one sentence explaining the classification
          is_shadow_ai : bool convenience flag
        """
        from ai_anomaly_defs import (
            KNOWN_AI_SERVING_PROCESS_NAMES,
            COMMON_DEV_OR_BROWSER_PROCESSES,
        )

        # Processes that are legitimate enterprise/productivity tools using AI
        ENTERPRISE_AI_PROCESS_NAMES = {
            "chrome.exe", "msedge.exe", "firefox.exe",
            "code.exe",            # VS Code + Copilot
            "teams.exe",           # Microsoft Teams
            "teams",
            "slack.exe", "slack",
            "outlook.exe",
            "winword.exe", "excel.exe", "powerpnt.exe",  # M365 Copilot
            "explorer.exe",
            "idea64.exe", "pycharm64.exe",               # JetBrains IDEs
            # Claude desktop app — consumer/enterprise chat, NOT the CLI
            # Disambiguated below by process path
            "claude.exe", "claude",
        }

        # Dev/agent tools — intentional AI use but not standard enterprise software
        DEV_AGENT_PROCESS_NAMES = {
            "aider.exe", "aider",          # Aider coding agent
            "cursor.exe", "cursor",        # Cursor IDE
            "continue",                    # Continue.dev
            "cody",                        # Sourcegraph Cody
            "goose.exe", "goose",          # Block Goose
            "amp",                         # Anthropic Amp
            "devin",                       # Cognition Devin
        }

        pname         = process_name.lower().strip()
        process_dir_l = process_dir.lower()
        matched_lists = {m["matched_list"] for m in matched_artifacts}

        # ── Claude desktop app vs Claude Code CLI disambiguation ──────────
        # Both show as claude.exe; path tells them apart.
        # Desktop app: %LOCALAPPDATA%\AnthropicClaude\  or  \AppData\Local\AnthropicClaude\
        # CLI:         .cargo\bin\, npm\, yarn\, or any PATH-style location
        if pname in ("claude.exe", "claude"):
            is_desktop = any(frag in process_dir_l for frag in (
                "anthropicclaude", "anthrpic", "appdata\\local\\claude",
                "applications\\claude",   # macOS
            ))
            is_cli = any(frag in process_dir_l for frag in (
                ".cargo", "node_modules", "npm", "yarn", "\\bin\\", "/bin/",
                "site-packages", "pipx",
            ))
            if is_desktop and not is_cli:
                return {
                    "type": "enterprise_ai",
                    "is_shadow_ai": False,
                    "reason": (
                        f"'{process_name}' is the Claude desktop application "
                        f"(path: {process_dir_l or 'unknown'}) — a consumer/enterprise chat app, "
                        f"not an agentic CLI tool."
                    ),
                }
            else:
                # CLI or unknown — treat as dev_tool (more conservative)
                return {
                    "type": "dev_tool",
                    "is_shadow_ai": False,
                    "reason": (
                        f"'{process_name}' appears to be the Claude Code CLI "
                        f"(path: {process_dir_l or 'unknown'}) — an agentic coding tool "
                        f"that can execute code and shell commands. Monitoring warranted."
                    ),
                }

        # ── Generic interpreter + AI module file/path evidence → shadow AI ──
        # This is the key case: python.exe alone is not shadow AI, but
        # python.exe + torch_cpu.dll + huggingface cache paths absolutely is.
        ai_module_evidence = [
            m["value"] for m in matched_artifacts
            if m["matched_list"] in (
                "AI_MODULE_FILENAME_PATTERNS",
                "AI_MODULE_PATH_PATTERNS",
                "MODEL_PATH_PATTERNS",
                "KNOWN_AI_SERVING_PROCESS_NAMES",
            )
        ]
        is_generic = (
            "GENERIC_INTERPRETER_PROCESS_NAMES" in matched_lists
            or "TOOL_PROCESS_NAMES" in matched_lists
        )
        if ai_module_evidence and is_generic:
            return {
                "type": "shadow_ai",
                "is_shadow_ai": True,
                "reason": (
                    f"'{process_name}' is a generic interpreter running AI model workloads. "
                    f"AI model artifacts matched: {', '.join(ai_module_evidence[:4])}. "
                    f"This constitutes shadow AI until explicitly authorized."
                ),
            }

        # ── Enterprise app: matched COMMON_DEV_OR_BROWSER_PROCESSES or known list ──
        if (
            "COMMON_DEV_OR_BROWSER_PROCESSES" in matched_lists
            or any(pname in (e.lower(), e.lower().replace(".exe", "")) for e in ENTERPRISE_AI_PROCESS_NAMES)
        ):
            return {
                "type": "enterprise_ai",
                "is_shadow_ai": False,
                "reason": (
                    f"'{process_name}' is a known enterprise application that uses AI "
                    f"(matched COMMON_DEV_OR_BROWSER_PROCESSES or enterprise app list). "
                    f"AI usage is expected; alert is about behavioral deviation, not unauthorized deployment."
                ),
            }

        # ── Dev/agent tool: known coding agent / CLI ──────────────────────────────
        if any(pname in (d.lower(), d.lower().replace(".exe", "")) for d in DEV_AGENT_PROCESS_NAMES):
            return {
                "type": "dev_tool",
                "is_shadow_ai": False,
                "reason": (
                    f"'{process_name}' is a developer AI agent or CLI tool. "
                    f"It may be authorized but is not a standard enterprise app; monitoring is warranted."
                ),
            }

        # ── Shadow AI: standalone AI server matched KNOWN_AI_SERVING_PROCESS_NAMES ─
        if "KNOWN_AI_SERVING_PROCESS_NAMES" in matched_lists:
            return {
                "type": "shadow_ai",
                "is_shadow_ai": True,
                "reason": (
                    f"'{process_name}' matched KNOWN_AI_SERVING_PROCESS_NAMES — "
                    f"a standalone AI server or local model runtime not typically approved for "
                    f"enterprise use. This constitutes shadow AI until explicitly authorized."
                ),
            }

        # ── Shadow AI inferred from ai_risk tags ──────────────────────────────────
        shadow_tags = {"Shadow AI", "Unauthorized AI Deployment", "shadow_ai", "unauthorized_ai"}
        if any(r in shadow_tags for r in ai_risks):
            return {
                "type": "shadow_ai",
                "is_shadow_ai": True,
                "reason": (
                    f"'{process_name}' was tagged as shadow AI by the detection system "
                    f"(ai_risk: {', '.join(r for r in ai_risks if r in shadow_tags)})."
                ),
            }

        # ── Unknown / generic interpreter (python.exe etc.) ──────────────────────
        if "GENERIC_INTERPRETER_PROCESS_NAMES" in matched_lists or "TOOL_PROCESS_NAMES" in matched_lists:
            return {
                "type": "unknown",
                "is_shadow_ai": False,
                "reason": (
                    f"'{process_name}' is a generic interpreter or tool process. "
                    f"AI classification is based on its network/behavioral profile, "
                    f"not the process name alone. Intent cannot be determined without further context."
                ),
            }

        return {
            "type": "unknown",
            "is_shadow_ai": False,
            "reason": (
                f"Insufficient data to classify '{process_name}' as shadow AI or enterprise AI. "
                f"Review matched_artifacts for details."
            ),
        }

    def _determine_final_status(
        self,
        llm_status: str,
        verdict: str,
        severity: str,
        impact: Dict,
        deployment: Dict,
    ) -> Tuple[str, str]:
        """
        Post-processes the LLM's recommended_status with deterministic overrides.
        Returns (final_status, override_reason).

        Override rules (evaluated in priority order):
          1. MALICIOUS / CRITICAL  → always ESCALATE
          2. Impact present        → never CLOSED; use MONITOR if LLM said CLOSED/OPEN
          3. Shadow AI             → never CLOSED; at minimum MONITOR
          4. Dev tool              → never CLOSED; at minimum MONITOR
          5. FALSE_POSITIVE        → CLOSED (unless overridden above)
          6. Otherwise keep LLM status
        """
        has_impact = (
            bool(impact.get("data_exfiltration"))
            or bool(impact.get("system_modification"))
            or bool(impact.get("possible_credentials_compromised"))
        )
        is_shadow_ai  = deployment.get("is_shadow_ai", False)
        deploy_type   = deployment.get("type", "unknown")

        # 1. Always escalate critical/malicious
        if verdict == "MALICIOUS" or severity == "CRITICAL":
            return "ESCALATE", "Verdict is MALICIOUS or severity is CRITICAL — escalation required."

        # 2. Impact present — never silently close
        if has_impact and llm_status == "CLOSED":
            reason_parts = []
            if impact.get("data_exfiltration"):
                reason_parts.append("outbound data transfer detected")
            if impact.get("system_modification"):
                reason_parts.append("file system modification detected")
            if impact.get("possible_credentials_compromised"):
                reason_parts.append("possible credential artifact access")
            return "MONITOR", f"Impact present ({'; '.join(reason_parts)}) — cannot auto-close."

        # 3. Shadow AI — keep open for human review
        if is_shadow_ai and llm_status == "CLOSED":
            return "MONITOR", (
                "Shadow AI process — incident requires human authorization review "
                "before it can be closed."
            )

        # 4. Dev tool — at minimum monitor
        if deploy_type == "dev_tool" and llm_status == "CLOSED":
            return "MONITOR", (
                "Developer AI tool — not standard enterprise software; "
                "requires human review before closing."
            )

        # 5. FALSE_POSITIVE with no impact and no shadow AI → allow close
        if verdict == "FALSE_POSITIVE" and not has_impact and not is_shadow_ai:
            return "CLOSED", "False positive with no impact and no shadow AI — auto-closed."

        # 6. Keep LLM status
        return llm_status, ""

    # -------------------------------------------------------------------------
    # Impact + RCA + recommended actions (deterministic)
    # -------------------------------------------------------------------------

    def _build_impact(self, inc: Dict, evidence: Dict) -> Dict:
        key_artifacts = evidence.get("key_artifacts") or {}
        bytes_sent = int((evidence.get("network_volume") or {}).get("bytes_sent", 0))

        has_exfil = bytes_sent > 0
        has_modification = bool(
            key_artifacts.get("modified_files") or key_artifacts.get("new_dirs")
        )

        credential_indicators = []
        for p in key_artifacts.get("new_files", []):
            s = str(p).lower()
            if any(x in s for x in [
                "keychain", "login.keychain", ".ssh", "id_rsa", "id_ed25519",
                ".aws", ".azure", ".config/gcloud", "credentials", "token",
                "secret", "vault", "sam", "lsass"
            ]):
                credential_indicators.append(p)

        return {
            "data_exfiltration": has_exfil,
            "system_modification": has_modification,
            "possible_credentials_compromised": bool(credential_indicators),
            "credential_artifacts": credential_indicators,
        }

    def _build_root_cause_analysis(self, inc: Dict, evidence: Dict) -> str:
        key_artifacts = evidence.get("key_artifacts") or {}
        process       = inc.get("process") or "unknown process"
        child_procs   = key_artifacts.get("new_processes") or []
        new_ips       = key_artifacts.get("new_ips") or []
        modified      = key_artifacts.get("modified_files") or []

        deployment  = inc.get("ai_deployment_type") or {}
        deploy_type = deployment.get("type", "unknown")
        ai_context  = inc.get("ai_agent_context") or {}
        matched     = ai_context.get("matched_artifacts") or []

        # ── Opening sentence — specific to deployment type ────────────────
        ai_evidence = [
            m["value"] for m in matched
            if m["matched_list"] in (
                "AI_MODULE_FILENAME_PATTERNS", "AI_MODULE_PATH_PATTERNS",
                "MODEL_PATH_PATTERNS", "KNOWN_AI_SERVING_PROCESS_NAMES",
                "LLM_API_DOMAINS",
            )
        ]

        if deploy_type == "shadow_ai":
            if ai_evidence:
                parts = [
                    f"Process '{process}' was identified as a potential shadow AI deployment "
                    f"based on AI model artifacts: {', '.join(ai_evidence[:4])}."
                ]
            else:
                parts = [f"Process '{process}' was identified as a potential shadow AI deployment."]
        elif deploy_type == "dev_tool":
            parts = [
                f"Process '{process}' is a developer AI agent or tool "
                f"not in the approved enterprise baseline."
            ]
        elif deploy_type == "enterprise_ai":
            parts = [
                f"Process '{process}' is a known enterprise AI-enabled application "
                f"that deviated from its expected behavioral baseline."
            ]
        else:
            if ai_evidence:
                parts = [
                    f"Process '{process}' was flagged for AI-related activity "
                    f"based on: {', '.join(ai_evidence[:3])}."
                ]
            else:
                parts = [f"Process '{process}' was flagged for AI-related behavioral anomalies."]

        # ── Behavioural detail ────────────────────────────────────────────
        if child_procs:
            names = [p.get("process") for p in child_procs if isinstance(p, dict) and p.get("process")]
            if names:
                parts.append(
                    f"It spawned child processes not previously associated with this workflow: "
                    f"{', '.join(names[:5])}."
                )
        if new_ips:
            parts.append("It contacted new network destinations outside the normal baseline.")
        if modified:
            parts.append("It also modified files, which increases the likelihood of meaningful host impact.")

        return " ".join(parts)

    def _build_recommended_actions(self, inc: Dict, evidence: Dict) -> List[str]:
        anomalies = inc.get("anomalies") or []
        user = str(inc.get("user") or "").strip()
        process = str(inc.get("process") or "this process").strip()

        anomaly_types = {
            str(a.get("anomaly_type") or a.get("type") or "").strip()
            for a in anomalies
            if a.get("anomaly_type") or a.get("type")
        }

        actions: List[str] = []
        if (
            "EVENT_NEW_AI_AGENT_NOT_IN_BASELINE" in anomaly_types
            or "LOG_AI_AGENT_IN_LEARNING_PHASE" in anomaly_types
        ):
            if user:
                actions.append(
                    f"Verify with user {user} that using '{process}' was intentional and approved by company policy"
                )
                actions.append(f"Suggest security compliance training to user {user}")
            else:
                actions.append(
                    f"Verify that using '{process}' was intentional and approved by company policy"
                )
        return actions

    # -------------------------------------------------------------------------
    # Unified report builder — BOTH paths produce identical schema
    # -------------------------------------------------------------------------

    def _build_final_report(
        self,
        inc: Dict,
        incident_id: str,
        anomalies: List[Dict],
        new_iocs: Dict,
        vt: Dict,
        abuse: Dict,
        threat_summary: Dict,
        deterministic_impact: Dict,
        deterministic_rca: str,
        deterministic_actions: Optional[List[str]] = None,
        llm: Optional[Dict] = None,
        llm_fixed: Optional[Dict] = None,
        default_verdict: str = "UNKNOWN",
        default_severity: str = "UNKNOWN",
        default_status: str = "OPEN",
        default_headline: str = "",
        default_story: str = "",
        default_verdict_reasoning: str = "",
    ) -> Dict:
        llm = llm or {}
        llm_fixed = llm_fixed or {}
        deterministic_actions = deterministic_actions or []

        # ── AI agent classification (always deterministic) ───────────────
        ai_agent_classification = inc.get("ai_agent_context") or {}
        llm_ai_note = llm_fixed.get("ai_agent_classification_note") or ""
        if llm_ai_note:
            ai_agent_classification = {**ai_agent_classification, "llm_note": llm_ai_note}

        # ── AI deployment type (deterministic) ───────────────────────────
        deployment = inc.get("ai_deployment_type") or {"type": "unknown", "is_shadow_ai": False, "reason": ""}

        # ── Impact (LLM or deterministic fallback) ───────────────────────
        final_impact = llm_fixed.get("impact") or deterministic_impact

        # ── Status: LLM suggestion post-processed with deterministic rules ─
        raw_status = llm_fixed.get("recommended_status") or default_status
        raw_verdict = llm_fixed.get("verdict") or default_verdict
        raw_severity = llm_fixed.get("severity") or default_severity
        final_status, status_override_reason = self._determine_final_status(
            llm_status=raw_status,
            verdict=raw_verdict,
            severity=raw_severity,
            impact=final_impact,
            deployment=deployment,
        )

        return make_json_serializable({
            "incident_id":       incident_id,
            "created_at":        datetime.now().isoformat(),
            "verdict":           raw_verdict,
            "severity":          raw_severity,
            "recommended_status": final_status,
            "status_override_reason": status_override_reason,   # non-empty only when deterministic rule fired
            "confidence":        llm_fixed.get("confidence"),
            "headline":          llm_fixed.get("headline") or default_headline,
            "story":             llm_fixed.get("story") or default_story,
            "root_cause_analysis": llm_fixed.get("root_cause_analysis") or deterministic_rca,
            "domain_name": inc.get("domain_name", "ACME"),
            # ── WHY this process is an AI agent ─────────────────────────
            "ai_agent_classification": ai_agent_classification,
            # ── shadow AI vs enterprise AI vs dev tool ───────────────────
            "ai_deployment_type": deployment,
            # ── impact ──────────────────────────────────────────────────
            "impact":            final_impact,
            # ── findings / MITRE / analytics ────────────────────────────────
            "key_findings":      llm_fixed.get("key_findings") or [],
            "mitre_attack":      llm_fixed.get("mitre_attack") or [],
            "behavioral_analytics_note": llm_fixed.get("behavioral_analytics_note") or "",
            "threat_intel_summary":      llm_fixed.get("threat_intel") or "",
            "verdict_reasoning": llm_fixed.get("verdict_reasoning") or default_verdict_reasoning,
            "excluded_fp_alerts": llm_fixed.get("excluded_fp_alerts") or "None.",
            # ── actions ─────────────────────────────────────────────────────
            "recommended_actions": llm_fixed.get("recommended_actions") or deterministic_actions,
            "false_positive_reason": llm_fixed.get("false_positive_reason"),
            "compromised_assets": llm_fixed.get("compromised_assets") or [
                x for x in [
                    str(inc.get("machine") or "")[:20],
                    str(inc.get("user") or "")[:20],
                ] if x
            ],
            # ── grouped alerts summary — one entry per alert merged into this incident ──
            "grouped_alerts_count": len(anomalies),
            "grouped_alerts": [
                {
                    "alert_id":   a.get("alert_id") or a.get("anomaly_type"),
                    "alert_type": a.get("anomaly_type") or a.get("type"),
                    "severity":   a.get("severity"),
                    "confidence": a.get("confidence"),
                    "timestamp":  (a.get("row_fields") or {}).get("timestamp"),
                    "reason":     a.get("reason"),
                    "ai_risk":    a.get("ai_risk") or [],
                }
                for a in anomalies
            ],
            # ── grouping ────────────────────────────────────────────────────
            "is_grouped_incident": bool(inc.get("is_group")),
            "link_reasons":        inc.get("link_reasons", []),
            # ── assets: ONLY the host-level entities ────────────────────────
            # process is NOT an asset — it has its own block below.
            "assets": {
                "machine":    inc.get("machine"),
                "user":       inc.get("user"),
                "os":         inc.get("OS") or "",
                "os_version": inc.get("OSVersion") or "",
                "host_type":  inc.get("HostType") or "",
            },
            # ── process context: everything about the AI agent process ───────
            "process_context": {
                "name":        inc.get("process"),
                "pid":         inc.get("pid"),
                "hash":        inc.get("process_hash"),
                "signer":      inc.get("signer"),
                "dir":         inc.get("process_dir") or "",
                "parent":      inc.get("parent_process") or {},
            },
            "network_volume": {
                "bytes_sent":     int(inc.get("bytes_sent") or 0),
                "bytes_received": int(inc.get("bytes_received") or 0),
            },
            # ── TI / IOCs ───────────────────────────────────────────────────
            "new_iocs_for_ti": new_iocs,
            "threat_intel": {
                "summary":    threat_summary,
                "virustotal": vt,
                "abuseipdb":  abuse,
            },
            # ── meta ────────────────────────────────────────────────────────
            "validator_notes": llm_fixed.get("_validator_notes", []),
            "llm_provider":    llm.get("provider"),
            "llm_status":      llm.get("status"),
            "anomalies":       anomalies,
            "status":          llm_fixed.get("recommended_status") or default_status,
        })

    # -------------------------------------------------------------------------
    # CSV ingestion + grouping
    # -------------------------------------------------------------------------

    def analyze_alerts_from_csv(
        self,
        csv_path: str,
        output_dir: Optional[str] = None,
        max_incidents: Optional[int] = None
    ) -> List[Dict]:
        df = pd.read_csv(csv_path)
        incidents = self._group_rows_into_incidents(df)
        if max_incidents:
            incidents = incidents[:max_incidents]
        reports: List[Dict] = []
        for idx, inc in enumerate(incidents, 1):
            print(f"\n[{idx}/{len(incidents)}] Incident {inc['incident_id']}  ({inc['machine']} / {inc['process']} / pid={inc['pid']})")
            report = self.analyze_incident(inc)
            reports.append(report)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                out = os.path.join(output_dir, f"incident_{inc['incident_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(make_json_serializable(report), f, indent=2)
                print(f"  💾 Saved {out}")
        return reports

    def _group_rows_into_incidents(self, df: pd.DataFrame) -> List[Dict]:
        def _pick_col(df, *candidates):
            """Return the first column name that exists in df, or None."""
            for c in candidates:
                if c in df.columns:
                    return c
            return None

        col_machine  = _pick_col(df, "machine", "MachineName", "Machine", "hostname", "Hostname")
        col_process  = _pick_col(df, "process", "ProcessName", "Process", "process_name")
        col_pid      = _pick_col(df, "pid", "Pid", "PID", "ProcessId", "process_id")
        col_creation = _pick_col(df, "timestamp", "CreationTime", "Timestamp", "EventTime", "event_time")
        col_alert_id = _pick_col(df, "alert_id", "AlertId", "alert_Id", "AltertId")
        col_user     = _pick_col(df, "user", "UserName", "User", "username", "AccountName")
        col_hash     = _pick_col(df, "ProcessHash", "process_hash", "MD5", "SHA256", "FileHash")
        col_os       = _pick_col(df, "OS", "os", "OperatingSystem", "OSName", "os_name")
        col_osver    = _pick_col(df, "OSVersion", "os_version", "OSVer", "OsVersion", "os_ver")
        col_hosttype = _pick_col(df, "HostType", "host_type", "DeviceType", "device_type", "MachineType")

        if "PidCreationTime" in df.columns:
            df["_proc_inst"] = df["PidCreationTime"].astype(str)
            def _pid_from_pct(x):
                try: return int(str(x).split("_", 1)[0])
                except: return 0
            def _ct_from_pct(x):
                try: return int(str(x).split("_", 1)[1])
                except: return 0
            df["_pid_norm"] = df["_proc_inst"].map(_pid_from_pct)
            df["_ct_norm"]  = df["_proc_inst"].map(_ct_from_pct)
        else:
            df["_pid_norm"] = df[col_pid].fillna(0).astype(int)
            df["_ct_norm"]  = df[col_creation].fillna(0).astype(int)
            df["_proc_inst"] = df["_pid_norm"].astype(str) + "_" + df["_ct_norm"].astype(str)

        group_cols = [col_process, "_pid_norm"]
        if "BytesSent"     in df.columns: df["BytesSent"]     = pd.to_numeric(df["BytesSent"],     errors="coerce")
        if "BytesReceived" in df.columns: df["BytesReceived"] = pd.to_numeric(df["BytesReceived"], errors="coerce")

        incidents: List[Dict] = []
        for _, g in df.groupby(group_cols):
            if col_creation in g.columns:
                g = g.sort_values(by=[col_creation], ascending=True)
            first = g.iloc[0]

            bytes_sent     = int((g["BytesSent"].max()     if "BytesSent"     in g.columns else 0) or 0)
            bytes_received = int((g["BytesReceived"].max() if "BytesReceived" in g.columns else 0) or 0)

            all_alert_ids = []
            if col_alert_id:
                all_alert_ids = [str(x) for x in g[col_alert_id].dropna().tolist()]
            incident_id = all_alert_ids[0] if all_alert_ids else f"INCIDENT_{first[col_machine]}_{first[col_process]}_{int(first['_pid_norm'])}"
            creation_time = int(first[col_creation]) if col_creation in g.columns and pd.notna(first[col_creation]) else 0

            g = g.copy()
            if col_creation in g.columns:
                g = g.sort_values(by=[col_creation], ascending=True)

            parent = {
                "name":              first.get("ParentProcessName"),
                "dir":               first.get("ParentProcessDir"),
                "args":              first.get("ParentProcessArgs"),
                "signer":            first.get("ParentProcessSigner"),
                "classification":    first.get("ParentProcessClassification"),
                "integrity_level":   first.get("ParentProcessIntegrityLevel"),
                "md5":               first.get("ParentProcessMD5"),
                "ppid_creation_time": first.get("ProcessPPidCreationTime"),
            }

            anomalies        = self._rows_to_anomalies(g)
            suspicious_files = _extract_suspicious_files_from_anomaly_json(g)

            incidents.append({
                "incident_id":      incident_id,
                "alert_ids":        all_alert_ids,
                "is_group":         len(g) > 1,
                "machine":          str(first[col_machine]),
                "user":             str(first[col_user]) if col_user in g.columns else None,
                "process":          str(first[col_process]),
                "pid":              int(first["_pid_norm"]),
                "creation_time":    int(first["_ct_norm"]),
                "process_hash":     str(first[col_hash]) if col_hash and pd.notna(first[col_hash]) else None,
                "process_dir":      str(first.get("ProcessDir") or first.get("process_dir") or ""),
                "domain_name": str(first.get("domain_name") or "ACME"),
                "bytes_sent":       bytes_sent,
                "bytes_received":   bytes_received,
                "parent_process":   parent,
                "anomalies":        anomalies,
                "raw_rows_count":   int(len(g)),
                "creation_time":    creation_time,
                "suspicious_files": suspicious_files,
                "OS":               str(first[col_os]) if col_os and pd.notna(first[col_os]) else "",
                "OSVersion":        str(first[col_osver]) if col_osver and pd.notna(first[col_osver]) else "",
                "HostType":         str(first[col_hosttype]) if col_hosttype and pd.notna(first[col_hosttype]) else "",
                # Why was this process identified as an AI agent?
                "ai_agent_context": self._extract_ai_agent_context(
                    {
                        "process":           str(first[col_process]) if col_process else "",
                        "process_dir":       str(first.get("ProcessDir") or first.get("process_dir") or ""),
                        "contacted_domains": [],
                        "contacted_ports":   [],
                        "accessed_files":    suspicious_files.get("accessed_files", []),
                        "accessed_dirs":     suspicious_files.get("modified_files", []),  # best available on CSV path
                    },
                    anomalies,
                ),
            })
            # Derive ai_deployment_type now that ai_agent_context is built
        incidents[-1]["ai_deployment_type"] = self._classify_ai_deployment_type(
                matched_artifacts=incidents[-1]["ai_agent_context"].get("matched_artifacts", []),
                ai_risks=incidents[-1]["ai_agent_context"].get("ai_risk_categories", []),
                process_name=incidents[-1]["process"],
                process_dir=incidents[-1].get("process_dir", ""),
            )
            

        incidents.sort(key=lambda x: x.get("creation_time", 0), reverse=True)
        return incidents

    def _rows_to_anomalies(self, g: pd.DataFrame) -> List[Dict]:
        anomalies: List[Dict] = []
        has_br = "baseline_relevant_json" in g.columns
        for _, row in g.iterrows():
            anomaly_type = row.get("anomaly_type") or row.get("AnomalyType")
            if not isinstance(anomaly_type, str) or not anomaly_type.strip():
                continue
            br = _safe_json_loads(row.get("baseline_relevant_json")) if has_br else None
            anomalies.append({
                "anomaly_type": anomaly_type,
                "type":         anomaly_type,
                "confidence":   float(row.get("confidence_score") or row.get("confidence") or row.get("Confidence") or 0.0),
                "baseline_relevant_json": br or {},
                "reason": (br or {}).get("detection_reason") or (br or {}).get("reason") or None,
                # Populate ai_risk from ALERT_CLASSIFICATION so CSV path matches JSON path
                "ai_risk": ALERT_CLASSIFICATION.get(anomaly_type, {}).get("ai_risk", []),
                "row_fields": {"timestamp": int(row.get("timestamp") or row.get("CreationTime") or 0)},
            })
        return anomalies

    # -------------------------------------------------------------------------
    # IOC extraction
    # -------------------------------------------------------------------------

    def _extract_new_iocs_from_baseline_relevant(self, anomalies: List[Dict], process_hash: Optional[str]) -> Dict[str, List[str]]:
        new_domains: List[str] = []
        new_ips:     List[str] = []
        new_hashes:  List[str] = []

        if process_hash:
            new_hashes.append(process_hash)

        for a in anomalies or []:
            br = a.get("baseline_relevant_json") or {}
            if not isinstance(br, dict):
                continue
            for k, v in br.items():
                if not isinstance(k, str) or not k.startswith("new_"):
                    continue
                if isinstance(v, list):
                    for item in v:
                        if item is None: continue
                        s = str(item).strip()
                        if not s: continue
                        if "domain" in k:
                            (new_ips if _looks_like_ip(s) else new_domains).append(s)
                        elif "ip" in k:
                            for part in s.split(";"):
                                part = part.strip()
                                if part: new_ips.append(part)
                elif isinstance(v, str):
                    s = v.strip()
                    if s:
                        if "domain" in k: new_domains.append(s)
                        elif "ip" in k:
                            for part in s.split(";"):
                                part = part.strip()
                                if part: new_ips.append(part)

        new_ips = [ip for ip in new_ips if _looks_like_ip(ip) and not _is_private_ip(ip)]
        return {
            "domains":     _dedupe_keep_order(new_domains),
            "ips":         _dedupe_keep_order(new_ips),
            "file_hashes": _dedupe_keep_order(new_hashes),
        }

    # -------------------------------------------------------------------------
    # Enrichment cache helpers
    # -------------------------------------------------------------------------

    def _get_cached(self, ns: str, key: str) -> Optional[Any]:
        ck = (ns, key)
        if ck not in self._cache: return None
        ts, val = self._cache[ck]
        if time.time() - ts > self.cache_ttl_long:
            del self._cache[ck]; return None
        return val

    def _set_cached(self, ns: str, key: str, val: Any):
        self._cache[(ns, key)] = (time.time(), val)

    def _check_virustotal(self, iocs: Dict[str, List[str]]) -> Dict:
        results = {"domains": {}, "ips": {}, "files": {}, "errors": []}
        if not self.vt_client: return results
        domains = list(iocs.get("domains") or [])[:10]
        ips     = list(iocs.get("ips")     or [])[:10]
        hashes  = list(iocs.get("file_hashes") or [])[:5]
        print(f"     [VT] calling: domains={len(domains)}, ips={len(ips)}, hashes={len(hashes)}")
        for d in domains:
            cached = self._get_cached("vt_domain", d)
            if cached is not None: results["domains"][d] = cached; continue
            try:
                vt = self.vt_client.get_domain_report(d)
                results["domains"][d] = vt; self._set_cached("vt_domain", d, vt); time.sleep(0.25)
            except Exception as e: results["errors"].append({"ioc": d, "error": str(e)})
        for ip in ips:
            cached = self._get_cached("vt_ip", ip)
            if cached is not None: results["ips"][ip] = cached; continue
            try:
                vt = self.vt_client.get_ip_report(ip)
                results["ips"][ip] = vt; self._set_cached("vt_ip", ip, vt); time.sleep(0.25)
            except Exception as e: results["errors"].append({"ioc": ip, "error": str(e)})
        for h in hashes:
            cached = self._get_cached("vt_file", h)
            if cached is not None: results["files"][h] = cached; continue
            try:
                vt = self.vt_client.get_file_report(h)
                results["files"][h] = vt; self._set_cached("vt_file", h, vt); time.sleep(0.25)
            except Exception as e: results["errors"].append({"ioc": h, "error": str(e)})
        return results

    def _check_abuseipdb(self, iocs: Dict[str, List[str]]) -> Dict:
        results = {"ips": {}, "errors": []}
        if not self.abuse_client: return results
        ips = list(iocs.get("ips") or [])[:10]
        print(f"     [AbuseIPDB] calling: ips={len(ips)}")
        for ip in ips:
            cached = self._get_cached("abuse_ip", ip)
            if cached is not None: results["ips"][ip] = cached; continue
            try:
                abuse = self.abuse_client.check_ip(ip)
                results["ips"][ip] = abuse; self._set_cached("abuse_ip", ip, abuse); time.sleep(0.1)
            except Exception as e: results["errors"].append({"ioc": ip, "error": str(e)})
        return results

    # -------------------------------------------------------------------------
    # Incident analysis entry point
    # -------------------------------------------------------------------------

    def _build_deterministic_conclusion(self, inc, vt, abuse, threat_summary):
        anomaly_types = {a.get("anomaly_type") for a in inc.get("anomalies", []) if a.get("anomaly_type")}
        vt_ips, abuse_ips = vt.get("ips", {}), abuse.get("ips", {})
        malicious_vt = [ip for ip, r in vt_ips.items()   if isinstance(r, dict) and r.get("positives", 0) > 0]
        high_abuse   = [ip for ip, r in abuse_ips.items() if isinstance(r, dict) and r.get("abuseConfidenceScore", 0) >= 50]
        rep = ("Some contacted IPs show elevated reputation risk and require review."
               if malicious_vt or high_abuse
               else "All contacted IPs have no known malicious reputation.")
        bs = int(inc.get("bytes_sent") or 0)
        data = f"Outbound data transfer of {bs} bytes was observed." if bs else "No outbound data transfer was observed."
        return (
            f"This incident was triggered by behavioral anomalies ({', '.join(sorted(anomaly_types))}). "
            f"The process {inc.get('process')} on host {inc.get('machine')} established connections "
            f"to network destinations not previously seen in the baseline. {rep} {data} "
            f"There is no current evidence indicating malicious activity."
        )

    def analyze_incident(self, inc: Dict) -> Dict:
        incident_id = inc["incident_id"]
        anomalies   = inc.get("anomalies") or []

        #has_alert = any(
        #    str(a.get("anomaly_type") or a.get("type") or "").startswith("ALERT_")
        #    for a in anomalies
        #)
        
        has_alert = any(
            (
                (t := str(a.get("anomaly_type") or a.get("type") or "")).startswith("ALERT_")
                or t in {
                    "EVENT_NEW_AI_AGENT_NOT_IN_BASELINE",
                    "LOG_AI_AGENT_IN_LEARNING_PHASE",
                }
            )
            for a in anomalies
        )

        child_hash = inc.get("child_hash")
        new_iocs   = self._extract_new_iocs_from_baseline_relevant(anomalies, inc.get("process_hash"))
        if child_hash and child_hash not in new_iocs["file_hashes"]:
            new_iocs["file_hashes"].append(child_hash)

        # ------------------------------------------------------------------
        # Fast path: no ALERT_ anomalies — no LLM/VT/Abuse
        # ------------------------------------------------------------------
        if not has_alert:
            print(f"  ⏭️  No ALERT_ anomalies — skipping LLM/VT/Abuse enrichment.")
            machine_label = str(inc.get("machine") or "")[:20]
            user_label    = str(inc.get("user") or "")[:20]
            process_label = inc.get("process") or "unknown process"
            event_types   = list({
                str(a.get("anomaly_type") or a.get("type") or "")
                for a in anomalies if a.get("anomaly_type") or a.get("type")
            })
            summary = (
                f"{', '.join(event_types) or 'Informational event'} for AI process "
                f"'{process_label}' on {machine_label} / user {user_label}. "
                f"No ALERT_ anomalies — informational/learning phase only. No action required."
            )
            vt    = {"domains": {}, "ips": {}, "files": {}, "errors": []}
            abuse = {"ips": {}, "errors": []}
            threat_summary    = self._summarize_ti(vt, abuse)
            evidence          = self._build_evidence(inc, new_iocs, vt, abuse, threat_summary)
            deterministic_impact   = self._build_impact(inc, evidence)
            deterministic_rca      = self._build_root_cause_analysis(inc, evidence)
            deterministic_actions  = self._build_recommended_actions(inc, evidence)

            return self._build_final_report(
                inc=inc,
                incident_id=incident_id,
                anomalies=anomalies,
                new_iocs=new_iocs,
                vt=vt,
                abuse=abuse,
                threat_summary=threat_summary,
                deterministic_impact=deterministic_impact,
                deterministic_rca=deterministic_rca,
                deterministic_actions=deterministic_actions,
                llm={"provider": None, "status": "not_called"},
                llm_fixed={},
                default_verdict="BENIGN",
                default_severity="INFO",
                default_status="CLOSED",
                default_headline=summary,
                default_story=summary,
                default_verdict_reasoning="No ALERT_ anomalies were present; incident closed as informational.",
            )

        print(f"  🔎 New IOCs for TI: {len(new_iocs.get('domains', []))} domains, "
              f"{len(new_iocs.get('ips', []))} IPs, {len(new_iocs.get('file_hashes', []))} hashes")

        print("  2️⃣ Enriching with threat intelligence.")
        vt    = self._check_virustotal(new_iocs)
        abuse = self._check_abuseipdb(new_iocs)
        threat_summary   = self._summarize_ti(vt, abuse)
        evidence         = self._build_evidence(inc, new_iocs, vt, abuse, threat_summary)
        deterministic_impact  = self._build_impact(inc, evidence)
        deterministic_rca     = self._build_root_cause_analysis(inc, evidence)
        deterministic_actions = self._build_recommended_actions(inc, evidence)
        llm       = self._generate_llm_analysis(evidence)
        llm_fixed = self._validate_and_fix_llm_output(llm, evidence)
        det_conclusion = self._build_deterministic_conclusion(inc, vt, abuse, threat_summary)

        return self._build_final_report(
            inc=inc,
            incident_id=incident_id,
            anomalies=anomalies,
            new_iocs=new_iocs,
            vt=vt,
            abuse=abuse,
            threat_summary=threat_summary,
            deterministic_impact=deterministic_impact,
            deterministic_rca=deterministic_rca,
            deterministic_actions=deterministic_actions,
            llm=llm,
            llm_fixed=llm_fixed,
            default_verdict="UNKNOWN",
            default_severity="UNKNOWN",
            default_status="OPEN",
            default_headline=llm_fixed.get("headline") or self._fallback_summary(inc, threat_summary),
            default_story=det_conclusion,
            default_verdict_reasoning=det_conclusion,
        )

    def _summarize_ti(self, vt: Dict, abuse: Dict) -> Dict:
        vt_domains = vt.get("domains") or {}
        vt_ips     = vt.get("ips")     or {}
        vt_files   = vt.get("files")   or {}
        return {
            "virustotal": {"checked": len(vt_domains) + len(vt_ips) + len(vt_files), "errors": len(vt.get("errors") or [])},
            "abuseipdb":  {"checked": len(abuse.get("ips") or {}), "errors": len(abuse.get("errors") or [])},
        }

    @staticmethod
    def _classify_artifact(path: str) -> str:
        import re as _re
        if not path or not isinstance(path, str): return ""
        p = path.lower()
        if any(t in p for t in ("/tmp/", "\\temp\\", "\\tmp\\", "/var/folders/", "appdata\\local\\temp")):
            return "[TEMP PATH]"
        if _re.search(r'\.(tmp|temp|cache|lock|swp|bak|~)$', p): return "[TEMP FILE]"
        basename = _re.split(r'[/\\]', path)[-1]
        if _re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', basename, _re.I): return "[GUID/RANDOM NAME]"
        if _re.match(r'^[0-9a-f]{16,}$', basename, _re.I): return "[RANDOM HEX NAME]"
        if len(basename) >= 12 and _re.match(r'^[A-Za-z0-9_\-\.]+$', basename):
            vowels = sum(1 for c in basename.lower() if c in 'aeiou')
            if len(basename) > 0 and vowels / len(basename) < 0.10: return "[LIKELY RANDOM NAME]"
        if _re.match(r'^\.com\.[a-z]+\.[a-z]+\.[A-Za-z0-9]{4,}$', basename): return "[TEMP/SOCKET FILE]"
        return ""

    def _annotate_artifacts(self, items: List[str]) -> List[str]:
        out = []
        for item in items:
            note = self._classify_artifact(str(item))
            out.append(f"{item} {note}".strip() if note else item)
        return out

    def _extract_key_artifacts(self, anomalies: List[Dict]) -> Dict:
        result: Dict[str, List] = {
            "new_ips": [], "new_domains": [], "new_ports": [], "new_dirs": [],
            "new_files": [], "new_extensions": [], "new_users": [], "new_signers": [],
            "new_processes": [], "modified_files": [], "elevated_integrity": [],
            "unusual_parents": [], "excessive_transfer": [],
        }
        for a in anomalies:
            alert_type = a.get("anomaly_type") or a.get("type") or ""
            ai = a.get("anomalous_item") or {}
            br = a.get("baseline_relevant_json") or {}
            if "NEW_IPS" in alert_type:
                result["new_ips"] += [x for x in (ai.get("new_ips") or br.get("new_ips") or []) if x]
                for entry in (ai.get("new_ips_analysis") or br.get("new_ips_analysis") or []):
                    if isinstance(entry, dict) and entry.get("ip"):
                        result["new_ips"].append(f"{entry['ip']} ({entry.get('details', '')})")
            elif "NEW_DOMAINS" in alert_type:
                result["new_domains"] += [x for x in (ai.get("new_domains") or br.get("new_domains") or []) if x]
            elif "NEW_PORTS" in alert_type:
                result["new_ports"] += [str(x) for x in (ai.get("new_ports") or br.get("new_ports") or []) if x]
            elif "NEW_DIRECTORIES" in alert_type:
                result["new_dirs"] += self._annotate_artifacts([x for x in (ai.get("new_directories") or br.get("new_dirs") or []) if x])
            elif "ACCESSING_MANY_NEW_FILES" in alert_type:
                result["new_files"] += self._annotate_artifacts([x for x in (ai.get("new_files") or br.get("new_files_sample") or []) if x])
            elif "NEW_FILE_EXTENSIONS" in alert_type:
                result["new_extensions"] += [x for x in (ai.get("new_extensions") or br.get("new_extensions") or []) if x]
                result["new_extensions"] += [x for x in (ai.get("high_risk_extensions") or br.get("high_risk_extensions") or []) if x]
            elif "NEW_USER" in alert_type:
                u = ai.get("new_user") or br.get("observed_user")
                if u: result["new_users"].append(u)
            elif "SIGNER_CHANGED" in alert_type:
                s = ai.get("new_signer") or br.get("observed_signer")
                if s: result["new_signers"].append(s)
            elif "SPAWNED_PROCESS" in alert_type or "NEW_SPAWNED" in alert_type:
                entry = {k: v for k, v in {
                    "process": a.get("child_process") or ai.get("process"),
                    "args":    a.get("child_args")    or ai.get("args"),
                    "hash":    a.get("child_hash")    or ai.get("hash"),
                    "signer":  a.get("child_signer")  or ai.get("signer"),
                    "dir":     a.get("child_dir")     or ai.get("dir"),
                    "similarity_to_baseline": ai.get("similarity_to_baseline"),
                }.items() if v}
                if entry: result["new_processes"].append(entry)
            elif "MODEL_FILE" in alert_type:
                f = ai.get("file") or br.get("observed_file")
                if f: result["modified_files"].append({"file": f, "user": ai.get("modifying_user") or br.get("observed_user"), "args": ai.get("modifying_args")})
            elif "ELEVATED_PRIVILEGES" in alert_type:
                result["elevated_integrity"].append({"level": ai.get("integrity_level") or br.get("observed_integrity_level"), "delta_rank": ai.get("delta_rank") or br.get("delta_rank")})
            elif "UNUSUAL_PARENT" in alert_type:
                p = ai.get("unusual_parent") or br.get("observed_parent") or {}
                if p: result["unusual_parents"].append(p)
            elif "EXCESSIVE_TRANSFER" in alert_type:
                result["excessive_transfer"].append({"bytes_sent": ai.get("bytes_sent"), "bytes_received": ai.get("bytes_received"), "z_score": ai.get("z_score") or br.get("z_score"), "baseline_mean": br.get("baseline_bytes_sent_mean"), "baseline_p99": br.get("baseline_bytes_sent_p99")})
            elif "PROCESS_RUNNING_FROM_NEW_LOCATION" in alert_type:
                loc = ai.get("new_process_dir") or br.get("observed_process_dir")
                if loc:
                    note = self._classify_artifact(str(loc))
                    result["new_dirs"].append(f"[PROCESS DIR] {loc}" + (f" {note}" if note else ""))
        for k in result:
            if result[k] and isinstance(result[k][0], str):
                result[k] = _dedupe_keep_order(result[k])
        return {k: v for k, v in result.items() if v}

    def _build_evidence(self, inc: Dict, new_iocs: Dict, vt: Dict, abuse: Dict, ti_summary: Dict) -> Dict:
        machine       = str(inc.get("machine") or "")
        user          = str(inc.get("user") or "")
        machine_short = machine[:20]
        user_short    = user[:20]

        alert_breakdown: List[Dict] = []
        for a in inc.get("anomalies") or []:
            alert_type = a.get("anomaly_type") or a.get("type") or ""
            entry: Dict = {
                "alert_type":     alert_type,
                "severity":       a.get("severity"),
                "confidence":     a.get("confidence"),
                "details":        a.get("details"),
                "anomalous_item": a.get("anomalous_item") or {},
            }
            if "SPAWNED" in alert_type:
                entry["child_process"]  = a.get("child_process")
                entry["child_args"]     = a.get("child_args")
                entry["child_hash"]     = a.get("child_hash")
                entry["child_signer"]   = a.get("child_signer")
                entry["child_dir"]      = a.get("child_dir")
                entry["child_activity"] = a.get("child_activity")
            br = a.get("baseline_relevant_json") or {}
            if br: entry["baseline_vs_observed"] = br
            alert_breakdown.append(entry)

        reasons: List[Dict] = []
        for a in inc.get("anomalies") or []:
            br = a.get("baseline_relevant_json") or {}
            for k, v in br.items():
                if isinstance(k, str) and k.endswith("_analysis") and isinstance(v, list):
                    reasons.extend(v)

        return {
            "incident": {
                "incident_id":  inc.get("incident_id"),
                "alert_ids":    inc.get("alert_ids", []),
                "is_group":     bool(inc.get("is_group")),
                "link_reasons": inc.get("link_reasons", []),
                "alert_count":  inc.get("raw_rows_count"),
                "machine":      machine_short,
                "user":         user_short,
                "process":      inc.get("process"),
                "signer":       inc.get("signer"),
                "pid":          inc.get("pid"),
                "first_seen":   inc.get("first_seen"),
                "last_seen":    inc.get("last_seen"),
                "process_hash": inc.get("process_hash"),
                "child_hash":   inc.get("child_hash"),
                "os":           inc.get("OS"),
                "os_version":   inc.get("OSVersion"),
                "host_type":    inc.get("HostType"),
            },
            "assets_strict": {
                "compromised_assets": [x for x in [machine_short, user_short] if x],
            },
            "network_volume": {
                "bytes_sent":     int(inc.get("bytes_sent") or 0),
                "bytes_received": int(inc.get("bytes_received") or 0),
            },
            "processes": {
                "process":        {"name": inc.get("process"), "pid": inc.get("pid"), "hash": inc.get("process_hash")},
                "parent_process": inc.get("parent_process") or {},
            },
            "network_observations": {
                "contacted_ips":     inc.get("contacted_ips", []),
                "contacted_domains": inc.get("contacted_domains", []),
                "contacted_ports":   inc.get("contacted_ports", []),
            },
            "file_system_artifacts": inc.get("suspicious_files", {"modified_files": [], "accessed_files": []}),
            "alert_breakdown":            alert_breakdown,
            "key_artifacts":              self._extract_key_artifacts(inc.get("anomalies") or []),
            "baseline_relevant_reasons":  reasons[:50],
            "new_iocs_for_ti":            new_iocs,
            "threat_intel_summary":       ti_summary,
            "virustotal_raw":             vt,
            "abuseipdb_raw":              abuse,
            # Why this process was identified as an AI agent
            "ai_agent_context":           inc.get("ai_agent_context") or {},
            # Shadow AI / enterprise AI / dev tool classification
            # LLM uses this to calibrate severity and recommended actions
            "ai_deployment_type":         inc.get("ai_deployment_type") or {},
        }

    # -------------------------------------------------------------------------
    # LLM prompt
    # -------------------------------------------------------------------------

    def _build_llm_prompt(self, evidence: Dict) -> str:
        evidence_json = json.dumps(make_json_serializable(evidence), indent=2)

        prompt = f"""You are a senior SOC analyst writing an incident report for a human analyst who needs to decide whether to act or close a ticket.

CONTEXT: This is a behavioral detection system monitoring AI agent processes (like Claude, Copilot, etc.) for signs of abuse or compromise. Alerts fire when the process deviates from its learned baseline — not because of signatures or known malware. The process itself is legitimate; the question is whether it is doing something unexpected that warrants investigation.

Your job: read all the evidence and write a clear, specific, opinionated report.

EVIDENCE GUIDE:
- evidence.ai_agent_context: explains WHY this process was identified as an AI agent.
  ai_risk_categories lists the risk tags (e.g. "Shadow AI", "Unauthorized AI Deployment").
  matched_artifacts is a list of {{value, matched_list, match_type}} entries — the EXACT artifacts
  that triggered AI classification. Each entry names the specific value (e.g. "torch_cpu.dll",
  "c:\\users\\...\\huggingface\\hub\\...", "python.exe") and which definition list it matched
  (e.g. AI_MODULE_FILENAME_PATTERNS, AI_MODULE_PATH_PATTERNS, KNOWN_AI_SERVING_PROCESS_NAMES).
  You MUST cite specific matched_artifacts values in root_cause_analysis, story, and
  ai_agent_classification_note. Never say "the process was flagged" without naming what matched.
- evidence.ai_deployment_type: classifies the process as one of:
    "shadow_ai"     — standalone AI server (ollama, lmstudio, vllm, openclaw, etc.)
                      OR generic interpreter (python.exe) with AI model file/path evidence.
                      NOT approved enterprise software. Always treat as higher risk.
                      Do NOT recommend CLOSED. Minimum: verify authorization with user.
    "enterprise_ai" — known enterprise app using AI (Teams, Chrome, VS Code, Office).
                      AI usage is expected; alert is about behavioral deviation, not deployment.
                      Lower baseline risk for the deployment itself.
    "dev_tool"      — developer AI agent or CLI (aider, cursor, claude CLI, goose, etc.).
                      May be authorized but not standard enterprise software.
                      Do NOT recommend CLOSED without explicit authorization evidence.
    "unknown"       — generic interpreter (python.exe, node, etc.) with no file/path evidence.
                      Intent unclear; use behavioral evidence to determine risk.
  Use this to frame root_cause_analysis, calibrate severity, and choose recommended actions.
- evidence.file_system_artifacts: files and directories the process touched.
  accessed_files may contain AI model weights, CUDA libraries, tokenizer configs, or framework
  DLLs (e.g. torch_cpu.dll, cudnn_*.dll, *.safetensors, *.gguf, tokenizer.json) — these are
  strong indicators of active AI model execution and should be named explicitly in the story.
  accessed_dirs may contain model cache paths (e.g. .cache/huggingface/hub/..., venv/.../torch)
  — name them and explain what they indicate (local model execution, specific model identity).
- evidence.ai_agent_context.classification_alert_details lists the specific alerts that
  triggered AI classification with their details and detection reasons.
- evidence.key_artifacts: the actual anomalous items per alert type. These are the facts of the case.
  Artifacts annotated [TEMP PATH], [TEMP FILE], [GUID/RANDOM NAME], [LIKELY RANDOM NAME], [TEMP/SOCKET FILE] are transient/ephemeral — flag them and reduce their weight.
  If ALL artifacts carry one of these annotations → verdict=FALSE_POSITIVE, recommended_status=CLOSED.
- evidence.alert_breakdown: each alert. Skip FP alerts — exclude from story/findings/recommendations. Note the excluded count.
  For SPAWNED_PROCESS alerts: name the process, args, hash, signer, dir. Explain what it does and why an AI agent spawning it is notable.
- evidence.incident.machine / user / process / signer: use as-is (may be obfuscated).
- evidence.processes.parent_process: what launched the AI agent (if known).
- evidence.network_volume: bytes sent/received.
- evidence.virustotal_raw / evidence.abuseipdb_raw: only cite if they show something.
- evidence.incident.link_reasons: why alerts were grouped.
- evidence.incident.os / os_version / host_type: describe the system.

RULES:
1) Every claim must reference a specific artifact from the evidence.
2) For spawned processes: name the process, args, explain what it does in plain English.
3) For new IPs/domains: name them. Note geo context from AbuseIPDB if available.
4) For new ports: name the IANA service.
5) Do NOT reference mitre_attack — it is unreliable.
6) If bytes_sent > 0 alongside new IPs in different geographic regions, flag GDPR concern.
7) Write in plain English. Never use "baseline deviation" or "anomaly type" without explaining what it means.
8) Be opinionated. Give a clear verdict.
9) Exclude FP alerts from story and recommendations. Note how many were excluded.
10) Recommended actions — final decisions only, chosen from:
    - "Limit credentials and permissions given to process<process name> under user <user>" if if   NOT enterprise_ai or dev_tool or shadow AI in use
    - "Verify with user <user> that this behavior was intentional"
    - "Add IOC <artifact>" — ONLY if TI confirmed malicious
    - "Stop process <process name, pid> from running"
    - "Trigger a full forensics investigation and sanitization on machine <machine>, process <pid>"
    - "Trigger credentials renewal for user <user>" — if even vague suspicion credentials were compromised
    - "Perform security compliance training to user <user>" — if shadow AI in use or data sent out
    - "Isolate machine <machine>"
    - "Isolate user <user>"
    - "Reinstall/update application <process name>" — if model manipulation suspected    
    Do NOT suggest log review, further monitoring, or correlation.
    Pick only genuinely warranted actions .
11) Do not state "failed signer verification" unless evidence explicitly says so.
12) On macOS/Linux, missing signer info is common — do not describe it as a failure.
13) Do not infer credential compromise from process name or directory alone. Only if evidence shows access to credential material.
14) Use evidence.incident.os, os_version, host_type when describing the system.

EVIDENCE_JSON:
{evidence_json}

OUTPUT — return a single JSON object:

{{
  "verdict": "BENIGN"|"SUSPICIOUS"|"MALICIOUS"|"FALSE_POSITIVE",
  "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
  "recommended_status": "CLOSED"|"OPEN"|"ESCALATE",
  "confidence": 0.0-1.0,

  "headline": "One sentence: what happened, on which machine/process, and what the verdict is.",

  "story": "3-6 sentences of plain English. Name the machine, process, user. Walk through what happened. Name every significant non-FP artifact. End with a clear verdict statement.",

  "ai_agent_classification_note": "One sentence explaining WHY this specific process was identified as an AI agent, referencing evidence.ai_agent_context.ai_risk_categories and classification_alert_details. Example: 'Claude.app was flagged as a new AI agent (shadow_ai) because EVENT_NEW_AI_AGENT_NOT_IN_BASELINE fired when the process appeared outside the approved baseline for this tenant.'",

  "key_findings": [
    "One concrete finding per entry — name the artifact, explain its significance.",
    "EXCLUDE artifacts annotated [TEMP PATH/FILE/GUID/RANDOM/SOCKET].",
    "..."
  ],

  "threat_intel": "One sentence on VT/AbuseIPDB, or 'No threat intelligence hits.' if clean.",

  "mitre_attack": [
    "Only include techniques directly supported by non-FP evidence. Format: 'TXXXX - Technique Name: one sentence.'",
    "..."
  ],

  "behavioral_analytics_note": "One sentence on why behavioral analytics are used here — why deviation from baseline is meaningful regardless of reputation.",

  "verdict_reasoning": "2-3 sentences: why this verdict, referencing the combination of non-FP evidence.",

  "excluded_fp_alerts": "e.g. '2 alerts excluded: transient file extension artifacts.' or 'None.'",

  "recommended_actions": [
    "Final action from the approved list above, with specific values filled in.",
    "..."
  ],

  "compromised_assets": ["exact values from evidence.assets_strict.compromised_assets"],

  "false_positive_reason": "Only if verdict=FALSE_POSITIVE. Explain which artifacts are transient."
}}

Return ONLY the JSON object. No preamble, no markdown.
"""
        return prompt

    def _generate_llm_analysis(self, evidence: Dict) -> Dict:
        print(f"  🤖 Calling LLM: provider={self.llm_client.provider}, model={self.llm_client.model}")
        prompt   = self._build_llm_prompt(evidence)
        response = self.llm_client.analyze(prompt)

        primary_error = response if isinstance(response, str) and response.startswith("LLM Error") else None
        print(response)

        parsed = None
        if isinstance(response, str):
            try:
                parsed = json.loads(response)
            except Exception:
                try:
                    s = response
                    start, end = s.find('{'), s.rfind('}')
                    if start != -1 and end != -1 and end > start:
                        parsed = json.loads(s[start:end+1])
                except Exception:
                    parsed = None

        if isinstance(response, str) and not response.startswith("LLM Error"):
            return {
                "status":   "ok" if parsed else "partial",
                "analysis": response,
                "parsed":   parsed,
                "provider": self.llm_client.provider,
                "reason":   None if parsed else "LLM returned text but JSON parsing was partial",
            }

        if isinstance(response, str) and "insufficient_quota" in response.lower():
            print("⚠️ OpenAI quota exceeded – falling back to Ollama")
            fallback          = LLMClient(provider="ollama", model=os.getenv("OLLAMA_MODEL", "llama3"))
            fallback_response = fallback.analyze(prompt)
            if isinstance(fallback_response, str) and not fallback_response.startswith("LLM Error"):
                parsed = self._parse_llm_json(fallback_response)
                return {"status": "ok" if parsed else "error", "analysis": fallback_response, "parsed": parsed, "provider": "ollama", "note": "Fallback due to OpenAI quota exhaustion"}
            return {"status": "error", "reason": fallback_response or "Ollama fallback failed", "provider": "ollama"}

        return {"status": "error", "reason": primary_error or response or "Unknown LLM error", "provider": self.llm_client.provider}

    def _parse_llm_json(self, s: Any) -> Optional[Dict]:
        if not isinstance(s, str): return None
        s = s.strip()
        start, end = s.find("{"), s.rfind("}")
        if start == -1 or end == -1 or end <= start: return None
        try: return json.loads(s[start:end + 1])
        except: return None

    # -------------------------------------------------------------------------
    # Validation
    # -------------------------------------------------------------------------

    def _validate_and_fix_llm_output(self, llm: Dict, evidence: Dict) -> Dict:
        notes:  List[str] = []
        parsed = (llm or {}).get("parsed") or {}
        if not isinstance(parsed, dict):
            # LLM returned text but JSON parsing failed.
            # Try one more time to extract a JSON object from the raw text.
            raw = (llm or {}).get("analysis") or ""
            if raw:
                recovered = self._parse_llm_json(raw)
                if isinstance(recovered, dict):
                    notes.append("Recovered JSON from raw LLM text on second attempt.")
                    parsed = recovered
                else:
                    print(f"  ❌ _validate_and_fix_llm_output: JSON unrecoverable. "
                          f"llm_status={llm.get('status')}, reason={llm.get('reason')}")
                    return {"_validator_notes": [f"LLM output missing/invalid JSON. status={llm.get('status')}, reason={llm.get('reason')}"]}
            else:
                return {"_validator_notes": [f"LLM output missing/invalid JSON. status={llm.get('status')}, reason={llm.get('reason')}"]}

        strict_assets = evidence.get("assets_strict", {}).get("compromised_assets", [])
        if parsed.get("compromised_assets") != strict_assets:
            notes.append("Overrode compromised_assets to match assets_strict.")
            parsed["compromised_assets"] = strict_assets
        impact = parsed.get("impact") if isinstance(parsed.get("impact"), dict) else {}
        if impact and impact.get("compromised_assets") != strict_assets:
            impact["compromised_assets"] = strict_assets
            parsed["impact"] = impact

        allowed = set()
        ni = evidence.get("new_iocs_for_ti") or {}
        for d in ni.get("domains") or []: allowed.add(f"domain:{d}")
        for ip in ni.get("ips") or []:    allowed.add(f"ip:{ip}")
        for h in ni.get("file_hashes") or []: allowed.add(f"hash:{h}")
        ki = parsed.get("key_indicators")
        if isinstance(ki, list):
            filtered = [x for x in ki if isinstance(x, str) and x in allowed]
            if filtered != ki: notes.append("Filtered key_indicators to subset of new_iocs_for_ti.")
            parsed["key_indicators"] = filtered

        bytes_sent = int((evidence.get("network_volume") or {}).get("bytes_sent", 0))
        if isinstance(parsed.get("impact"), dict):
            if bytes_sent == 0 and parsed["impact"].get("data_exposure") == "LIKELY":
                notes.append("Downgraded data_exposure LIKELY→POSSIBLE: bytes_sent=0.")
                parsed["impact"]["data_exposure"] = "POSSIBLE"

        TEMP_ANNOTATIONS = ("[TEMP PATH]", "[TEMP FILE]", "[GUID/RANDOM NAME]", "[LIKELY RANDOM NAME]", "[TEMP/SOCKET FILE]")
        ka = evidence.get("key_artifacts") or {}
        all_artifact_values = [str(x) for v in ka.values() if isinstance(v, list) for x in v if x]
        if all_artifact_values and all(any(tag in a for tag in TEMP_ANNOTATIONS) for a in all_artifact_values):
            if parsed.get("recommended_status") != "CLOSED":
                notes.append("Auto-closed: all anomalous artifacts are temp/random/ephemeral.")
                parsed["verdict"]             = "FALSE_POSITIVE"
                parsed["recommended_status"]  = "CLOSED"
                parsed["severity"]            = "LOW"
                parsed["confidence"]          = 0.95

        parsed["_validator_notes"] = notes
        return parsed

    # -------------------------------------------------------------------------
    # JSON alert ingestion
    # -------------------------------------------------------------------------

    def analyze_alerts_from_json_dir(
        self,
        json_dir: str,
        output_dir: Optional[str] = None,
        max_incidents: Optional[int] = None,
    ) -> List[Dict]:
        alerts = self._load_json_alerts(json_dir)
        if not alerts:
            print(f"⚠️  No alert JSON files found in {json_dir}")
            return []
        print(f"📂 Loaded {len(alerts)} alert JSON files from {json_dir}")
        incidents = self._group_json_alerts_into_incidents(alerts)
        print(f"🗂️  Grouped into {len(incidents)} incidents")
        if max_incidents:
            incidents = incidents[:max_incidents]
        reports: List[Dict] = []
        for idx, inc in enumerate(incidents, 1):
            print(f"\n[{idx}/{len(incidents)}] Incident {inc['incident_id']}  ({inc['machine']} / {inc['process']} / pid={inc['pid']})")
            report = self.analyze_incident(inc)
            reports.append(report)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                fname = f"incident_{inc['incident_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

                out = os.path.join(output_dir, fname)
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(make_json_serializable(report), f, indent=2)
                print(f"  💾 Saved {out}")
                _maybe_generate_pdf(report, os.path.join(output_dir, fname.replace(".json", ".pdf")))
                

        return reports

    def _load_json_alerts(self, json_dir: str) -> List[Dict]:
        alerts = []
        for fname in sorted(os.listdir(json_dir)):
            if not (fname.startswith("alert_") and fname.endswith(".json")): continue
            fpath = os.path.join(json_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["_source_file"] = fname
                alerts.append(data)
            except Exception as e:
                print(f"  ⚠️  Skipping {fname}: {e}")
        return alerts

    def _group_json_alerts_into_incidents(self, alerts: List[Dict]) -> List[Dict]:
        n = len(alerts)
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]; x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb: parent[ra] = rb

        proc_inst:    Dict[tuple, List[int]] = {}
        machine_proc: Dict[tuple, List[int]] = {}
        proc_pid:     Dict[tuple, List[int]] = {}
        parent_chain: Dict[str, List[int]]   = {}   # ppid_ct (no machine) → alert indices
        pid_ct_index: Dict[str, List[int]]   = {}   # own pid_ct → alert indices
        ioc_index:    Dict[str, List[int]]   = {}

        for i, alert in enumerate(alerts):
            a   = alert.get("alert") or {}
            pp  = alert.get("parent_process") or {}
            bl  = alert.get("baseline") or {}
            rel = bl.get("relevant") or {}
            machine = str(a.get("machine") or "")
            process = str(a.get("process") or "")
            pid     = str(a.get("pid") or "")
            proc_inst.setdefault((machine, process, pid), []).append(i)
            machine_proc.setdefault((machine, process), []).append(i)
            proc_pid.setdefault((process, pid), []).append(i)
            anom    = alert.get("anomaly") or {}
            ppid_ct = anom.get("child_pid_creation_time") or pp.get("ppid_creation_time")
            ppid_ct = anom.get("child_pid_creation_time") or pp.get("ppid_creation_time")
            if ppid_ct and str(ppid_ct).strip() and str(ppid_ct) not in ("nan", "None"):
                parent_chain.setdefault(str(ppid_ct), []).append(i)

            own_pid_ct = (
                a.get("pid_creation_time")
                or a.get("PidCreationTime")
                or anom.get("pid_creation_time")
            )
            if own_pid_ct and str(own_pid_ct).strip() and str(own_pid_ct) not in ("nan", "None"):
                pid_ct_index.setdefault(str(own_pid_ct), []).append(i)    
                
            for k, v in rel.items():
                if not isinstance(k, str) or not k.startswith(("new_", "observed_")): continue
                items = v if isinstance(v, list) else ([v] if v else [])
                for item in items:
                    if item and str(item).strip() and str(item) not in ("null", "None"):
                        ioc_index.setdefault(str(item).strip().lower(), []).append(i)
            ai = alert.get("anomalous_item") or {}
            for hfield in ("hash", "child_hash"):
                hval = ai.get(hfield) or anom.get("child_hash")
                if hval and str(hval).strip() and len(str(hval)) >= 8:
                    ioc_index.setdefault(str(hval).strip().lower(), []).append(i)

        for idxs in proc_inst.values():
            for j in range(1, len(idxs)): union(idxs[0], idxs[j])
        for idxs in machine_proc.values():
            if len(idxs) <= 3:
                for j in range(1, len(idxs)): union(idxs[0], idxs[j])
        for idxs in proc_pid.values():
            for j in range(1, len(idxs)): union(idxs[0], idxs[j])
        for idxs in parent_chain.values():
            for j in range(1, len(idxs)):
                union(idxs[0], idxs[j])
        # Pass B: parent↔child — alert whose own pid_ct == another's ppid_ct → merge
        for ppid_ct_val, child_idxs in parent_chain.items():
            for pi in pid_ct_index.get(ppid_ct_val, []):
                for ci in child_idxs:
                    union(pi, ci)
     
        for ioc, idxs in ioc_index.items():
            if len(ioc) < 4: continue
            for j in range(1, len(idxs)): union(idxs[0], idxs[j])

        groups: Dict[int, List[int]] = {}
        for i in range(n):
            groups.setdefault(find(i), []).append(i)

        incidents: List[Dict] = []
        for root, idxs in groups.items():
            group_alerts = sorted([alerts[i] for i in idxs],
                                   key=lambda x: int((x.get("alert") or {}).get("timestamp") or 0))
            first_alert  = group_alerts[0].get("alert") or {}
            first_anom   = group_alerts[0].get("anomaly") or {}
            first_obs    = first_anom.get("observed") or {}
            first_parent = group_alerts[0].get("parent_process") or {}
            first_top    = group_alerts[0]

            def _pick_field(*keys, dicts):
                """Return first non-empty value for any key across the given dicts."""
                for d in dicts:
                    for k in keys:
                        v = d.get(k)
                        if v and str(v).strip() and str(v).strip().lower() not in ("", "nan", "none"):
                            return str(v).strip()
                return ""
            alert_ids    = [str((a.get("alert") or {}).get("alert_id") or a.get("_source_file", "")) for a in group_alerts]
            incident_id  = alert_ids[0] if alert_ids else f"INC_{root}"
            link_reasons = self._describe_incident_links(group_alerts, idxs, alerts, proc_inst, parent_chain, ioc_index)

            all_domains:  List[str] = []; all_ips: List[str] = []; all_ports: List[str] = []
            all_acc_files: List[str] = []; all_mod_files: List[str] = []; all_acc_dirs: List[str] = []
            max_bytes_sent = max_bytes_received = 0

            for a in group_alerts:
                al  = a.get("alert") or {}
                obs = (a.get("anomaly") or {}).get("observed") or {}
                max_bytes_sent     = max(max_bytes_sent,     int(al.get("bytes_sent")     or 0))
                max_bytes_received = max(max_bytes_received, int(al.get("bytes_received") or 0))
                all_domains   += [d  for d  in (obs.get("contacted_domains")       or []) if d  and str(d).strip()]
                all_ips       += [ip for ip in (obs.get("contacted_ips")            or []) if ip and str(ip).strip()]
                all_ports     += [p  for p  in (obs.get("contacted_ports")          or []) if p  and str(p).strip()]
                all_acc_files += [f  for f  in (obs.get("accessed_files")           or []) if f  and str(f).strip()]
                all_acc_dirs  += [d  for d  in (obs.get("accessed_dirs")            or []) if d  and str(d).strip()]
                all_mod_files += [f  for f  in (obs.get("modified_model_files")     or []) if f  and str(f).strip()]

            anomalies    = [a for a in [self._json_alert_to_anomaly(a) for a in group_alerts] if a]
            process_hash = first_alert.get("process_hash") or (first_anom.get("observed") or {}).get("process_hash")
            child_hash   = (group_alerts[0].get("anomalous_item") or {}).get("hash") or first_anom.get("child_hash")
            
            incidents.append({
                "incident_id":    incident_id,
                "alert_ids":      alert_ids,
                "is_group":       len(group_alerts) > 1,
                "link_reasons":   link_reasons,
                "machine":        str(first_alert.get("machine") or ""),
                "user":           str(first_alert.get("user") or ""),
                "process":        str(first_alert.get("process") or ""),
                "signer":         str(first_alert.get("signer") or ""),
                "pid":            int(first_alert.get("pid") or 0),
                "creation_time":  int(first_alert.get("timestamp") or 0),
                "first_seen":     str(first_alert.get("first_seen") or ""),
                "last_seen":      str(first_alert.get("last_seen") or ""),
                "domain_name": first_alert.get("domain_name") or first_top.get("domain_name") or "ACME",
                "process_hash":   process_hash,
                "child_hash":     child_hash,
                "bytes_sent":     max_bytes_sent,
                "bytes_received": max_bytes_received,
                "OS":        _pick_field("os", "OS", "OperatingSystem",          dicts=[first_obs, first_top, first_alert]),
                "OSVersion": _pick_field("os_version", "OSVersion", "OsVersion", dicts=[first_obs, first_top, first_alert]),
                "HostType":  _pick_field("host_type", "HostType", "DeviceType",  dicts=[first_obs, first_top, first_alert]),
                "parent_process": first_parent,
                "anomalies":      anomalies,
                "raw_rows_count": len(group_alerts),
                "contacted_ips":     _dedupe_keep_order(all_ips),
                "contacted_domains": _dedupe_keep_order(all_domains),
                "contacted_ports":   _dedupe_keep_order(all_ports),
                "suspicious_files": {
                    "accessed_files": _dedupe_keep_order(all_acc_files),
                    "accessed_dirs":  _dedupe_keep_order(all_acc_dirs),
                    "modified_files": _dedupe_keep_order(all_mod_files),
                },
                "_raw_alerts":    group_alerts,
                # Why was this process identified as an AI agent?
                "ai_agent_context": self._extract_ai_agent_context(
                    {
                        "process":           str(first_alert.get("process") or ""),
                        "process_dir":       str(first_alert.get("process_dir") or first_alert.get("ProcessDir") or ""),
                        "contacted_domains": _dedupe_keep_order(all_domains),
                        "contacted_ports":   _dedupe_keep_order(all_ports),
                        "accessed_files":    _dedupe_keep_order(all_acc_files),
                        "accessed_dirs":     _dedupe_keep_order(all_acc_dirs),
                    },
                    anomalies,
                ),
            })
            # Derive ai_deployment_type now that ai_agent_context is built
            incidents[-1]["ai_deployment_type"] = self._classify_ai_deployment_type(
                matched_artifacts=incidents[-1]["ai_agent_context"].get("matched_artifacts", []),
                ai_risks=incidents[-1]["ai_agent_context"].get("ai_risk_categories", []),
                process_name=incidents[-1]["process"],
            )

        incidents.sort(key=lambda x: x.get("creation_time", 0), reverse=True)
        return incidents

    def _describe_incident_links(self, group_alerts, idxs, all_alerts, proc_inst, parent_chain, ioc_index) -> List[str]:
        reasons: List[str] = []
        if len(group_alerts) == 1:
            return ["Single alert — no grouping applied."]
        a0      = group_alerts[0].get("alert") or {}
        machine = str(a0.get("machine") or "")
        process = str(a0.get("process") or "")
        pid     = str(a0.get("pid") or "")
        if len(proc_inst.get((machine, process, pid), [])) > 1:
            reasons.append(f"Same process instance: machine={machine}, process={process}, pid={pid}")
        elif any(str((a.get("alert") or {}).get("process") or "") == process and str((a.get("alert") or {}).get("pid") or "") == pid for a in group_alerts[1:]):
            reasons.append(f"Same process name + pid (machine-agnostic): process={process}, pid={pid}")
        idx_set     = set(idxs)
        shared_iocs = [ioc for ioc, ioc_idxs in ioc_index.items() if len(ioc) >= 4 and len(idx_set & set(ioc_idxs)) >= 2]
        if shared_iocs: reasons.append(f"Shared IOCs: {', '.join(shared_iocs[:10])}")
        for a in group_alerts:
            ppid_ct = (a.get("anomaly") or {}).get("child_pid_creation_time")
            if ppid_ct and len(parent_chain.get(str(ppid_ct), [])) > 1:
                reasons.append(f"Shared parent chain: ppid_creation_time={ppid_ct}"); break
        if not reasons:
            reasons.append(f"Same machine+process name: machine={machine}, process={process}")
        return reasons

    def _json_alert_to_anomaly(self, alert: Dict) -> Optional[Dict]:
        a    = alert.get("alert") or {}
        anom = alert.get("anomaly") or {}
        bl   = alert.get("baseline") or {}
        ai   = alert.get("anomalous_item") or {}
        alert_type = a.get("alert_type") or ""
        if not alert_type: return None
        return {
            "anomaly_type":           alert_type,
            "type":                   alert_type,
            "confidence":             float(a.get("confidence_score") or 0.0),
            "alert_id":               a.get("alert_id"),
            "severity":               a.get("severity"),
            "details":                a.get("details"),
            "mitre_attack":           a.get("mitre_attack") or [],
            "ai_risk":                a.get("ai_risk") or [],
            "soc_runbook":            a.get("soc_runbook") or {},
            "baseline_relevant_json": bl.get("relevant") or {},
            "reason":                 (bl.get("relevant") or {}).get("detection_reason"),
            "anomalous_item":         ai,
            "child_process":          anom.get("child_process"),
            "child_args":             anom.get("child_args"),
            "child_hash":             anom.get("child_hash"),
            "child_signer":           anom.get("child_signer"),
            "child_dir":              anom.get("child_dir"),
            "child_activity":         anom.get("child_activity"),
            "row_fields":             {"timestamp": int(a.get("timestamp") or 0)},
        }

    def _fallback_summary(self, inc: Dict, threat_summary: Dict) -> str:
        return (
            f"Process {inc.get('process')} (pid={inc.get('pid')}) on machine {inc.get('machine')} "
            f"for user {inc.get('user')} triggered {inc.get('raw_rows_count')} anomaly events. "
            f"New IOCs sent to TI: domains={len((inc.get('new_iocs_for_ti') or {}).get('domains', []))}, "
            f"ips={len((inc.get('new_iocs_for_ti') or {}).get('ips', []))}. "
            f"TI checked: VT={threat_summary.get('virustotal', {}).get('checked', 0)}, "
            f"AbuseIPDB={threat_summary.get('abuseipdb', {}).get('checked', 0)}."
        )


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("input", help="Path to alerts CSV file, or directory containing alert_*.json files")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--max-incidents", type=int, default=None)
    args = p.parse_args()
    analyzer = IncidentAnalyzer2()
    if os.path.isdir(args.input):
        analyzer.analyze_alerts_from_json_dir(json_dir=args.input, output_dir=args.output_dir, max_incidents=args.max_incidents)
        if args.output_dir:
            try:
                from incident_report_generator import generate_pdf
                tenant = os.getenv("TENANT_NAME", "Unknown Tenant")
                for fname in os.listdir(args.output_dir):
                    if fname.endswith(".json"):
                        json_path = os.path.join(args.output_dir, fname)
                        pdf_path  = json_path.replace(".json", ".pdf")
                        with open(json_path, encoding="utf-8") as f:
                            report = json.load(f)
                        generate_pdf(report, pdf_path, tenant_id=tenant)
            except ImportError:
                pass   # report generator not installed — skip silently
    else:
        analyzer.analyze_alerts_from_csv(csv_path=args.input, output_dir=args.output_dir, max_incidents=args.max_incidents)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

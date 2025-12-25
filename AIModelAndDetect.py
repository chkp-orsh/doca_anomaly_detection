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

#set servertimeout = 10m;
#set query_results_cache_max_age = 0d;
#set maxmemoryconsumptionperiterator=16106127360;

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
        
    def _execute_query(self, query, max_tries=3, sleepTimeinSecs=30):
        trys=0
        for trys in range(0,max_tries):
            try:
                str_error = None
                query = f"set servertimeout = 10m;\nset query_results_cache_max_age = 0d;\n{query}"
                properties = ClientRequestProperties()
                properties.set_option(ClientRequestProperties.request_timeout_option_name, timedelta(minutes=15))
                response = self.client.execute(self.database, query, properties=properties)
                return dataframe_from_result_table(response.primary_results[0])
            except Exception as e:
                str_error = str(e)
                str_conn_err ="Failed to resolve table expression named"
                print(f"❌ _execute_query Query error: {e} {str_conn_err}")
                if str_conn_err in str_error:
                    print ("traying again")
                    time.sleep (sleepTimeinSecs)
                    print ("After Sleep")
                    pass
                else:    
                    print(f"❌ str_conn_err EX Query error: {e}")
                    print ("eeeeeeeeeeeeeeeeeeeee")
                    print (query)
                    print ("eeeeeeeeeeeeeeeeeeeee")
                    raise
    
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
        
        print(f"\n📊 Query 1: AI process behavior from {lookback_value} {lookback_unit}(s) ago... on tenant {self.tenant_id}")
        
        query = f"""set servertimeout = 10m;
set query_results_cache_max_age = 0d;
set maxmemoryconsumptionperiterator=16106127360;
let longNetworkCon=15m;
let ToolProcessNames = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "zsh", "curl.exe", "curl", "wget", "python.exe", "python", "python3", "node.exe", "node", "sqlcmd", "psql", "mysql", "scp", "sftp", "ssh", "kubectl", "helm", "az", "aws", "gcloud"]);
let CommonDevOrBrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "code", "code.exe", "idea64.exe", "pycharm64.exe", "explorer.exe"]);
let LocalhostAddresses = dynamic(["127.0.0.1", "::1"]);
let CommonAIServingPorts = dynamic([11434, 7860, 5000, 5001, 8000, 8001, 8080, 8888, 8889, 9000, 9001]);
let LLMApiPathFragments = dynamic(["/v1/chat/completions", "/openai/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/images", "/v1/audio/transcriptions", "/responses", "/v1beta/models", ":generatecontent", "/dashscope/", "/chat/completions"]);
let LLMApiDomains = dynamic(["api.openai.com", "openai.azure.com", "api.anthropic.com", "claude.ai", "claude.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com", "api.mistral.ai", "api.perplexity.ai", "pplx-api.perplexity.ai", "api.cohere.ai", "api.x.ai", "llama.developer.meta.com", "api.deepseek.com", "dashscope.aliyuncs.com", "qwen-api.aliyuncs.com", "openrouter.ai", "api.together.xyz", "api.fireworks.ai", "api.groq.com"]);
let KnownAIServingProcessNames = dynamic(["tritonserver", "tensorflow_model_server", "onnxruntime_server", "vllm", "text-generation-inference", "text-generation-server", "llama", "llama-server", "ollama", "torchserve", "oobabooga", "koboldcpp", "lmstudio"]);
let GenericInterpreterProcessNames = dynamic(["python", "python3", "python.exe", "node", "node.exe", "java", "dotnet", "dotnet.exe", "go", "uvicorn", "gunicorn"]);
let AICmdlineKeywords = dynamic(["--model", "--models", "--model-path", "--model_dir", "model", "models", "text-generation-inference", "vllm", "llama.cpp", "tritonserver", "inference", "serve", "server", "llm", "embeddings"]);
let AIModuleFileNamePatterns = dynamic(["torch_cpu", "torch_cuda", "tensorflow", "onnxruntime", "ggml", "llama", "nvinfer", "tensorrt", "cudart", "cublas", "cudnn"]);
let AIModulePathPatterns = dynamic(["torch", "transformers", "tensorflow", "jax", "sentence_transformers", "huggingface", "llama", "gguf", "onnx", "checkpoints", "models"]);
let ModelFileExtensions = dynamic(["ckpt", "pt", "pth", "safetensors", "bin", "onnx", "pb", "meta", "gguf", "ggml", "gptq", "awq", "h5", "pkl", "model"]);
let TokenizerAndConfigExtensions = dynamic(["json", "yaml", "yml", "tokenizer", "spm", "bpe", "vocab"]);
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
or tolower(ParentProcessArgs) has_any (AICmdlineKeywords) 
or tolower(ProcessDir) has_any (LLMApiPathFragments) 
or tolower(ProcessDir) has_any (FileDirSearch) 
or tolower(ParentProcessDir) has_any (LLMApiPathFragments) 
or tolower(ParentProcessDir) has_any (FileDirSearch) 
or tolower(ProcessName) has_any (GenericInterpreterProcessNames) 
or tolower(ProcessName) has_any (CommonDevOrBrowserProcesses) 
or tolower(ProcessName) has_any (ToolProcessNames) 
or tolower(ParentProcessName) has_any (GenericInterpreterProcessNames) 
or tolower(ParentProcessName) has_any (CommonDevOrBrowserProcesses) or tolower(ParentProcessName) has_any (ToolProcessNames) or (FileExtension in (ExtSearch) and FileSize > 500) or tolower(NetworkPath) has_any (AIModulePathPatterns) or tolower(NetworkDomain) in (LLMApiDomains) or tolower(NetworkDestPort) in (CommonAIServingPorts) or tolower(NetworkSrcPort) in (CommonAIServingPorts) or ((NetworkDestIP in (LocalhostAddresses) or NetworkSrcIP in (LocalhostAddresses)) and NetworkConnectionDirection == "Incoming")
| extend hasModelFile = toint(FileExtension in (ModelFileExtensions) and FileSize > 50000000),
 hasTokenizerOrConfig = toint(FileExtension in (TokenizerAndConfigExtensions)), hasAiRuntimeFile = toint(FileName has_any (AIModuleFileNamePatterns)), hasAiRuntimePath = toint(FileDir has_any (AIModulePathPatterns) or NetworkPath has_any (AIModulePathPatterns)), isKnownAIServingProcess = toint(ProcessName has_any (KnownAIServingProcessNames)), isGenericInterpreter = toint(ProcessName has_any (GenericInterpreterProcessNames) or ParentProcessName has_any (GenericInterpreterProcessNames)), isToolProcess = toint(ProcessName has_any (ToolProcessNames) or ParentProcessName has_any (ToolProcessNames)), hasAiCmdline = toint(ProcessArgs has_any (AICmdlineKeywords) or ParentProcessArgs has_any (AICmdlineKeywords)), talksToLLMApi = toint(NetworkDomain in (LLMApiDomains) and NetworkPath has_any (LLMApiPathFragments)), usesAIServingPort = toint(NetworkDestPort in (CommonAIServingPorts) or NetworkSrcPort in (CommonAIServingPorts)), hasLocalhostInbound = toint((NetworkDestIP in (LocalhostAddresses) or NetworkSrcIP in (LocalhostAddresses)) and NetworkConnectionDirection == "Incoming"), hasLongConnection = coalesce(toint(unixtime_seconds_todatetime(NetworkConnectionCloseTime) - unixtime_seconds_todatetime(NetworkConnectionStartTime) > longNetworkCon), 0), hasSuspiciousArgs = toint(tolower(ProcessArgs) has_any (SuspiciousArgs) or tolower(ParentProcessArgs) has_any (SuspiciousArgs)), isSuspiciousDir = toint(tolower(FileDir) has_any (SuspiciousDirs) or tolower(ProcessDir) has_any (SuspiciousDirs) or tolower(ParentProcessDir) has_any (SuspiciousDirs)), isLargeFile = toint(FileSize > 100000000)
| extend aiScore = 5 * hasModelFile + 3 * hasTokenizerOrConfig + 4 * (hasAiRuntimeFile + hasAiRuntimePath) + 3 * isKnownAIServingProcess + 2 * hasAiCmdline + 2 * talksToLLMApi + 1 * usesAIServingPort + 1 * hasLocalhostInbound + 2 * hasLongConnection
| where aiScore >= 7
| summarize event_count = count(),
PidCreationTime = take_any(PidCreationTime), NetworkBytesSent_sum = sum(NetworkBytesSent), NetworkBytesReceived_sum = sum(NetworkBytesReceived), contacted_domains = make_set(NetworkDomain), contacted_ips = make_set(NetworkDestIP), contacted_ports = make_set(NetworkDestPort), network_paths = make_set(NetworkPath), accessed_files = make_set(FileName), accessed_dirs = make_set(FileDir),
 accessed_extensions = make_set(FileExtension),
 modified_files = make_set_if(FileName, isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0), modified_model_files = make_set_if(FileName, isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0 and FileExtension in (ModelFileExtensions)), file_mod_details = make_bag_if(pack("file", FileName, "user", UserName, "args", ProcessArgs), isnotempty(FileOpMask) and binary_and(FileOpMask, 38970) != 0), model_files_count = countif(hasModelFile == 1), large_file_count = countif(FileSize > 100000000), llm_api_count = countif(talksToLLMApi == 1), non_llm_count = countif(isnotempty(NetworkDomain) and talksToLLMApi == 0), suspicious_dir_count = countif(tolower(FileDir) has_any (SuspiciousDirs)), suspicious_args_count = countif(tolower(ProcessArgs) has_any (SuspiciousArgs)), aiScore_avg = avg(aiScore), ProcessDir = take_any(ProcessDir), ProcessArgs = take_any(ProcessArgs), UserName = take_any(UserName) by MachineName, ProcessName, Pid, CreationTime
     |take 10000"""

   
        #print ("=============")
        #print (query)
        #print ("=============")
        df = self._execute_query(query)
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
        parent_array = ', '.join([f'"{pct}"' for pct in ai_parent_pct_list])
        
        query = f"""set servertimeout = 10m;
    set query_results_cache_max_age = 0d;
    let AIParents = dynamic([{parent_array}]);
    database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
    | where OpTimeSecondsUTC between ({start_time} .. {end_time})
    | where ProcessPPidCreationTime in (AIParents)
    | project MachineName, ParentProcessName, ProcessPPidCreationTime, ProcessName, ProcessArgs, ProcessDir
    | take 100000"""
        
        df = self._execute_query(query)
        print(f"✅ Collected {len(df)} children of AI parents")
        return df
    
    
    
    
    
    
    
    
    
    def collect_child_spawning_data_old(self, lookback_value=1, lookback_unit='day'):
        """Query 2: Children spawned where PARENT matches AI detection criteria"""
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
        
        print(f"\n📊 Query 2: Child spawning from {lookback_value} {lookback_unit}(s) ago... for {self.tenant_id}")
        
        query = f"""set servertimeout = 10m;
    set query_results_cache_max_age = 0d;
    let ToolProcessNames = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "curl", "wget", "ssh", "scp", "kubectl", "nc.exe"]);
    let CommonDevOrBrowserProcesses = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "code.exe", "explorer.exe"]);
    let LLMApiDomains = dynamic(["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.mistral.ai", "api.groq.com"]);
    let KnownAIServingProcessNames = dynamic(["tritonserver", "vllm", "llama", "ollama", "torchserve", "lmstudio"]);
    let GenericInterpreterProcessNames = dynamic(["python", "python3", "python.exe", "node", "node.exe", "java", "uvicorn", "gunicorn"]);
    let AICmdlineKeywords = dynamic(["--model", "--models", "inference", "serve", "llm", "embeddings"]);
    let AIModulePathPatterns = dynamic(["torch", "transformers", "llama", "gguf", "onnx", "models"]);
    let LLMApiPathFragments = dynamic(["/v1/chat", "/v1/completions", "/v1/embeddings"]);
    let SuspiciousArgs = dynamic(["copy", "move", "scp", "curl", "wget", "download", "upload", "compress"]);
    database("9327dadc-4486-45cc-919a-23953d952df4-e8240").table("{self.tenant_id}")
    | where OpTimeSecondsUTC between ({start_time} .. {end_time})
    | where tolower(ParentProcessName) has_any (GenericInterpreterProcessNames) or tolower(ParentProcessName) has_any (KnownAIServingProcessNames) or tolower(ParentProcessArgs) has_any (AICmdlineKeywords) or tolower(ParentProcessDir) has_any (AIModulePathPatterns) or tolower(ParentProcessDir) has_any (LLMApiPathFragments)
    | extend isToolProcess = toint(ProcessName has_any (ToolProcessNames)), hasSuspiciousArgs = toint(tolower(ProcessArgs) has_any (SuspiciousArgs))
    | summarize spawned_processes = make_set(ProcessName), spawned_args = make_set(ProcessArgs), spawned_dirs = make_set(ProcessDir), tool_spawn_count = countif(isToolProcess == 1), total_children = count(), unique_children = dcount(ProcessName), suspicious_cmdline_count = countif(hasSuspiciousArgs == 1) by MachineName, ParentProcessName, ParentPid=ProcessPPid, ParentCreationTime=ProcessPCreationTime
    |take 10000"""
        
        df = self._execute_query(query)
        print(f"✅ Collected {len(df)} parent spawn records for {self.tenant_id}")
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
            'stats': {'instances': 0, 'avg_bytes_sent': 0, 'max_bytes_sent': 0}
        })
        
        # Build from process data
        for _, row in df_process.iterrows():
            key = (row['MachineName'], row['ProcessName'])
            
            if pd.notna(row.get('contacted_domains')):
                try:
                    domains = eval(row['contacted_domains'])
                    baselines[key]['contacted_domains'].update([d for d in domains if d])
                except: pass
            
            if pd.notna(row.get('contacted_ips')):
                try:
                    ips = eval(row['contacted_ips'])
                    baselines[key]['contacted_ips'].update([ip for ip in ips if ip])
                except: pass
            
            if pd.notna(row.get('contacted_ports')):
                try:
                    ports = eval(row['contacted_ports'])
                    baselines[key]['contacted_ports'].update([str(p) for p in ports if p])
                except: pass
            
            if pd.notna(row.get('network_paths')):
                try:
                    paths = eval(row['network_paths'])
                    baselines[key]['network_paths'].update([p for p in paths if p])
                except: pass

            a_fs=row.get('accessed_files')
            #if pd.notna(row.get('accessed_files')):
            if isinstance(a_fs,list):
                try:
                    #files = eval(row['accessed_files'])
                    baselines[key]['accessed_files'].update([f for f in a_fs if f])
                except: pass


            #if pd.notna(row.get('accessed_dirs')):
            dirs = row.get('accessed_dirs')
            if isinstance(dirs, list):
                try:
                    #dirs = eval(row['accessed_dirs'])
                    #baselines[key]['accessed_dirs'].update([d for d in dirs if d])
                    #baselines[key]['accessed_dirs'].update([d for d in dirs if d])
                    baselines[key]['accessed_dirs'].update([d for d in dirs if d])
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
            if pd.notna(row.get('file_ops_details')):
                try:
                    ops = eval(row['file_ops_details'])
                    for op in ops:
                        filename = op.get('file')
                        if not filename:
                            continue
                        
                        if filename not in baselines[key]['file_operations']:
                            baselines[key]['file_operations'][filename] = {
                                'operations': set(),
                                'users': set(),
                                'process_args': set()
                            }
                        
                        # Track which operations happened on this file
                        op_mask = op.get('op', 0)
                        if (op_mask & 16) == 16:  # Write
                            baselines[key]['file_operations'][filename]['operations'].add('Write')
                        if (op_mask & 2) == 2:  # Create
                            baselines[key]['file_operations'][filename]['operations'].add('Create')
                        
                        # Track users and args
                        if op.get('user'):
                            baselines[key]['file_operations'][filename]['users'].add(op['user'])
                        if op.get('args'):
                            baselines[key]['file_operations'][filename]['process_args'].add(op['args'])
                except:
                    pass
            
            
        # Build from child data
        for _, row in df_children.iterrows():
            key = (row['MachineName'], row['ParentProcessName'])
            
            spawned_p=row.get('spawned_processes')
            #if pd.notna(row.get('spawned_processes')):
            if isinstance(spawned_p,list):
                try:
                    #procs = eval(row['spawned_processes'])
                    baselines[key]['spawned_processes'].update([p for p in spawned_p if p])
                except: pass
            
            spawned_ar=row.get('spawned_args')
            #if pd.notna(row.get('spawned_args')):
            if isinstance(spawned_ar,list):
                try:
                    #args = eval(row['spawned_args'])
                    baselines[key]['spawned_args'].update([a for a in spawned_ar  if a])
                except: pass
        
        # Compute numeric stats
        for key in baselines:
            machine, process = key
            proc_subset = df_process[(df_process['MachineName'] == machine) & (df_process['ProcessName'] == process)]
            
            if len(proc_subset) > 0:
                baselines[key]['stats'] = {
                    'instances': len(proc_subset),
                    'avg_bytes_sent': float(proc_subset['NetworkBytesSent_sum'].mean()),
                    'max_bytes_sent': float(proc_subset['NetworkBytesSent_sum'].max())
                }
        
        print(f"✅ Built baselines for {len(baselines)} (machine, process) combinations for {self.tenant_id}")
        return dict(baselines)
    
    def save_baseline(self, baselines):
        """Save baseline to JSON"""
        baselines_json = {}
        for key, baseline in baselines.items():
            machine, process = key
            baselines_json[f"{machine}||{process}"] = {
                'spawned_processes': list(baseline['spawned_processes']),
                'spawned_args': list(baseline['spawned_args']),
                'contacted_domains': list(baseline['contacted_domains']),
                'contacted_ips': list(baseline['contacted_ips']),
                'contacted_ports': list(baseline['contacted_ports']),
                'network_paths': list(baseline['network_paths']),
                'accessed_files': list(baseline['accessed_files']),
                'accessed_dirs': list(baseline['accessed_dirs']),
                'accessed_extensions': list(baseline['accessed_extensions']),
                'users': list(baseline['users']),
                'process_args': list(baseline['process_args']),
                'file_operations': {
                    fname: {
                        'operations': list(fdata['operations']),
                        'users': list(fdata['users']),
                        'process_args': list(fdata['process_args'])
                    } for fname, fdata in baseline.get('file_operations', {}).items()
                },
                'stats': baseline['stats']
            }
        
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
            machine, process = key_str.split('||')
            baselines[(machine, process)] = {
                'spawned_processes': set(baseline['spawned_processes']),
                'spawned_args': set(baseline['spawned_args']),
                'contacted_domains': set(baseline['contacted_domains']),
                'contacted_ips': set(baseline['contacted_ips']),
                'contacted_ports': set(baseline['contacted_ports']),
                'network_paths': set(baseline['network_paths']),
                'accessed_files': set(baseline['accessed_files']),
                'accessed_dirs': set(baseline['accessed_dirs']),
                'accessed_extensions': set(baseline['accessed_extensions']),
                'users': set(baseline['users']),
                'process_args': set(baseline['process_args']),
                'file_operations': {
                    fname: {
                        'operations': set(fdata['operations']),
                        'users': set(fdata['users']),
                        'process_args': set(fdata['process_args'])
                    } for fname, fdata in baseline.get('file_operations', {}).items()
                },
                'stats': baseline['stats']
            }
        

        print(f"✅ Loaded baseline for {len(baselines)} combinations for {self.tenant_id}")
        return baselines
    
    def detect_anomalies(self, df_process, df_children, baselines):
        """Detect anomalies by comparing against baseline sets"""
        print("\n🔍 Detecting anomalies... for {self.tenant_id}")
        alerts = []
        
        # Process behavior anomalies
        for _, row in df_process.iterrows():
            key = (row['MachineName'], row['ProcessName'])
            if key not in baselines:
                continue
            
            baseline = baselines[key]
            anomalies = []
            
            # NEW DOMAINS
            if pd.notna(row.get('contacted_domains')):
                try:
                    current = set(eval(row['contacted_domains']))
                    new_items = current - baseline['contacted_domains']
                    if new_items:
                        anomalies.append({'type': 'NEW_DOMAINS', 'severity': 'HIGH', 'items': list(new_items)})
                except: pass
            
            # NEW IPS
            if pd.notna(row.get('contacted_ips')):
                try:
                    current = set(eval(row['contacted_ips']))
                    new_items = current - baseline['contacted_ips']
                    if new_items:
                        anomalies.append({'type': 'NEW_IPs', 'severity': 'HIGH', 'items': list(new_items)})
                except: pass
            
            # NEW PORTS
            if pd.notna(row.get('contacted_ports')):
                try:
                    current = set([str(p) for p in eval(row['contacted_ports'])])
                    new_items = current - baseline['contacted_ports']
                    if new_items:
                        anomalies.append({'type': 'NEW_PORTS', 'severity': 'MEDIUM', 'items': list(new_items)})
                except: pass
            
            # NEW DIRECTORIES
            if pd.notna(row.get('accessed_dirs')):
                try:
                    current = set(eval(row['accessed_dirs']))
                    new_items = current - baseline['accessed_dirs']
                    if new_items:
                        anomalies.append({'type': 'NEW_DIRECTORIES', 'severity': 'MEDIUM', 'items': list(new_items)[:20]})
                except: pass
            
            # EXCESSIVE DATA TRANSFER
            avg_sent = baseline['stats'].get('avg_bytes_sent', 0)
            if avg_sent > 0 and row['NetworkBytesSent_sum'] > avg_sent * 10:
                anomalies.append({'type': 'EXCESSIVE_TRANSFER', 'severity': 'CRITICAL', 'items': [f"{row['NetworkBytesSent_sum']/1e6:.1f}MB vs {avg_sent/1e6:.1f}MB avg"]})
# NEW MODEL FILE MODIFICATIONS
            if pd.notna(row.get('modified_model_files')):
                try:
                    modified = set(eval(row['modified_model_files']))
                    for file in modified:
                        if file not in baseline.get('file_operations', {}):
                            anomalies.append({
                                'type': 'NEW_MODEL_FILE_MODIFICATION',
                                'severity': 'CRITICAL',
                                'items': [f"Model file {file} modified - never modified before"]
                            })
                        else:
                            # File was modified before - check if by new user
                            file_baseline = baseline['file_operations'][file]
                            # Get user from file_mod_details
                            if pd.notna(row.get('file_mod_details')):
                                try:
                                    details = eval(row['file_mod_details'])
                                    for detail in details:
                                        if detail.get('file') == file:
                                            current_user = detail.get('user')
                                            if current_user and current_user not in file_baseline.get('users', set()):
                                                anomalies.append({
                                                    'type': 'MODEL_FILE_MODIFIED_BY_NEW_USER',
                                                    'severity': 'CRITICAL',
                                                    'items': [f"Model file {file} modified by new user {current_user}"]
                                                })
                                except: pass
                except: pass

            # Check file write operations
            if pd.notna(row.get('written_model_files')):
                try:
                    written = set(eval(row['written_model_files']))
                    for file in written:
                        if file not in baseline.get('file_operations', {}):
                            anomalies.append({
                                'type': 'NEW_MODEL_FILE_WRITE',
                                'severity': 'CRITICAL',
                                'items': [f"Model file {file} written - never written before"]
                            })
                except:
                    pass
            
            if anomalies:
                alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'machine': row['MachineName'],
                    'process': row['ProcessName'],
                    'pid': row['Pid'],
                    'user': row.get('UserName', 'N/A'),
                    'anomalies': anomalies
                })
        
        # Child spawning anomalies
        for _, row in df_children.iterrows():
            key = (row['MachineName'], row['ParentProcessName'])
            if key not in baselines:
                continue
            
            baseline = baselines[key]
            anomalies = []
            
            # NEW SPAWNED PROCESSES
            if pd.notna(row.get('spawned_processes')):
                try:
                    current = set(eval(row['spawned_processes']))
                    new_items = current - baseline['spawned_processes']
                    if new_items:
                        anomalies.append({'type': 'NEW_SPAWNED_PROCESSES', 'severity': 'CRITICAL', 'items': list(new_items)})
                except: pass
            
            # NEW SPAWNED PROCESSES with argument similarity checking
            if pd.notna(row.get('spawned_processes')) and pd.notna(row.get('spawned_args')):
                try:
                    current_procs = set(eval(row['spawned_processes']))
                    current_args_list = eval(row['spawned_args'])
                    
                    # Check each spawned process
                    for proc in current_procs:
                        if proc not in baseline['spawned_processes']:
                            # Completely new process spawned
                            anomalies.append({
                                'type': 'NEW_SPAWNED_PROCESS',
                                'severity': 'CRITICAL',
                                'items': [f"Never spawned before: {proc}"]
                            })
                        else:
                            # Process was spawned before - check arguments similarity
                            baseline_args = baseline.get('spawned_args', set())
                            
                            if baseline_args and current_args_list:
                                # Find maximum similarity between current args and any baseline arg
                                max_similarity = 0
                                for current_arg in current_args_list:
                                    for baseline_arg in baseline_args:
                                        similarity = SequenceMatcher(None, str(current_arg), str(baseline_arg)).ratio()
                                        max_similarity = max(max_similarity, similarity)
                                
                                # If most similar baseline arg is still very different, alert
                                if max_similarity < 0.6:
                                    anomalies.append({
                                        'type': 'SPAWNED_PROCESS_UNUSUAL_ARGS',
                                        'severity': 'HIGH',
                                        'items': [f"{proc} with unusual arguments (similarity: {max_similarity:.2f})"]
                                    })
                except: pass
                      
            
            if anomalies:
                alerts.append({
                    'timestamp': datetime.now().isoformat(),
                    'machine': row['MachineName'],
                    'process': row['ParentProcessName'],
                    'pid': row.get('ParentPid', 'N/A'),
                    'user': 'N/A',
                    'anomalies': anomalies
                })
        
        if alerts:
            print(f"🚨 Detected {len(alerts)} anomalous instances! for {self.tenant_id}")
            return pd.DataFrame(alerts)
        return pd.DataFrame()
    
    def save_alerts(self, alerts_df):
        """Save alerts to CSV"""
        if len(alerts_df) == 0:
            print ("No alerts for {self.tenant_id}")
            return
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(self.output_dir, 'alerts', f'alerts_{timestamp}.csv')
        
        alerts_flat = []
        for _, alert in alerts_df.iterrows():
            for anomaly in alert['anomalies']:
                alerts_flat.append({
                    'timestamp': alert['timestamp'],
                    'machine': alert['machine'],
                    'process': alert['process'],
                    'pid': alert['pid'],
                    'user': alert['user'],
                    'severity': anomaly['severity'],
                    'anomaly_type': anomaly['type'],
                    'details': str(anomaly['items'])
                })
        
        df_flat = pd.DataFrame(alerts_flat)
        df_flat.to_csv(filepath, index=False)
        
        master = os.path.join(self.output_dir, 'alerts', 'all_alerts.csv')
        if os.path.exists(master):
            df_flat.to_csv(master, mode='a', header=False, index=False)
        else:
            df_flat.to_csv(master, index=False)
        
        print(f"💾 Saved {len(alerts_flat)} alerts to {filepath} for {self.tenant_id}")


def execute(cluster, database, tenant, output_dir, mode, lookback_unit='day', 
            lookback_count=1, bootstrap_count=7, delay_seconds=5, baseline_offset=0):
    """Execute anomaly detection workflow"""
    detector = AIAgentAnomalyDetector(cluster, database, tenant, output_dir)
    
    print("="*80)
    print("🤖 AI Agent Anomaly Detection for {tenant}")
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
                df_child = detector.collect_child_spawning_data(period, lookback_unit)
                if len(df_proc) > 0:
                    all_process.append(df_proc)
                    successful += 1
                if len(df_child) > 0:
                    all_children.append(df_child)
                
                if period > 1:
                    time.sleep(delay_seconds)
            except Exception as e:
                print(f"❌ Error: 1 {e}")
                #print ("eeeeeeeeeeeeeeeeeeeee")
                #print (query)
                #print ("eeeeeeeeeeeeeeeeeeeee")
        
        print(f"\n✅ Collected {successful} periods for {tenant}")
        
        if all_process:
            baselines = detector.build_baseline(all_process, all_children)
            detector.save_baseline(baselines)
        else:
            print("⚠️  No data collected for {tenant}")
    
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
        df_child = detector.collect_child_spawning_data(detect_period, lookback_unit)
        
        if len(df_proc) > 0 or len(df_child) > 0:
            alerts = detector.detect_anomalies(df_proc, df_child, baselines)
            
            if len(alerts) > 0:
                detector.save_alerts(alerts)
                print("\n" + "="*80)
                print("🚨 ALERTS")
                print("="*80)
                for _, alert in alerts.iterrows():
                    print(f"\n[{alert['severity']}] {alert['process']} on {alert['machine']}")
                    print(f"  PID: {alert['pid']} | User: {alert['user']}")
                    print(f"  Type: {alert['anomaly_type']}")
                    print(f"  Details: {alert['details']}")
    
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
                print(f"   ❌ Error: 2 {e}")
    
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
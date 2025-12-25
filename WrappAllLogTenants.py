from azure.kusto.data import KustoConnectionStringBuilder, KustoClient
import pandas as pd
from collections import defaultdict
import csv
import os
from datetime import datetime, timedelta
import argparse
#import ai_anomaly_detector
import AIModelAndDetect9
from multiprocessing import Process
#from ai_anomaly_detector import execute
from AIModelAndDetect9 import execute
import time
import json, random
import hashlib


# ========= CONFIGURATION =========
CLUSTER = "https://datatubefollowerprdeu.westeurope.kusto.windows.net/"
DATABASE = "9327dadc-4486-45cc-919a-23953d952df4-e8240"
CLUSTERS =  [
            "https://datatubefollowerprdeu.westeurope.kusto.windows.net/"#,
            #"https://datatubeprodeastus2.eastus2.kusto.windows.net/"
            #"https://datatubefollowerprdus.eastus2.kusto.windows.net"
]

DATABASES = [
    "9327dadc-4486-45cc-919a-23953d952df4-e8240",
]

_clients_by_cluster = {}

def get_client(cluster_uri: str) -> KustoClient:
    if cluster_uri not in _clients_by_cluster:
        kcsb = KustoConnectionStringBuilder.with_az_cli_authentication(cluster_uri)
        _clients_by_cluster[cluster_uri] = KustoClient(kcsb)
    return _clients_by_cluster[cluster_uri]

# Auth via Azure CLI (`az login` must be done beforehand)
KCSB = KustoConnectionStringBuilder.with_az_cli_authentication(CLUSTER)

client = KustoClient(KCSB)

# ========= HELPERS =========

def get_all_tables(cluster_uri: str, database: str):
    """
    Returns a list of table names in the database.
    """
    show_tables_query = ".show tables details | where TotalRowCount >100000 and HotRowCount >1000  | project TableName"
    print ("============")
    print (cluster_uri)
    print (database)
    print (show_tables_query)
    print ("============")
    response = client.execute(database, show_tables_query)
    primary = response.primary_results[0]
    #print (primary)
    #print("Primary result type:", type(primary))
    #df = primary.to_dataframe()
    table_names = []
    for row in primary:               # iterate over KustoResultTable
        #print("Row:", row)            # optional: see what a row looks like
        table_names.append(row["TableName"])

    print(f"Found {len(table_names)} tables")
    print(f"[{cluster_uri} / {database}] Found {len(table_names)} tables")
    return table_names


def run_query_on_table(cluster_uri: str, database: str, table_name: str):
    """
    Runs the given KQL snippet on a specific table and returns a DataFrame.
    """
    client = get_client(cluster_uri)
    query = f"""
    database("{database}").table("{table_name}")//{table_name}
    | where action !in ("Block", "Prevent", "Drop") and (app_category has_any ("update","upgrade") and not (app_category has_any ("Spyware","Malicious Sites","Phishing"))
        and appi_name has_any ("Kaspersky","KAV","Sophos","FortiClient","Malwarebytes","Trend Micro","Symantec",
        "Panda Security","Antivirus","Antivir","avast!", "avast","Avira","trendmicro", "acronis","f5","ESET",
        "Defender","Webroot","Bitdefender", "AVG","G Data","Surfshark","Norton","Comodo", "Security", "EDR","XDR"))
    | project appi_name, app_category, app_risk, app_properties
    | summarize make_set(app_category), make_set(app_properties) by appi_name
    """

    print ("==================================")
    print (cluster_uri,database, query)
    print ("==================================")
    
    response = client.execute(database, query)
    primary = response.primary_results[0]
    
     # If primary has 0 rows, skip this table
    if primary.rows_count == 0:
        #print(f"  -> No results in table '{table_name}' (DB: {database}, Cluster: {cluster_uri})")
        return []
        
    print ("==================================")
    print (query)
    print (response)
    print (primary)
    print ("==================================")
    #df = response.to_dataframe()
    

    # Column names as seen by Kusto
    column_names = [c.column_name for c in primary.columns]

    rows = []
    for r in primary:  # each r is a KustoRow-like object
        # build a dict: {column_name: value, ...}
        row_dict = {col: r[i] for i, col in enumerate(column_names)}
        row_dict["TableName"] = table_name
        row_dict["Database"] = database
        row_dict["Cluster"] = cluster_uri
        rows.append(row_dict)
    
    print(f"  -> {len(rows)} results in '{table_name}' (DB: {database}, Cluster: {cluster_uri})")

    return rows






def safe_save_csv(filepath, fieldnames, rows):
    """
    Attempts to save to `filepath`. If the file is locked (Excel), retries using:
    <name>_<timestamp>.csv
    If that fails too, retries with _1, _2, ...
    """
    base, ext = os.path.splitext(filepath)

    # First, try the original file
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved CSV: {filepath}")
        return filepath

    except PermissionError:
        print(f"⚠️  File '{filepath}' is locked. Trying timestamped filename...")

    # Build timestamped name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamped_base = f"{base}_{timestamp}"
    attempt = 0

    while True:
        candidate = (
            f"{timestamped_base}{ext}"
            if attempt == 0
            else f"{timestamped_base}_{attempt}{ext}"
        )
        try:
            with open(candidate, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            print(f"Saved CSV: {candidate}")
            return candidate

        except PermissionError:
            print(f"⚠️  File '{candidate}' is also locked? Retrying...")
            attempt += 1

        except Exception as e:
            print(f"⚠️ Unexpected error while saving '{candidate}': {e}")
            attempt += 1

def collect_for_tenant(cluster, database, tenant, output_dir, mode, lookback_unit='day', 
            lookback_count=1, bootstrap_count=7, delay_seconds=5, offset=0):
                
        print ("============")
                    
        outPath=output_dir+"\\"+tenant+"\\"+"collection"
        print (outPath)
       
        tenant_dir = os.path.join(output_dir, tenant)
            
            # Check if baseline was created (means AI agents found)
        baseline_file = os.path.join(tenant_dir, 'collection','baselines', 'baseline_latest.json')
        print ("Wrapper - baseline file: ", baseline_file)
        
        current_time = datetime.now()
        twenty_four_hours_ago = current_time - timedelta(hours=24)
        
        if os.path.exists(baseline_file):
            if mode=="bootstrap" or mode == "collect":
                file_mod_time = datetime.fromtimestamp(os.path.getmtime(baseline_file))
                  # Get last modification time
                modification_timestamp = os.path.getmtime(baseline_file)
                modification_datetime = datetime.fromtimestamp(modification_timestamp)

                # Get creation time (platform-dependent)
                
                creation_timestamp = os.path.getctime(baseline_file)
                creation_datetime = datetime.fromtimestamp(creation_timestamp)
                if modification_datetime >= twenty_four_hours_ago or creation_datetime >= twenty_four_hours_ago or file_mod_time.date() == current_time.date():    
                #if file_mod_time.date() == datetime.now().date():
                    print(f"⏭️ Wrapper Skipping {tenant} - baseline already created or modified on: ",modification_datetime)
                    return
        print (f"⏭️ Wrapper - creating/addoing baseline for: ",baseline_file)
        print ("============")
        
        AIModelAndDetect9.execute(
            cluster=cluster,
            database=database,
            tenant=tenant,
            output_dir=outPath,
            mode=mode,
            lookback_unit=lookback_unit,
            bootstrap_count=bootstrap_count,
            delay_seconds=delay_seconds,
            baseline_offset=offset
            
            #mode='bootstrap',
            #lookback_unit='hour',
            #bootstrap_count=2,#168,
            #delay_seconds=5
            #lookback_unit='day',      # ← Changed to day
            #bootstrap_count=14,      # ← 7 days
            #delay_seconds=5
        )
        print(f"Wrapper [{tenant}] Data collection complete")
  
    

def main():
    parser = argparse.ArgumentParser(description='AI Agent Anomaly Detection System')
    parser.add_argument('--cluster', required=True, help='Kusto cluster URL')
    parser.add_argument('--database', required=True, help='Database name')
    parser.add_argument('--tenant', required=True, help='Tenant ID')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--mode', choices=['train', 'detect', 'daily_agg', 'bootstrap'], default='daily_agg')
    parser.add_argument('--lookback-unit', choices=['hour', 'day'], default='day')
    parser.add_argument('--lookback-count', type=int, default=1)
    parser.add_argument('--bootstrap-count', type=int, default=7)
    parser.add_argument('--delay-seconds', type=int, default=5)
    parser.add_argument('--offset', type=int, default=0)
    args = parser.parse_args()
    
    #detector = AIAgentAnomalyDetector(args.cluster, args.database, args.tenant, args.output_dir)
    
    
    all_rows = []
    
    # row counts per (cluster, database)
    db_row_counts = {}  # key: (cluster_uri, db) -> row count
    processes = []
    
    # 1. Collect rows from all DBs
    for cluster_uri in CLUSTERS:
        for db in DATABASES:
            key = (cluster_uri, db)
            db_row_counts[key] = 0
            tables = get_all_tables(cluster_uri,db)
            random.shuffle (tables)
            #safe_save_csv("c:\\tmp\\tables",fieldnames=["TableName", "TotalRowCount"],
            
            #tables[0]="ab9f0d29_bb7c_48b6_b3a3_80454fccc83f"
            ####print (tables)
            processes = []
            #i=0
            for i,t in enumerate (tables):
                if i<1000:
                    try:
                        max_parallel=20
                        sleep_time=4*args.bootstrap_count+4*args.lookback_count
                        print(f"{i} Wrapper Running query on table: {t} (DB: {db}, Cluster: {cluster_uri}),  have {max_parallel} processed lounched. Waiting {sleep_time} secs")
                        #input("Press Enter to continue...")
                        p = Process(target=collect_for_tenant, args=(cluster_uri, 
                                                        db, 
                                                        t, 
                                                        args.output_dir, 
                                                        args.mode,
                                                        args.lookback_unit,
                                                        args.lookback_count,
                                                        args.bootstrap_count,
                                                        args.delay_seconds,
                                                        args.offset))
                        
                        p.start()
                        processes.append({'tenant': t, 'process': p})
                        print(f"🚀 {i} Wrapper Launched collection for {t} (PID: {p.pid})")
                   
                        if (i%max_parallel==0):
                            print (f"@@@@@@@@@@@@@@@@ Wrapper: Current:{i} -  have {max_parallel} processed lounched. Waiting {sleep_time} secs")
                            
                            ##wait for all processes to finish before launching next 
                            keepChecking=True
                            while keepChecking:
                                running = sum(1 for p in processes if p['process'].is_alive())
                                if running == 0:
                                    break
                                if running == max_parallel: 
                                    print(f"@@@@@@@@@@@@@@@@ Wrapper {i} {running}/{len(processes)} still running... Sleeping {sleep_time}")
                                    time.sleep(sleep_time)
                                if running < max_parallel:
                                    print (f"Wrapper: Current:{i} -  have {running}/{len(processes)}, continue with next")
                                    time.sleep(5)#delay-seconds'
                                    keepChecking=False
                    
                    except Exception as e:
                        print(f" Wrapper Error querying table {t} in DB {db} on {cluster_uri}: {e}")
    # 2. NOW wait for ALL to complete (AFTER the loop)
                    print(f"\n✅ Wrapper Launched {len(processes)} processes - waiting for completion...")

    # 2. NOW wait for ALL to complete (AFTER the loop)
        print(f"\n✅ Wrapper Launched {len(processes)} processes - waiting for completion...")

            # Wait for all to finish
        while True:
            running = sum(1 for p in processes if p['process'].is_alive())
            if running == 0:
                break
            print(f"Wrapper  {running}/{len(processes)} still running...")
            time.sleep(sleep_time)

        print("\n" + "="*80)
        print("Wrapper SUMMARY")
        print("="*80)
        
        total_tenants = len(processes)
        tenants_with_ai = 0
        total_unique_agents = set()  # (machine, process) tuples
        total_instances = 0
        total_hosts = set()
        total_spawned_processes = set()
        total_baselines = 0
        tenants_with_alerts = 0
        total_alerts = 0

        for p_info in processes:
            tenant = p_info['tenant']
            tenant_dir = os.path.join(args.output_dir, tenant)
            
            # Check if baseline was created (means AI agents found)
            baseline_file = os.path.join(tenant_dir, 'collection','baselines', 'baseline_latest.json')
            #baseline_file = os.path.join(args.output_dir, 'baselines', 'baseline_latest.json')

            
            if os.path.exists(baseline_file):
                tenants_with_ai += 1
                #print ("Wrapper statistics reading: ", baseline_file)
                try:
                    with open(baseline_file, 'r') as f:
                        baseline = json.load(f)
                         
                        #print ("len baseline: ",len(baseline)) 
                    
                    total_baselines += len(baseline)
                    
                    for key_str, data in baseline.items():
                        machine, process, normalized_args,  signer = key_str.split('||')
                        total_unique_agents.add((machine, process, normalized_args))
                        total_hosts.add(machine)
                        #total_spawned_processes.add(data['spawned_processes'])
                        total_instances += data['stats'].get('instances', 0)
                except Exception as e:
                    print(f"  ⚠️  Could not read baseline for {tenant}: {e}")
            
            # Check if alerts were generated
            alerts_file = os.path.join(tenant_dir, 'collection','alerts', 'all_alerts.csv')
            if os.path.exists(alerts_file):
                try:
                    alerts_df = pd.read_csv(alerts_file)
                    if len(alerts_df) > 0:
                        tenants_with_alerts += 1
                        total_alerts += len(alerts_df)
                except:
                    pass

        # Print final summary
        print(f"\n📊 Wrapper Total tenants searched: {total_tenants}")
        print(f"\n🤖 Wrapper AI Agent Discovery:")
        print(f"   Wrapper Tenants with AI agents: {tenants_with_ai}")
        if tenants_with_ai > 0:
            print(f"   Wrapper Unique AI agents: {len(total_unique_agents)} (machine+process combinations)")
            print(f"   Wrapper Total process instances: {total_instances}")
            print(f"   Wrapper Unique hosts with AI: {len(total_hosts)}")
            print(f"   Wrapper Unique spawned: {len(total_spawned_processes)}")
            print(f"   Wrapper Models (baselines) created: {total_baselines}")

        print(f"\n🚨 Wrapper Alerts:")
        print(f"   Wrapper Tenants with alerts: {tenants_with_alerts}")
        print(f"   Wrapper Total alerts generated: {total_alerts}")

        print("\n" + "="*80)
        print("✅ Wrapper All tenants processed!")
        print("="*80)
        
        
        
        

        #print(f"\n✅ Started {len(tables)} parallel collection+training processes!")
        #print(f"Data and models will be saved to: {args.output_dir}\\<tenant_id>\\")
      
      



    

if __name__ == "__main__":
    print ("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL")

    main()

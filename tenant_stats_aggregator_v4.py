
"""
tenant_stats_aggregator.py

Aggregate per-tenant daily/period statistics produced by AIModelAndDetect13 (run per tenant)
into cross-tenant metrics + CSVs + plots.

Directory assumptions (robust / best-effort):
- You pass a root folder that contains one folder per tenant (any depth OK).
- Each tenant folder may contain:
    - stats/collection_summary.csv
    - stats/collection_agents.csv
    - alerts/all_alerts.csv   (or alerts/alerts_*.csv)

Outputs:
- <out_dir>/aggregates/*.csv
- <out_dir>/plots/*.png

Usage:
    from tenant_stats_aggregator import aggregate_all_tenants
    result = aggregate_all_tenants("/path/to/root")
    print(result["files"])
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


# Your category mapping (extend as needed)
import sys


# Default categories (v1) + safe additions (no removals). Override via aggregate_all_tenants(categories=...)
AGENT_CATEGORIES = {
    "browser": {
        "chrome", "msedge", "firefox", "brave", "opera", "chromium",
        # additions
        "overwolfbrowser", "arc", "vivaldi"
    },

    "dev_tool": {
        "python", "node", "npm", "java", "dotnet",
        "code", "clang", "pycharm", "jetbrains","git","ideaiu","phpstorm64",
        "intellijidea","intelliphp","webstorm","rg.exe","rterm",
        # additions from your list
        "datagrip", "rider", "goland", "jetbrains-toolbox", "jetbrains_client",
        "uv", "pip", "rscript", "rsession", "ruby",
        # optional (appears in list, but broad—use only if you want it classified as dev_tool)
        "cmd", "powershell"
    },

    "dedicated_ai": {
        "claude", "chatgpt", "ollama", "lmstudio","llama","tensorflow",
        "open-webui", "openwebui", "vllm", "torchserve", "tritonserver","sllm",
        # additions from your list
        "lm studio", "lm-studio", "ondevice_sllm_agent",
        # optional (if you ever see them)
        "kobold", "oobabooga", "text-generation-webui"
    },

    "communication": {
        "teams", "outlook", "slack", "zoom", "webex", "discord","Zalo",
        # additions (you had these in the original, but keeping)
    },

    "setup": {
        "msiexec", "setup", "update", "installer", "7z",
        # additions from your list
        "uninstall", "un_a", "old-uninstaller", "shipit",
        "googlecloudsdkinstaller",
        # mac-ish installers you had
        "jamf", "cleanmymac"
    },

    "system": {
        "dllhost", "explorer", "docker","system","taskhostw","virtualmachine","certutil",
        # additions from your list / common noise
        "svchost", "searchprotocolhost", "collectguestlogs", "cleanmgr", "compattelrunner",
        "openhandlecollector",
        # docker variants
        "dockerd", "com.docker.backend"
    },

    "shells": {"pwsh", "powershell", "bash", "zsh", "sh","rscript"},

    # NEW
    "gaming": {
        # from your list
        "minecraft", "overwolf", "roblox",
        # common gaming ecosystems (likely to show up later)
        "steam", "epicgames", "battle.net", "battlenet", "riotclient", "riot",
        "ubisoft", "uplay", "origin", "ea", "gog", "galaxyclient",
        # common game capture/overlay tools
        "obs", "streamlabs", "nvidia broadcast", "nvbroadcast", "geforceexperience",
    },
}


DEFAULT_STATS_REL_PATH = Path("stats") / "collection_agents.csv"
DEFAULT_AGENTS_REL = Path("stats") / "collection_agents.csv"
DEFAULT_SUMMARY_REL = Path("stats") / "collection_summary.csv"


def _norm_proc_name(proc: str) -> str:
    """
    Normalize process names for aggregation:
      - lower
      - strip surrounding spaces
      - remove trailing '.exe'
    """
    if proc is None or (isinstance(proc, float) and np.isnan(proc)):
        return "unknown"
    p = str(proc).strip().lower()
    if p.endswith(".exe"):
        p = p[:-4]
    return p or "unknown"


def _proc_category(proc: str, categories: Dict[str, set]) -> str:
    """
    Map process name to a category using substring inclusion.
    Example:
      - 'chrome.exe' → browser
      - 'python3.11' → dev_tool
      - 'ollama-server' → dedicated_ai
    """
    p = _norm_proc_name(proc)

    if p == "unknown":
        return "other"

    for category, needles in categories.items():
        for needle in needles:
            # substring match
            if needle in p:
                return category

    return "other"


def _discover_tenants(root: Path) -> List[Tuple[str, Path]]:
    """
    Discover tenant folders by locating stats/collection_agents.csv or stats/collection_summary.csv.
    Returns (tenant_id, tenant_path).

    Fix: tenant_id is inferred as the FIRST directory component under `root` that contains the stats folder,
    rather than the immediate parent folder name of "stats". This prevents 'always 1 tenant' issues when
    your wrapper writes outputs under a common subfolder name for all tenants.
    """
    root = root.expanduser().resolve()

    # prefer summary if exists, else agents
    matches = list(root.rglob(str(DEFAULT_SUMMARY_REL)))
    if not matches:
        matches = list(root.rglob(str(DEFAULT_AGENTS_REL)))

    tenants: List[Tuple[str, Path]] = []
    for m in matches:
        tenant_path = m.parents[1]  # .../<tenant-ish>/stats/<file>.csv
        try:
            rel = tenant_path.relative_to(root)
            tenant_id = rel.parts[0] if rel.parts else tenant_path.name
        except Exception:
            tenant_id = tenant_path.name
        tenants.append((tenant_id, tenant_path))

    # de-dup by (tenant_id, tenant_path)
    seen = set()
    uniq: List[Tuple[str, Path]] = []
    for tid, tpath in tenants:
        key = (tid, str(tpath))
        if key not in seen:
            uniq.append((tid, tpath))
            seen.add(key)

    return sorted(uniq, key=lambda x: x[0])

def _read_csv_safe(path: Path) -> Optional[pd.DataFrame]:
    try:
        if not path.exists():
            return None
        df = pd.read_csv(path)
        if df.empty:
            return df
        return df
    except Exception:
        return None

def _load_collection_summary(tenant_id: str, tenant_path: Path) -> Optional[pd.DataFrame]:
    """Load stats/collection_summary.csv for a tenant (if exists)."""
    p = tenant_path / "stats" / "collection_summary.csv"
    df = _read_csv_safe(p)
    if df is None or df.empty:
        return None

    if "tenant" not in df.columns:
        df["tenant"] = tenant_id
    else:
        df["tenant"] = df["tenant"].fillna(tenant_id)

    if "period_start" in df.columns:
        df["period_start"] = pd.to_datetime(df["period_start"], errors="coerce")
        df["day"] = df["period_start"].dt.date
    elif "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["day"] = df["timestamp"].dt.date
    else:
        return None

    # expected numeric columns
    for col in ["total_agents", "rows_returned", "agents_added"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    return df

def _load_collection_agents(tenant_id: str, tenant_path: Path) -> Optional[pd.DataFrame]:
    p = tenant_path / "stats" / "collection_agents.csv"
    df = _read_csv_safe(p)
    if df is None:
        return None
    df["tenant"] = tenant_id

    # Period columns might be named 'period_start/period_end' from the earlier patch
    # If not present but 'timestamp' exists, fall back to it.
    if "period_start" in df.columns:
        df["period_start"] = pd.to_datetime(df["period_start"], errors="coerce", utc=False)
        df["day"] = df["period_start"].dt.date
    elif "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=False)
        df["day"] = df["timestamp"].dt.date
    else:
        # can't aggregate by day
        return None

    # Standardize columns used in aggregations
    for c in ["machine", "user", "process", "ai_score"]:
        if c not in df.columns:
            df[c] = np.nan

    df["process_norm"] = df["process"].apply(_norm_proc_name)
    df["category"] = df["process"].apply(lambda x: _proc_category(x, AGENT_CATEGORIES))
    return df

def _load_alerts_flat(tenant_id: str, tenant_path: Path) -> Optional[pd.DataFrame]:
    """
    Load per-tenant alerts. Prefer alerts/all_alerts.csv.
    Fall back to concatenating alerts/alerts_*.csv.

    IMPORTANT: creates df['day'] from df['timestamp'] so daily plots/aggregations work.
    """
    alerts_dir = tenant_path / "alerts"

    master = alerts_dir / "all_alerts.csv"
    df = _read_csv_safe(master)
    if df is None:
        parts = []
        if alerts_dir.exists():
            for p in sorted(alerts_dir.glob("alerts_*.csv")):
                d = _read_csv_safe(p)
                if d is not None and not d.empty:
                    parts.append(d)
        if not parts:
            return None
        df = pd.concat(parts, ignore_index=True)

    if df.empty:
        df["tenant"] = tenant_id
        df["day"] = pd.NaT
        return df

    df["tenant"] = tenant_id

    if "timestamp" not in df.columns:
        # If timestamp missing, can't do daily alert counts reliably
        return None

    ts = df["timestamp"]
    if pd.api.types.is_numeric_dtype(ts):
        # infer unit from magnitude
        s = pd.to_numeric(ts, errors="coerce")
        vmax = s.dropna().max()
        if pd.isna(vmax):
            df["timestamp"] = pd.to_datetime(ts, errors="coerce")
        elif vmax > 1e17:
            df["timestamp"] = pd.to_datetime(s, unit="ns", errors="coerce")
        elif vmax > 1e14:
            df["timestamp"] = pd.to_datetime(s, unit="us", errors="coerce")
        elif vmax > 1e11:
            df["timestamp"] = pd.to_datetime(s, unit="ms", errors="coerce")
        else:
            df["timestamp"] = pd.to_datetime(s, unit="s", errors="coerce")
    else:
        df["timestamp"] = pd.to_datetime(ts, errors="coerce")

    # ✅ This is the missing piece in v4:
    df["day"] = df["timestamp"].dt.date

    # Ensure expected columns exist
    for c in ["severity", "anomaly_type"]:
        if c not in df.columns:
            df[c] = "UNKNOWN"

    return df



def _ensure_out_dirs(out_dir: Path) -> Tuple[Path, Path]:
    agg_dir = out_dir / "aggregates"
    plot_dir = out_dir / "plots"
    agg_dir.mkdir(parents=True, exist_ok=True)
    plot_dir.mkdir(parents=True, exist_ok=True)
    return agg_dir, plot_dir


def _plot_time_series(df: pd.DataFrame, date_col: str, value_col: str, title: str, out_path: Path):
    if df.empty:
        return
    x = pd.to_datetime(df[date_col])
    y = df[value_col].astype(float)
    plt.figure()
    plt.plot(x, y, marker="o")
    plt.title(title)
    plt.xlabel("Date")
    plt.ylabel(value_col)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()




def _plot_hist(series: pd.Series, title: str, xlabel: str, out_path: Path):
    if series is None or series.empty:
        return
    s = pd.to_numeric(series, errors="coerce").dropna()
    if s.empty:
        return
    plt.figure()
    plt.hist(s)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel("count")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()



def aggregate_all_tenants(
    root_dir: str,
    out_dir: Optional[str] = None,
    top_n_processes_per_day: int = 50,
    categories: Optional[Dict[str, set]] = None,
) -> Dict[str, object]:
    """
    Aggregate all tenants under root_dir.

    Parameters
    ----------
    root_dir : str
        Root folder containing per-tenant output folders.
    out_dir : str | None
        Where to write aggregate outputs. Default: <root_dir>/aggregate_report
    top_n_processes_per_day : int
        Keep only top-N processes per day (by instances) in the 'process_daily_topN.csv'.
        Full process table is also written but might be large.
    categories : dict | None
        Override category mapping. If None, uses AGENT_CATEGORIES.

    Returns
    -------
    dict containing:
      - dataframes: dict[str, pd.DataFrame]
      - files: dict[str, str]  (output file paths)
      - tenants: list[str]
    """
    root = Path(root_dir).expanduser().resolve()
    if out_dir is None:
        out = root / "aggregate_report"
    else:
        out = Path(out_dir).expanduser().resolve()

    # allow overriding categories
    global AGENT_CATEGORIES
    if categories is not None:
        AGENT_CATEGORIES = categories

    tenants = _discover_tenants(root)

    summaries_all = []
    agents_all = []
    alerts_all = []
    for tenant_id, tenant_path in tenants:
        df_summary = _load_collection_summary(tenant_id, tenant_path)
        if df_summary is not None and not df_summary.empty:
            summaries_all.append(df_summary)

        df_agents = _load_collection_agents(tenant_id, tenant_path)
        if df_agents is not None and not df_agents.empty:
            agents_all.append(df_agents)

        df_alerts = _load_alerts_flat(tenant_id, tenant_path)
        if df_alerts is not None and not df_alerts.empty:
            alerts_all.append(df_alerts)

    summaries = pd.concat(summaries_all, ignore_index=True) if summaries_all else pd.DataFrame()
    agents = pd.concat(agents_all, ignore_index=True) if agents_all else pd.DataFrame()
    alerts = pd.concat(alerts_all, ignore_index=True) if alerts_all else pd.DataFrame()

    agg_dir, plot_dir = _ensure_out_dirs(out)

    files: Dict[str, str] = {}
    dataframes: Dict[str, pd.DataFrame] = {}

        # ---- De-dupe within tenant-day to avoid multi-run/day inflation ----
    if 'summaries' in locals() and not summaries.empty and {'tenant','day','total_agents'}.issubset(summaries.columns):
        summaries = (
            summaries.dropna(subset=['day'])
                     .groupby(['tenant','day'], as_index=False)
                     .agg(total_agents=('total_agents','max'),
                          rows_returned=('rows_returned','max'),
                          agents_added=('agents_added','max'))
        )

    if not agents.empty and {'tenant','day','machine','process_norm','user'}.issubset(agents.columns):
        # Keep one row per (tenant, day, machine, process, user) (and signer/args if present)
        dedup_cols = ['tenant','day','machine','process_norm','user']
        if 'signer' in agents.columns:
            dedup_cols.append('signer')
        if 'process_args' in agents.columns and agents['process_args'].notna().any():
            dedup_cols.append('process_args')
        agents = agents.drop_duplicates(subset=dedup_cols)

# ---- Daily core metrics (from agents) ----
    if not agents.empty:
        # Prefer per-tenant daily summary (robust tenant counting). Fallback to agents if summary missing.
        if 'summaries' in locals() and not summaries.empty and {'tenant','day','total_agents'}.issubset(summaries.columns):
            daily_tenants_with_agents = (
                summaries[summaries['total_agents'] > 0]
                        .groupby('day')['tenant']
                        .nunique()
                        .reset_index(name='tenants_with_agents')
                        .sort_values('day')
            )
        else:
            daily_tenants_with_agents = (
                agents.dropna(subset=['day'])
                      .groupby('day')['tenant']
                      .nunique()
                      .reset_index(name='tenants_with_agents')
                      .sort_values('day')
            )

        daily_agents = (
            agents.dropna(subset=["day"])
                  .groupby("day")
                  .size()
                  .reset_index(name="agents_instances")
                  .sort_values("day")
        )

        daily_unique_agents = (
            agents.dropna(subset=["day"])
                  .groupby("day")[["tenant", "machine", "process_norm", "user"]]
                  .apply(lambda g: g.drop_duplicates(subset=["tenant", "machine", "process_norm", "user"]).shape[0])
                  .reset_index(name="agents_unique_by_tenant_machine_process_user")
                  .sort_values("day")
        )

        daily_machines_with_agents = (
            agents.dropna(subset=["day"])
                  .groupby("day")["machine"]
                  .nunique()
                  .reset_index(name="machines_with_agents")
                  .sort_values("day")
        )

        # "machines with users per day" interpreted as number of unique (machine,user) pairs with agents
        daily_machine_user_pairs = (
            agents.dropna(subset=["day"])
                  .groupby("day")[["machine", "user"]]
                  .apply(lambda g: g.drop_duplicates().shape[0])
                  .reset_index(name="machine_user_pairs_with_agents")
                  .sort_values("day")
        )

        core_daily = daily_tenants_with_agents.merge(daily_agents, on="day", how="outer") \
                                             .merge(daily_unique_agents, on="day", how="outer") \
                                             .merge(daily_machines_with_agents, on="day", how="outer") \
                                             .merge(daily_machine_user_pairs, on="day", how="outer") \
                                             .fillna(0)

        
        # ---- Process daily WITH category (simple, additive CSV) ----
        # ---- Process daily WITH category (simple, additive CSV) ----
        if not agents.empty and {"day", "tenant", "machine", "user", "process_norm", "category"}.issubset(agents.columns):
            process_daily_with_category = (
                agents.dropna(subset=["day"])
                .groupby(["day", "process_norm", "category"])
                .agg(
                    tenants=("tenant", "nunique"),
                    instances=("process_norm", "size"),
                    machines=("machine", "nunique"),
                    users=("user", "nunique"),
                )
                .reset_index()
                .sort_values(["day", "instances"], ascending=[True, False])
            )

            process_daily_with_category_path = agg_dir / "process_daily_with_category.csv"
            process_daily_with_category.to_csv(process_daily_with_category_path, index=False)

        
        
        core_daily_path = agg_dir / "core_daily_metrics.csv"
        core_daily.to_csv(core_daily_path, index=False)
        files["core_daily_metrics"] = str(core_daily_path)
        dataframes["core_daily_metrics"] = core_daily

        _plot_time_series(core_daily, "day", "tenants_with_agents",
                          "Number of tenants with agents per day", plot_dir / "tenants_with_agents_per_day.png")
        files["plot_tenants_with_agents"] = str(plot_dir / "tenants_with_agents_per_day.png")

        _plot_time_series(core_daily, "day", "agents_instances",
                          "Number of agent instances per day", plot_dir / "agents_instances_per_day.png")
        files["plot_agents_instances"] = str(plot_dir / "agents_instances_per_day.png")

        _plot_time_series(core_daily, "day", "machines_with_agents",
                          "Number of machines with agents per day", plot_dir / "machines_with_agents_per_day.png")
        files["plot_machines_with_agents"] = str(plot_dir / "machines_with_agents_per_day.png")

        _plot_time_series(core_daily, "day", "machine_user_pairs_with_agents",
                          "Number of machine-user pairs with agents per day", plot_dir / "machine_user_pairs_per_day.png")
        files["plot_machine_user_pairs"] = str(plot_dir / "machine_user_pairs_per_day.png")

        # ---- Process daily aggregation ----
        proc_daily = (
            agents.dropna(subset=["day"])
                  .groupby(["day", "process_norm"])
                  .agg(
                      tenants=("tenant", "nunique"),
                      instances=("process_norm", "size"),
                      machines=("machine", "nunique"),
                      users=("user", "nunique"),
                  )
                  .reset_index()
                  .sort_values(["day", "instances"], ascending=[True, False])
        )
        proc_daily_path = agg_dir / "process_daily_full.csv"
        proc_daily.to_csv(proc_daily_path, index=False)
        files["process_daily_full"] = str(proc_daily_path)
        dataframes["process_daily_full"] = proc_daily

        # Top-N per day (practical for "massy" outputs)
        if top_n_processes_per_day is not None and top_n_processes_per_day > 0:
            proc_daily_top = (
                proc_daily.groupby("day", group_keys=False)
                          .apply(lambda g: g.head(top_n_processes_per_day))
                          .reset_index(drop=True)
            )
            proc_top_path = agg_dir / f"process_daily_top{top_n_processes_per_day}.csv"
            proc_daily_top.to_csv(proc_top_path, index=False)
            files["process_daily_topN"] = str(proc_top_path)
            dataframes["process_daily_topN"] = proc_daily_top

        # ---- Category daily aggregation ----
        cat_daily = (
            agents.dropna(subset=["day"])
                  .groupby(["day", "category"])
                  .agg(
                      tenants=("tenant", "nunique"),
                      instances=("category", "size"),
                      machines=("machine", "nunique"),
                      users=("user", "nunique"),
                  )
                  .reset_index()
                  .sort_values(["day", "instances"], ascending=[True, False])
        )
        cat_daily_path = agg_dir / "category_daily.csv"
        cat_daily.to_csv(cat_daily_path, index=False)
        files["category_daily"] = str(cat_daily_path)
        dataframes["category_daily"] = cat_daily

        # Category plot: pivot to time-series per category (many lines possible; keep manageable by top categories overall)
        top_cats = (
            cat_daily.groupby("category")["instances"].sum()
            .sort_values(ascending=False)
            .head(8)
            .index
            .tolist()
        )
        cat_pivot = (cat_daily[cat_daily["category"].isin(top_cats)]
                     .pivot_table(index="day", columns="category", values="instances", aggfunc="sum", fill_value=0)
                     .sort_index())
        if not cat_pivot.empty:
            plt.figure()
            for col in cat_pivot.columns:
                plt.plot(pd.to_datetime(cat_pivot.index), cat_pivot[col], marker="o", label=col)
            plt.title("Agent categories per day (top categories)")
            plt.xlabel("Date")
            plt.ylabel("instances")
            plt.xticks(rotation=45, ha="right")
            plt.legend()
            plt.tight_layout()
            cat_plot_path = plot_dir / "categories_per_day.png"
            plt.savefig(cat_plot_path, dpi=150)
            plt.close()
            files["plot_categories_per_day"] = str(cat_plot_path)

    # ---- Agent lifetime stats (first_seen -> last_seen) ----
    if not agents.empty and 'day' in agents.columns:
        key_cols = ['tenant', 'machine', 'process_norm', 'user']
        if 'signer' in agents.columns:
            key_cols.append('signer')
        if 'process_args' in agents.columns and agents['process_args'].notna().any():
            key_cols.append('process_args')

        life = (
            agents.dropna(subset=['day'])
                  .groupby(key_cols)['day']
                  .agg(first_seen='min', last_seen='max')
                  .reset_index()
        )
        life['first_seen'] = pd.to_datetime(life['first_seen'])
        life['last_seen'] = pd.to_datetime(life['last_seen'])
        life['lifetime_days'] = (life['last_seen'] - life['first_seen']).dt.days + 1

        life_path = agg_dir / 'agent_lifetimes.csv'
        life.to_csv(life_path, index=False)
        files['agent_lifetimes'] = str(life_path)
        dataframes['agent_lifetimes'] = life

        life_summary = pd.DataFrame([{
            'count': int(life['lifetime_days'].count()),
            'min_days': int(life['lifetime_days'].min()) if not life.empty else 0,
            'max_days': int(life['lifetime_days'].max()) if not life.empty else 0,
            'median_days': float(life['lifetime_days'].median()) if not life.empty else 0,
            'mean_days': float(life['lifetime_days'].mean()) if not life.empty else 0,
        }])
        life_summary_path = agg_dir / 'agent_lifetime_summary.csv'
        life_summary.to_csv(life_summary_path, index=False)
        files['agent_lifetime_summary'] = str(life_summary_path)
        dataframes['agent_lifetime_summary'] = life_summary

        _plot_hist(life['lifetime_days'], 'Agent lifetime distribution', 'lifetime_days',
                   plot_dir / 'agent_lifetime_hist.png')
        files['plot_agent_lifetime_hist'] = str(plot_dir / 'agent_lifetime_hist.png')

        # New vs disappearing per day (based on first/last seen)
        new_agents = (
            life.groupby(life['first_seen'].dt.date)
                .size()
                .reset_index(name='new_agents')
                .rename(columns={'first_seen': 'day'})
        )
        disappearing_agents = (
            life.groupby(life['last_seen'].dt.date)
                .size()
                .reset_index(name='disappearing_agents')
                .rename(columns={'last_seen': 'day'})
        )
        new_vs_gone = (
            new_agents.merge(disappearing_agents, on='day', how='outer')
                      .fillna(0)
                      .sort_values('day')
        )
        new_vs_gone_path = agg_dir / 'agents_new_vs_disappearing_daily.csv'
        new_vs_gone.to_csv(new_vs_gone_path, index=False)
        files['agents_new_vs_disappearing_daily'] = str(new_vs_gone_path)
        dataframes['agents_new_vs_disappearing_daily'] = new_vs_gone

        _plot_time_series(new_vs_gone, 'day', 'new_agents',
                          'New agents per day (first seen)', plot_dir / 'new_agents_per_day.png')
        files['plot_new_agents_per_day'] = str(plot_dir / 'new_agents_per_day.png')

        _plot_time_series(new_vs_gone, 'day', 'disappearing_agents',
                          'Disappearing agents per day (last seen)', plot_dir / 'disappearing_agents_per_day.png')
        files['plot_disappearing_agents_per_day'] = str(plot_dir / 'disappearing_agents_per_day.png')

    # ---- Process daily WITH category + reason (additive output) ----
    # (Put this right after you have `agents` ready with: day, tenant, machine, user, process_norm, category)
    reason_col = None
    for c in ["reason_added", "reason", "add_reason", "baseline_reason"]:
        if c in agents.columns:
            reason_col = c
            break

    if reason_col is not None:
        def _top_reason(series: pd.Series) -> str:
            s = series.dropna().astype(str).str.strip()
            if s.empty:
                return ""
            return s.value_counts().index[0]

        process_daily_with_category_and_reason = (
            agents.dropna(subset=["day"])
            .groupby(["day", "process_norm", "category"])
            .agg(
                tenants=("tenant", "nunique"),
                instances=("process_norm", "size"),
                machines=("machine", "nunique"),
                users=("user", "nunique"),
                top_reason=(reason_col, _top_reason),
            )
            .reset_index()
            .sort_values(["day", "instances"], ascending=[True, False])
        )

        out_path = agg_dir / "process_daily_with_category_and_reason.csv"
        process_daily_with_category_and_reason.to_csv(out_path, index=False)
    else:
        # If you want, you can print a one-liner instead of silently skipping:
        # print("No reason column found in collection_agents.csv; skipped process_daily_with_category_and_reason.csv")
        pass


    # ---- Alerts / Events / Info daily (by anomaly_type prefix, NOT severity) ----
    if not alerts.empty and "anomaly_type" in alerts.columns and "day" in alerts.columns:
        alerts["anomaly_type"] = alerts["anomaly_type"].astype(str)

        def _kind_from_anomaly_type(a: str) -> str:
            a = ("" if a is None else str(a)).strip().upper()
            if a.startswith("ALERT_"):
                return "alert"
            if a.startswith("EVENTS"):
                return "event"
            if a.startswith("LOG_"):
                return "info"
            print (f"alert: {a}")
            return "other"

        alerts["kind"] = alerts["anomaly_type"].apply(_kind_from_anomaly_type)

        alerts_daily = (
            alerts.dropna(subset=["day"])
            .groupby(["day", "kind"])
            .size()
            .reset_index(name="count")
        )

        alerts_daily_pivot = (
            alerts_daily.pivot_table(index="day", columns="kind", values="count", aggfunc="sum", fill_value=0)
            .reset_index()
            .sort_values("day")
        )

        # Always include columns even if missing in data (stable schema)
        for col in ["alert", "event", "info", "other"]:
            if col not in alerts_daily_pivot.columns:
                alerts_daily_pivot[col] = 0

        out_path = agg_dir / "alerts_events_info_daily.csv"
        alerts_daily_pivot[["day", "alert", "event", "info", "other"]].to_csv(out_path, index=False)

        # Plots (separate files, like you requested)
        _plot_time_series(alerts_daily_pivot, "day", "alert",
                          "Number of alerts per day (ALERT_*)", plot_dir / "alerts_per_day.png")
        _plot_time_series(alerts_daily_pivot, "day", "event",
                          "Number of events per day (EVENT_*)", plot_dir / "events_per_day.png")
        _plot_time_series(alerts_daily_pivot, "day", "info",
                          "Number of info logs per day (LOG_*)", plot_dir / "info_per_day.png")

    
    
    '''
    # ---- Alerts metrics (from alerts) ----
    if not alerts.empty:
        alerts["anomaly_type"] = alerts["anomaly_type"].astype(str)
        alerts["severity"] = alerts["severity"].astype(str)

        def _classify(row) -> str:
            t = row["anomaly_type"]
            s = row["severity"].upper()
            if t.startswith("ALERT_"):
                return "alert"
            if t.startswith("EVENT_"):
                return "event"
            if s == "INFO" or t.startswith("INFO_"):
                return "info"
            return "other"

        alerts["kind"] = alerts.apply(_classify, axis=1)

        alerts_daily = (
            alerts.dropna(subset=["day"])
                  .groupby(["day", "kind"])
                  .size()
                  .reset_index(name="count")
        )
        alerts_daily_pivot = (
            alerts_daily.pivot_table(index="day", columns="kind", values="count", aggfunc="sum", fill_value=0)
                        .reset_index()
                        .sort_values("day")
        )
        alerts_path = agg_dir / "alerts_daily.csv"
        alerts_daily_pivot.to_csv(alerts_path, index=False)
        files["alerts_daily"] = str(alerts_path)
        dataframes["alerts_daily"] = alerts_daily_pivot

        # plots for alerts/events/info if exist
        for col in [c for c in ["alert", "event", "info"] if c in alerts_daily_pivot.columns]:
            _plot_time_series(alerts_daily_pivot, "day", col, f"Number of {col}s per day", plot_dir / f"{col}s_per_day.png")
            files[f"plot_{col}s_per_day"] = str(plot_dir / f"{col}s_per_day.png")
    '''
    return {
        "tenants": [t for t, _ in tenants],
        "dataframes": dataframes,
        "files": files,
        "out_dir": str(out),
        "notes": {
            "process_daily_full_may_be_large": True,
            "process_daily_topN_written": bool(top_n_processes_per_day and top_n_processes_per_day > 0),
            "alerts_kind_logic": "kind=alert if anomaly_type starts with ALERT_; kind=event if starts with EVENT_; kind=info if severity==INFO or anomaly_type starts with INFO_",
        }
    }

if __name__ == '__main__':
    args = sys.argv
    print (globals()[sys.argv[1]] (*args[2:]))
    
#C:\Users\tamaral\AppData\Local\Programs\Python\Python313>python.exe c:\Data\Data\scripts\AIAnomalyDetector\tenant_stats_aggregator_V2.py aggregate_all_tenants  c:\tmp\ai_detections_data31
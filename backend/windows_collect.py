import base64
import json
import platform
import re
import socket
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def collect_process_snapshot(*, sample_ms: int = 200, limit: int = 250, timeout_s: int = 10) -> Dict[str, Any]:
    """タスクマネージャ相当のプロセス情報を収集して、簡易分析を返す。

    Windows 環境ではプロセス属性の取得が遅くなるケースがあるため、timeout_s を超えた場合は
    途中までの（部分）結果を返す。
    """

    hostname = socket.gethostname()
    collected_at = _now_iso()

    # CPU% をそれっぽく取るために、interval=None の事前呼び出し→sleep→再呼び出し
    try:
        psutil.cpu_percent(interval=None)
    except Exception:
        pass

    start_monotonic = time.monotonic()

    # cpu_percent をそれっぽくするための priming
    procs: List[psutil.Process] = []
    for proc in psutil.process_iter(attrs=["pid", "name"], ad_value=None):
        procs.append(proc)
        try:
            proc.cpu_percent(interval=None)
        except Exception:
            pass

    sleep_s = max(0.05, min(2.0, sample_ms / 1000.0))
    time.sleep(sleep_s)

    processes: List[Dict[str, Any]] = []
    processed = 0
    timed_out = False

    for proc in procs:
        if time.monotonic() - start_monotonic > max(1, int(timeout_s)):
            timed_out = True
            break
        try:
            info: Dict[str, Any] = {}
            info["pid"] = proc.pid
            # 重い属性（username/status/create_time など）は全件取得すると遅いので省略。
            info["username"] = None

            with proc.oneshot():
                try:
                    info["name"] = proc.name()
                except Exception:
                    info["name"] = None

                try:
                    info["cpu_percent"] = float(proc.cpu_percent(interval=None))
                except Exception:
                    info["cpu_percent"] = None

                try:
                    mem = proc.memory_info()
                    info["memory_rss"] = int(getattr(mem, "rss", 0))
                except Exception:
                    info["memory_rss"] = None

                try:
                    info["memory_percent"] = float(proc.memory_percent())
                except Exception:
                    info["memory_percent"] = None

            processes.append(info)
            processed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    # 上位だけ username を後付け（必要最小限）
    def _enrich_username(items: List[Dict[str, Any]]) -> None:
        for p in items:
            pid = p.get("pid")
            if not isinstance(pid, int):
                continue
            try:
                pr = psutil.Process(pid)
                with pr.oneshot():
                    p["username"] = pr.username()
            except Exception:
                p["username"] = None

    # 並び替え（CPU%→RSS）
    processes_sorted = sorted(
        processes,
        key=lambda p: (
            (p.get("cpu_percent") if isinstance(p.get("cpu_percent"), (int, float)) else 0.0),
            (p.get("memory_rss") if isinstance(p.get("memory_rss"), int) else 0),
        ),
        reverse=True,
    )
    processes_sorted = processes_sorted[: max(1, min(2000, limit))]

    top_cpu = sorted(
        processes,
        key=lambda p: (p.get("cpu_percent") if isinstance(p.get("cpu_percent"), (int, float)) else 0.0),
        reverse=True,
    )[:50]
    top_mem = sorted(
        processes,
        key=lambda p: (p.get("memory_rss") if isinstance(p.get("memory_rss"), int) else 0),
        reverse=True,
    )[:50]

    _enrich_username(top_cpu)
    _enrich_username(top_mem)

    high_cpu = [p for p in processes if (p.get("cpu_percent") or 0) >= 50]
    high_mem = [p for p in processes if (p.get("memory_rss") or 0) >= 1_000_000_000]  # >=1GB

    summary = {
        "collected_at": collected_at,
        "hostname": hostname,
        "sample_ms": int(sample_ms),
        "process_count": len(processes),
        "processed_count": processed,
        "timed_out": timed_out,
        "top_cpu": top_cpu,
        "top_memory_rss": top_mem,
        "high_cpu_count": len(high_cpu),
        "high_memory_count": len(high_mem),
    }

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "summary": summary,
        "processes": processes_sorted,
    }


def collect_windows_services(*, limit: int = 500, timeout_s: int = 10) -> Dict[str, Any]:
    """タスクマネージャーの「サービス」相当の一覧を返す（Windows専用）。"""

    hostname = socket.gethostname()
    collected_at = _now_iso()

    if not is_windows():
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": "Not running on Windows"},
            "services": [],
        }

    if not hasattr(psutil, "win_service_iter"):
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": "psutil.win_service_iter is not available"},
            "services": [],
        }

    limit_i = max(1, min(5000, _safe_int(limit, 500)))
    timeout_i = max(1, min(60, _safe_int(timeout_s, 10)))

    start_monotonic = time.monotonic()
    timed_out = False

    services: List[Dict[str, Any]] = []
    for svc in psutil.win_service_iter():
        if len(services) >= limit_i:
            break
        if time.monotonic() - start_monotonic > timeout_i:
            timed_out = True
            break
        try:
            d = svc.as_dict()
            if not isinstance(d, dict):
                continue
            services.append(
                {
                    "name": d.get("name"),
                    "display_name": d.get("display_name"),
                    "status": d.get("status"),
                    "start_type": d.get("start_type"),
                    "pid": d.get("pid"),
                    "username": d.get("username"),
                    "binpath": d.get("binpath"),
                }
            )
        except Exception:
            continue

    # running を先頭に
    services.sort(
        key=lambda s: (
            0 if str(s.get("status") or "").lower() == "running" else 1,
            str(s.get("name") or ""),
        )
    )

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "summary": {
            "count": len(services),
            "limit": limit_i,
            "timed_out": timed_out,
        },
        "services": services,
    }


def collect_startup_apps(*, limit: int = 200, timeout_s: int = 15) -> Dict[str, Any]:
    """タスクマネージャーの「スタートアップ」相当（Windows専用）。

    できるだけタスクマネージャーに近い情報を返すため、複数ソースを統合する:
    - Win32_StartupCommand（WMI/CIM）
    - レジストリ Run/RunOnce（HKCU/HKLM, WOW6432Node 含む）
    - スタートアップフォルダ（ユーザー/共通）
    - StartupApproved（有効/無効の推定）
    """

    hostname = socket.gethostname()
    collected_at = _now_iso()

    if not is_windows():
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": "Not running on Windows"},
            "startup_apps": [],
        }

    limit_i = max(1, min(5000, _safe_int(limit, 200)))
    timeout_i = max(5, min(120, _safe_int(timeout_s, 15)))

    ps_parts = [
        "$ErrorActionPreference = 'SilentlyContinue'; ",
        "$items = @(); $seen = @{}; ",
        "$approved = @{}; ",
        "$keys = @('Run','Run32','StartupFolder','StartupFolder32','Startup','Startup32'); ",
        "foreach ($hive in @('HKCU','HKLM')) { ",
        "  foreach ($k in $keys) { ",
        "    $sub = ('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\' + $k); ",
        "    $root = 'HKCU:'; if ($hive -eq 'HKLM') { $root = 'HKLM:' }; ",
        "    $path = ($root + '\\' + $sub); ",
        "    try { ",
        "      if (Test-Path $path) { ",
        "        $rk = Get-Item -LiteralPath $path; ",
        "        foreach ($n in $rk.GetValueNames()) { ",
        "          $v = $rk.GetValue($n, $null, 'DoNotExpandEnvironmentNames'); ",
        "          $b0 = $null; if ($v -is [byte[]] -and $v.Length -ge 1) { $b0 = [int]$v[0] }; ",
        "          $st = 'unknown'; if ($b0 -eq 2) { $st = 'enabled' } elseif ($b0 -eq 3) { $st = 'disabled' }; ",
        "          $ak = ($hive + '|' + $k + '|' + $n); $approved[$ak] = $st; ",
        "        } ",
        "      } ",
        "    } catch { } ",
        "  } ",
        "}; ",
        "function Add-Item($name,$command,$location,$user,$source,$approvedHive,$approvedKey,$approvedName) { ",
        "  if (-not $name) { return }; ",
        "  $k = (([string]$name).ToLowerInvariant() + '|' + ([string]$command).ToLowerInvariant() + '|' + ([string]$location).ToLowerInvariant() + '|' + ([string]$user).ToLowerInvariant()); ",
        "  if ($script:seen.ContainsKey($k)) { return }; $script:seen[$k] = $true; ",
        "  $enabled = 'unknown'; ",
        "  if ($approvedHive -and $approvedKey -and $approvedName) { ",
        "    $ak = ([string]$approvedHive + '|' + [string]$approvedKey + '|' + [string]$approvedName); ",
        "    if ($script:approved.ContainsKey($ak)) { $enabled = $script:approved[$ak] } ",
        "  }; ",
        "  $script:items += [pscustomobject]@{ name=$name; command=$command; location=$location; user=$user; source=$source; enabled=$enabled; approved_hive=$approvedHive; approved_key=$approvedKey; approved_name=$approvedName }; ",
        "}; ",
        "try { ",
        "  $cims = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue; ",
        "  foreach ($c in @($cims)) { Add-Item $c.Name $c.Command $c.Location $c.User 'cim' $null $null $null } ",
        "} catch { } ",
        "$regTargets = @(); ",
        "$regTargets += @{ hive='HKCU'; base='Software\\Microsoft\\Windows\\CurrentVersion'; name='Run'; approved='Run' }; ",
        "$regTargets += @{ hive='HKCU'; base='Software\\Microsoft\\Windows\\CurrentVersion'; name='RunOnce'; approved='Run' }; ",
        "$regTargets += @{ hive='HKLM'; base='Software\\Microsoft\\Windows\\CurrentVersion'; name='Run'; approved='Run' }; ",
        "$regTargets += @{ hive='HKLM'; base='Software\\Microsoft\\Windows\\CurrentVersion'; name='RunOnce'; approved='Run' }; ",
        "$regTargets += @{ hive='HKLM'; base='Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion'; name='Run'; approved='Run32' }; ",
        "$regTargets += @{ hive='HKLM'; base='Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion'; name='RunOnce'; approved='Run32' }; ",
        "foreach ($t in $regTargets) { ",
        "  $root = 'HKCU:'; if ($t.hive -eq 'HKLM') { $root = 'HKLM:' }; ",
        "  $path = ($root + '\\' + $t.base + '\\' + $t.name); ",
        "  try { ",
        "    if (Test-Path $path) { ",
        "      $rk = Get-Item -LiteralPath $path; ",
        "      foreach ($n in $rk.GetValueNames()) { ",
        "        $v = $rk.GetValue($n, $null, 'DoNotExpandEnvironmentNames'); ",
        "        $cmd = $null; if ($v -ne $null) { $cmd = [string]$v }; ",
        "        $loc = ($t.hive + '\\' + $t.base + '\\' + $t.name); ",
        "        Add-Item $n $cmd $loc $t.hive ('registry:' + $t.name) $t.hive $t.approved $n; ",
        "      } ",
        "    } ",
        "  } catch { } ",
        "}; ",
        "try { ",
        "  $folders = @(); ",
        "  $folders += @{ path = [Environment]::GetFolderPath('Startup'); user='HKCU' }; ",
        "  $folders += @{ path = [Environment]::GetFolderPath('CommonStartup'); user='HKLM' }; ",
        "  foreach ($f in $folders) { ",
        "    if ($f.path -and (Test-Path -LiteralPath $f.path)) { ",
        "      foreach ($fi in Get-ChildItem -LiteralPath $f.path -File -ErrorAction SilentlyContinue) { ",
        "        $nm = $fi.BaseName; $cmd = $fi.FullName; ",
        "        Add-Item $nm $cmd $f.path $f.user 'startup_folder' $f.user 'StartupFolder' $fi.Name; ",
        "      } ",
        "    } ",
        "  } ",
        "} catch { } ",
        f"$dedup = @($items) | Select-Object -First {limit_i}; ",
        "$enabledCount = (@($dedup | Where-Object { $_.enabled -eq 'enabled' })).Count; ",
        "$disabledCount = (@($dedup | Where-Object { $_.enabled -eq 'disabled' })).Count; ",
        "$unknownCount = (@($dedup | Where-Object { $_.enabled -ne 'enabled' -and $_.enabled -ne 'disabled' })).Count; ",
        f"$out = [pscustomobject]@{{ summary = @{{ count = $dedup.Count; enabled = $enabledCount; disabled = $disabledCount; unknown = $unknownCount; limit = {limit_i} }}; startup_apps = $dedup }}; ",
        "$json = $out | ConvertTo-Json -Depth 6 -Compress; ",
        "if (-not $json) { $json = '{}' }; ",
        "[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))",
    ]

    ps = "".join(ps_parts)

    data, err = _run_powershell_base64_json(ps, timeout_i)
    if err:
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": err},
            "startup_apps": [],
        }

    if not isinstance(data, dict):
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": "unexpected payload"},
            "startup_apps": [],
        }

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {"count": 0, "limit": limit_i}
    apps = data.get("startup_apps") if isinstance(data.get("startup_apps"), list) else []

    normalized: List[Dict[str, Any]] = []
    for a in apps:
        if not isinstance(a, dict):
            continue
        normalized.append(
            {
                "name": a.get("name") or a.get("Name"),
                "command": a.get("command") or a.get("Command"),
                "location": a.get("location") or a.get("Location"),
                "user": a.get("user") or a.get("User"),
                "source": a.get("source"),
                "enabled": a.get("enabled"),
                "approved_hive": a.get("approved_hive"),
                "approved_key": a.get("approved_key"),
                "approved_name": a.get("approved_name"),
            }
        )

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "summary": summary,
        "startup_apps": normalized,
    }


def _run_powershell_json(command: str, timeout_s: int) -> Tuple[Optional[Any], Optional[str]]:
    """PowerShell を実行して JSON を受け取る。"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_s,
        )
    except Exception as e:
        return None, f"powershell execution failed: {e}"

    if result.returncode != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        return None, f"powershell returned {result.returncode}: {err}"

    raw = (result.stdout or "").strip()
    if not raw:
        return [], None

    try:
        return json.loads(raw), None
    except Exception as e:
        return None, f"failed to parse JSON: {e}"


def _run_powershell_base64_json(command: str, timeout_s: int) -> Tuple[Optional[Any], Optional[str]]:
    """PowerShell を実行して Base64(JSON) を受け取る。

    Windows PowerShell の出力エンコーディング差異や、メッセージ本文に含まれる文字が原因で
    JSON が壊れるケースがあるため、PowerShell 側で UTF-8 の Base64 にしてから受け取る。
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout_s,
        )
    except Exception as e:
        return None, f"powershell execution failed: {e}"

    if result.returncode != 0:
        err = (result.stderr or "").strip() or (result.stdout or "").strip()
        return None, f"powershell returned {result.returncode}: {err}"

    raw = (result.stdout or "").strip()
    if not raw:
        return [], None

    try:
        data = base64.b64decode(raw.encode("ascii"), validate=False)
        text = data.decode("utf-8", errors="strict")
        return json.loads(text), None
    except Exception as e:
        return None, f"failed to decode base64 json: {e}"


def collect_eventlog(
    *,
    log_name: str = "System",
    since_hours: int = 24,
    max_events: int = 200,
    timeout_s: int = 30,
) -> Dict[str, Any]:
    """イベントビューア相当のイベントログを収集して簡易分析を返す。"""

    hostname = socket.gethostname()
    collected_at = _now_iso()

    if not is_windows():
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "log_name": log_name,
            "since_hours": int(since_hours),
            "max_events": int(max_events),
            "summary": {"error": "Not running on Windows"},
            "events": [],
        }

    # PowerShell の単一引用符や特殊文字でコマンドが壊れたり注入にならないよう、ログ名を制限する。
    # 例: Microsoft-Windows-Windows Defender/Operational
    log_name = (log_name or "").strip()
    if not log_name:
        log_name = "System"
    if not re.fullmatch(r"[A-Za-z0-9 _\-\/().]+", log_name):
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "log_name": log_name,
            "since_hours": int(since_hours),
            "max_events": int(max_events),
            "summary": {
                "error": "Invalid log_name. Allowed chars: letters, numbers, space, _-/.()",
            },
            "events": [],
        }

    since_hours_i = max(1, min(24 * 365, _safe_int(since_hours, 24)))
    max_events_i = max(1, min(5000, _safe_int(max_events, 200)))

    # ConvertTo-Json の出力が文字コード/エスケープの影響で壊れることがあるため、UTF-8 Base64 で返す
    ps = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        f"$since=(Get-Date).AddHours(-{since_hours_i}); "
        # イベントが0件、またはログが存在しない場合でも例外で止めず空配列として扱う
        "try { "
        f"  $events = Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime=$since}} -MaxEvents {max_events_i} -ErrorAction Stop; "
        "} catch { "
        "  $events = @(); "
        "}; "
        "$items = @($events) | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, LogName, MachineName, Message; "
        "$json = @($items) | ConvertTo-Json -Depth 4 -Compress; "
        "if (-not $json) { $json = '[]' }; "
        "[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))"
    )

    data, err = _run_powershell_base64_json(ps, timeout_s=timeout_s)
    if err:
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "log_name": log_name,
            "since_hours": since_hours_i,
            "max_events": max_events_i,
            "summary": {"error": err},
            "events": [],
        }

    # 0件/1件/複数件を配列に統一
    events: List[Dict[str, Any]]
    if data is None:
        events = []
    elif isinstance(data, list):
        events = [e for e in data if isinstance(e, dict)]
    elif isinstance(data, dict):
        events = [data]
    else:
        events = []

    summary = analyze_eventlog(events)
    summary.update(
        {
            "collected_at": collected_at,
            "hostname": hostname,
            "log_name": log_name,
            "since_hours": since_hours_i,
            "max_events": max_events_i,
        }
    )

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "log_name": log_name,
        "since_hours": since_hours_i,
        "max_events": max_events_i,
        "summary": summary,
        "events": events,
    }


def collect_eventlog_log_list(*, limit: int = 200, timeout_s: int = 30) -> Dict[str, Any]:
    """利用可能なイベントログの一覧を返す（イベントビューアの「ログ」一覧相当）。"""

    hostname = socket.gethostname()
    collected_at = _now_iso()

    if not is_windows():
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": "Not running on Windows"},
            "logs": [],
        }

    limit_i = max(1, min(2000, _safe_int(limit, 200)))
    timeout_i = max(5, min(120, _safe_int(timeout_s, 30)))

    # ログ数が多い環境があるため、先頭 limit 件のみ返す
    ps = (
        f"$logs = Get-WinEvent -ListLog * | Sort-Object LogName | Select-Object -First {limit_i} "
        "| Select-Object LogName, LogType, IsEnabled, RecordCount, FileSize, LastWriteTime; "
        "$json = @($logs) | ConvertTo-Json -Depth 4 -Compress; "
        "[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))"
    )

    data, err = _run_powershell_base64_json(ps, timeout_i)
    if err:
        return {
            "collected_at": collected_at,
            "hostname": hostname,
            "summary": {"error": err},
            "logs": [],
        }

    logs: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for x in data:
            if isinstance(x, dict):
                logs.append(x)
    elif isinstance(data, dict):
        logs.append(data)

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "summary": {"count": len(logs), "limit": limit_i},
        "logs": logs,
    }


def analyze_eventlog(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    levels = Counter()
    providers = Counter()
    ids = Counter()

    latest_time: Optional[str] = None
    error_samples: List[Dict[str, Any]] = []

    for e in events:
        lvl = e.get("LevelDisplayName")
        if isinstance(lvl, str) and lvl:
            levels[lvl] += 1

        prov = e.get("ProviderName")
        if isinstance(prov, str) and prov:
            providers[prov] += 1

        eid = e.get("Id")
        if eid is not None:
            ids[str(eid)] += 1

        tc = e.get("TimeCreated")
        if isinstance(tc, str) and tc:
            # ざっくり latest を取る（フォーマット混在を想定して文字列比較はしない）
            if latest_time is None:
                latest_time = tc

        if (isinstance(lvl, str) and lvl.lower() in ("error", "critical", "warning")) and len(error_samples) < 50:
            error_samples.append(
                {
                    "TimeCreated": e.get("TimeCreated"),
                    "Id": e.get("Id"),
                    "LevelDisplayName": e.get("LevelDisplayName"),
                    "ProviderName": e.get("ProviderName"),
                    "Message": (e.get("Message") or "")[:300],
                }
            )

    return {
        "event_count": len(events),
        "level_counts": dict(levels),
        "top_providers": providers.most_common(10),
        "top_event_ids": ids.most_common(10),
        "latest_time_seen": latest_time,
        "error_samples": error_samples,
    }


def collect_app_usage_sample(*, timeout_s: int = 10, limit: int = 2000) -> Dict[str, Any]:
    """プロセスの累積カウンタを収集（アプリ履歴の“材料”）。

    - CPU時間: psutil.Process.cpu_times() (user/system)
    - IO: psutil.Process.io_counters() (read_bytes/write_bytes)
    これらは“累積値”なので、2つのサンプルの差分を取ると期間中の使用量になる。
    """

    hostname = socket.gethostname()
    collected_at = _now_iso()

    start_monotonic = time.monotonic()
    limit_i = max(1, min(5000, _safe_int(limit, 2000)))

    rows: List[Dict[str, Any]] = []
    processed = 0
    timed_out = False

    for proc in psutil.process_iter(attrs=["pid", "name"], ad_value=None):
        if len(rows) >= limit_i:
            break
        if time.monotonic() - start_monotonic > max(1, int(timeout_s)):
            timed_out = True
            break

        try:
            with proc.oneshot():
                pid = proc.pid
                try:
                    name = proc.name()
                except Exception:
                    name = None

                try:
                    create_time = float(proc.create_time())
                except Exception:
                    create_time = None

                try:
                    ct = proc.cpu_times()
                    cpu_user = float(getattr(ct, "user", 0.0) or 0.0)
                    cpu_system = float(getattr(ct, "system", 0.0) or 0.0)
                except Exception:
                    cpu_user = None
                    cpu_system = None

                try:
                    io = proc.io_counters()
                    io_read = int(getattr(io, "read_bytes", 0) or 0)
                    io_write = int(getattr(io, "write_bytes", 0) or 0)
                except Exception:
                    io_read = None
                    io_write = None

            rows.append(
                {
                    "pid": pid,
                    "name": name,
                    "create_time": create_time,
                    "cpu_user": cpu_user,
                    "cpu_system": cpu_system,
                    "io_read_bytes": io_read,
                    "io_write_bytes": io_write,
                }
            )
            processed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "summary": {
            "processed_count": processed,
            "timed_out": timed_out,
            "limit": limit_i,
        },
        "processes": rows,
    }

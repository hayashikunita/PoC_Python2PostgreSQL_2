import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def _coerce_simple(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        # Keep payload small and JSON-friendly.
        return value.hex()[:512]
    return str(value)


def _reg_type_name(reg_type: Optional[int]) -> str:
    # Avoid importing winreg unless on Windows.
    if reg_type is None:
        return "UNKNOWN"
    try:
        import winreg  # type: ignore

        mapping = {
            getattr(winreg, "REG_SZ", -1): "REG_SZ",
            getattr(winreg, "REG_EXPAND_SZ", -1): "REG_EXPAND_SZ",
            getattr(winreg, "REG_DWORD", -1): "REG_DWORD",
            getattr(winreg, "REG_QWORD", -1): "REG_QWORD",
            getattr(winreg, "REG_MULTI_SZ", -1): "REG_MULTI_SZ",
            getattr(winreg, "REG_BINARY", -1): "REG_BINARY",
        }
        return mapping.get(reg_type, f"REG_{reg_type}")
    except Exception:
        return f"REG_{reg_type}"


def read_registry_value(*, hive: str, key_path: str, value_name: str) -> Dict[str, Any]:
    """Read a Windows registry value.

    Returns a JSON-serializable dict with exists/value/type/error.
    """

    result: Dict[str, Any] = {
        "hive": hive,
        "key_path": key_path,
        "value_name": value_name,
        "exists": False,
        "value": None,
        "value_type": None,
        "error": None,
    }

    if not is_windows():
        result["error"] = "Not running on Windows"
        return result

    try:
        import winreg  # type: ignore

        hive_upper = (hive or "").upper()
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        }
        root = hive_map.get(hive_upper)
        if root is None:
            result["error"] = f"Unsupported hive: {hive}"
            return result

        with winreg.OpenKey(root, key_path, 0, winreg.KEY_READ) as key:
            value, reg_type = winreg.QueryValueEx(key, value_name)
            result["exists"] = True
            result["value"] = _coerce_simple(value)
            result["value_type"] = _reg_type_name(reg_type)
            return result
    except FileNotFoundError:
        return result
    except PermissionError as e:
        result["error"] = f"PermissionError: {e}"
        return result
    except OSError as e:
        result["error"] = f"OSError: {e}"
        return result
    except Exception as e:
        result["error"] = f"Error: {e}"
        return result


def _evaluate_check(*, actual: Dict[str, Any], operator: str, expected: Any) -> Tuple[str, str]:
    """Return (level, message). level is one of ok/warn/error."""

    if actual.get("error"):
        return "error", str(actual.get("error"))

    exists = bool(actual.get("exists"))
    val = actual.get("value")

    op = (operator or "").lower().strip()

    if op in ("", "exists"):
        return ("ok", "存在します") if exists else ("warn", "見つかりません")

    if op == "nonempty":
        if not exists:
            return "warn", "見つかりません"
        if isinstance(val, str) and val.strip() != "":
            return "ok", "値があります"
        if val is None:
            return "warn", "値が空です"
        return "ok", "値があります"

    if op == "equals":
        if not exists:
            return "warn", "見つかりません"
        # Compare as string for robustness.
        if str(val) == str(expected):
            return "ok", "期待値と一致"
        return "warn", f"期待値と不一致（期待={expected} 実際={val}）"

    return "warn", f"未対応の判定ルール: {operator}"


def get_default_registry_checks() -> List[Dict[str, Any]]:
    return [
        {
            "id": "computer_name",
            "title": "コンピューター名",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
            "value_name": "ComputerName",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "product_name",
            "title": "Windows製品名",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "ProductName",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "edition_id",
            "title": "Windowsエディション",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "EditionID",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "display_version",
            "title": "Windowsバージョン（DisplayVersion）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "DisplayVersion",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "current_version",
            "title": "Windowsバージョン（CurrentVersion）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "CurrentVersion",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "build_number",
            "title": "ビルド番号",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "CurrentBuildNumber",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "ubr",
            "title": "更新ビルド番号（UBR）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "UBR",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "registered_owner",
            "title": "登録所有者（RegisteredOwner）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "value_name": "RegisteredOwner",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "timezone",
            "title": "タイムゾーン（TimeZoneKeyName）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            "value_name": "TimeZoneKeyName",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "domain",
            "title": "ドメイン（TCP/IP Domain）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "value_name": "Domain",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "dns_hostname",
            "title": "DNSホスト名（Hostname）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "value_name": "Hostname",
            "operator": "nonempty",
            "expected": None,
        },
        {
            "id": "active_probing",
            "title": "NLA Active Probing",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet",
            "value_name": "EnableActiveProbing",
            "operator": "equals",
            "expected": 1,
        },
        {
            "id": "uac_enable_lua",
            "title": "UAC有効（EnableLUA）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value_name": "EnableLUA",
            "operator": "equals",
            "expected": 1,
        },
        {
            "id": "rdp_deny",
            "title": "リモートデスクトップ無効（fDenyTSConnections）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "value_name": "fDenyTSConnections",
            "operator": "equals",
            "expected": 1,
        },
        {
            "id": "firewall_public",
            "title": "Windows Firewall（PublicProfile）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            "value_name": "EnableFirewall",
            "operator": "equals",
            "expected": 1,
        },
        {
            "id": "firewall_standard",
            "title": "Windows Firewall（StandardProfile）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            "value_name": "EnableFirewall",
            "operator": "equals",
            "expected": 1,
        },
        {
            "id": "proxy_enable",
            "title": "プロキシ有効（ProxyEnable）",
            "hive": "HKCU",
            "key_path": r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "value_name": "ProxyEnable",
            "operator": "equals",
            "expected": 0,
        },
        {
            "id": "proxy_server",
            "title": "プロキシ設定（ProxyServer）",
            "hive": "HKCU",
            "key_path": r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "value_name": "ProxyServer",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "w32time_ntp_server",
            "title": "NTPサーバ（W32Time NtpServer）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
            "value_name": "NtpServer",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "w32time_type",
            "title": "時刻同期方式（W32Time Type）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
            "value_name": "Type",
            "operator": "nonempty",
            "expected": None,
        },

        # --- Windows Update / WSUS ---
        {
            "id": "wsus_use_wuserver",
            "title": "WSUS利用（UseWUServer）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "value_name": "UseWUServer",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "wsus_server",
            "title": "WSUSサーバ（WUServer）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            "value_name": "WUServer",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "wsus_status_server",
            "title": "WSUSステータスサーバ（WUStatusServer）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
            "value_name": "WUStatusServer",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "wu_no_auto_update",
            "title": "自動更新無効（NoAutoUpdate）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "value_name": "NoAutoUpdate",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "wu_au_options",
            "title": "自動更新モード（AUOptions）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "value_name": "AUOptions",
            "operator": "exists",
            "expected": None,
        },

        # --- Microsoft Defender ---
        {
            "id": "defender_disable_antispyware_policy",
            "title": "Defender無効ポリシー（DisableAntiSpyware）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "value_name": "DisableAntiSpyware",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "defender_disable_realtime_policy",
            "title": "Defenderリアルタイム保護無効（DisableRealtimeMonitoring）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "value_name": "DisableRealtimeMonitoring",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "defender_disable_realtime_local",
            "title": "Defenderリアルタイム保護無効（ローカル設定）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "value_name": "DisableRealtimeMonitoring",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "defender_tamper_protection",
            "title": "Defender改ざん防止（TamperProtection）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows Defender\Features",
            "value_name": "TamperProtection",
            "operator": "exists",
            "expected": None,
        },

        # --- BitLocker ---
        {
            "id": "bitlocker_fve_policy_exists",
            "title": "BitLockerポリシー（FVE）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\FVE",
            "value_name": "EnableBDEWithNoTPM",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "bitlocker_enable_no_tpm",
            "title": "BitLocker: TPMなし許可（EnableBDEWithNoTPM）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\FVE",
            "value_name": "EnableBDEWithNoTPM",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "bitlocker_os_recovery",
            "title": "BitLocker: OS回復オプション（OSRecovery）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\FVE",
            "value_name": "OSRecovery",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "bitlocker_os_manage_dra",
            "title": "BitLocker: DRA（OSManageDRA）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Policies\Microsoft\FVE",
            "value_name": "OSManageDRA",
            "operator": "exists",
            "expected": None,
        },

        # --- SMB ---
        {
            "id": "smb1_server",
            "title": "SMB1（サーバ）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "value_name": "SMB1",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "smb2_server",
            "title": "SMB2（サーバ）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "value_name": "SMB2",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "smb_signing_server",
            "title": "SMB署名必須（サーバ RequireSecuritySignature）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "value_name": "RequireSecuritySignature",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "smb_signing_client",
            "title": "SMB署名必須（クライアント RequireSecuritySignature）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "value_name": "RequireSecuritySignature",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "smb_insecure_guest",
            "title": "不正なゲストログオン許可（AllowInsecureGuestAuth）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "value_name": "AllowInsecureGuestAuth",
            "operator": "equals",
            "expected": 0,
        },

        # --- Logon / Local Security (registry-representable subset) ---
        {
            "id": "dont_display_last_user",
            "title": "最終ログオンユーザーを表示しない（DontDisplayLastUserName）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value_name": "DontDisplayLastUserName",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "legal_notice_caption",
            "title": "ログオンメッセージ（Caption）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value_name": "LegalNoticeCaption",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "legal_notice_text",
            "title": "ログオンメッセージ（Text）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value_name": "LegalNoticeText",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "limit_blank_password_use",
            "title": "空パスワードのネットワークログオン制限（LimitBlankPasswordUse）",
            "hive": "HKLM",
            "key_path": r"SYSTEM\CurrentControlSet\Control\Lsa",
            "value_name": "LimitBlankPasswordUse",
            "operator": "equals",
            "expected": 1,
        },
        {
            "id": "cached_logons_count",
            "title": "キャッシュログオン（CachedLogonsCount）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "value_name": "CachedLogonsCount",
            "operator": "exists",
            "expected": None,
        },
        {
            "id": "disable_cad",
            "title": "Ctrl+Alt+Del不要（DisableCAD）",
            "hive": "HKLM",
            "key_path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "value_name": "DisableCAD",
            "operator": "exists",
            "expected": None,
        },
    ]


def collect_registry_report() -> Dict[str, Any]:
    hostname = socket.gethostname()
    collected_at = _now_iso()

    checks = get_default_registry_checks()
    results: List[Dict[str, Any]] = []

    for c in checks:
        actual = read_registry_value(hive=c["hive"], key_path=c["key_path"], value_name=c["value_name"])
        level, message = _evaluate_check(actual=actual, operator=c.get("operator", ""), expected=c.get("expected"))
        results.append(
            {
                **c,
                "actual": {
                    "exists": actual.get("exists"),
                    "value": actual.get("value"),
                    "value_type": actual.get("value_type"),
                    "error": actual.get("error"),
                },
                "level": level,
                "message": message,
            }
        )

    return {
        "collected_at": collected_at,
        "hostname": hostname,
        "is_windows": is_windows(),
        "checks": results,
    }
